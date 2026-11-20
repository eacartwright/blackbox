//! `bbx install` / `bbx uninstall`.

use crate::service::{DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};
use anyhow::{anyhow, bail, Context, Result};
use bbx_collect::{blackbox, bootinfo};
use bbx_core::config::Config;
use bbx_core::paths::Paths;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub struct InstallOptions {
    pub profile: Option<String>,
    pub system_changes: bool,
    pub start: bool,
}

pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), 4, &mut len);
        CloseHandle(tok);
        ok != 0 && e.TokenIsElevated != 0
    }
}

fn require_admin() -> Result<()> {
    if !is_elevated() {
        bail!("this command must be run from an elevated (Administrator) prompt");
    }
    Ok(())
}

fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("BlackBox")
}

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            eprintln!("  ! {cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
            false
        }
        Err(e) => {
            eprintln!("  ! could not run {cmd}: {e}");
            false
        }
    }
}

fn wait_for_state(svc: &windows_service::service::Service, want: ServiceState, timeout: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if svc.query_status().map(|s| s.current_state == want).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

pub fn install(opts: InstallOptions) -> Result<()> {
    require_admin()?;
    let paths = Paths::from_env();
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

    // Stop an existing instance so its exe can be replaced.
    let existing = mgr
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .ok();
    if let Some(svc) = &existing {
        if svc.query_status()?.current_state != ServiceState::Stopped {
            println!("Stopping the running BlackBox service...");
            svc.stop().ok();
            wait_for_state(svc, ServiceState::Stopped, Duration::from_secs(30));
        }
    }

    // 1. Program files.
    let dir = install_dir();
    std::fs::create_dir_all(&dir)?;
    let exe_src = std::env::current_exe()?;
    let exe_dst = dir.join("bbx.exe");
    if !same_file(&exe_src, &exe_dst) {
        std::fs::copy(&exe_src, &exe_dst).with_context(|| format!("copy to {}", exe_dst.display()))?;
    }
    println!("Installed {}", exe_dst.display());

    // 2. Data directories, locked to SYSTEM + Administrators; users may only
    //    drop marker files into triggers\.
    paths.ensure()?;
    let root = paths.root.display().to_string();
    run("icacls", &[&root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/Q"]);
    run("icacls", &[&paths.triggers().display().to_string(), "/grant", "*S-1-5-32-545:(WD,AD,S)", "/Q"]);
    println!("Data directory {root} (SYSTEM and Administrators only)");

    // 3. Config.
    let cfg_path = paths.config();
    let mut cfg = Config::load(&cfg_path);
    if let Some(p) = &opts.profile {
        cfg.profile = p.clone();
    }
    if !cfg_path.exists() || opts.profile.is_some() {
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg)?)?;
        println!("Wrote {}", cfg_path.display());
    }

    // 4. Service with automatic restart on failure.
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_dst.clone(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = match existing {
        Some(svc) => {
            svc.change_config(&info)?;
            svc
        }
        None => mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)?,
    };
    svc.set_description(DESCRIPTION)?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
        ]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    println!("Service '{SERVICE_NAME}' registered (automatic start, restarts on failure)");

    // 5. Make Windows record more.
    if opts.system_changes {
        apply_system_changes();
    } else {
        println!("Skipping system changes (--no-system-changes)");
    }

    if opts.start {
        svc.start(&[] as &[&str])?;
        if wait_for_state(&svc, ServiceState::Running, Duration::from_secs(15)) {
            println!("Service started. Recording.");
        } else {
            println!("Service start requested; check `bbx status` in a few seconds.");
        }
    }
    Ok(())
}

fn apply_system_changes() {
    println!("Configuring Windows to keep more evidence:");
    for ch in ["Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-DriverFrameworks-UserMode/Operational"] {
        if run("wevtutil", &["sl", ch, "/e:true"]) {
            println!("  - enabled event channel {ch}");
        }
    }
    for log in ["System", "Application"] {
        if run("wevtutil", &["sl", log, "/ms:134217728"]) {
            println!("  - {log} event log size set to 128 MB");
        }
    }
    // Keep a kernel dump on bugcheck (Automatic memory dump) unless dumps are
    // already set to kernel/complete/automatic/active.
    const CC: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl";
    let current = bootinfo::reg_dword(CC, "CrashDumpEnabled").unwrap_or(7);
    if current == 0 || current == 3 {
        if run("reg", &["add", &format!(r"HKLM\{CC}"), "/v", "CrashDumpEnabled", "/t", "REG_DWORD", "/d", "7", "/f"]) {
            println!("  - crash dumps changed from {current} to Automatic memory dump");
        }
    }
    // Manual crash for total freezes: hold Right Ctrl, press Scroll Lock twice.
    for svc in ["kbdhid", "i8042prt", "hyperkbd"] {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{svc}\Parameters");
        run("reg", &["add", &key, "/v", "CrashOnCtrlScroll", "/t", "REG_DWORD", "/d", "1", "/f"]);
    }
    println!("  - CrashOnCtrlScroll enabled (after the next reboot, hold Right Ctrl + press Scroll Lock twice to force a dump during a total freeze)");
}

pub fn uninstall(purge: bool) -> Result<()> {
    require_admin()?;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(svc) => {
            if svc.query_status()?.current_state != ServiceState::Stopped {
                svc.stop().ok();
                wait_for_state(&svc, ServiceState::Stopped, Duration::from_secs(30));
            }
            svc.delete()?;
            println!("Service removed");
        }
        Err(_) => println!("Service was not installed"),
    }
    blackbox::stop()?;
    println!("Black-box ETW session stopped");
    let paths = Paths::from_env();
    if purge {
        std::fs::remove_dir_all(&paths.root).map_err(|e| anyhow!("removing {}: {e}", paths.root.display()))?;
        println!("Deleted {}", paths.root.display());
    } else {
        println!("Recorded data kept in {} (use --purge to delete it)", paths.root.display());
    }
    println!(
        "Note: event log sizes, crash-dump and CrashOnCtrlScroll settings were left as they are.\n\
         The program itself is in {}; delete that folder once the service is gone.",
        install_dir().display()
    );
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}
