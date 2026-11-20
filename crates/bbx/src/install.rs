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

/// Protected DACL: SYSTEM and Administrators, full control, inherited by
/// subfolders and files. Nothing else.
pub const ROOT_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Replace a path's DACL with the one in `sddl` (and its protected flag).
pub fn set_exact_dacl(path: &Path, sddl: &str) -> Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    const SDDL_REVISION_1: u32 = 1;
    let w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let p: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
            bail!("invalid SDDL: {}", std::io::Error::last_os_error());
        }
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
        let rc = SetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        );
        LocalFree(sd as _);
        if rc != 0 {
            bail!("SetNamedSecurityInfo failed: {}", std::io::Error::from_raw_os_error(rc as i32));
        }
    }
    Ok(())
}

const RUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

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

    // 1. Program files (stop user agents first: their exe would be locked).
    run("taskkill", &["/IM", "bbx-agent.exe", "/F"]);
    let dir = install_dir();
    std::fs::create_dir_all(&dir)?;
    let exe_src = std::env::current_exe()?;
    let exe_dst = dir.join("bbx.exe");
    if !same_file(&exe_src, &exe_dst) {
        std::fs::copy(&exe_src, &exe_dst).with_context(|| format!("copy to {}", exe_dst.display()))?;
    }
    println!("Installed {}", exe_dst.display());
    let agent_src = exe_src.with_file_name("bbx-agent.exe");
    let agent_dst = dir.join("bbx-agent.exe");
    let have_agent = if agent_src.exists() {
        if !same_file(&agent_src, &agent_dst) {
            std::fs::copy(&agent_src, &agent_dst).with_context(|| format!("copy to {}", agent_dst.display()))?;
        }
        println!("Installed {}", agent_dst.display());
        true
    } else {
        println!("Note: bbx-agent.exe not found next to bbx.exe; the user-session agent will not be installed");
        false
    };

    // 2. Data directories, locked to SYSTEM + Administrators; users may only
    //    drop marker files into triggers\.
    paths.ensure()?;
    let root = paths.root.display().to_string();
    // Exactly SYSTEM + Administrators, protected from inheritance. Replacing
    // the whole DACL also removes entries added later by hand (e.g. Explorer's
    // "Continue" prompt grants the clicking account full control).
    if let Err(e) = set_exact_dacl(&paths.root, ROOT_SDDL) {
        eprintln!("  ! could not set permissions on {root}: {e:#}");
    }
    let children = format!("{root}\\*");
    if !run("icacls", &[&children, "/reset", "/T", "/C", "/Q"]) {
        // Files with a broken ACL can't be reset until Administrators own them.
        run("takeown", &["/F", &root, "/R", "/A", "/D", "Y"]);
        if !run("icacls", &[&children, "/reset", "/T", "/C", "/Q"]) {
            eprintln!("  ! some files under {root} could not be reset; see the messages above");
        }
    }
    // Users: create files in triggers\ (and only touch their own), read public\.
    run("icacls", &[&paths.triggers().display().to_string(), "/grant", "*S-1-5-32-545:(WD,AD,S)", "*S-1-3-0:(OI)(CI)(IO)M", "/Q"]);
    run("icacls", &[&paths.public().display().to_string(), "/grant", "*S-1-5-32-545:(OI)(CI)RX", "/Q"]);
    println!("Data directory {root} (SYSTEM and Administrators only; users can drop marks and read agent settings)");

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

    // 6. User-session agent at every sign-in, and now for this user.
    if have_agent {
        let cmd = format!("\"{}\"", agent_dst.display());
        if run("reg", &["add", RUN_KEY, "/v", "BlackBoxAgent", "/t", "REG_SZ", "/d", &cmd, "/f"]) {
            println!("Tray agent will start at every user sign-in");
        }
        // Launch through Explorer so it runs unelevated as the signed-in user.
        if std::process::Command::new("explorer.exe").arg(&agent_dst).spawn().is_ok() {
            println!("Tray agent started for this session");
        }
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

/// Deliberate stop: the service and both ETW sessions. (A crashed service
/// leaves the black box running on purpose; a requested stop must not, or
/// nothing would prune its files.)
pub fn stop_recording() -> Result<()> {
    require_admin()?;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP).context("BlackBox is not installed")?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        svc.stop()?;
        if !wait_for_state(&svc, ServiceState::Stopped, Duration::from_secs(30)) {
            bail!("the service did not stop within 30 s");
        }
    }
    blackbox::stop()?;
    bbx_collect::etwlive::stop_session(bbx_collect::etwlive::LIVE_SESSION);
    println!("BlackBox stopped recording. Start it again with `bbx start` (it also starts at the next boot).");
    Ok(())
}

pub fn start_recording() -> Result<()> {
    require_admin()?;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START).context("BlackBox is not installed")?;
    if svc.query_status()?.current_state != ServiceState::Running {
        svc.start(&[] as &[&str])?;
        if !wait_for_state(&svc, ServiceState::Running, Duration::from_secs(15)) {
            bail!("the service did not report running within 15 s; see `bbx status`");
        }
    }
    println!("BlackBox is recording.");
    Ok(())
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
    bbx_collect::etwlive::stop_session(bbx_collect::etwlive::LIVE_SESSION);
    if Config::load(&Paths::from_env().config()).packet_capture {
        bbx_collect::pktmon::stop();
    }
    run("reg", &["delete", RUN_KEY, "/v", "BlackBoxAgent", "/f"]);
    run("taskkill", &["/IM", "bbx-agent.exe", "/F"]);
    println!("Tray agent removed");
    println!("Black-box and live ETW sessions stopped");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(p: &Path) -> String {
        let o = Command::new("icacls").arg(p).output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    #[test]
    fn exact_dacl_removes_extra_entries() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("root");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("f.bin"), b"x").unwrap();
        // An extra explicit entry, like Explorer's "Continue" adds.
        assert!(Command::new("icacls").arg(&dir).args(["/grant", "*S-1-5-32-545:(OI)(CI)F", "/Q"]).status().unwrap().success());
        assert!(acl(&dir).contains(r"BUILTIN\Users"));

        set_exact_dacl(&dir, ROOT_SDDL).unwrap();
        let a = acl(&dir);
        assert!(!a.contains(r"BUILTIN\Users"), "{a}");
        assert!(a.contains(r"NT AUTHORITY\SYSTEM:(OI)(CI)(F)") && a.contains(r"BUILTIN\Administrators:(OI)(CI)(F)"), "{a}");
        assert_eq!(a.lines().filter(|l| l.contains(":(")).count(), 2, "{a}");

        // Give ourselves back access so the temp dir can be removed.
        set_exact_dacl(&dir, "D:P(A;OICI;FA;;;WD)").unwrap();
    }
}
