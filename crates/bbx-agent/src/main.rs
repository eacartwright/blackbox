//! bbx-agent: BlackBox's eyes inside each interactive session.
//!
//! Runs as the signed-in user (started at logon), shows a tray icon, and
//! reports what the SYSTEM service can't see: hung windows, the display
//! turning off, session lock/unlock, foreground app, idle/active, UI stalls,
//! and an "It just happened" button / hotkey (Ctrl+Alt+Shift+B). Optionally
//! keeps a ring of low-resolution screenshots, saved only with incidents.
//!
//! Talks to the service only through files (see bbx_core::agentproto).

#![windows_subsystem = "windows"]

mod outbox;
mod service;
mod screens;
mod watch;

use bbx_core::agentproto::{AgentSettings, IncidentSignal, MarkFile};
use bbx_core::paths::Paths;
use bbx_core::time::now_ft;
use std::cell::RefCell;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::{RegisterPowerSettingNotification, POWERBROADCAST_SETTING};
use windows_sys::Win32::System::RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_LARGE_ICON, NIIF_USER, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const TIMER_ID: usize = 1;
const TICK_MS: u32 = 2000;
const HOTKEY_ID: i32 = 1;
const CMD_MARK: usize = 100;
const CMD_ABOUT: usize = 101;
const CMD_TOGGLE: usize = 102;
const CMD_EXIT: usize = 103;
const CMD_VIEW: usize = 104;
const CMD_SEND: usize = 105;
/// Posted by the "Send to technician" worker thread when the export ends.
const WM_EXPORT_DONE: u32 = WM_APP + 2;
/// Posted when the elevated viewer has said where its page is.
const WM_VIEW_READY: u32 = WM_APP + 3;
const ERROR_ALREADY_EXISTS: u32 = 183;
const DEVICE_NOTIFY_WINDOW_HANDLE: u32 = 0;
const PBT_APMSUSPEND: usize = 0x4;
const PBT_APMRESUMESUSPEND: usize = 0x7;
const PBT_APMRESUMEAUTOMATIC: usize = 0x12;
const PBT_POWERSETTINGCHANGE: usize = 0x8013;
const WM_WTSSESSION_CHANGE_: u32 = 0x02B1;
/// GUID_CONSOLE_DISPLAY_STATE {6FE69556-704A-47A0-8F24-C28D936FDA47}
const GUID_CONSOLE_DISPLAY_STATE: windows_sys::core::GUID = windows_sys::core::GUID::from_u128(0x6fe69556_704a_47a0_8f24_c28d936fda47);

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct Agent {
    hwnd: HWND,
    paths: Paths,
    settings: AgentSettings,
    settings_checked: Instant,
    out: outbox::Outbox,
    watch: watch::Watcher,
    screens: screens::Ring,
    last_tick: Instant,
    last_signal: Option<String>,
    /// Last seen service state, to announce when recording stops or starts.
    service_running: Option<bool>,
    taskbar_created: u32,
    /// Suppress stall detection right after resume/unlock.
    quiet_until: Instant,
}

thread_local! {
    static AGENT: RefCell<Option<Agent>> = const { RefCell::new(None) };
}

fn with_agent(f: impl FnOnce(&mut Agent)) {
    AGENT.with(|a| {
        if let Ok(mut g) = a.try_borrow_mut() {
            if let Some(agent) = g.as_mut() {
                f(agent);
            }
        }
    });
}

fn session_id() -> u32 {
    let mut s = 0u32;
    unsafe { windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(std::process::id(), &mut s) };
    s
}

fn load_settings(paths: &Paths) -> AgentSettings {
    std::fs::read(paths.public().join("agent.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn main() {
    // `--start` (the Start menu shortcut): turn recording back on first. Done
    // before the single-instance check so it also works while the tray icon
    // is already showing "not recording".
    if std::env::args().any(|a| a == "--start") && service::running() == Some(false) {
        if let Err(why) = service::run_elevated_wait(std::ptr::null_mut(), "start", 60_000) {
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    wide(&format!("BlackBox could not start recording: {why}.")).as_ptr(),
                    wide("BlackBox").as_ptr(),
                    MB_OK | MB_ICONWARNING,
                );
            }
        }
    }
    // One agent per session.
    let name = wide(r"Local\BlackBoxAgent");
    let _mutex = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return;
    }
    let paths = Paths::from_env();
    let user = std::env::var("USERNAME").unwrap_or_default();
    let session = session_id();

    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("BlackBoxAgentWindow");
        // The window's own icon: Windows may use it for the app in
        // notifications (otherwise a generic "i" shows in their header).
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class.as_ptr(),
            hIcon: balloon_icon(),
            hIconSm: tray_icon(true),
            ..std::mem::zeroed()
        };
        RegisterClassExW(&wc);
        // A hidden top-level window (not message-only: those miss broadcast
        // messages like WM_DISPLAYCHANGE and TaskbarCreated).
        let hwnd = CreateWindowExW(0, class.as_ptr(), wide("BlackBox Agent").as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null());
        if hwnd.is_null() {
            return;
        }
        let settings = load_settings(&paths);
        let taskbar_created = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());
        AGENT.with(|a| {
            *a.borrow_mut() = Some(Agent {
                hwnd,
                out: outbox::Outbox::new(paths.triggers(), session, user.clone()),
                watch: watch::Watcher::new(settings.hung_window_s),
                screens: screens::Ring::new(),
                settings,
                settings_checked: Instant::now(),
                paths: paths.clone(),
                last_tick: Instant::now(),
                last_signal: read_signal(&paths).map(|s| s.id),
                service_running: service::running(),
                taskbar_created,
                quiet_until: Instant::now() + Duration::from_secs(10),
            })
        });
        add_tray(hwnd);
        RegisterHotKey(hwnd, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, 'B' as u32);
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        RegisterPowerSettingNotification(hwnd as _, &GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_WINDOW_HANDLE);
        SetTimer(hwnd, TIMER_ID, TICK_MS, None);
        with_agent(|a| a.out.push("agent", "", 0, "started", 0.0, true));

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        remove_tray(hwnd);
        with_agent(|a| {
            a.out.push("agent", "", 0, "stopped", 0.0, true);
            a.out.flush();
        });
    }
}

/// Tray tooltip text (max 127 characters).
const TIP_RECORDING: &str = "BlackBox is ON";
const TIP_STOPPED: &str = "BlackBox is OFF";

fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

/// Icon resource ids embedded by build.rs (assets/blackbox*.ico).
const ICON_RECORDING: u16 = 1;
const ICON_STOPPED: u16 = 2;

/// The tray icon at the small-icon size for this display's DPI.
fn tray_icon(recording: bool) -> HICON {
    let id = if recording { ICON_RECORDING } else { ICON_STOPPED };
    unsafe {
        let (cx, cy) = (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
        let h = LoadImageW(GetModuleHandleW(std::ptr::null()), id as usize as *const u16, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
        if h.is_null() {
            LoadIconW(std::ptr::null_mut(), IDI_INFORMATION)
        } else {
            h as HICON
        }
    }
}

fn add_tray(hwnd: HWND) {
    let recording = service::running() != Some(false);
    let mut nid = icon_data(hwnd);
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = tray_icon(recording);
    copy_into(&mut nid.szTip, if recording { TIP_RECORDING } else { TIP_STOPPED });
    unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
}

/// Tooltip and icon (red dot / grey ring) for the recording state.
fn set_tip(hwnd: HWND, recording: bool) {
    let mut nid = icon_data(hwnd);
    nid.uFlags = NIF_TIP | NIF_ICON;
    nid.hIcon = tray_icon(recording);
    let tip = if recording { TIP_RECORDING } else { TIP_STOPPED };
    copy_into(&mut nid.szTip, tip);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
}

fn remove_tray(hwnd: HWND) {
    let nid = icon_data(hwnd);
    unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
}

/// The BlackBox icon at notification size (the big icon in the toast).
fn balloon_icon() -> HICON {
    unsafe {
        let (cx, cy) = (GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
        LoadImageW(GetModuleHandleW(std::ptr::null()), ICON_RECORDING as usize as *const u16, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR) as HICON
    }
}

fn balloon(hwnd: HWND, title: &str, text: &str) {
    let mut nid = icon_data(hwnd);
    // Re-send the tray icon too: the notification header may take its
    // small icon from it.
    nid.uFlags = NIF_INFO | NIF_ICON;
    nid.hIcon = tray_icon(service::running() != Some(false));
    // Our own icon instead of Windows' generic "i".
    let icon = balloon_icon();
    if icon.is_null() {
        nid.dwInfoFlags = NIIF_INFO;
    } else {
        nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
        nid.hBalloonIcon = icon;
    }
    copy_into(&mut nid.szInfoTitle, title);
    copy_into(&mut nid.szInfo, text);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, CMD_MARK, wide("Capture Incident\tCtrl+Alt+Shift+B").as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        // Both read the recordings, which only administrators can (UAC prompt).
        AppendMenuW(menu, MF_STRING, CMD_VIEW, wide("View recordings…").as_ptr());
        let busy = if EXPORTING.load(std::sync::atomic::Ordering::SeqCst) { MF_GRAYED } else { 0 };
        AppendMenuW(menu, MF_STRING | busy, CMD_SEND, wide("Send to technician…").as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        // Stopping or starting the service needs an administrator (UAC prompt).
        let toggle = match service::running() {
            Some(true) => Some("Stop recording…"),
            Some(false) => Some("Start recording…"),
            None => None, // service not installed
        };
        if let Some(t) = toggle {
            AppendMenuW(menu, MF_STRING, CMD_TOGGLE, wide(t).as_ptr());
        }
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_ABOUT, wide("About BlackBox").as_ptr());
        AppendMenuW(menu, MF_STRING, CMD_EXIT, wide("Exit…").as_ptr());
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, std::ptr::null());
        DestroyMenu(menu);
        match cmd as usize {
            CMD_MARK => mark(),
            CMD_TOGGLE => {
                let verb = if service::running() == Some(true) { "stop" } else { "start" };
                if !service::run_elevated(hwnd, verb) {
                    balloon(hwnd, "BlackBox", "Not changed: administrator approval is needed to stop or start recording.");
                }
            }
            CMD_EXIT => exit(hwnd),
            CMD_VIEW => view_recordings(hwnd),
            CMD_SEND => send_to_technician(hwnd),
            CMD_ABOUT => {
                MessageBoxW(
                    hwnd,
                    wide("BlackBox records what this PC is doing so that freezes, crashes and slowdowns can be investigated afterwards.\n\nIf something goes wrong, use \"Capture Incident\" (or press Ctrl+Alt+Shift+B) right away. Your IT support will be able to see what happened just before.").as_ptr(),
                    wide("BlackBox").as_ptr(),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            _ => {}
        }
    }
}

/// Tray "Exit": stop recording (service and black box, behind UAC), then
/// close the tray agent. Both come back at the next restart / sign-in.
fn exit(hwnd: HWND) {
    unsafe {
        let ok = MessageBoxW(
            hwnd,
            wide("Stop recording and close BlackBox?\n\nProblems that happen from now on will not be captured. BlackBox starts again the next time this PC restarts, or open BlackBox from the Start menu.").as_ptr(),
            wide("Exit BlackBox").as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        );
        if ok != IDYES {
            return;
        }
    }
    if service::running() == Some(true) {
        // Waiting blocks our message loop; don't log that as a desktop stall.
        with_agent(|a| a.quiet_until = Instant::now() + Duration::from_secs(90));
        if let Err(why) = service::run_elevated_wait(hwnd, "stop", 60_000) {
            balloon(hwnd, "BlackBox is still running", &format!("Not stopped: {why}."));
            return;
        }
    }
    unsafe { DestroyWindow(hwnd) };
}

static VIEW_RESULT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Tray "View recordings": start the viewer elevated (it must read the
/// recordings) without a browser, wait for it to write its page address to
/// a file, then open that address as this user. An elevated process can't
/// open the user's browser (explorer.exe just shows Documents).
fn view_recordings(hwnd: HWND) {
    let file = std::env::temp_dir().join(format!("blackbox-view-{}-{}.txt", std::process::id(), local_stamp()));
    let _ = std::fs::remove_file(&file);
    // Runs hidden; it quits 10 minutes after the browser page closes.
    let args = format!("view --local --idle-exit 600 --url-file \"{}\"", file.display());
    if !service::run_elevated(hwnd, &args) {
        balloon(hwnd, "BlackBox", "Not opened: administrator approval is needed to view the recordings.");
        return;
    }
    let hwnd_v = hwnd as isize;
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let text = loop {
            if let Ok(s) = std::fs::read_to_string(&file) {
                let _ = std::fs::remove_file(&file);
                break s.trim().to_string();
            }
            if t0.elapsed() > Duration::from_secs(120) {
                break "ERROR: the viewer did not start".to_string();
            }
            std::thread::sleep(Duration::from_millis(300));
        };
        *VIEW_RESULT.lock().unwrap() = Some(text);
        unsafe { PostMessageW(hwnd_v as HWND, WM_VIEW_READY, 0, 0) };
    });
}

fn view_ready(hwnd: HWND) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let Some(text) = VIEW_RESULT.lock().unwrap().take() else { return };
    unsafe {
        if text.starts_with("http://127.0.0.1:") {
            ShellExecuteW(hwnd, wide("open").as_ptr(), wide(&text).as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL);
        } else if text == "EMPTY" {
            MessageBoxW(
                hwnd,
                wide("BlackBox hasn't recorded anything on this PC yet.\n\nIt starts recording as soon as it's installed; try again in a minute.").as_ptr(),
                wide("View recordings").as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            );
        } else {
            let why = text.strip_prefix("ERROR: ").unwrap_or(&text);
            MessageBoxW(hwnd, wide(&format!("The recordings could not be opened.\n\n{why}")).as_ptr(), wide("View recordings").as_ptr(), MB_OK | MB_ICONWARNING);
        }
    }
}

static EXPORTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EXPORT_RESULT: std::sync::Mutex<Option<Result<std::path::PathBuf, String>>> = std::sync::Mutex::new(None);

/// This user's Desktop (follows OneDrive / folder redirection).
fn desktop_dir() -> std::path::PathBuf {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath};
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        if SHGetKnownFolderPath(&FOLDERID_Desktop, 0, std::ptr::null_mut(), &mut p) == 0 && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            CoTaskMemFree(p as _);
            return s.into();
        }
    }
    std::path::PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default()).join("Desktop")
}

fn local_stamp() -> String {
    let t = unsafe {
        let mut t = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t);
        t
    };
    format!("{:04}{:02}{:02}-{:02}{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute)
}

/// Tray "Send to technician": export the newest incident (or the last 30
/// minutes) to the Desktop, encrypted for the technician when a key is set,
/// then show it in Explorer. The export runs elevated on a worker thread.
fn send_to_technician(hwnd: HWND) {
    let ok = unsafe {
        MessageBoxW(
            hwnd,
            wide("Save what BlackBox recorded so your IT support can look at it?\n\nThis saves the most recent incident (or, if there isn't one from today, the last 30 minutes) as a file on your Desktop. Send that file to your IT support by email or file sharing.\n\nIt can take a minute and the file may be large.").as_ptr(),
            wide("Send to technician").as_ptr(),
            MB_YESNO | MB_ICONQUESTION,
        )
    };
    if ok != IDYES || EXPORTING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into());
    let base = desktop_dir().join(format!("BlackBox-{computer}-{}.zip", local_stamp()));
    balloon(hwnd, "BlackBox: saving", "Saving the recording to your Desktop. This can take a minute.");
    let hwnd_v = hwnd as isize;
    std::thread::spawn(move || {
        let hwnd = hwnd_v as HWND;
        let args = format!("export --latest --out \"{}\"", base.display());
        let res = service::run_elevated_wait(hwnd, &args, 15 * 60_000).and_then(|_| {
            let enc = std::path::PathBuf::from(format!("{}.age", base.display()));
            [enc, base.clone()].into_iter().find(|p| p.exists()).ok_or_else(|| "the file was not created".to_string())
        });
        *EXPORT_RESULT.lock().unwrap() = Some(res);
        unsafe { PostMessageW(hwnd, WM_EXPORT_DONE, 0, 0) };
    });
}

fn export_done(hwnd: HWND) {
    EXPORTING.store(false, std::sync::atomic::Ordering::SeqCst);
    match EXPORT_RESULT.lock().unwrap().take() {
        Some(Ok(path)) => {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            balloon(hwnd, "BlackBox: saved to your Desktop", &format!("{name}\nSend this file to your IT support."));
            std::process::Command::new("explorer.exe").arg(format!("/select,{}", path.display())).spawn().ok();
        }
        Some(Err(why)) => balloon(hwnd, "BlackBox: not saved", &format!("The recording was not saved: {why}.")),
        None => {}
    }
}

fn mark() {
    with_agent(|a| {
        let fg = watch::foreground_process().unwrap_or_default();
        let mf = MarkFile { note: format!("user pressed Capture Incident (foreground: {fg})"), user: a.out.user.clone(), session: a.out.session, foreground: fg };
        a.out.push("mark", &mf.foreground, 0, "", 0.0, true);
        a.out.flush();
        a.out.write_mark(&mf);
        if a.settings.screenshots {
            a.screens.capture(a.settings.screenshot_width, a.settings.screenshot_frames);
            a.out.write_shots("mark", &a.screens);
        }
        balloon(a.hwnd, "BlackBox: saved", "Thanks. What the PC was doing just before now has been saved for your IT support.");
    });
}

fn read_signal(paths: &Paths) -> Option<IncidentSignal> {
    std::fs::read(paths.public().join("incident.json")).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

fn on_tick() {
    with_agent(|a| {
        let gap = a.last_tick.elapsed();
        a.last_tick = Instant::now();
        // Our own message loop ran late: the user session stalled.
        if gap > Duration::from_millis(TICK_MS as u64 * 3) && Instant::now() > a.quiet_until {
            a.out.push("ui_stall", "", 0, "the desktop session stopped processing messages", gap.as_millis() as f64, true);
        }
        // Announce recording stopping or starting (by anyone, not just us).
        let now_running = service::running();
        if now_running.is_some() && now_running != a.service_running {
            if a.service_running.is_some() {
                let (title, text) = if now_running == Some(true) {
                    ("BlackBox: recording", "BlackBox is recording again.")
                } else {
                    ("BlackBox: stopped", "BlackBox has stopped recording. Problems from now on will not be captured.")
                };
                balloon(a.hwnd, title, text);
            }
            a.service_running = now_running;
            set_tip(a.hwnd, now_running == Some(true));
        }
        if a.settings_checked.elapsed() > Duration::from_secs(60) {
            a.settings_checked = Instant::now();
            a.settings = load_settings(&a.paths);
            a.watch.hung_after = a.settings.hung_window_s;
        }
        for e in a.watch.tick() {
            let urgent = e.kind == "hung" || e.kind == "hung_end";
            if e.kind == "hung" && a.settings.screenshots {
                a.screens.capture(a.settings.screenshot_width, a.settings.screenshot_frames);
                a.out.write_shots("hung", &a.screens);
            }
            a.out.push(&e.kind, &e.proc, e.pid, &e.detail, e.value, urgent);
        }
        if a.settings.screenshots && a.screens.due(a.settings.screenshot_interval_s) {
            a.screens.capture(a.settings.screenshot_width, a.settings.screenshot_frames);
        } else if !a.settings.screenshots {
            a.screens.clear();
        }
        // A new incident opened by the service: hand over our frames.
        if let Some(sig) = read_signal(&a.paths) {
            if a.last_signal.as_deref() != Some(sig.id.as_str()) {
                a.last_signal = Some(sig.id.clone());
                if a.settings.screenshots && now_ft() - sig.at_ft < 600 * bbx_core::time::FT_PER_SEC {
                    a.out.write_shots(&sig.id, &a.screens);
                }
            }
        }
        a.out.maybe_flush();
    });
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_TIMER if wp == TIMER_ID => on_tick(),
        WM_EXPORT_DONE => export_done(hwnd),
        WM_VIEW_READY => view_ready(hwnd),
        WM_HOTKEY if wp as i32 == HOTKEY_ID => mark(),
        WM_TRAY => match lp as u32 {
            WM_RBUTTONUP | WM_CONTEXTMENU | WM_LBUTTONDBLCLK => show_menu(hwnd),
            _ => {}
        },
        WM_POWERBROADCAST => {
            match wp {
                PBT_POWERSETTINGCHANGE if lp != 0 => {
                    let s = &*(lp as *const POWERBROADCAST_SETTING);
                    if s.PowerSetting.data1 == GUID_CONSOLE_DISPLAY_STATE.data1 && s.DataLength >= 4 {
                        let state = std::ptr::read_unaligned(s.Data.as_ptr() as *const u32);
                        let what = match state { 0 => "off", 1 => "on", 2 => "dimmed", _ => "unknown" };
                        with_agent(|a| {
                            let idle = watch::idle_seconds();
                            a.out.push("display", "", 0, what, idle, true);
                            if state == 1 {
                                a.quiet_until = Instant::now() + Duration::from_secs(10);
                            }
                        });
                    }
                }
                PBT_APMSUSPEND => with_agent(|a| {
                    a.out.push("power", "", 0, "suspend", 0.0, true);
                    a.out.flush();
                }),
                PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC => with_agent(|a| {
                    a.quiet_until = Instant::now() + Duration::from_secs(15);
                    a.out.push("power", "", 0, "resume", 0.0, true);
                }),
                _ => {}
            }
            return 1;
        }
        WM_WTSSESSION_CHANGE_ => {
            let what = match wp { 1 => "console_connect", 2 => "console_disconnect", 3 => "remote_connect", 4 => "remote_disconnect", 5 => "logon", 6 => "logoff", 7 => "lock", 8 => "unlock", _ => "other" };
            with_agent(|a| {
                a.quiet_until = Instant::now() + Duration::from_secs(10);
                a.out.push("session", "", 0, what, 0.0, true);
            });
        }
        WM_DISPLAYCHANGE => {
            let (w, h) = ((lp & 0xFFFF) as u32, ((lp >> 16) & 0xFFFF) as u32);
            let monitors = GetSystemMetrics(SM_CMONITORS);
            with_agent(|a| a.out.push("resolution", "", 0, &format!("{w}x{h}, {monitors} monitor(s)"), monitors as f64, true));
        }
        WM_QUERYENDSESSION => return 1,
        WM_ENDSESSION => with_agent(|a| {
            a.out.push("session", "", 0, "ending", 0.0, true);
            a.out.flush();
        }),
        WM_DESTROY => PostQuitMessage(0),
        m if m != 0 && AGENT.with(|a| a.try_borrow().ok().and_then(|g| g.as_ref().map(|x| x.taskbar_created))) == Some(m) => {
            // Explorer restarted (crashed?): put the icon back and note it.
            add_tray(hwnd);
            with_agent(|a| a.out.push("shell", "explorer.exe", 0, "taskbar recreated (Explorer restarted)", 0.0, true));
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}
