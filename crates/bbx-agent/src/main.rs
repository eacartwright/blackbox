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
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
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
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
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
const TIP_RECORDING: &str = "BlackBox is recording. Something went wrong? Right-click > Capture Incident (Ctrl+Alt+Shift+B)";
const TIP_STOPPED: &str = "BlackBox is NOT recording. Right-click > Start recording to turn it back on.";

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

fn add_tray(hwnd: HWND) {
    let mut nid = icon_data(hwnd);
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_INFORMATION) };
    copy_into(&mut nid.szTip, TIP_RECORDING);
    unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
}

fn set_tip(hwnd: HWND, recording: bool) {
    let mut nid = icon_data(hwnd);
    nid.uFlags = NIF_TIP;
    let tip = if recording { TIP_RECORDING } else { TIP_STOPPED };
    copy_into(&mut nid.szTip, tip);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
}

fn remove_tray(hwnd: HWND) {
    let nid = icon_data(hwnd);
    unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
}

fn balloon(hwnd: HWND, title: &str, text: &str) {
    let mut nid = icon_data(hwnd);
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    copy_into(&mut nid.szInfoTitle, title);
    copy_into(&mut nid.szInfo, text);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, CMD_MARK, wide("Capture Incident\tCtrl+Alt+Shift+B").as_ptr());
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
            wide("Stop recording and close BlackBox?\n\nProblems that happen from now on will not be captured. BlackBox starts again the next time this PC restarts.").as_ptr(),
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
