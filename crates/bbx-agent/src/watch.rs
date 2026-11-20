//! Session watchers polled every tick: hung windows, foreground app, idle.

use std::collections::HashMap;
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetForegroundWindow, GetWindow, GetWindowThreadProcessId, IsHungAppWindow, IsWindowVisible, GW_OWNER,
};

pub struct Event {
    pub kind: String,
    pub proc: String,
    pub pid: u32,
    pub detail: String,
    pub value: f64,
}

struct Hung {
    since: Instant,
    pid: u32,
    proc: String,
    class: String,
    reported: bool,
}

pub struct Watcher {
    pub hung_after: u64,
    hung: HashMap<isize, Hung>,
    fg: String,
    fg_candidate: String,
    idle: bool,
    names: HashMap<u32, String>,
}

pub const IDLE_AFTER_S: f64 = 120.0;

pub fn exe_name(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        full.rsplit('\\').next().unwrap_or(&full).to_string()
    }
}

fn window_pid(h: HWND) -> u32 {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(h, &mut pid) };
    pid
}

fn class_name(h: HWND) -> String {
    let mut buf = [0u16; 128];
    let n = unsafe { GetClassNameW(h, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub fn foreground_process() -> Option<String> {
    let h = unsafe { GetForegroundWindow() };
    if h.is_null() {
        return None;
    }
    Some(exe_name(window_pid(h)))
}

pub fn idle_seconds() -> f64 {
    let mut li = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    if unsafe { GetLastInputInfo(&mut li) } == 0 {
        return 0.0;
    }
    unsafe { GetTickCount() }.wrapping_sub(li.dwTime) as f64 / 1000.0
}

unsafe extern "system" fn collect(h: HWND, lp: LPARAM) -> i32 {
    let v = &mut *(lp as *mut Vec<HWND>);
    if IsWindowVisible(h) != 0 && GetWindow(h, GW_OWNER).is_null() {
        v.push(h);
    }
    1
}

impl Watcher {
    pub fn new(hung_after: u64) -> Self {
        Self { hung_after, hung: HashMap::new(), fg: String::new(), fg_candidate: String::new(), idle: false, names: HashMap::new() }
    }

    fn name(&mut self, pid: u32) -> String {
        if self.names.len() > 5000 {
            self.names.clear();
        }
        self.names.entry(pid).or_insert_with(|| exe_name(pid)).clone()
    }

    pub fn tick(&mut self) -> Vec<Event> {
        let mut out = Vec::new();

        // Hung top-level windows. IsHungAppWindow is true once a window has
        // not pumped messages for ~5 s.
        let mut wins: Vec<HWND> = Vec::new();
        unsafe { EnumWindows(Some(collect), &mut wins as *mut _ as LPARAM) };
        let mut now_hung: Vec<isize> = Vec::new();
        for h in wins {
            if unsafe { IsHungAppWindow(h) } == 0 {
                continue;
            }
            let key = h as isize;
            now_hung.push(key);
            if !self.hung.contains_key(&key) {
                let pid = window_pid(h);
                let proc = self.name(pid);
                self.hung.insert(key, Hung { since: Instant::now(), pid, proc, class: class_name(h), reported: false });
            }
        }
        let hung_after = self.hung_after.max(1) as f64;
        for (key, hg) in self.hung.iter_mut() {
            // +5 s: Windows only calls a window hung after ~5 s of silence.
            let secs = hg.since.elapsed().as_secs_f64() + 5.0;
            if now_hung.contains(key) && !hg.reported && secs >= hung_after {
                hg.reported = true;
                out.push(Event { kind: "hung".into(), proc: hg.proc.clone(), pid: hg.pid, detail: format!("window class {}", hg.class), value: secs });
            }
        }
        let ended: Vec<isize> = self.hung.keys().filter(|k| !now_hung.contains(k)).copied().collect();
        for k in ended {
            if let Some(hg) = self.hung.remove(&k) {
                if hg.reported {
                    let secs = hg.since.elapsed().as_secs_f64() + 5.0;
                    out.push(Event { kind: "hung_end".into(), proc: hg.proc, pid: hg.pid, detail: "responding again or closed".into(), value: secs });
                }
            }
        }

        // Foreground app (exe only, no titles), once stable for one tick.
        if let Some(fg) = foreground_process() {
            if fg != self.fg && fg == self.fg_candidate && !fg.is_empty() {
                self.fg = fg.clone();
                out.push(Event { kind: "foreground".into(), proc: fg, pid: 0, detail: String::new(), value: 0.0 });
            }
            self.fg_candidate = foreground_process().unwrap_or_default();
        }

        // Idle / active transitions.
        let idle_s = idle_seconds();
        if !self.idle && idle_s >= IDLE_AFTER_S {
            self.idle = true;
            out.push(Event { kind: "idle".into(), proc: String::new(), pid: 0, detail: String::new(), value: idle_s });
        } else if self.idle && idle_s < IDLE_AFTER_S {
            self.idle = false;
            out.push(Event { kind: "active".into(), proc: String::new(), pid: 0, detail: String::new(), value: 0.0 });
        }
        out
    }
}
