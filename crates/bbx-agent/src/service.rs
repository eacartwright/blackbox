//! The BlackBox service as seen from the user's session: is it running, and
//! ask an administrator (UAC) to stop or start it.

use crate::wide;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// Some(true) running, Some(false) installed but not running, None not installed.
pub fn running() -> Option<bool> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return None;
        }
        let svc = OpenServiceW(scm, wide("BlackBox").as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return None;
        }
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        let ok = QueryServiceStatus(svc, &mut st) != 0;
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        ok.then(|| st.dwCurrentState == SERVICE_RUNNING || st.dwCurrentState == SERVICE_START_PENDING)
    }
}

/// Run `bbx.exe <verb>` (next to this exe) elevated. Shows the UAC prompt;
/// returns false if it could not be started (e.g. the user said no).
pub fn run_elevated(hwnd: HWND, verb: &str) -> bool {
    let Some(bbx) = std::env::current_exe().ok().map(|p| p.with_file_name("bbx.exe")) else { return false };
    let file: Vec<u16> = bbx.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let r = unsafe { ShellExecuteW(hwnd, wide("runas").as_ptr(), file.as_ptr(), wide(verb).as_ptr(), std::ptr::null(), SW_HIDE) };
    r as isize > 32
}
