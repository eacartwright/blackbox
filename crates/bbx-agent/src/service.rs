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

/// Run `bbx.exe <verb>` elevated and wait (up to `timeout_ms`) for it to
/// finish. Err says why it didn't work: UAC declined, failed, or timed out.
pub fn run_elevated_wait(hwnd: HWND, verb: &str, timeout_ms: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let Some(bbx) = std::env::current_exe().ok().map(|p| p.with_file_name("bbx.exe")) else { return Err("bbx.exe not found".into()) };
    let file: Vec<u16> = bbx.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let (runas, params) = (wide("runas"), wide(verb));
    unsafe {
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = hwnd;
        sei.lpVerb = runas.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = SW_HIDE;
        if ShellExecuteExW(&mut sei) == 0 || sei.hProcess.is_null() {
            return Err("administrator approval is needed".into());
        }
        let waited = WaitForSingleObject(sei.hProcess, timeout_ms);
        let mut code = 1u32;
        let got = GetExitCodeProcess(sei.hProcess, &mut code) != 0;
        CloseHandle(sei.hProcess);
        if waited != WAIT_OBJECT_0 {
            return Err("it is taking too long".into());
        }
        if !got || code != 0 {
            return Err(format!("bbx {verb} failed (code {code})"));
        }
    }
    Ok(())
}
