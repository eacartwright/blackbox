//! Identity of the current boot and machine.

use crate::util::{from_wide, tick_ms, wide};
use bbx_core::time::{now_ft, FT_PER_MS, FT_PER_SEC};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Windows' boot counter (0 if unavailable).
    pub boot_id: u64,
    /// Boot time as FILETIME, rounded to the second.
    pub boot_ft: i64,
    pub uptime_ms: u64,
}

pub fn current() -> BootInfo {
    let up = tick_ms();
    let raw = now_ft() - up as i64 * FT_PER_MS;
    let boot_ft = (raw + FT_PER_SEC / 2) / FT_PER_SEC * FT_PER_SEC;
    let boot_id = reg_dword(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
        "BootId",
    )
    .unwrap_or(0) as u64;
    BootInfo { boot_id, boot_ft, uptime_ms: up }
}

pub fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(key), wide(value));
    let mut data: u32 = 0;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut data as *mut u32).cast(), &mut size)
    };
    (rc == 0).then_some(data)
}

pub fn reg_string(key: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(key), wide(value));
    let mut buf = vec![0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size)
    };
    (rc == 0).then(|| from_wide(&buf))
}

/// "Windows 11 Pro 24H2 (build 26100.2605)"
pub fn os_description() -> String {
    const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut product = reg_string(CV, "ProductName").unwrap_or_else(|| "Windows".into());
    let build = reg_string(CV, "CurrentBuild").unwrap_or_default();
    // ProductName still says "Windows 10" on Windows 11.
    if build.parse::<u32>().unwrap_or(0) >= 22000 {
        product = product.replace("Windows 10", "Windows 11");
    }
    let ver = reg_string(CV, "DisplayVersion").unwrap_or_default();
    let ubr = reg_dword(CV, "UBR").map(|u| format!(".{u}")).unwrap_or_default();
    format!("{product} {ver} (build {build}{ubr})").replace("  ", " ")
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}
