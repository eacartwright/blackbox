//! Kernel paths (`\Device\HarddiskVolume3\Users\...`) to drive-letter paths.

use crate::util::{from_wide, wide};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

pub struct DevicePaths {
    /// (device prefix with trailing '\', "C:")
    map: Vec<(String, String)>,
}

impl DevicePaths {
    pub fn load() -> Self {
        let mut map = Vec::new();
        for l in b'A'..=b'Z' {
            let drive = format!("{}:", l as char);
            let mut buf = vec![0u16; 1024];
            let n = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let target = from_wide(&buf);
                if !target.is_empty() {
                    map.push((format!("{target}\\"), drive));
                }
            }
        }
        // Longest prefix first (\Device\HarddiskVolume10 before ...Volume1).
        map.sort_by_key(|(t, _)| std::cmp::Reverse(t.len()));
        Self { map }
    }

    pub fn to_dos(&self, p: &str) -> String {
        for (dev, drive) in &self.map {
            if p.len() >= dev.len() && p[..dev.len()].eq_ignore_ascii_case(dev) {
                return format!("{drive}\\{}", &p[dev.len()..]);
            }
        }
        p.strip_prefix(r"\??\").unwrap_or(p).to_string()
    }
}

/// `\REGISTRY\MACHINE\SOFTWARE\X` -> `HKLM\SOFTWARE\X`
pub fn reg_short(k: &str) -> String {
    let upper = k.to_ascii_uppercase();
    for (long, short) in [(r"\REGISTRY\MACHINE", "HKLM"), (r"\REGISTRY\USER", "HKU"), (r"\REGISTRY\A", "HKAPP")] {
        if upper.starts_with(long) {
            return format!("{short}{}", &k[long.len()..]);
        }
    }
    k.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_system_drive() {
        let d = DevicePaths::load();
        let sysdrive = std::env::var("SystemDrive").unwrap_or("C:".into());
        let (dev, _) = d.map.iter().find(|(_, l)| l.eq_ignore_ascii_case(&sysdrive)).unwrap();
        assert_eq!(d.to_dos(&format!("{dev}Windows\\notepad.exe")).to_ascii_uppercase(), format!("{sysdrive}\\WINDOWS\\NOTEPAD.EXE").to_ascii_uppercase());
        assert_eq!(reg_short(r"\REGISTRY\MACHINE\SOFTWARE\Foo"), r"HKLM\SOFTWARE\Foo");
    }
}
