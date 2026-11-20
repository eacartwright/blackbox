//! NT native queries: one call returns every process's counters
//! (SystemProcessInformation), and pool usage by tag
//! (SystemPoolTagInformation), which is how driver memory leaks show up.
//!
//! Struct offsets are for 64-bit Windows (x64 and ARM64).

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(h: HANDLE, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;

const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_POOLTAG_INFORMATION: u32 = 22;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

const _: () = assert!(std::mem::size_of::<usize>() == 8, "BlackBox targets 64-bit Windows");

/// 8-byte aligned byte buffer.
struct AlignedBuf(Vec<u64>);

impl AlignedBuf {
    fn new(bytes: usize) -> Self {
        Self(vec![0u64; bytes.div_ceil(8)])
    }
    fn len(&self) -> usize {
        self.0.len() * 8
    }
    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), self.len()) }
    }
}

fn query_system(class: u32, mut size: usize) -> Result<(AlignedBuf, usize)> {
    for _ in 0..8 {
        let mut buf = AlignedBuf::new(size);
        let mut ret: u32 = 0;
        let st = unsafe { NtQuerySystemInformation(class, buf.ptr(), buf.len() as u32, &mut ret) };
        if st >= 0 {
            return Ok((buf, ret as usize));
        }
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW {
            // The table can grow between calls; leave headroom.
            size = (ret as usize).max(size * 2) + 64 * 1024;
            continue;
        }
        return Err(anyhow!("NtQuerySystemInformation({class}) failed: 0x{:08X}", st as u32));
    }
    Err(anyhow!("NtQuerySystemInformation({class}): buffer kept growing"))
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
    pub create_ft: i64,
    /// User + kernel CPU, 100 ns units.
    pub cpu_100ns: u64,
    pub hard_faults: u32,
    pub handles: u32,
    pub session: u32,
    pub ws: u64,
    pub peak_ws: u64,
    pub private: u64,
    pub peak_private: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
}

/// Every process on the system, in one syscall.
pub fn processes() -> Result<Vec<ProcInfo>> {
    let (buf, _) = query_system(SYSTEM_PROCESS_INFORMATION, 512 * 1024)?;
    let b = buf.bytes();
    let base = b.as_ptr() as usize;
    let mut out = Vec::with_capacity(400);
    let mut off = 0usize;
    loop {
        if off + 256 > b.len() {
            break;
        }
        let next = rd_u32(b, off) as usize;
        let name_len = rd_u16(b, off + 56) as usize;
        let name_ptr = rd_u64(b, off + 64) as usize;
        let name = if name_ptr != 0 && name_len > 0 && name_ptr >= base && name_ptr + name_len <= base + b.len() {
            let s = name_ptr - base;
            let units: Vec<u16> = b[s..s + name_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::new()
        };
        let pid = rd_u64(b, off + 80) as u32;
        out.push(ProcInfo {
            pid,
            ppid: rd_u64(b, off + 88) as u32,
            name: if pid == 0 { "Idle".into() } else { name },
            threads: rd_u32(b, off + 4),
            create_ft: rd_u64(b, off + 32) as i64,
            cpu_100ns: rd_u64(b, off + 40) + rd_u64(b, off + 48),
            hard_faults: rd_u32(b, off + 16),
            handles: rd_u32(b, off + 96),
            session: rd_u32(b, off + 100),
            peak_ws: rd_u64(b, off + 136),
            ws: rd_u64(b, off + 144),
            private: rd_u64(b, off + 184),
            peak_private: rd_u64(b, off + 192),
            read_bytes: rd_u64(b, off + 232),
            write_bytes: rd_u64(b, off + 240),
            other_bytes: rd_u64(b, off + 248),
        });
        if next == 0 {
            break;
        }
        off += next;
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct PoolTagInfo {
    pub tag: String,
    pub paged_allocs: u32,
    pub paged_frees: u32,
    pub paged_used: u64,
    pub np_allocs: u32,
    pub np_frees: u32,
    pub np_used: u64,
}

pub fn pool_tags() -> Result<Vec<PoolTagInfo>> {
    let (buf, _) = query_system(SYSTEM_POOLTAG_INFORMATION, 256 * 1024)?;
    let b = buf.bytes();
    let count = rd_u32(b, 0) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = 8 + i * 40;
        if o + 40 > b.len() {
            break;
        }
        let tag: String = b[o..o + 4]
            .iter()
            .map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '?' })
            .collect();
        out.push(PoolTagInfo {
            tag,
            paged_allocs: rd_u32(b, o + 4),
            paged_frees: rd_u32(b, o + 8),
            paged_used: rd_u64(b, o + 16),
            np_allocs: rd_u32(b, o + 24),
            np_frees: rd_u32(b, o + 28),
            np_used: rd_u64(b, o + 32),
        });
    }
    Ok(out)
}

/// Full command line of a process (needs PROCESS_QUERY_LIMITED_INFORMATION).
pub fn process_cmdline(h: HANDLE) -> Option<String> {
    let mut size = 1024usize;
    for _ in 0..4 {
        let mut buf = AlignedBuf::new(size);
        let mut ret: u32 = 0;
        let st = unsafe { NtQueryInformationProcess(h, PROCESS_COMMAND_LINE_INFORMATION, buf.ptr(), buf.len() as u32, &mut ret) };
        if st >= 0 {
            let b = buf.bytes();
            let len = rd_u16(b, 0) as usize;
            let ptr = rd_u64(b, 8) as usize;
            let base = b.as_ptr() as usize;
            if ptr < base || ptr + len > base + b.len() {
                return None;
            }
            let s = ptr - base;
            let units: Vec<u16> = b[s..s + len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            return Some(String::from_utf16_lossy(&units));
        }
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW {
            size = (ret as usize).max(size * 2) + 64;
            continue;
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_table_parses() {
        let p = processes().unwrap();
        assert!(p.len() > 10);
        let sys = p.iter().find(|p| p.pid == 4).expect("System process");
        assert_eq!(sys.name, "System");
        let me = p.iter().find(|p| p.pid == std::process::id()).expect("own process");
        assert!(me.name.to_ascii_lowercase().ends_with(".exe"), "{}", me.name);
        assert!(me.ws > 0 && me.private > 0 && me.threads > 0);
    }

    #[test]
    fn own_cmdline() {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let c = process_cmdline(unsafe { GetCurrentProcess() }).unwrap();
        assert!(c.to_ascii_lowercase().contains("bbx_collect"), "{c}");
    }

    #[test]
    fn pool_tags_parse() {
        let t = pool_tags().unwrap();
        assert!(t.len() > 100);
        assert!(t.iter().any(|t| t.np_used > 0));
    }
}
