//! The black box: a kernel-owned ETW session writing Procmon-grade detail
//! (process, thread, image, disk, file, registry, network, hard faults) to a
//! rolling set of .etl files. See ARCHITECTURE.md §3, tier 1.
//!
//! * Sequential files, rotated by the service (`EVENT_TRACE_CONTROL_UPDATE`
//!   with a new file name) when the current file reaches `blackbox_file_mb`
//!   or `blackbox_roll_s`, so all but the newest file are always complete,
//!   even after a power cut. (Kernel/system-logger sessions reject the
//!   self-rolling NEWFILE mode.) Each file is capped by the kernel at 4x the
//!   roll size, so a dead service can't fill the disk.
//! * The session outlives the service: a collector crash doesn't stop it,
//!   and a restarted service adopts it by name.
//! * BlackBox never parses these files while recording.

use crate::util::{below_normal_priority, from_wide, wide, wide_path};
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{BlackBox, RecordType};
use bbx_core::time::{ft_to_utc, utc_to_ft, FT_PER_SEC};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const SESSION_NAME: &str = "BlackBox-Recorder";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub d1: u32,
    pub d2: u16,
    pub d3: u16,
    pub d4: [u8; 8],
}

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
    Guid { d1, d2, d3, d4 }
}

#[repr(C)]
pub(crate) struct WnodeHeader {
    pub(crate) buffer_size: u32,
    pub(crate) provider_id: u32,
    pub(crate) historical_context: u64,
    pub(crate) timestamp: i64,
    pub(crate) guid: Guid,
    pub(crate) client_context: u32,
    pub(crate) flags: u32,
}

#[repr(C)]
pub(crate) struct EventTraceProperties {
    pub(crate) wnode: WnodeHeader,
    pub(crate) buffer_size: u32,
    pub(crate) minimum_buffers: u32,
    pub(crate) maximum_buffers: u32,
    pub(crate) maximum_file_size: u32,
    pub(crate) log_file_mode: u32,
    pub(crate) flush_timer: u32,
    pub(crate) enable_flags: u32,
    pub(crate) age_limit: i32,
    pub(crate) number_of_buffers: u32,
    pub(crate) free_buffers: u32,
    pub(crate) events_lost: u32,
    pub(crate) buffers_written: u32,
    pub(crate) log_buffers_lost: u32,
    pub(crate) real_time_buffers_lost: u32,
    pub(crate) logger_thread_id: *mut c_void,
    pub(crate) log_file_name_offset: u32,
    pub(crate) logger_name_offset: u32,
}

const _: () = assert!(std::mem::size_of::<EventTraceProperties>() == 120);

#[link(name = "advapi32", kind = "raw-dylib")]
extern "system" {
    pub(crate) fn StartTraceW(handle: *mut u64, name: *const u16, props: *mut EventTraceProperties) -> u32;
    pub(crate) fn ControlTraceW(handle: u64, name: *const u16, props: *mut EventTraceProperties, code: u32) -> u32;
    pub(crate) fn EnableTraceEx2(
        handle: u64,
        provider: *const Guid,
        control: u32,
        level: u8,
        any: u64,
        all: u64,
        timeout: u32,
        params: *const c_void,
    ) -> u32;
}

pub(crate) const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
const EVENT_TRACE_FILE_MODE_SEQUENTIAL: u32 = 0x0000_0001;
#[cfg(test)]
const EVENT_TRACE_FILE_MODE_NEWFILE: u32 = 0x0000_0008;
pub(crate) const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;
pub(crate) const CONTROL_QUERY: u32 = 0;
pub(crate) const CONTROL_STOP: u32 = 1;
const CONTROL_UPDATE: u32 = 2;
pub(crate) const CONTROL_FLUSH: u32 = 3;
pub(crate) const ENABLE_PROVIDER: u32 = 1;
pub(crate) const ERROR_ALREADY_EXISTS: u32 = 183;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;

// Kernel (SystemTraceProvider) flags.
pub(crate) const F_PROCESS: u32 = 0x0000_0001;
pub(crate) const F_THREAD: u32 = 0x0000_0002;
pub(crate) const F_IMAGE_LOAD: u32 = 0x0000_0004;
const F_PROCESS_COUNTERS: u32 = 0x0000_0008;
const F_CSWITCH: u32 = 0x0000_0010;
const F_DPC: u32 = 0x0000_0020;
const F_INTERRUPT: u32 = 0x0000_0040;
pub(crate) const F_DISK_IO: u32 = 0x0000_0100;
pub(crate) const F_DISK_FILE_IO: u32 = 0x0000_0200;
const F_DISPATCHER: u32 = 0x0000_0800;
const F_MEMORY_HARD_FAULTS: u32 = 0x0000_2000;
pub(crate) const F_NETWORK_TCPIP: u32 = 0x0001_0000;
pub(crate) const F_REGISTRY: u32 = 0x0002_0000;
const F_PROFILE: u32 = 0x0100_0000;
const F_FILE_IO: u32 = 0x0200_0000;
pub(crate) const F_FILE_IO_INIT: u32 = 0x0400_0000;

pub fn kernel_flags(deep: bool) -> u32 {
    let standard = F_PROCESS
        | F_THREAD
        | F_IMAGE_LOAD
        | F_PROCESS_COUNTERS
        | F_DISK_IO
        | F_DISK_FILE_IO
        | F_MEMORY_HARD_FAULTS
        | F_NETWORK_TCPIP
        | F_REGISTRY
        | F_FILE_IO
        | F_FILE_IO_INIT;
    if deep {
        standard | F_CSWITCH | F_DPC | F_INTERRUPT | F_DISPATCHER | F_PROFILE
    } else {
        standard
    }
}

/// (name, guid, level, keywords) of manifest providers added to the session.
const PROVIDERS: &[(&str, Guid, u8, u64)] = &[
    ("Microsoft-Windows-Kernel-Power", guid(0x331C3B3A, 0x2005, 0x44C2, [0xAC, 0x5E, 0x77, 0x22, 0x0C, 0x37, 0xD6, 0xB4]), 4, u64::MAX),
    ("Microsoft-Windows-Kernel-PnP", guid(0x9C205A39, 0x1250, 0x487D, [0xAB, 0xD7, 0xE8, 0x31, 0xC6, 0x29, 0x05, 0x39]), 4, u64::MAX),
    ("Microsoft-Windows-DNS-Client", guid(0x1C95126E, 0x7EEA, 0x49A9, [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D]), 4, u64::MAX),
    // Warnings and errors only: StorPort's verbose keywords log every I/O.
    ("Microsoft-Windows-StorPort", guid(0xC4636A1E, 0x7986, 0x4646, [0xBF, 0x10, 0x7B, 0xC3, 0xB4, 0xA7, 0x6E, 0x8E]), 3, u64::MAX),
];

/// Our session's GUID (identifies the logger, not a provider).
const SESSION_GUID: Guid = guid(0xB1AC_B0C5, 0x5E55, 0x4B1D, [0x9A, 0x7E, 0x0B, 0x1A, 0xC4, 0xB0, 0x00, 0x01]);

const NAME_CHARS: usize = 1024;

/// EVENT_TRACE_PROPERTIES followed by room for the session and file names.
pub(crate) struct PropsBuf(pub(crate) Vec<u64>);

impl PropsBuf {
    pub(crate) fn new() -> Self {
        let bytes = 120 + 2 * NAME_CHARS * 2;
        let mut v = PropsBuf(vec![0u64; bytes.div_ceil(8)]);
        let p = v.props();
        p.wnode.buffer_size = bytes as u32;
        p.wnode.flags = WNODE_FLAG_TRACED_GUID;
        p.logger_name_offset = 120;
        p.log_file_name_offset = (120 + NAME_CHARS * 2) as u32;
        v
    }
    pub(crate) fn props(&mut self) -> &mut EventTraceProperties {
        unsafe { &mut *(self.0.as_mut_ptr() as *mut EventTraceProperties) }
    }
    #[cfg(test)]
    pub(crate) fn set_file_pub(&mut self, path: &Path) {
        self.set_file(path)
    }
    fn set_file(&mut self, path: &Path) {
        let w = wide_path(path);
        let off = self.props().log_file_name_offset as usize;
        let n = w.len().min(NAME_CHARS);
        unsafe {
            let dst = (self.0.as_mut_ptr() as *mut u8).add(off) as *mut u16;
            std::ptr::copy_nonoverlapping(w.as_ptr(), dst, n);
        }
    }
    fn file(&mut self) -> String {
        let off = self.props().log_file_name_offset as usize;
        unsafe {
            let p = (self.0.as_ptr() as *const u8).add(off) as *const u16;
            from_wide(std::slice::from_raw_parts(p, NAME_CHARS))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionInfo {
    pub running: bool,
    pub file: String,
    pub buffers_written: u32,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub handle: u64,
}

fn control(code: u32) -> std::result::Result<SessionInfo, u32> {
    let mut pb = PropsBuf::new();
    let name = wide(SESSION_NAME);
    let rc = unsafe { ControlTraceW(0, name.as_ptr(), pb.props(), code) };
    if rc != 0 {
        return Err(rc);
    }
    let file = pb.file();
    let p = pb.props();
    Ok(SessionInfo {
        running: true,
        file,
        buffers_written: p.buffers_written,
        events_lost: p.events_lost,
        log_buffers_lost: p.log_buffers_lost,
        handle: p.wnode.historical_context,
    })
}

/// Current state of the black-box session.
pub fn query() -> std::result::Result<SessionInfo, String> {
    match control(CONTROL_QUERY) {
        Ok(i) => Ok(i),
        Err(ERROR_WMI_INSTANCE_NOT_FOUND) => Ok(SessionInfo::default()),
        Err(ERROR_ACCESS_DENIED) => Err("access denied (run as administrator)".into()),
        Err(e) => Err(format!("ControlTrace query failed: {e}")),
    }
}

pub fn stop() -> Result<()> {
    match control(CONTROL_STOP) {
        Ok(_) | Err(ERROR_WMI_INSTANCE_NOT_FOUND) => Ok(()),
        Err(e) => Err(anyhow!("stopping black-box session failed: {e}")),
    }
}

fn next_file(dir: &Path) -> PathBuf {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S-%3f");
    dir.join(format!("bb-{stamp}.etl"))
}

fn fill(pb: &mut PropsBuf, file: &Path, deep: bool, file_mb: u32, buffer_kb: u32) {
    pb.set_file(file);
    let p = pb.props();
    p.wnode.guid = SESSION_GUID;
    p.wnode.client_context = 1; // QPC timestamps
    p.buffer_size = buffer_kb.clamp(64, 1024);
    p.minimum_buffers = 16;
    p.maximum_buffers = 64; // at most 64 x buffer_size of nonpaged memory
    p.maximum_file_size = file_mb.max(8) * 4; // hard cap if rotation stops
    p.log_file_mode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p.flush_timer = 1;
    p.enable_flags = kernel_flags(deep);
}

/// Switch the running session to a fresh file; the previous file is closed
/// and complete. Returns the new file's path.
pub fn rotate(dir: &Path, deep: bool, file_mb: u32, buffer_kb: u32) -> Result<PathBuf> {
    control(CONTROL_FLUSH).ok();
    let file = next_file(dir);
    let mut pb = PropsBuf::new();
    fill(&mut pb, &file, deep, file_mb, buffer_kb);
    let name = wide(SESSION_NAME);
    let rc = unsafe { ControlTraceW(0, name.as_ptr(), pb.props(), CONTROL_UPDATE) };
    if rc != 0 {
        return Err(anyhow!("switching black-box file failed: {rc}"));
    }
    Ok(file)
}

/// Rotate using the settings in config.json (CLI and incidents).
pub fn roll() -> Result<()> {
    let paths = bbx_core::paths::Paths::from_env();
    let cfg = bbx_core::config::Config::load(&paths.config());
    rotate(&paths.blackbox(), cfg.deep(), cfg.blackbox_file_mb, cfg.blackbox_buffer_kb).map(|_| ())
}

/// Start a new session writing to `<dir>\bb-<timestamp>.etl`.
pub fn start(dir: &Path, deep: bool, file_mb: u32, buffer_kb: u32) -> Result<SessionInfo> {
    std::fs::create_dir_all(dir)?;
    let file = next_file(dir);
    let mut pb = PropsBuf::new();
    fill(&mut pb, &file, deep, file_mb, buffer_kb);
    let name = wide(SESSION_NAME);
    let mut handle = 0u64;
    let rc = unsafe { StartTraceW(&mut handle, name.as_ptr(), pb.props()) };
    match rc {
        0 => {}
        ERROR_ALREADY_EXISTS => return query().map_err(|e| anyhow!(e)),
        ERROR_ACCESS_DENIED => return Err(anyhow!("starting the black-box ETW session needs administrator rights")),
        e => return Err(anyhow!("StartTrace failed: {e}")),
    }
    for (pname, g, level, kw) in PROVIDERS {
        let rc = unsafe { EnableTraceEx2(handle, g, ENABLE_PROVIDER, *level, *kw, 0, 0, std::ptr::null()) };
        if rc != 0 {
            log::warn!("enabling {pname} in the black box failed: {rc}");
        }
    }
    Ok(SessionInfo { running: true, file: file.display().to_string(), handle, ..Default::default() })
}

#[derive(Debug, Clone)]
pub struct EtlFile {
    pub path: PathBuf,
    pub size: u64,
    pub created_ft: i64,
    pub modified_ft: i64,
}

pub fn list_files(dir: &Path) -> Vec<EtlFile> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return v };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| !x.eq_ignore_ascii_case("etl")) {
            continue;
        }
        let Ok(m) = e.metadata() else { continue };
        let ft = |t: std::io::Result<std::time::SystemTime>| t.map(|t| utc_to_ft(chrono::DateTime::<chrono::Utc>::from(t))).unwrap_or(0);
        v.push(EtlFile { size: m.len(), created_ft: ft(m.created()), modified_ft: ft(m.modified()), path: p });
    }
    v.sort_by_key(|f| f.modified_ft);
    v
}

/// Delete the oldest .etl files until the directory fits `max_bytes`.
/// Files in use by the kernel fail to delete and are skipped.
pub fn prune(dir: &Path, max_bytes: u64) -> (usize, u64) {
    let files = list_files(dir);
    let mut total: u64 = files.iter().map(|f| f.size).sum();
    let (mut n, mut freed) = (0, 0);
    for f in &files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(&f.path).is_ok() {
            total -= f.size;
            freed += f.size;
            n += 1;
        }
    }
    (n, freed)
}

/// Hard-link (or copy, across volumes) every .etl overlapping [from, to]
/// into `dest`. Hard links keep the data alive after the black box prunes
/// its own copy, at no extra disk cost.
pub fn link_window(dir: &Path, dest: &Path, from_ft: i64, to_ft: i64) -> Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::CreateHardLinkW;
    std::fs::create_dir_all(dest)?;
    let mut n = 0;
    for f in list_files(dir) {
        if f.modified_ft < from_ft || f.created_ft > to_ft {
            continue;
        }
        let target = dest.join(f.path.file_name().unwrap());
        if target.exists() {
            continue;
        }
        let (a, b) = (wide_path(&target), wide_path(&f.path));
        if unsafe { CreateHardLinkW(a.as_ptr(), b.as_ptr(), std::ptr::null()) } == 0 {
            std::fs::copy(&f.path, &target)?;
        }
        n += 1;
    }
    Ok(n)
}

/// Collector loop: ensure the session runs, roll on schedule, prune to budget.
pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let cfg = &ctx.cfg;
    let dir = ctx.paths.blackbox();
    if !cfg.blackbox_enabled {
        ctx.status("blackbox", "info", "black box disabled in config");
        return Ok(());
    }
    let ensure = |ctx: &Ctx| -> Result<SessionInfo> {
        match query() {
            Ok(i) if i.running => Ok(i),
            Ok(_) => {
                let i = start(&dir, cfg.deep(), cfg.blackbox_file_mb, cfg.blackbox_buffer_kb)?;
                ctx.emit(RecordType::BlackBox, &BlackBox { action: "started".into(), session: SESSION_NAME.into(), detail: i.file.clone() });
                Ok(i)
            }
            Err(e) => Err(anyhow!(e)),
        }
    };
    let info = ensure(ctx)?;
    ctx.emit(RecordType::BlackBox, &BlackBox { action: "active".into(), session: SESSION_NAME.into(), detail: info.file.clone() });

    let roll_every = Duration::from_secs(cfg.blackbox_roll_s.max(30));
    let mut last_roll = Instant::now();
    let mut last_prune = Instant::now() - Duration::from_secs(3600);
    let mut last_lost = info.events_lost + info.log_buffers_lost;
    while !ctx.stop.wait(Duration::from_secs(5)) {
        let info = match ensure(ctx) {
            Ok(i) => i,
            Err(e) => {
                ctx.status("blackbox", "error", format!("session not running and could not be restarted: {e:#}"));
                continue;
            }
        };
        let lost = info.events_lost + info.log_buffers_lost;
        if lost > last_lost {
            ctx.status("blackbox", "warn", format!("black box dropped {} buffers/events (system under heavy load)", lost - last_lost));
            last_lost = lost;
        }
        let current_mb = std::fs::metadata(&info.file).map(|m| m.len() / 1048576).unwrap_or(0);
        if last_roll.elapsed() >= roll_every || current_mb >= cfg.blackbox_file_mb as u64 {
            last_roll = Instant::now();
            if let Err(e) = rotate(&dir, cfg.deep(), cfg.blackbox_file_mb, cfg.blackbox_buffer_kb) {
                ctx.status("blackbox", "warn", format!("{e:#}"));
            }
        }
        if last_prune.elapsed() >= Duration::from_secs(60) {
            last_prune = Instant::now();
            let (n, freed) = prune(&dir, cfg.blackbox_max_mb * 1048576);
            if n > 0 {
                log::debug!("black box pruned {n} files ({} MB)", freed / 1048576);
            }
        }
    }
    // Deliberately leave the session running: it keeps recording through a
    // service restart, and is stopped only by `bbx uninstall`.
    Ok(())
}

pub fn fmt_window(from_ft: i64, to_ft: i64) -> String {
    format!("{} .. {} ({} s)", ft_to_utc(from_ft), ft_to_utc(to_ft), (to_ft - from_ft) / FT_PER_SEC)
}

#[cfg(test)]
mod probe {
    use super::*;

    fn try_start(mode: u32, flags: u32, file_mb: u32) -> u32 {
        let dir = std::env::temp_dir().join("bbx-probe");
        std::fs::create_dir_all(&dir).unwrap();
        let mut pb = PropsBuf::new();
        let file = if mode & EVENT_TRACE_FILE_MODE_NEWFILE != 0 { "probe-%d.etl" } else { "probe.etl" };
        pb.set_file(&dir.join(file));
        {
            let p = pb.props();
            p.wnode.guid = SESSION_GUID;
            p.wnode.client_context = 1;
            p.buffer_size = 256;
            p.minimum_buffers = 16;
            p.maximum_buffers = 64;
            p.maximum_file_size = file_mb;
            p.log_file_mode = mode;
            p.flush_timer = 1;
            p.enable_flags = flags;
        }
        let name = wide("BlackBox-Probe");
        let mut h = 0u64;
        let rc = unsafe { StartTraceW(&mut h, name.as_ptr(), pb.props()) };
        if rc == 0 {
            let mut pb2 = PropsBuf::new();
            unsafe { ControlTraceW(0, name.as_ptr(), pb2.props(), CONTROL_STOP) };
        }
        rc
    }

    #[test]
    #[ignore]
    fn probe_modes() {
        let sys = EVENT_TRACE_SYSTEM_LOGGER_MODE;
        let nf = EVENT_TRACE_FILE_MODE_NEWFILE;
        let seq = 0x1u32; // SEQUENTIAL
        let k = kernel_flags(false);
        for (label, mode, flags, mb) in [
            ("newfile+sys+flags", nf | sys, k, 64),
            ("newfile+sys", nf | sys, 0, 64),
            ("seq+sys+flags", seq | sys, k, 64),
            ("seq+sys+flags nomax", seq | sys, k, 0),
            ("newfile only", nf, 0, 64),
            ("seq only", seq, 0, 64),
        ] {
            println!("{label:<24} -> {}", try_start(mode, flags, mb));
        }
    }
}
