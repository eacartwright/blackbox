//! Live ETW consumer: a real-time kernel session decoded in-process and
//! rolled up into the journal every window (default 10 s):
//!
//! * process start/end with command line, user and **exit code** (including
//!   processes that live for milliseconds);
//! * kernel driver loads;
//! * network: bytes / connects / retransmits per process × remote endpoint;
//! * DNS queries per process with status and answers;
//! * disk I/O per process × file with worst latency;
//! * file writes, creates, deletes and renames per process × path;
//! * registry writes, creates and deletes per process × key/value.
//!
//! Events we don't use (file reads, registry queries, ...) are rejected by
//! (provider, opcode) before any decoding, which keeps the cost low.

use crate::blackbox::{
    ControlTraceW, EnableTraceEx2, Guid, PropsBuf, StartTraceW, CONTROL_QUERY, CONTROL_STOP, ENABLE_PROVIDER,
    ERROR_ACCESS_DENIED, ERROR_WMI_INSTANCE_NOT_FOUND, EVENT_TRACE_SYSTEM_LOGGER_MODE, F_DISK_FILE_IO, F_DISK_IO,
    F_FILE_IO_INIT, F_IMAGE_LOAD, F_NETWORK_TCPIP, F_PROCESS, F_REGISTRY, F_THREAD,
};
use crate::devpath::{reg_short, DevicePaths};
use crate::rollup::Rollup;
use crate::tdh::{event_guid, Decoder};
use crate::util::wide;
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{
    DiskActivity, DiskIoRow, DnsQueries, DnsRow, DriverLoad, FileActivity, FileRow, NetFlows, NetRow, ProcessEnd,
    ProcessStart, RecordType, RegRow, RegistryActivity,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_LOGFILEW};

pub const LIVE_SESSION: &str = "BlackBox-Live";

#[link(name = "advapi32", kind = "raw-dylib")]
extern "system" {
    fn OpenTraceW(logfile: *mut EVENT_TRACE_LOGFILEW) -> u64;
    fn ProcessTrace(handles: *const u64, count: u32, start: *const c_void, end: *const c_void) -> u32;
    fn CloseTrace(handle: u64) -> u32;
}

const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

const LIVE_FLAGS: u32 = F_PROCESS | F_THREAD | F_IMAGE_LOAD | F_DISK_IO | F_DISK_FILE_IO | F_NETWORK_TCPIP | F_REGISTRY | F_FILE_IO_INIT;
const LIVE_GUID: Guid = Guid { d1: 0xB1AC_B0C5, d2: 0x5E55, d3: 0x4B1D, d4: [0x9A, 0x7E, 0x0B, 0x1A, 0xC4, 0xB0, 0x00, 0x02] };
const DNS_CLIENT: Guid = Guid { d1: 0x1C95126E, d2: 0x7EEA, d3: 0x49A9, d4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D] };

// Classic kernel event classes (EventHeader.ProviderId) and DNS-Client.
const G_PROCESS: u128 = 0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c;
const G_THREAD: u128 = 0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c;
const G_DISKIO: u128 = 0x3d6fa8d4_fe05_11d0_9dda_00c04fd7ba7c;
const G_IMAGE: u128 = 0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518;
const G_FILEIO: u128 = 0x90cbdc39_4a3e_11d1_84f4_0000f80464e3;
const G_TCPIP: u128 = 0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2;
const G_UDPIP: u128 = 0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80;
const G_REGISTRY: u128 = 0xae53722e_c863_11d2_8659_00c04fa321a1;
const G_DNS: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;

const WINDOW: Duration = Duration::from_secs(10);
const MAX_MAP: usize = 200_000;

fn control(name: &str, code: u32) -> std::result::Result<crate::blackbox::SessionInfo, u32> {
    let mut pb = PropsBuf::new();
    let n = wide(name);
    let rc = unsafe { ControlTraceW(0, n.as_ptr(), pb.props(), code) };
    if rc != 0 {
        return Err(rc);
    }
    let p = pb.props();
    Ok(crate::blackbox::SessionInfo {
        running: true,
        events_lost: p.events_lost,
        log_buffers_lost: p.real_time_buffers_lost,
        buffers_written: p.buffers_written,
        ..Default::default()
    })
}

/// Start (or restart) a real-time kernel session named `name`.
pub fn start_session(name: &str) -> Result<()> {
    // A session left behind by a crashed consumer would hold a system-logger
    // slot and buffer events nobody reads: replace it.
    match control(name, CONTROL_STOP) {
        Ok(_) | Err(ERROR_WMI_INSTANCE_NOT_FOUND) => {}
        Err(e) => log::warn!("stopping stale {name} session: {e}"),
    }
    let mut pb = PropsBuf::new();
    {
        let p = pb.props();
        p.wnode.guid = LIVE_GUID;
        p.wnode.client_context = 1;
        p.buffer_size = 128;
        p.minimum_buffers = 16;
        p.maximum_buffers = 96;
        p.log_file_mode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        p.log_file_name_offset = 0;
        p.flush_timer = 1;
        p.enable_flags = LIVE_FLAGS;
    }
    let n = wide(name);
    let mut handle = 0u64;
    match unsafe { StartTraceW(&mut handle, n.as_ptr(), pb.props()) } {
        0 => {}
        ERROR_ACCESS_DENIED => return Err(anyhow!("the live ETW session needs administrator rights")),
        e => return Err(anyhow!("StartTrace({name}) failed: {e}")),
    }
    let rc = unsafe { EnableTraceEx2(handle, &DNS_CLIENT, ENABLE_PROVIDER, 4, u64::MAX, 0, 0, std::ptr::null()) };
    if rc != 0 {
        log::warn!("enabling DNS-Client in the live session failed: {rc}");
    }
    Ok(())
}

pub fn stop_session(name: &str) {
    control(name, CONTROL_STOP).ok();
}

/// Collector entry point (service): consume until stop.
pub fn run(ctx: &Ctx) -> Result<()> {
    run_named(ctx, LIVE_SESSION)
}

pub fn run_named(ctx: &Ctx, name: &str) -> Result<()> {
    start_session(name)?;
    consume(ctx, name)
}

/// Attach to an already-started real-time session and process it until stop.
fn consume(ctx: &Ctx, name: &str) -> Result<()> {
    let mut state = Box::new(LiveState::new(ctx));
    let mut wname = wide(name);
    let mut lf: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    lf.LoggerName = wname.as_mut_ptr();
    lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.Anonymous2.EventRecordCallback = Some(on_event_record);
    lf.Context = (&mut *state as *mut LiveState).cast();
    let h = unsafe { OpenTraceW(&mut lf) };
    if h == INVALID_PROCESSTRACE_HANDLE {
        stop_session(name);
        return Err(anyhow!("OpenTrace({name}) failed: {}", std::io::Error::last_os_error()));
    }

    let rc = std::thread::scope(|s| {
        // Watchdog: stops the session on shutdown (which ends ProcessTrace)
        // and reports dropped buffers.
        s.spawn(|| {
            let mut last_lost = 0u32;
            loop {
                if ctx.stop.wait(Duration::from_secs(30)) {
                    stop_session(name);
                    return;
                }
                match control(name, CONTROL_QUERY) {
                    Ok(i) => {
                        let lost = i.events_lost + i.log_buffers_lost;
                        if lost > last_lost {
                            ctx.status("etwlive", "warn", format!("live ETW dropped {} events/buffers (consumer fell behind)", lost - last_lost));
                            last_lost = lost;
                        }
                    }
                    Err(_) => return, // session gone; ProcessTrace will return
                }
            }
        });
        ctx.etw_process.store(true, Ordering::SeqCst);
        ctx.status("etwlive", "info", format!("live ETW session {name} running"));
        let rc = unsafe { ProcessTrace(&h, 1, std::ptr::null(), std::ptr::null()) };
        ctx.etw_process.store(false, Ordering::SeqCst);
        if !ctx.stop.is_set() {
            stop_session(name); // also releases the watchdog via the query failing
        }
        rc
    });
    unsafe { CloseTrace(h) };
    state.flush();
    log::info!(
        "live ETW: {} events, {} decoded, {} schema failures",
        state.events, state.decoded, state.dec.schema_failures
    );
    if ctx.stop.is_set() {
        Ok(())
    } else {
        Err(anyhow!("live ETW session ended unexpectedly (ProcessTrace returned {rc})"))
    }
}

unsafe extern "system" fn on_event_record(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }
    let r = &*rec;
    let st = r.UserContext as *mut LiveState;
    if st.is_null() {
        return;
    }
    // A panic must never unwind into ETW (that would abort the process).
    let _ = catch_unwind(AssertUnwindSafe(|| (*st).on_event(r)));
}

#[derive(Hash, PartialEq, Eq)]
struct NetKey(u32, &'static str, String);

struct LiveState<'a> {
    ctx: &'a Ctx,
    dec: Decoder,
    dev: DevicePaths,
    tid_pid: HashMap<u32, u32>,
    names: HashMap<u32, String>,
    files: HashMap<u64, String>,
    kcb: HashMap<u64, String>,
    sids: HashMap<String, String>,
    net: Rollup<NetKey, NetRow>,
    dns: Rollup<(u32, String, u32, u32), DnsRow>,
    disk: Rollup<(u32, u32, String), DiskIoRow>,
    file: Rollup<(u32, String), FileRow>,
    reg: Rollup<(u32, String, String), RegRow>,
    last_flush: Instant,
    qpc_freq: f64,
    self_pid: u32,
    events: u64,
    decoded: u64,
}

fn qpc_freq() -> f64 {
    let mut f = 0i64;
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut f) };
    if f > 0 { f as f64 } else { 10_000_000.0 }
}

impl<'a> LiveState<'a> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            dec: Decoder::default(),
            dev: DevicePaths::load(),
            tid_pid: HashMap::new(),
            names: HashMap::new(),
            files: HashMap::new(),
            kcb: HashMap::new(),
            sids: HashMap::new(),
            net: Rollup::new(200, 200),
            dns: Rollup::new(200, 200),
            disk: Rollup::new(150, 100),
            file: Rollup::new(200, 300),
            reg: Rollup::new(200, 200),
            last_flush: Instant::now(),
            qpc_freq: qpc_freq(),
            self_pid: std::process::id(),
            events: 0,
            decoded: 0,
        }
    }

    fn name(&self, pid: u32) -> String {
        self.names.get(&pid).cloned().unwrap_or_default()
    }

    fn on_event(&mut self, r: &EVENT_RECORD) {
        self.events += 1;
        let g = event_guid(r);
        let op = r.EventHeader.EventDescriptor.Opcode;
        let hpid = r.EventHeader.ProcessId;
        match g {
            G_PROCESS => self.process(r, op),
            G_THREAD => self.thread(r, op),
            G_IMAGE if op == 10 => self.image(r),
            G_FILEIO => self.fileio(r, op, hpid),
            G_DISKIO if op == 10 || op == 11 => self.diskio(r, op, hpid),
            G_TCPIP => self.net(r, op, "tcp"),
            G_UDPIP => self.net(r, op, "udp"),
            G_REGISTRY => self.registry(r, op, hpid),
            G_DNS if r.EventHeader.EventDescriptor.Id == 3008 => self.dns(r, hpid),
            _ => {}
        }
        if self.last_flush.elapsed() >= WINDOW {
            self.flush();
        }
    }

    fn process(&mut self, r: &EVENT_RECORD, op: u8) {
        match op {
            1 | 3 => {
                let Some(d) = self.dec.decode(r, &["ProcessId", "ParentId", "SessionId", "UserSID", "ImageFileName", "CommandLine"]) else { return };
                self.decoded += 1;
                let pid = d.u64("ProcessId") as u32;
                let name = d.str("ImageFileName");
                self.names.insert(pid, name.clone());
                if op == 1 {
                    let image = crate::process::open(pid).map(|h| crate::process::image_path(&h)).unwrap_or_default();
                    let user = self.account(&d.str("UserSID"));
                    self.ctx.emit_at(
                        RecordType::ProcessStart,
                        r.EventHeader.TimeStamp,
                        &ProcessStart {
                            pid,
                            ppid: d.u64("ParentId") as u32,
                            create_ft: r.EventHeader.TimeStamp,
                            session: d.u64("SessionId") as u32,
                            name,
                            image,
                            cmdline: self.ctx.redactor.apply(&d.str("CommandLine")),
                            user,
                            source: "etw".into(),
                        },
                    );
                }
            }
            2 => {
                let Some(d) = self.dec.decode(r, &["ProcessId", "ExitStatus", "ImageFileName"]) else { return };
                self.decoded += 1;
                let pid = d.u64("ProcessId") as u32;
                let st = self.ctx.procstats.lock().unwrap().get(&pid).copied().unwrap_or_default();
                let name = Some(d.str("ImageFileName")).filter(|n| !n.is_empty()).unwrap_or_else(|| self.name(pid));
                self.ctx.emit_at(
                    RecordType::ProcessEnd,
                    r.EventHeader.TimeStamp,
                    &ProcessEnd {
                        pid,
                        create_ft: st.create_ft,
                        name,
                        exit_code: Some(d.u64("ExitStatus") as u32 as i32),
                        cpu_ms: st.cpu_ms,
                        peak_ws_kb: st.peak_ws_kb,
                        peak_private_kb: st.peak_private_kb,
                        source: "etw".into(),
                    },
                );
            }
            _ => {}
        }
    }

    fn account(&mut self, sid: &str) -> String {
        if sid.is_empty() {
            return String::new();
        }
        if let Some(a) = self.sids.get(sid) {
            return a.clone();
        }
        let a = lookup_sid(sid).unwrap_or_else(|| sid.to_string());
        self.sids.insert(sid.to_string(), a.clone());
        a
    }

    fn thread(&mut self, r: &EVENT_RECORD, op: u8) {
        match op {
            1 | 3 => {
                if let Some(d) = self.dec.decode(r, &["ProcessId", "TThreadId"]) {
                    if self.tid_pid.len() > MAX_MAP {
                        self.tid_pid.clear();
                    }
                    self.tid_pid.insert(d.u64("TThreadId") as u32, d.u64("ProcessId") as u32);
                }
            }
            2 | 4 => {
                if let Some(d) = self.dec.decode(r, &["ProcessId", "TThreadId"]) {
                    self.tid_pid.remove(&(d.u64("TThreadId") as u32));
                }
            }
            _ => {}
        }
    }

    fn image(&mut self, r: &EVENT_RECORD) {
        let Some(d) = self.dec.decode(r, &["ImageBase", "ImageSize", "ProcessId", "FileName"]) else { return };
        if d.u64("ProcessId") != 0 {
            return; // DLLs: the black box has them
        }
        self.decoded += 1;
        self.ctx.emit_at(
            RecordType::DriverLoad,
            r.EventHeader.TimeStamp,
            &DriverLoad { path: self.dev.to_dos(&d.str("FileName")), base: format!("0x{:X}", d.u64("ImageBase")), size: d.u64("ImageSize") },
        );
    }

    fn remember_file(&mut self, key: u64, path: String) {
        if key == 0 || path.is_empty() {
            return;
        }
        if self.files.len() > MAX_MAP {
            self.files.clear();
        }
        self.files.insert(key, path);
    }

    fn file_name(&self, keys: &[u64]) -> String {
        keys.iter().find_map(|k| self.files.get(k)).cloned().unwrap_or_else(|| "?".into())
    }

    fn fileio(&mut self, r: &EVENT_RECORD, op: u8, pid: u32) {
        match op {
            // Name, FileCreate, FileRundown: FileObject (really the file key) -> name
            0 | 32 | 36 => {
                if let Some(d) = self.dec.decode(r, &["FileObject", "FileName"]) {
                    let p = self.dev.to_dos(&d.str("FileName"));
                    self.remember_file(d.u64("FileObject"), p);
                }
            }
            35 => {
                if let Some(d) = self.dec.decode(r, &["FileObject"]) {
                    self.files.remove(&d.u64("FileObject"));
                }
            }
            64 => {
                let Some(d) = self.dec.decode(r, &["FileObject", "CreateOptions", "OpenPath"]) else { return };
                let path = self.dev.to_dos(&d.str("OpenPath"));
                self.remember_file(d.u64("FileObject"), path.clone());
                // Count only opens that create or overwrite (disposition in the
                // top byte of CreateOptions): SUPERSEDE, CREATE, OVERWRITE(_IF).
                let disp = (d.u64("CreateOptions") >> 24) & 0xFF;
                if pid != self.self_pid && matches!(disp, 0 | 2 | 4 | 5) {
                    self.decoded += 1;
                    let proc = self.name(pid);
                    if let Some(row) = self.file.row((pid, path.clone()), || FileRow { pid, proc, path, ..Default::default() }) {
                        row.creates += 1;
                    }
                }
            }
            68 | 70 | 71 | 79 | 80 => {
                if pid == self.self_pid {
                    return;
                }
                let Some(d) = self.dec.decode(r, &["FileObject", "FileKey", "IoSize", "FileName"]) else { return };
                self.decoded += 1;
                let named = self.dev.to_dos(&d.str("FileName"));
                let path = if named.is_empty() { self.file_name(&[d.u64("FileKey"), d.u64("FileObject")]) } else { named };
                let proc = self.name(pid);
                let Some(row) = self.file.row((pid, path.clone()), || FileRow { pid, proc, path, ..Default::default() }) else { return };
                match op {
                    68 => {
                        row.writes += 1;
                        row.write_bytes += d.u64("IoSize");
                    }
                    70 | 79 => row.deletes += 1,
                    _ => row.renames += 1,
                }
            }
            _ => {}
        }
    }

    fn diskio(&mut self, r: &EVENT_RECORD, op: u8, hpid: u32) {
        let Some(d) = self.dec.decode(r, &["DiskNumber", "TransferSize", "FileObject", "HighResResponseTime", "IssuingThreadId"]) else { return };
        self.decoded += 1;
        let tid = d.u64("IssuingThreadId") as u32;
        let pid = self.tid_pid.get(&tid).copied().unwrap_or(if hpid == u32::MAX { 0 } else { hpid });
        let disk = d.u64("DiskNumber") as u32;
        let file = self.file_name(&[d.u64("FileObject")]);
        let ms = d.u64("HighResResponseTime") as f64 * 1000.0 / self.qpc_freq;
        let size = d.u64("TransferSize");
        let proc = self.name(pid);
        let Some(row) = self.disk.row((pid, disk, file.clone()), || DiskIoRow { pid, proc, disk, file, ..Default::default() }) else { return };
        if op == 10 {
            row.reads += 1;
            row.read_bytes += size;
        } else {
            row.writes += 1;
            row.write_bytes += size;
        }
        row.max_ms = row.max_ms.max(ms as f32);
        row.total_ms += ms as f32;
    }

    fn net(&mut self, r: &EVENT_RECORD, op: u8, proto: &'static str) {
        // v4 opcodes; v6 variants are +16.
        let base = if op >= 26 { op - 16 } else { op };
        if !matches!(base, 10 | 11 | 12 | 14 | 15) {
            return;
        }
        let Some(d) = self.dec.decode(r, &["PID", "size", "daddr", "dport"]) else { return };
        self.decoded += 1;
        let pid = d.u64("PID") as u32;
        let addr = d.str("daddr");
        let remote = if addr.contains(':') { format!("[{addr}]:{}", d.u64("dport")) } else { format!("{addr}:{}", d.u64("dport")) };
        let proc = self.name(pid);
        let Some(row) = self.net.row(NetKey(pid, proto, remote.clone()), || NetRow { pid, proc, proto: proto.into(), remote, ..Default::default() }) else { return };
        let size = d.u64("size");
        match base {
            10 => row.sent += size,
            11 => row.recv += size,
            12 | 15 => row.connects += 1,
            14 => row.retrans += 1,
            _ => {}
        }
    }

    fn registry(&mut self, r: &EVENT_RECORD, op: u8, pid: u32) {
        match op {
            // KCBCreate, KCBRundownBegin/End: handle -> full key path
            22 | 24 | 25 => {
                if let Some(d) = self.dec.decode(r, &["KeyHandle", "KeyName"]) {
                    if self.kcb.len() > MAX_MAP {
                        self.kcb.clear();
                    }
                    self.kcb.insert(d.u64("KeyHandle"), d.str("KeyName"));
                }
            }
            23 => {
                if let Some(d) = self.dec.decode(r, &["KeyHandle"]) {
                    self.kcb.remove(&d.u64("KeyHandle"));
                }
            }
            10 | 12 | 14 | 15 => {
                if pid == self.self_pid {
                    return;
                }
                let Some(d) = self.dec.decode(r, &["KeyHandle", "KeyName"]) else { return };
                self.decoded += 1;
                let base = self.kcb.get(&d.u64("KeyHandle")).cloned().unwrap_or_default();
                let name = d.str("KeyName");
                // Value operations carry the value name in KeyName; key
                // operations carry a path relative to KeyHandle.
                let (key, value) = match op {
                    14 | 15 => (base, name),
                    _ if name.starts_with('\\') || base.is_empty() => (name, String::new()),
                    _ => (format!("{base}\\{name}"), String::new()),
                };
                let key = reg_short(&key);
                let proc = self.name(pid);
                let Some(row) = self.reg.row((pid, key.clone(), value.clone()), || RegRow { pid, proc, key, value, ..Default::default() }) else { return };
                match op {
                    10 => row.creates += 1,
                    14 => row.sets += 1,
                    _ => row.deletes += 1,
                }
            }
            _ => {}
        }
    }

    fn dns(&mut self, r: &EVENT_RECORD, pid: u32) {
        let Some(d) = self.dec.decode(r, &["QueryName", "QueryType", "QueryStatus", "QueryResults"]) else { return };
        self.decoded += 1;
        let (name, qtype, status) = (d.str("QueryName"), d.u64("QueryType") as u32, d.u64("QueryStatus") as u32);
        let proc = self.name(pid);
        let results = crate::util::truncate(d.str("QueryResults"), 300);
        if let Some(row) = self.dns.row((pid, name.clone(), qtype, status), || DnsRow { pid, proc, name, qtype, status, results, ..Default::default() }) {
            row.count += 1;
        }
    }

    fn flush(&mut self) {
        let w = self.last_flush.elapsed().as_secs().max(1) as u32;
        self.last_flush = Instant::now();
        let ctx = self.ctx;
        if !self.net.is_empty() {
            let (rows, dropped) = self.net.take();
            ctx.emit(RecordType::NetFlows, &NetFlows { window_s: w, rows, dropped });
        }
        if !self.dns.is_empty() {
            let (rows, dropped) = self.dns.take();
            ctx.emit(RecordType::DnsQueries, &DnsQueries { window_s: w, rows, dropped });
        }
        if !self.disk.is_empty() {
            let (rows, dropped) = self.disk.take();
            ctx.emit(RecordType::DiskActivity, &DiskActivity { window_s: w, rows, dropped });
        }
        if !self.file.is_empty() {
            let (rows, dropped) = self.file.take();
            ctx.emit(RecordType::FileActivity, &FileActivity { window_s: w, rows, dropped });
        }
        if !self.reg.is_empty() {
            let (rows, dropped) = self.reg.take();
            ctx.emit(RecordType::RegistryActivity, &RegistryActivity { window_s: w, rows, dropped });
        }
        // Forget exited processes' names only after their last rollup.
        if self.names.len() > 20_000 {
            self.names.clear();
        }
    }
}

/// "S-1-5-18" -> "NT AUTHORITY\SYSTEM"
fn lookup_sid(sid: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::LookupAccountSidW;
    let w = wide(sid);
    let mut psid: windows_sys::Win32::Security::PSID = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut psid) } == 0 {
        return None;
    }
    let (mut name, mut dom) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut nl, mut dl) = (256u32, 256u32);
    let mut use_ = 0;
    let ok = unsafe { LookupAccountSidW(std::ptr::null(), psid, name.as_mut_ptr(), &mut nl, dom.as_mut_ptr(), &mut dl, &mut use_) };
    unsafe { LocalFree(psid as _) };
    (ok != 0).then(|| format!("{}\\{}", String::from_utf16_lossy(&dom[..dl as usize]), String::from_utf16_lossy(&name[..nl as usize])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bbx_core::config::Config;
    use bbx_core::journal::{self, JournalOptions, JournalWriter};
    use bbx_core::paths::Paths;
    use std::sync::Arc;

    /// A user-mode real-time session with only DNS-Client: needs no admin
    /// rights, and exercises OpenTrace/ProcessTrace, the callback, TDH
    /// schema loading, decoding and rollup flushing end to end.
    fn start_dns_only(name: &str) -> Result<()> {
        control(name, CONTROL_STOP).ok();
        let mut pb = PropsBuf::new();
        {
            let p = pb.props();
            p.wnode.client_context = 1;
            p.buffer_size = 64;
            p.log_file_mode = EVENT_TRACE_REAL_TIME_MODE;
            p.log_file_name_offset = 0;
            p.flush_timer = 1;
        }
        let n = wide(name);
        let mut h = 0u64;
        let rc = unsafe { StartTraceW(&mut h, n.as_ptr(), pb.props()) };
        if rc != 0 {
            return Err(anyhow!("StartTrace: {rc}"));
        }
        let rc = unsafe { EnableTraceEx2(h, &DNS_CLIENT, ENABLE_PROVIDER, 4, u64::MAX, 0, 0, std::ptr::null()) };
        if rc != 0 {
            return Err(anyhow!("EnableTraceEx2: {rc}"));
        }
        Ok(())
    }

    #[test]
    fn live_dns_queries_are_decoded() {
        let name = "BlackBox-Test-DNS";
        if let Err(e) = start_dns_only(name) {
            eprintln!("skipping: cannot start a user ETW session here ({e})");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        paths.ensure().unwrap();
        let (j, _) = JournalWriter::open(&paths.journal(), JournalOptions::default()).unwrap();
        let stop = crate::Stop::new();
        let ctx = Ctx::new(Arc::new(j), Config::default(), paths.clone(), stop.clone(), 0);
        let host = format!("bbx-test-{}.example.invalid", std::process::id());
        std::thread::scope(|s| {
            let c = &ctx;
            let t = s.spawn(move || consume(c, name));
            std::thread::sleep(Duration::from_millis(1500));
            use std::net::ToSocketAddrs;
            let _ = (host.as_str(), 80).to_socket_addrs(); // NXDOMAIN is fine
            std::thread::sleep(Duration::from_millis(3000));
            stop.signal();
            stop_session(name);
            t.join().unwrap().ok();
        });
        ctx.journal.commit().unwrap();
        let mut found = None;
        journal::for_each_record(&paths.journal(), None, None, |r| {
            if r.rtype == RecordType::DnsQueries as u16 {
                let q: DnsQueries = r.parse().unwrap();
                found = q.rows.into_iter().find(|row| row.name.eq_ignore_ascii_case(&host)).or(found.take());
            }
            true
        })
        .unwrap();
        let row = found.expect("our DNS query should be in a DnsQueries record");
        assert_eq!(row.pid, std::process::id());
        assert_ne!(row.status, 0, "an .invalid name must fail");
    }

    #[test]
    fn sid_lookup() {
        let a = super::lookup_sid("S-1-5-18").unwrap();
        assert!(a.ends_with("\\SYSTEM"), "{a}");
    }
}
