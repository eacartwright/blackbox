//! Offline black-box reader: replays .etl files and returns Procmon-style
//! rows (time, process, operation, path, detail) for a time window. Works
//! on any Windows machine without admin rights: the technician's viewer
//! uses it to drill into the seconds around an incident.
//!
//! The whole of each file is read (so file-object, registry-handle and
//! process-name maps built from earlier events are available), but only
//! events inside the window become rows, and reading stops at the window end.

use crate::devpath::{reg_short, DevicePaths};
use crate::etwlive::{
    qpc_freq, CloseTrace, OpenTraceW, ProcessTrace, G_DISKIO, G_DNS, G_FILEIO, G_IMAGE, G_PROCESS, G_REGISTRY, G_TCPIP, G_THREAD,
    G_UDPIP, INVALID_PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
};
use crate::tdh::{event_guid, Decoder, Value};
use crate::util::wide_path;
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use windows_sys::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_LOGFILEW};

const G_EVENTTRACE: u128 = 0x68fdd900_4a3e_11d1_84f4_0000f80464e3;

#[derive(Debug, Clone, Serialize, Default)]
pub struct EtlRow {
    pub ft: i64,
    pub pid: u32,
    pub tid: u32,
    pub proc: String,
    /// file | registry | network | disk | process | image | dns | other
    pub kind: &'static str,
    pub op: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct EtlStats {
    pub events: u64,
    pub rows: usize,
    pub truncated: bool,
    pub files: usize,
}

pub struct Query {
    pub from_ft: i64,
    pub to_ft: i64,
    pub max_rows: usize,
    /// Case-insensitive substring over process, operation, path and detail.
    pub filter: Option<String>,
    /// Kinds to include (empty = all).
    pub kinds: Vec<String>,
    /// Include read-type operations (file reads, registry queries/opens,
    /// directory enumeration). They dominate the volume.
    pub reads: bool,
    /// pid -> name hints from the journal (processes older than the trace).
    pub names: HashMap<u32, String>,
}

struct State {
    q: Query,
    dec: Decoder,
    dev: DevicePaths,
    names: HashMap<u32, String>,
    tid_pid: HashMap<u32, u32>,
    files: HashMap<u64, String>,
    kcb: HashMap<u64, String>,
    rows: Vec<EtlRow>,
    stats: EtlStats,
    qpc: f64,
    filter: Option<String>,
}

fn file_op(op: u8) -> Option<(&'static str, bool)> {
    // (name, is_read_type)
    Some(match op {
        64 => ("CreateFile", false),
        65 => ("Cleanup", true),
        66 => ("CloseFile", true),
        67 => ("ReadFile", true),
        68 => ("WriteFile", false),
        69 => ("SetInformation", false),
        70 => ("DeleteFile", false),
        71 => ("RenameFile", false),
        72 => ("QueryDirectory", true),
        73 => ("FlushBuffers", false),
        74 => ("QueryInformation", true),
        75 => ("FileSystemControl", true),
        77 => ("NotifyChangeDirectory", true),
        79 => ("DeletePath", false),
        80 => ("RenamePath", false),
        81 => ("SetLinkPath", false),
        _ => return None,
    })
}

fn reg_op(op: u8) -> Option<(&'static str, bool)> {
    Some(match op {
        10 => ("RegCreateKey", false),
        11 => ("RegOpenKey", true),
        12 => ("RegDeleteKey", false),
        13 => ("RegQueryKey", true),
        14 => ("RegSetValue", false),
        15 => ("RegDeleteValue", false),
        16 => ("RegQueryValue", true),
        17 => ("RegEnumKey", true),
        18 => ("RegEnumValue", true),
        19 => ("RegQueryMultipleValue", true),
        20 => ("RegSetInfoKey", false),
        21 => ("RegFlushKey", false),
        26 => ("RegVirtualize", true),
        27 => ("RegCloseKey", true),
        _ => return None,
    })
}

fn net_op(op: u8) -> Option<&'static str> {
    let base = if op >= 26 { op - 16 } else { op };
    Some(match base {
        10 => "Send",
        11 => "Receive",
        12 => "Connect",
        13 => "Disconnect",
        14 => "Retransmit",
        15 => "Accept",
        16 => "Reconnect",
        17 => "Fail",
        _ => return None,
    })
}

impl State {
    fn name(&self, pid: u32) -> String {
        self.names.get(&pid).or_else(|| self.q.names.get(&pid)).cloned().unwrap_or_default()
    }

    fn want(&self, kind: &str) -> bool {
        self.q.kinds.is_empty() || self.q.kinds.iter().any(|k| k == kind)
    }

    #[allow(clippy::too_many_arguments)]
    fn push(&mut self, ft: i64, pid: u32, tid: u32, kind: &'static str, op: String, path: String, detail: String) {
        if ft < self.q.from_ft || ft > self.q.to_ft || !self.want(kind) {
            return;
        }
        let proc = self.name(pid);
        if let Some(f) = &self.filter {
            let hay = format!("{proc}\u{1}{op}\u{1}{path}\u{1}{detail}").to_lowercase();
            if !hay.contains(f.as_str()) {
                return;
            }
        }
        if self.rows.len() >= self.q.max_rows {
            self.stats.truncated = true;
            return;
        }
        self.rows.push(EtlRow { ft, pid, tid, proc, kind, op, path, detail });
    }

    fn on_event(&mut self, r: &EVENT_RECORD) {
        self.stats.events += 1;
        let h = &r.EventHeader;
        let (g, op, ft, hpid, tid) = (event_guid(r), h.EventDescriptor.Opcode, h.TimeStamp, h.ProcessId, h.ThreadId);
        let in_window = ft >= self.q.from_ft && ft <= self.q.to_ft;
        match g {
            G_EVENTTRACE => {}
            G_PROCESS => {
                let Some(d) = self.dec.decode(r, &[]) else { return };
                let pid = d.u64("ProcessId") as u32;
                let image = d.str("ImageFileName");
                if matches!(op, 1 | 3) {
                    self.names.insert(pid, image.clone());
                }
                match op {
                    1 => self.push(ft, pid, tid, "process", "Process Start".into(), image, format!("parent {}  {}", d.u64("ParentId"), d.str("CommandLine"))),
                    2 => {
                        let code = d.u64("ExitStatus") as u32;
                        self.push(ft, pid, tid, "process", "Process Exit".into(), image, format!("exit 0x{code:X}"))
                    }
                    _ => {}
                }
            }
            G_THREAD => {
                if let Some(d) = self.dec.decode(r, &["ProcessId", "TThreadId"]) {
                    let (p, t) = (d.u64("ProcessId") as u32, d.u64("TThreadId") as u32);
                    match op {
                        1 | 3 => {
                            self.tid_pid.insert(t, p);
                            if op == 1 && in_window && self.want("thread") {
                                self.push(ft, p, t, "process", "Thread Create".into(), String::new(), format!("tid {t}"));
                            }
                        }
                        2 | 4 => {
                            self.tid_pid.remove(&t);
                        }
                        _ => {}
                    }
                }
            }
            G_IMAGE if op == 10 && in_window => {
                if let Some(d) = self.dec.decode(r, &["ImageBase", "ImageSize", "ProcessId", "FileName"]) {
                    let path = self.dev.to_dos(&d.str("FileName"));
                    self.push(ft, d.u64("ProcessId") as u32, tid, "image", "Load Image".into(), path, format!("base 0x{:X} size {}", d.u64("ImageBase"), d.u64("ImageSize")));
                }
            }
            G_FILEIO => match op {
                0 | 32 | 36 => {
                    if let Some(d) = self.dec.decode(r, &["FileObject", "FileName"]) {
                        let p = self.dev.to_dos(&d.str("FileName"));
                        self.files.insert(d.u64("FileObject"), p);
                    }
                }
                _ => {
                    let Some((name, readish)) = file_op(op) else { return };
                    if op == 64 {
                        // Always keep the object -> name map, even outside the window.
                        let Some(d) = self.dec.decode(r, &[]) else { return };
                        let p = self.dev.to_dos(&d.str("OpenPath"));
                        self.files.insert(d.u64("FileObject"), p.clone());
                        if in_window {
                            let opts = d.u64("CreateOptions");
                            let disp = match (opts >> 24) & 0xFF { 0 => "Supersede", 1 => "Open", 2 => "Create", 3 => "OpenIf", 4 => "Overwrite", 5 => "OverwriteIf", _ => "?" };
                            self.push(ft, hpid, tid, "file", name.into(), p, format!("{disp}, share 0x{:X}, attrs 0x{:X}", d.u64("ShareAccess"), d.u64("FileAttributes")));
                        }
                        return;
                    }
                    if !in_window || (readish && !self.q.reads) {
                        return;
                    }
                    let Some(d) = self.dec.decode(r, &[]) else { return };
                    let named = self.dev.to_dos(&d.str("FileName"));
                    let path = if !named.is_empty() {
                        named
                    } else {
                        [d.u64("FileKey"), d.u64("FileObject")].iter().find_map(|k| self.files.get(k)).cloned().unwrap_or_else(|| "?".into())
                    };
                    let detail = match op {
                        67 | 68 => format!("offset {}, length {}", d.u64("Offset"), d.u64("IoSize")),
                        _ => format!("class {}", d.u64("InfoClass")),
                    };
                    self.push(ft, hpid, tid, "file", name.into(), path, detail);
                }
            },
            G_DISKIO if (op == 10 || op == 11) && in_window => {
                let Some(d) = self.dec.decode(r, &["DiskNumber", "TransferSize", "ByteOffset", "FileObject", "HighResResponseTime", "IssuingThreadId"]) else { return };
                let itid = d.u64("IssuingThreadId") as u32;
                let pid = self.tid_pid.get(&itid).copied().unwrap_or(if hpid == u32::MAX { 0 } else { hpid });
                let ms = d.u64("HighResResponseTime") as f64 * 1000.0 / self.qpc;
                let path = self.files.get(&d.u64("FileObject")).cloned().unwrap_or_default();
                let opn = if op == 10 { "Disk Read" } else { "Disk Write" };
                self.push(ft, pid, itid, "disk", opn.into(), path, format!("disk {} offset {} length {} took {ms:.2} ms", d.u64("DiskNumber"), d.u64("ByteOffset"), d.u64("TransferSize")));
            }
            G_TCPIP | G_UDPIP if in_window => {
                let Some(opn) = net_op(op) else { return };
                let Some(d) = self.dec.decode(r, &[]) else { return };
                let proto = if g == G_TCPIP { "TCP" } else { "UDP" };
                let (da, sa) = (d.str("daddr"), d.str("saddr"));
                let fmt = |a: &str, p: u64| if a.contains(':') { format!("[{a}]:{p}") } else { format!("{a}:{p}") };
                let path = format!("{} -> {}", fmt(&sa, d.u64("sport")), fmt(&da, d.u64("dport")));
                let pid = d.get("PID").map(|v| v.as_u64() as u32).unwrap_or(hpid);
                self.push(ft, pid, tid, "network", format!("{proto} {opn}"), path, format!("length {}", d.u64("size")));
            }
            G_REGISTRY => match op {
                22 | 24 | 25 => {
                    if let Some(d) = self.dec.decode(r, &["KeyHandle", "KeyName"]) {
                        self.kcb.insert(d.u64("KeyHandle"), d.str("KeyName"));
                    }
                }
                23 => {}
                _ => {
                    let Some((name, readish)) = reg_op(op) else { return };
                    if !in_window || (readish && !self.q.reads) {
                        return;
                    }
                    let Some(d) = self.dec.decode(r, &["Status", "KeyHandle", "KeyName"]) else { return };
                    let base = self.kcb.get(&d.u64("KeyHandle")).cloned().unwrap_or_default();
                    let n = d.str("KeyName");
                    let path = match op {
                        14 | 15 | 16 | 18 => format!("{}\\{n}", reg_short(&base)),
                        _ if n.starts_with('\\') || base.is_empty() => reg_short(&n),
                        _ => reg_short(&format!("{base}\\{n}")),
                    };
                    let st = d.u64("Status") as u32;
                    let detail = if st == 0 { "SUCCESS".into() } else { format!("status 0x{st:08X}") };
                    self.push(ft, hpid, tid, "registry", name.into(), path, detail);
                }
            },
            G_DNS if in_window => {
                if r.EventHeader.EventDescriptor.Id != 3008 {
                    return;
                }
                if let Some(d) = self.dec.decode(r, &["QueryName", "QueryType", "QueryStatus", "QueryResults"]) {
                    self.push(ft, hpid, tid, "dns", "DNS Query".into(), d.str("QueryName"), format!("type {} status {} {}", d.u64("QueryType"), d.u64("QueryStatus"), d.str("QueryResults")));
                }
            }
            _ if in_window && self.want("other") => {
                // Anything else (Kernel-Power, Kernel-PnP, StorPort, ...): show
                // its schema names and all decoded fields.
                let Some(schema) = self.dec.schema_of(r) else { return };
                let Some(d) = self.dec.decode(r, &[]) else { return };
                let fields: Vec<String> = d.props.iter().take(12).map(|(k, v)| format!("{k}={}", fmt_value(v))).collect();
                let op_name = [schema.task_name.as_str(), schema.opcode_name.as_str(), schema.event_name.as_str()]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("/");
                let op_name = if op_name.is_empty() { format!("event {}", r.EventHeader.EventDescriptor.Id) } else { op_name };
                let prov = schema.provider_name.trim_start_matches("Microsoft-Windows-").to_string();
                self.push(ft, hpid, tid, "other", format!("{prov}: {op_name}"), String::new(), fields.join(", "));
            }
            _ => {}
        }
    }
}

fn fmt_value(v: &Value) -> String {
    match v {
        Value::U(x) if *x > 0xFFFF => format!("0x{x:X}"),
        other => {
            let s = other.as_str();
            if s.chars().count() > 120 { s.chars().take(120).collect::<String>() + "…" } else { s }
        }
    }
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }
    let r = &*rec;
    let st = r.UserContext as *mut State;
    if !st.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| (*st).on_event(r)));
    }
}

/// Read rows from `files` (merged in time order by ETW) for the query window.
pub fn read(files: &[PathBuf], q: Query) -> Result<(Vec<EtlRow>, EtlStats)> {
    if files.is_empty() {
        return Err(anyhow!("no black-box files cover this time"));
    }
    if files.len() > 63 {
        return Err(anyhow!("too many black-box files for one read ({}); narrow the window", files.len()));
    }
    let filter = q.filter.as_ref().map(|f| f.to_lowercase()).filter(|f| !f.is_empty());
    let mut st = Box::new(State {
        dec: Decoder::default(),
        dev: DevicePaths::load(),
        names: HashMap::new(),
        tid_pid: HashMap::new(),
        files: HashMap::new(),
        kcb: HashMap::new(),
        rows: Vec::new(),
        stats: EtlStats { files: files.len(), ..Default::default() },
        qpc: qpc_freq(),
        filter,
        q,
    });
    let mut names: Vec<Vec<u16>> = files.iter().map(|p| wide_path(p)).collect();
    let mut handles = Vec::new();
    for n in names.iter_mut() {
        let mut lf: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        lf.LogFileName = n.as_mut_ptr();
        lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.Anonymous2.EventRecordCallback = Some(on_event);
        lf.Context = (&mut *st as *mut State).cast();
        let h = unsafe { OpenTraceW(&mut lf) };
        if h != INVALID_PROCESSTRACE_HANDLE {
            handles.push(h);
        }
    }
    if handles.is_empty() {
        return Err(anyhow!("could not open any black-box file: {}", std::io::Error::last_os_error()));
    }
    // Stop at the end of the window (FILETIME).
    let end = st.q.to_ft;
    let rc = unsafe { ProcessTrace(handles.as_ptr(), handles.len() as u32, std::ptr::null(), (&end as *const i64).cast()) };
    for h in handles {
        unsafe { CloseTrace(h) };
    }
    if rc != 0 && st.stats.events == 0 {
        return Err(anyhow!("ProcessTrace failed: {rc}"));
    }
    st.rows.sort_by_key(|r| r.ft);
    st.stats.rows = st.rows.len();
    let State { rows, stats, .. } = *st;
    Ok((rows, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blackbox::{ControlTraceW, EnableTraceEx2, PropsBuf, StartTraceW, CONTROL_STOP, ENABLE_PROVIDER};
    use crate::util::wide;

    /// Record a tiny user-mode trace (no admin needed) with the DNS-Client
    /// provider, then read it back through the offline reader.
    #[test]
    fn reads_back_a_recorded_trace() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.etl");
        let name = wide("BlackBox-Test-EtlRead");
        let mut pb = PropsBuf::new();
        unsafe { ControlTraceW(0, name.as_ptr(), pb.props(), CONTROL_STOP) };
        let mut pb = PropsBuf::new();
        {
            let p = pb.props();
            p.wnode.client_context = 1;
            p.buffer_size = 64;
            p.log_file_mode = 0x1; // sequential
            p.flush_timer = 1;
        }
        pb.set_file_pub(&file);
        let mut h = 0u64;
        let rc = unsafe { StartTraceW(&mut h, name.as_ptr(), pb.props()) };
        if rc != 0 {
            eprintln!("skipping: cannot start a user trace here ({rc})");
            return;
        }
        let dns = crate::blackbox::Guid { d1: 0x1C95126E, d2: 0x7EEA, d3: 0x49A9, d4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D] };
        unsafe { EnableTraceEx2(h, &dns, ENABLE_PROVIDER, 4, u64::MAX, 0, 0, std::ptr::null()) };
        let host = format!("bbx-etl-{}.example.invalid", std::process::id());
        use std::net::ToSocketAddrs;
        let _ = (host.as_str(), 80).to_socket_addrs();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let mut pb = PropsBuf::new();
        unsafe { ControlTraceW(0, name.as_ptr(), pb.props(), CONTROL_STOP) };

        let q = Query { from_ft: 0, to_ft: i64::MAX, max_rows: 10_000, filter: Some(host.clone()), kinds: vec![], reads: true, names: HashMap::new() };
        let (rows, stats) = read(&[file], q).unwrap();
        assert!(stats.events > 0);
        let row = rows.iter().find(|r| r.kind == "dns").expect("our DNS query should be in the trace");
        assert!(row.path.eq_ignore_ascii_case(&host));
        assert_eq!(row.pid, std::process::id());
    }
}
