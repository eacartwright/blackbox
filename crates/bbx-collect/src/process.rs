//! Process sampler: per-process resource rows every interval (only the
//! processes that did something, plus a full table periodically), and
//! process start/end records with image path, user and full command line.
//!
//! Phase 2's ETW consumer adds exact start/stop times, exit codes and
//! processes that live shorter than one interval.

use crate::ntapi::{self, ProcInfo};
use crate::util::below_normal_priority;
use crate::ctx::ProcStat;
use crate::Ctx;
use anyhow::Result;
use bbx_core::records::{ProcRow, ProcessEnd, ProcessSample, ProcessStart, RecordType};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, LookupAccountSidW, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Seen {
    info: ProcInfo,
    peak_ws: u64,
    peak_private: u64,
}

pub(crate) struct ProcHandle(pub(crate) HANDLE);
impl Drop for ProcHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) fn open(pid: u32) -> Option<ProcHandle> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    (!h.is_null()).then_some(ProcHandle(h))
}

pub(crate) fn image_path(h: &ProcHandle) -> String {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..len as usize])
}

fn process_user(h: &ProcHandle, cache: &mut HashMap<Vec<u8>, String>) -> String {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut tok) } == 0 {
        return String::new();
    }
    let tok = ProcHandle(tok);
    let mut buf = vec![0u64; 64];
    let mut len = 0u32;
    if unsafe { GetTokenInformation(tok.0, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len) } == 0 {
        return String::new();
    }
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = tu.User.Sid;
    // Cache by SID bytes; LookupAccountSid can be slow (domain lookups).
    let sid_len = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
    let key = unsafe { std::slice::from_raw_parts(sid as *const u8, sid_len) }.to_vec();
    if let Some(n) = cache.get(&key) {
        return n.clone();
    }
    let (mut name, mut dom) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut nl, mut dl) = (256u32, 256u32);
    let mut use_ = 0;
    let ok = unsafe { LookupAccountSidW(std::ptr::null(), sid, name.as_mut_ptr(), &mut nl, dom.as_mut_ptr(), &mut dl, &mut use_) };
    let s = if ok != 0 {
        format!("{}\\{}", String::from_utf16_lossy(&dom[..dl as usize]), String::from_utf16_lossy(&name[..nl as usize]))
    } else {
        String::new()
    };
    cache.insert(key, s.clone());
    s
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let interval = Duration::from_millis(ctx.cfg.process_sample_ms.max(500));
    let full_every = Duration::from_secs(ctx.cfg.process_full_s.max(10));
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
    let mut seen: HashMap<u32, Seen> = HashMap::new();
    let mut users: HashMap<Vec<u8>, String> = HashMap::new();
    let mut last_full = Instant::now();
    let mut last_tick = Instant::now();
    let mut first = true;

    loop {
        let procs = ntapi::processes()?;
        let dt = last_tick.elapsed().as_secs_f64().max(0.001);
        last_tick = Instant::now();
        let full = first || last_full.elapsed() >= full_every;
        if full {
            last_full = Instant::now();
        }

        let mut rows = Vec::new();
        let mut alive: HashMap<u32, ()> = HashMap::with_capacity(procs.len());
        let mut top: Option<(f64, String)> = None;

        for p in procs {
            if p.pid == 0 {
                continue; // Idle: its CPU is the system's idle time
            }
            alive.insert(p.pid, ());
            let prev: Option<ProcInfo> =
                seen.get(&p.pid).filter(|s| s.info.create_ft == p.create_ft).map(|s| s.info.clone());
            let prev = prev.as_ref();
            let is_new = prev.is_none();
            if is_new {
                // pid reuse: the old process with this pid is gone.
                let etw = ctx.etw_process_active();
                if let Some(old) = seen.remove(&p.pid) {
                    if !etw {
                        emit_end(ctx, &old);
                    }
                }
                // With live ETW running, starts come from ETW (exact time,
                // short-lived processes); the sampler only does the inventory.
                if first || !etw {
                    emit_start(ctx, &p, if first { "inventory" } else { "sampler" }, &mut users);
                }
            }
            let (cpu_pct, rd, wr, ot, hf) = match prev {
                Some(s) => (
                    100.0 * (p.cpu_100ns.saturating_sub(s.cpu_100ns)) as f64 / (dt * 1e7 * cores),
                    p.read_bytes.saturating_sub(s.read_bytes) as f64 / dt,
                    p.write_bytes.saturating_sub(s.write_bytes) as f64 / dt,
                    p.other_bytes.saturating_sub(s.other_bytes) as f64 / dt,
                    p.hard_faults.saturating_sub(s.hard_faults) as f64 / dt,
                ),
                None => (0.0, 0.0, 0.0, 0.0, 0.0),
            };
            let interesting = full
                || is_new
                || cpu_pct >= 0.5
                || rd + wr + ot >= 64.0 * 1024.0
                || hf >= 50.0
                || prev.is_some_and(|s| {
                    (p.private as i64 - s.private as i64).abs() >= 8 << 20
                        || (p.handles as i64 - s.handles as i64).abs() >= 50
                });
            if interesting {
                rows.push(ProcRow(
                    p.pid,
                    (cpu_pct * 10.0).round().min(1000.0) as u16,
                    p.ws / 1024,
                    p.private / 1024,
                    p.handles,
                    p.threads,
                    rd as u64,
                    wr as u64,
                    ot as u64,
                    hf as u32,
                ));
            }
            if top.as_ref().map_or(true, |(c, _)| cpu_pct > *c) && cpu_pct > 0.0 {
                top = Some((cpu_pct, format!("{}({}) {:.1}%", p.name, p.pid, cpu_pct)));
            }
            let (pw, pp) = seen.get(&p.pid).filter(|_| !is_new).map(|s| (s.peak_ws, s.peak_private)).unwrap_or((0, 0));
            seen.insert(
                p.pid,
                Seen { peak_ws: pw.max(p.peak_ws), peak_private: pp.max(p.peak_private).max(p.private), info: p },
            );
        }

        // Exited processes.
        let gone: Vec<u32> = seen.keys().filter(|pid| !alive.contains_key(pid)).copied().collect();
        let etw = ctx.etw_process_active();
        for pid in gone {
            if let Some(s) = seen.remove(&pid) {
                if !etw {
                    emit_end(ctx, &s);
                }
            }
        }
        {
            // Lifetime totals for ETW process-end records.
            let mut st = ctx.procstats.lock().unwrap();
            st.clear();
            for s in seen.values() {
                st.insert(
                    s.info.pid,
                    ProcStat {
                        create_ft: s.info.create_ft,
                        cpu_ms: s.info.cpu_100ns / 10_000,
                        peak_ws_kb: s.peak_ws / 1024,
                        peak_private_kb: s.peak_private / 1024,
                    },
                );
            }
        }

        ctx.update_vitals(|v| v.top = top.map(|t| t.1));
        if !first {
            let names = if full { seen.values().map(|s| (s.info.pid, s.info.name.clone())).collect() } else { Vec::new() };
            ctx.emit(
                RecordType::ProcessSample,
                &ProcessSample { interval_ms: (dt * 1000.0) as u32, full, rows, names },
            );
        }
        first = false;
        if ctx.stop.wait(interval) {
            return Ok(());
        }
    }
}

fn emit_start(ctx: &Ctx, p: &ProcInfo, source: &str, users: &mut HashMap<Vec<u8>, String>) {
    let (image, cmdline, user) = match open(p.pid) {
        Some(h) => (
            image_path(&h),
            ntapi::process_cmdline(h.0).map(|c| ctx.redactor.apply(&c)).unwrap_or_default(),
            process_user(&h, users),
        ),
        None => Default::default(),
    };
    ctx.emit(
        RecordType::ProcessStart,
        &ProcessStart {
            pid: p.pid,
            ppid: p.ppid,
            create_ft: p.create_ft,
            session: p.session,
            name: p.name.clone(),
            image,
            cmdline,
            user,
            source: source.into(),
        },
    );
}

fn emit_end(ctx: &Ctx, s: &Seen) {
    ctx.emit(
        RecordType::ProcessEnd,
        &ProcessEnd {
            pid: s.info.pid,
            create_ft: s.info.create_ft,
            name: s.info.name.clone(),
            exit_code: None,
            cpu_ms: s.info.cpu_100ns / 10_000,
            peak_ws_kb: s.peak_ws / 1024,
            peak_private_kb: s.peak_private / 1024,
            source: "sampler".into(),
        },
    );
}
