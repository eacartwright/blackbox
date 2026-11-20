//! Performance counters (PDH): disk latency/queue/throughput, NIC rates,
//! CPU utility and performance (throttling), DPC/interrupt time, thermal
//! zones and their passive limit, paging, and GPU engines and memory.
//!
//! English counter names are used so this works on any Windows locale.

use crate::util::{below_normal_priority, from_wide_ptr, wide};
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{CpuPdh, DiskRow, GpuEngineRow, GpuProcRow, GpuSample, NicRow, PdhSample, RecordType, ThermalRow};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
};

const PDH_FMT_DOUBLE: u32 = 0x0000_0200;
const PDH_FMT_NOCAP100: u32 = 0x0000_8000;
const PDH_MORE_DATA: u32 = 0x8000_07D2;
const PDH_CSTATUS_VALID_DATA: u32 = 0;
const PDH_CSTATUS_NEW_DATA: u32 = 1;

pub struct Query {
    h: isize,
    counters: HashMap<&'static str, isize>,
}

impl Drop for Query {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.h as _) };
    }
}

impl Query {
    pub fn new() -> Result<Self> {
        let mut h = 0isize;
        let rc = unsafe { PdhOpenQueryW(std::ptr::null(), 0, (&mut h as *mut isize).cast()) };
        if rc != 0 {
            return Err(anyhow!("PdhOpenQuery failed: 0x{rc:08X}"));
        }
        Ok(Self { h, counters: HashMap::new() })
    }

    /// Add a counter; returns false (and logs at debug) if this machine
    /// doesn't have it (e.g. no thermal zones, no GPU counters).
    pub fn add(&mut self, key: &'static str, path: &str) -> bool {
        let w = wide(path);
        let mut c = 0isize;
        let rc = unsafe { PdhAddEnglishCounterW(self.h as _, w.as_ptr(), 0, (&mut c as *mut isize).cast()) };
        if rc != 0 {
            log::debug!("counter {path} unavailable: 0x{rc:08X}");
            return false;
        }
        self.counters.insert(key, c);
        true
    }

    pub fn collect(&self) -> Result<()> {
        let rc = unsafe { PdhCollectQueryData(self.h as _) };
        if rc != 0 {
            return Err(anyhow!("PdhCollectQueryData failed: 0x{rc:08X}"));
        }
        Ok(())
    }

    /// (instance, value) pairs; empty if the counter is missing.
    pub fn values(&self, key: &str) -> Vec<(String, f64)> {
        let Some(&c) = self.counters.get(key) else { return vec![] };
        let mut size = 0u32;
        let mut count = 0u32;
        let rc = unsafe {
            PdhGetFormattedCounterArrayW(c as _, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &mut size, &mut count, std::ptr::null_mut())
        };
        if rc != PDH_MORE_DATA || size == 0 {
            return vec![];
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 1];
        let rc = unsafe {
            PdhGetFormattedCounterArrayW(c as _, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &mut size, &mut count, buf.as_mut_ptr().cast())
        };
        if rc != 0 {
            return vec![];
        }
        // PDH_FMT_COUNTERVALUE_ITEM_W (x64): { LPWSTR szName; { DWORD CStatus; pad; double } } = 24 bytes
        let base = buf.as_ptr() as *const u8;
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            unsafe {
                let item = base.add(i * 24);
                let name = from_wide_ptr(std::ptr::read_unaligned(item as *const *const u16));
                let status = std::ptr::read_unaligned(item.add(8) as *const u32);
                let val = std::ptr::read_unaligned(item.add(16) as *const f64);
                if status == PDH_CSTATUS_VALID_DATA || status == PDH_CSTATUS_NEW_DATA {
                    out.push((name, val));
                }
            }
        }
        out
    }

    pub fn single(&self, key: &str) -> f64 {
        self.values(key).first().map(|v| v.1).unwrap_or(0.0)
    }
}

fn main_query() -> Result<Query> {
    let mut q = Query::new()?;
    q.add("disk_sec", r"\PhysicalDisk(*)\Avg. Disk sec/Transfer");
    q.add("disk_q", r"\PhysicalDisk(*)\Current Disk Queue Length");
    q.add("disk_bps", r"\PhysicalDisk(*)\Disk Bytes/sec");
    q.add("disk_idle", r"\PhysicalDisk(*)\% Idle Time");
    q.add("nic_rx", r"\Network Interface(*)\Bytes Received/sec");
    q.add("nic_tx", r"\Network Interface(*)\Bytes Sent/sec");
    q.add("cpu_util", r"\Processor Information(_Total)\% Processor Utility");
    q.add("cpu_perf", r"\Processor Information(_Total)\% Processor Performance");
    q.add("cpu_dpc", r"\Processor Information(_Total)\% DPC Time");
    q.add("cpu_intr", r"\Processor Information(_Total)\% Interrupt Time");
    q.add("cpu_queue", r"\System\Processor Queue Length");
    q.add("pages_in", r"\Memory\Pages Input/sec");
    q.add("tz_temp", r"\Thermal Zone Information(*)\Temperature");
    q.add("tz_passive", r"\Thermal Zone Information(*)\% Passive Limit");
    Ok(q)
}

fn gpu_query() -> Result<Query> {
    let mut q = Query::new()?;
    q.add("gpu_eng", r"\GPU Engine(*)\Utilization Percentage");
    q.add("gpu_proc_mem", r"\GPU Process Memory(*)\Dedicated Usage");
    q.add("gpu_ded", r"\GPU Adapter Memory(*)\Dedicated Usage");
    q.add("gpu_shared", r"\GPU Adapter Memory(*)\Shared Usage");
    Ok(q)
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let interval = Duration::from_millis(ctx.cfg.pdh_sample_ms.max(500));
    let gpu_every = Duration::from_millis(ctx.cfg.gpu_sample_ms.max(1000));
    let main = main_query()?;
    let gpu = gpu_query().ok();
    main.collect()?; // rate counters need two samples
    if let Some(g) = &gpu {
        g.collect().ok();
    }
    let mut last_gpu = Instant::now();

    while !ctx.stop.wait(interval) {
        main.collect()?;
        let mut s = sample_main(&main);
        if let Some(g) = &gpu {
            if last_gpu.elapsed() >= gpu_every && g.collect().is_ok() {
                last_gpu = Instant::now();
                s.gpu = Some(sample_gpu(g));
            }
        }
        let worst_ms = s.disks.iter().map(|d| d.ms).fold(0.0, f32::max);
        let worst_q = s.disks.iter().map(|d| d.queue).fold(0.0, f32::max);
        ctx.update_vitals(|v| {
            v.disk_ms = worst_ms;
            v.disk_q = worst_q;
        });
        ctx.emit(RecordType::PdhSample, &s);
    }
    Ok(())
}

fn by_instance(q: &Query, key: &str) -> HashMap<String, f64> {
    q.values(key).into_iter().filter(|(n, _)| n != "_Total").collect()
}

fn sample_main(q: &Query) -> PdhSample {
    let sec = by_instance(q, "disk_sec");
    let qlen = by_instance(q, "disk_q");
    let bps = by_instance(q, "disk_bps");
    let idle = by_instance(q, "disk_idle");
    let mut disks: Vec<DiskRow> = sec
        .iter()
        .map(|(n, v)| DiskRow {
            disk: n.clone(),
            ms: (*v * 1000.0) as f32,
            queue: *qlen.get(n).unwrap_or(&0.0) as f32,
            bps: *bps.get(n).unwrap_or(&0.0),
            idle_pct: *idle.get(n).unwrap_or(&100.0) as f32,
        })
        .collect();
    disks.sort_by(|a, b| a.disk.cmp(&b.disk));

    let rx = by_instance(q, "nic_rx");
    let tx = by_instance(q, "nic_tx");
    let mut nics: Vec<NicRow> = rx
        .iter()
        .map(|(n, v)| NicRow { nic: n.clone(), rx_bps: *v, tx_bps: *tx.get(n).unwrap_or(&0.0) })
        .collect();
    nics.sort_by(|a, b| a.nic.cmp(&b.nic));

    let passive = by_instance(q, "tz_passive");
    let thermal = by_instance(q, "tz_temp")
        .into_iter()
        .map(|(n, k)| ThermalRow {
            celsius: (k - 273.15) as f32,
            passive_pct: *passive.get(&n).unwrap_or(&100.0) as f32,
            zone: n,
        })
        .collect();

    PdhSample {
        cpu: CpuPdh {
            utility: q.single("cpu_util") as f32,
            perf: q.single("cpu_perf") as f32,
            dpc_pct: q.single("cpu_dpc") as f32,
            intr_pct: q.single("cpu_intr") as f32,
            queue: q.single("cpu_queue") as f32,
        },
        disks,
        nics,
        gpu: None,
        thermal,
        pages_in: q.single("pages_in") as f32,
    }
}

/// Instance names look like
/// `pid_1234_luid_0x00000000_0x0000D1F7_phys_0_eng_3_engtype_VideoDecode`.
fn parse_gpu_instance(name: &str) -> (u32, String, String) {
    let pid = name
        .strip_prefix("pid_")
        .and_then(|r| r.split('_').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let engtype = name.split("_engtype_").nth(1).unwrap_or("").to_string();
    // Engine identity without the pid: luid + phys + eng index.
    let engine = name.split_once("_luid_").map(|(_, r)| r.split("_engtype_").next().unwrap_or(r).to_string()).unwrap_or_default();
    (pid, engine, engtype)
}

fn sample_gpu(q: &Query) -> GpuSample {
    // Per physical engine: sum of all processes' use. Per engine type: the
    // busiest engine of that type (what Task Manager shows).
    let mut engine_total: HashMap<(String, String), f64> = HashMap::new();
    let mut proc_max: HashMap<u32, f64> = HashMap::new();
    let mut proc_engine: HashMap<(u32, String), f64> = HashMap::new();
    for (name, v) in q.values("gpu_eng") {
        let (pid, engine, engtype) = parse_gpu_instance(&name);
        *engine_total.entry((engine.clone(), engtype)).or_default() += v;
        *proc_engine.entry((pid, engine)).or_default() += v;
    }
    for ((pid, _), v) in proc_engine {
        let e = proc_max.entry(pid).or_default();
        *e = e.max(v);
    }
    let mut by_type: HashMap<String, f64> = HashMap::new();
    for ((_, t), v) in engine_total {
        let e = by_type.entry(t).or_default();
        *e = e.max(v.min(100.0));
    }
    let mut engines: Vec<GpuEngineRow> = by_type
        .into_iter()
        .filter(|(t, _)| !t.is_empty())
        .map(|(engine, pct)| GpuEngineRow { engine, pct: pct as f32 })
        .collect();
    engines.sort_by(|a, b| b.pct.total_cmp(&a.pct));

    let mut mem: HashMap<u32, f64> = HashMap::new();
    for (name, v) in q.values("gpu_proc_mem") {
        let (pid, _, _) = parse_gpu_instance(&name);
        *mem.entry(pid).or_default() += v;
    }
    let mut procs: Vec<GpuProcRow> = proc_max
        .iter()
        .map(|(&pid, &pct)| GpuProcRow { pid, pct: pct.min(100.0) as f32, dedicated_mb: (mem.get(&pid).copied().unwrap_or(0.0) / 1048576.0) as f32 })
        .filter(|p| p.pid != 0 && (p.pct >= 1.0 || p.dedicated_mb >= 256.0))
        .collect();
    procs.sort_by(|a, b| b.pct.total_cmp(&a.pct));
    procs.truncate(10);

    let sum = |k: &str| q.values(k).iter().map(|v| v.1).sum::<f64>() / 1048576.0;
    GpuSample { engines, procs, dedicated_mb: sum("gpu_ded") as f32, shared_mb: sum("gpu_shared") as f32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_instance_names() {
        let (pid, eng, t) = parse_gpu_instance("pid_1234_luid_0x00000000_0x0000D1F7_phys_0_eng_3_engtype_VideoDecode");
        assert_eq!(pid, 1234);
        assert_eq!(eng, "0x00000000_0x0000D1F7_phys_0_eng_3");
        assert_eq!(t, "VideoDecode");
    }

    #[test]
    fn main_counters_sample() {
        let q = main_query().unwrap();
        q.collect().unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        q.collect().unwrap();
        let s = sample_main(&q);
        assert!(!s.disks.is_empty(), "expected at least one physical disk");
        assert!(s.cpu.utility >= 0.0);
    }
}
