//! System-wide sampler: CPU, commit, memory, pool totals, object counts,
//! BlackBox's own footprint, and per-tag pool usage (driver leaks).

use crate::ntapi;
use crate::util::below_normal_priority;
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{PoolSample, PoolTag, RecordType, SystemSample};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::ProcessStatus::{
    GetPerformanceInfo, GetProcessMemoryInfo, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes, GetSystemTimes};

fn ft64(f: &FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

#[derive(Default, Clone, Copy)]
struct CpuTimes {
    idle: u64,
    kernel: u64, // includes idle
    user: u64,
    self_cpu: u64,
}

fn cpu_times() -> CpuTimes {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut i, mut k, mut u) = (z, z, z);
    let (mut c, mut e, mut sk, mut su) = (z, z, z, z);
    unsafe {
        GetSystemTimes(&mut i, &mut k, &mut u);
        GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut sk, &mut su);
    }
    CpuTimes { idle: ft64(&i), kernel: ft64(&k), user: ft64(&u), self_cpu: ft64(&sk) + ft64(&su) }
}

fn perf_info() -> Result<PERFORMANCE_INFORMATION> {
    let mut pi: PERFORMANCE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetPerformanceInfo(&mut pi, std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32) };
    if ok == 0 {
        return Err(anyhow!("GetPerformanceInfo failed: {}", std::io::Error::last_os_error()));
    }
    Ok(pi)
}

fn self_memory() -> (f32, f32) {
    let mut m: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    m.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    unsafe {
        GetProcessMemoryInfo(GetCurrentProcess(), (&mut m as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(), m.cb);
    }
    (m.WorkingSetSize as f32 / 1048576.0, m.PrivateUsage as f32 / 1048576.0)
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let interval = Duration::from_millis(ctx.cfg.system_sample_ms.max(500));
    let pool_every = Duration::from_secs(ctx.cfg.pool_sample_s.max(5));
    let mut prev = cpu_times();
    let mut last_pool = Instant::now() - pool_every;
    let mut pool_prev: HashMap<String, u64> = HashMap::new();

    // Memory vitals don't need a delta: publish them immediately so the very
    // first heartbeats already carry a known state.
    if let Ok(pi) = perf_info() {
        let pg = pi.PageSize as u64;
        ctx.update_vitals(|v| {
            v.commit_pct = if pi.CommitLimit > 0 { 100.0 * pi.CommitTotal as f32 / pi.CommitLimit as f32 } else { 0.0 };
            v.avail_mb = pi.PhysicalAvailable as u64 * pg / 1048576;
        });
    }

    while !ctx.stop.wait(interval) {
        let now = cpu_times();
        let total = (now.kernel - prev.kernel) + (now.user - prev.user);
        let idle = now.idle - prev.idle;
        let (cpu, kern) = if total > 0 {
            (
                100.0 * (total.saturating_sub(idle)) as f64 / total as f64,
                100.0 * (now.kernel - prev.kernel).saturating_sub(idle) as f64 / total as f64,
            )
        } else {
            (0.0, 0.0)
        };
        // Wall-clock-equivalent: system busy time is summed over all cores.
        let self_cpu = if total > 0 { 100.0 * (now.self_cpu - prev.self_cpu) as f64 / total as f64 } else { 0.0 };
        prev = now;

        let pi = perf_info()?;
        let pg = pi.PageSize as u64;
        let mb = |pages: usize| pages as u64 * pg / 1048576;
        let (self_ws, self_priv) = self_memory();
        let s = SystemSample {
            cpu: cpu as f32,
            cpu_kernel: kern as f32,
            commit_mb: mb(pi.CommitTotal),
            commit_limit_mb: mb(pi.CommitLimit),
            commit_peak_mb: mb(pi.CommitPeak),
            phys_mb: mb(pi.PhysicalTotal),
            avail_mb: mb(pi.PhysicalAvailable),
            cache_mb: mb(pi.SystemCache),
            paged_pool_mb: mb(pi.KernelPaged),
            nonpaged_pool_mb: mb(pi.KernelNonpaged),
            handles: pi.HandleCount,
            processes: pi.ProcessCount,
            threads: pi.ThreadCount,
            self_cpu: self_cpu as f32,
            self_ws_mb: self_ws,
            self_private_mb: self_priv,
        };
        ctx.update_vitals(|v| {
            v.cpu = s.cpu;
            v.commit_pct = if s.commit_limit_mb > 0 { 100.0 * s.commit_mb as f32 / s.commit_limit_mb as f32 } else { 0.0 };
            v.avail_mb = s.avail_mb;
        });
        ctx.emit(RecordType::SystemSample, &s);

        if last_pool.elapsed() >= pool_every {
            last_pool = Instant::now();
            match ntapi::pool_tags() {
                Ok(tags) => ctx.emit(RecordType::PoolSample, &pool_sample(tags, &mut pool_prev)),
                Err(e) => log::debug!("pool tags unavailable: {e:#}"),
            }
        }
    }
    Ok(())
}

/// Top 20 tags by bytes, plus any tag that grew by ≥ 8 MB since last time.
fn pool_sample(tags: Vec<ntapi::PoolTagInfo>, prev: &mut HashMap<String, u64>) -> PoolSample {
    const TOP: usize = 20;
    const GROWTH: i64 = 8 * 1024 * 1024;
    let mut rows: Vec<PoolTag> = tags
        .into_iter()
        .map(|t| {
            let total = t.paged_used + t.np_used;
            let delta = prev.get(&t.tag).map(|&p| total as i64 - p as i64).unwrap_or(0);
            prev.insert(t.tag.clone(), total);
            PoolTag {
                tag: t.tag,
                paged: t.paged_used,
                nonpaged: t.np_used,
                allocs: (t.paged_allocs as i64 - t.paged_frees as i64) + (t.np_allocs as i64 - t.np_frees as i64),
                delta,
            }
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.paged + r.nonpaged));
    let mut keep: Vec<PoolTag> = Vec::new();
    for (i, r) in rows.into_iter().enumerate() {
        if i < TOP || r.delta >= GROWTH {
            keep.push(r);
        }
    }
    PoolSample { tags: keep }
}
