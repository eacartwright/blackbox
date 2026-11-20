//! Detectors: decide when something is worth an incident (which keeps the
//! black-box window and an event log export). Pure logic, unit-tested; the
//! incident manager applies cooldowns and rate limits.

use bbx_core::records::{Device, EventLog, Vitals};
use bbx_core::time::{now_ft, FT_PER_SEC};

/// (kind, reason)
pub type Finding = (String, String);

struct EventRule {
    providers: &'static [&'static str],
    ids: &'static [u32],
    /// 0 = any level; otherwise only levels 1..=max_level
    max_level: u8,
    what: &'static str,
}

const EVENT_RULES: &[EventRule] = &[
    EventRule { providers: &["Display"], ids: &[4101], max_level: 0, what: "display driver stopped responding and was recovered (TDR)" },
    EventRule { providers: &["Microsoft-Windows-WHEA-Logger"], ids: &[], max_level: 3, what: "hardware error reported by the CPU/chipset (WHEA)" },
    EventRule {
        providers: &["storahci", "stornvme", "iaStorA", "iaStorAC", "iaStorAVC", "iaStorV", "nvme", "disk", "Disk"],
        ids: &[129],
        max_level: 0,
        what: "storage controller reset a device (I/O stalled)",
    },
    EventRule { providers: &["disk", "Disk"], ids: &[7, 11, 51, 153, 157], max_level: 0, what: "disk error / retried I/O / surprise removal" },
    EventRule { providers: &["Ntfs", "Microsoft-Windows-Ntfs"], ids: &[55, 98, 140], max_level: 0, what: "file system error" },
    EventRule { providers: &["Application Hang"], ids: &[1002], max_level: 0, what: "application stopped responding" },
    EventRule { providers: &["Application Error"], ids: &[1000], max_level: 0, what: "application crashed" },
    EventRule { providers: &["Microsoft-Windows-Resource-Exhaustion-Detector"], ids: &[2004], max_level: 0, what: "Windows low on virtual memory" },
    EventRule { providers: &["Microsoft-Windows-Kernel-Processor-Power"], ids: &[37], max_level: 0, what: "CPU speed limited by firmware (thermal/power)" },
    EventRule { providers: &["Service Control Manager"], ids: &[7031, 7034], max_level: 0, what: "a service terminated unexpectedly" },
];

/// Only react to events that just happened (not backfill or boot replay).
const EVENT_MAX_AGE_S: i64 = 300;

pub fn match_event(e: &EventLog) -> Option<Finding> {
    if now_ft() - e.event_ft > EVENT_MAX_AGE_S * FT_PER_SEC {
        return None;
    }
    // Live kernel reports (GPU/USB/network watchdogs) arrive as WER 1001.
    if e.provider == "Windows Error Reporting" && e.id == 1001 {
        let m = e.message.as_deref().unwrap_or("");
        if m.contains("LiveKernelEvent") {
            return Some(("event:LiveKernelEvent".into(), format!("live kernel event (driver watchdog): {}", first_line(m))));
        }
        return None;
    }
    for r in EVENT_RULES {
        if !r.providers.iter().any(|p| p.eq_ignore_ascii_case(&e.provider)) {
            continue;
        }
        if !r.ids.is_empty() && !r.ids.contains(&e.id) {
            continue;
        }
        if r.max_level > 0 && !(1..=r.max_level).contains(&e.level) {
            continue;
        }
        let detail = e.message.as_deref().map(first_line).unwrap_or_default();
        return Some((format!("event:{}/{}", e.provider, e.id), format!("{}: {detail}", r.what)));
    }
    None
}

fn first_line(s: &str) -> String {
    let l = s.lines().next().unwrap_or("").trim();
    if l.chars().count() > 200 { l.chars().take(200).collect::<String>() + "…" } else { l.to_string() }
}

/// Device classes whose loss or failure is incident-worthy.
const CRITICAL_CLASSES: &[&str] = &["DiskDrive", "Display", "SCSIAdapter", "hdc", "Net", "Volume", "USB"];

pub fn match_device(d: &Device) -> Option<Finding> {
    let critical = CRITICAL_CLASSES.iter().any(|c| c.eq_ignore_ascii_case(&d.dev.class));
    match d.action.as_str() {
        "removed" if critical && !d.dev.class.eq_ignore_ascii_case("USB") => {
            Some((format!("device_removed:{}", d.dev.class), format!("{} device disappeared: {}", d.dev.class, d.dev.name)))
        }
        "problem" if critical => Some((
            format!("device_problem:{}", d.dev.class),
            format!("{} device entered problem code {}: {}", d.dev.class, d.dev.problem, d.dev.name),
        )),
        _ => None,
    }
}

/// Sustained-condition detector over heartbeats (one call per heartbeat).
#[derive(Default)]
pub struct VitalsDetector {
    cpu_s: u32,
    commit_s: u32,
    lowmem_s: u32,
    disk_s: u32,
}

pub const CPU_SECONDS: u32 = 30;
pub const COMMIT_SECONDS: u32 = 10;
pub const LOWMEM_SECONDS: u32 = 10;
pub const DISK_SECONDS: u32 = 5;
pub const STARVED_MS: i64 = 3000;

impl VitalsDetector {
    pub fn on_heartbeat(&mut self, v: &Vitals, jitter_ms: i64) -> Vec<Finding> {
        let mut out = Vec::new();
        let known = v.avail_mb > 0 || v.commit_pct > 0.0;
        let tick = |c: &mut u32, cond: bool| -> bool {
            if cond { *c += 1 } else { *c = 0 }
            *c > 0
        };
        tick(&mut self.cpu_s, v.cpu >= 95.0);
        tick(&mut self.commit_s, known && v.commit_pct >= 90.0);
        tick(&mut self.lowmem_s, known && v.avail_mb < 256);
        tick(&mut self.disk_s, v.disk_ms >= 1000.0);
        let top = v.top.as_deref().map(|t| format!(" (busiest: {t})")).unwrap_or_default();
        if self.cpu_s == CPU_SECONDS {
            out.push(("cpu_saturated".into(), format!("CPU at or above 95% for {CPU_SECONDS} s{top}")));
        }
        if self.commit_s == COMMIT_SECONDS {
            out.push(("commit_exhaustion".into(), format!("commit charge at {:.0}% of the limit for {COMMIT_SECONDS} s{top}", v.commit_pct)));
        }
        if self.lowmem_s == LOWMEM_SECONDS {
            out.push(("low_memory".into(), format!("under 256 MB of RAM available for {LOWMEM_SECONDS} s{top}")));
        }
        if self.disk_s == DISK_SECONDS {
            out.push(("disk_stall".into(), format!("disk latency at or above 1 s for {DISK_SECONDS} s (queue {:.0})", v.disk_q)));
        }
        if jitter_ms >= STARVED_MS {
            out.push(("system_stall".into(), format!("BlackBox's heartbeat ran {:.1} s late: the whole system stalled", jitter_ms as f64 / 1000.0)));
        }
        out
    }
}

/// Pool leak detector: growth of a tag since it was first seen.
#[derive(Default)]
pub struct PoolDetector {
    baseline: std::collections::HashMap<String, u64>,
    reported: std::collections::HashMap<String, u64>,
}

pub const POOL_LEAK_BYTES: u64 = 1 << 30;

impl PoolDetector {
    pub fn on_sample(&mut self, tags: &[bbx_core::records::PoolTag]) -> Vec<Finding> {
        let mut out = Vec::new();
        for t in tags {
            let total = t.paged + t.nonpaged;
            let base = *self.baseline.entry(t.tag.clone()).or_insert(total);
            let growth = total.saturating_sub(base);
            // Report each further 1 GB of growth once.
            let level = growth / POOL_LEAK_BYTES;
            if level >= 1 && self.reported.get(&t.tag).copied().unwrap_or(0) < level {
                self.reported.insert(t.tag.clone(), level);
                out.push((
                    format!("pool_leak:{}", t.tag),
                    format!("kernel pool tag '{}' grew by {} MB since recording started (likely driver memory leak)", t.tag, growth / 1048576),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bbx_core::records::{DeviceRow, PoolTag};

    fn ev(provider: &str, id: u32, level: u8, age_s: i64) -> EventLog {
        EventLog { provider: provider.into(), id, level, event_ft: now_ft() - age_s * FT_PER_SEC, message: Some("msg".into()), ..Default::default() }
    }

    #[test]
    fn events() {
        assert!(match_event(&ev("Display", 4101, 3, 1)).is_some());
        assert!(match_event(&ev("storahci", 129, 3, 1)).unwrap().0.contains("storahci/129"));
        assert!(match_event(&ev("Microsoft-Windows-WHEA-Logger", 17, 3, 1)).is_some());
        assert!(match_event(&ev("Microsoft-Windows-WHEA-Logger", 17, 4, 1)).is_none(), "informational WHEA is ignored");
        assert!(match_event(&ev("Display", 4101, 3, 3600)).is_none(), "old events don't trigger");
        assert!(match_event(&ev("Service Control Manager", 7036, 4, 1)).is_none());
        let mut w = ev("Windows Error Reporting", 1001, 4, 1);
        w.message = Some("Fault bucket LKD_0x141_Tdr:6_IMAGE_nvlddmkm.sys, type 0\nEvent Name: LiveKernelEvent".into());
        assert_eq!(match_event(&w).unwrap().0, "event:LiveKernelEvent");
    }

    #[test]
    fn devices() {
        let d = |action: &str, class: &str| Device {
            action: action.into(),
            dev: DeviceRow { id: "X".into(), name: "Samsung SSD".into(), class: class.into(), problem: 43 },
            old_problem: 0,
        };
        assert!(match_device(&d("removed", "DiskDrive")).is_some());
        assert!(match_device(&d("removed", "USB")).is_none(), "USB unplugging is routine");
        assert!(match_device(&d("problem", "Display")).is_some());
        assert!(match_device(&d("added", "DiskDrive")).is_none());
        assert!(match_device(&d("problem", "Mouse")).is_none());
    }

    #[test]
    fn sustained_cpu_fires_once() {
        let mut det = VitalsDetector::default();
        let v = Vitals { cpu: 99.0, commit_pct: 50.0, avail_mb: 4000, ..Default::default() };
        let mut fired = 0;
        for _ in 0..100 {
            fired += det.on_heartbeat(&v, 0).iter().filter(|f| f.0 == "cpu_saturated").count();
        }
        assert_eq!(fired, 1);
        // Recovers, then saturates again: fires again.
        det.on_heartbeat(&Vitals { cpu: 10.0, ..v.clone() }, 0);
        let again: usize = (0..CPU_SECONDS).map(|_| det.on_heartbeat(&v, 0).len()).sum();
        assert_eq!(again, 1);
    }

    #[test]
    fn unknown_vitals_dont_fire_memory_rules() {
        let mut det = VitalsDetector::default();
        for _ in 0..60 {
            assert!(det.on_heartbeat(&Vitals::default(), 0).is_empty());
        }
    }

    #[test]
    fn stall() {
        let mut det = VitalsDetector::default();
        let f = det.on_heartbeat(&Vitals { avail_mb: 4000, commit_pct: 40.0, ..Default::default() }, 8000);
        assert_eq!(f[0].0, "system_stall");
    }

    #[test]
    fn pool_leak() {
        let mut det = PoolDetector::default();
        let tag = |np: u64| vec![PoolTag { tag: "Leak".into(), nonpaged: np, ..Default::default() }];
        assert!(det.on_sample(&tag(100 << 20)).is_empty());
        assert!(det.on_sample(&tag(900 << 20)).is_empty());
        assert_eq!(det.on_sample(&tag((100 << 20) + POOL_LEAK_BYTES)).len(), 1);
        assert!(det.on_sample(&tag((200 << 20) + POOL_LEAK_BYTES)).is_empty(), "same level reported once");
        assert_eq!(det.on_sample(&tag((100 << 20) + 2 * POOL_LEAK_BYTES)).len(), 1);
    }
}
