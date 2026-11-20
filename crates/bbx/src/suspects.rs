//! Suspects: deterministic rules that rank likely causes from a dataset,
//! each with the evidence behind it. Shown in the viewer, printed by
//! `bbx suspects`, and the backbone of the AI digest (the model is asked to
//! confirm, rank or reject them, not to start from nothing).

use crate::dataset::Dataset;
#[cfg(test)]
use crate::dataset::Rec;
use crate::report::exit_code;
use bbx_core::classifier::VerdictKind;
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{fmt_local, FT_PER_SEC};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct Suspect {
    /// 0..100, higher = more likely to matter.
    pub score: u32,
    /// memory | disk | cpu | gpu | hardware | storage | crash | hang | device |
    /// network | power | shutdown | context
    pub category: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_ft: Option<i64>,
    pub evidence: Vec<String>,
}

fn s(score: u32, category: &str, title: impl Into<String>, detail: impl Into<String>, at: Option<i64>, evidence: Vec<String>) -> Suspect {
    Suspect { score, category: category.into(), title: title.into(), detail: detail.into(), at_ft: at, evidence }
}

fn t(ft: i64) -> String {
    fmt_local(ft)[11..19].to_string()
}

/// +10 when within 5 minutes of the moment of interest.
fn near(ds: &Dataset, ft: i64) -> u32 {
    if (ft - ds.at_ft).abs() <= 300 * FT_PER_SEC { 10 } else { 0 }
}

fn names(ds: &Dataset) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for r in &ds.records {
        if r.is(RecordType::ProcessStart) {
            if let Some(p) = r.parse::<rec::ProcessStart>() {
                m.insert(p.pid, p.name);
            }
        } else if r.is(RecordType::ProcessSample) {
            if let Some(p) = r.parse::<rec::ProcessSample>() {
                m.extend(p.names);
            }
        }
    }
    m
}

pub fn analyze(ds: &Dataset) -> Vec<Suspect> {
    let mut out = Vec::new();
    let names = names(ds);
    let name = |pid: u32| names.get(&pid).cloned().unwrap_or_else(|| format!("pid {pid}"));
    let beats: Vec<(i64, rec::Heartbeat)> = ds.records_of(RecordType::Heartbeat).filter_map(|r| Some((r.ft, r.parse()?))).collect();
    let events: Vec<(i64, rec::EventLog)> = ds.records_of(RecordType::EventLog).filter_map(|r| Some((r.ft, r.parse()?))).collect();

    // ---- How the last boot ended
    if let Some(v) = &ds.verdict {
        let score = match v.kind {
            VerdictKind::Bugcheck => 95,
            VerdictKind::HangThenForcedOff => 90,
            VerdictKind::ForcedOffWhileAlive | VerdictKind::DegradedThenReset => 85,
            VerdictKind::SleepTransitionFailure => 80,
            VerdictKind::AbruptStop => 70,
            VerdictKind::CollectorCrashed => 30,
            _ => 0,
        };
        if score > 0 {
            out.push(s(score, "shutdown", format!("Last boot ended: {:?}", v.kind), v.summary.clone(), v.last_alive_ft, v.details.clone()));
        }
    }

    // ---- Memory: commit pressure and who grew
    if let Some((ft, hb)) = beats.iter().max_by(|a, b| a.1.vitals.commit_pct.total_cmp(&b.1.vitals.commit_pct)) {
        if hb.vitals.commit_pct >= 90.0 {
            let growers = memory_growers(ds, &name);
            out.push(s(
                80 + near(ds, *ft),
                "memory",
                format!("Commit charge reached {:.0}% of the limit", hb.vitals.commit_pct),
                "Windows was close to running out of committed memory (RAM + page file). Allocations fail and the system can freeze or kill processes.",
                Some(*ft),
                growers,
            ));
        }
    }
    let low: Vec<&(i64, rec::Heartbeat)> = beats.iter().filter(|(_, h)| h.vitals.avail_mb > 0 && h.vitals.avail_mb < 300).collect();
    if low.len() >= 10 {
        let paging = ds
            .records_of(RecordType::PdhSample)
            .filter_map(|r| r.parse::<rec::PdhSample>())
            .map(|p| p.pages_in)
            .fold(0.0f32, f32::max);
        out.push(s(
            70 + near(ds, low[0].0),
            "memory",
            "Physical memory nearly exhausted",
            format!("Under 300 MB of RAM was free for {} s; peak hard page-ins {paging:.0}/s (thrashing makes everything crawl).", low.len()),
            Some(low[0].0),
            memory_growers(ds, &name),
        ));
    }

    // ---- Kernel pool (driver leaks)
    let pools: Vec<rec::PoolSample> = ds.records_of(RecordType::PoolSample).filter_map(|r| r.parse()).collect();
    if let (Some(first), Some(last)) = (pools.first(), pools.last()) {
        for tg in &last.tags {
            let before = first.tags.iter().find(|x| x.tag == tg.tag).map(|x| x.paged + x.nonpaged).unwrap_or(0);
            let grew = (tg.paged + tg.nonpaged).saturating_sub(before);
            if grew >= 512 << 20 {
                out.push(s(80, "memory", format!("Kernel pool tag '{}' grew {} MB", tg.tag, grew >> 20), "A driver is allocating kernel memory and not freeing it. Find the driver that owns the tag (e.g. `findstr /m /l /s {tag} %SystemRoot%\\System32\\drivers\\*.sys`).".replace("{tag}", &tg.tag), None, vec![]));
            }
        }
    }

    // ---- Disk stalls
    if let Some((ft, hb)) = beats.iter().max_by(|a, b| a.1.vitals.disk_ms.total_cmp(&b.1.vitals.disk_ms)) {
        if hb.vitals.disk_ms >= 1000.0 {
            let mut ev: Vec<String> = top_slow_io(ds, 5);
            ev.extend(events.iter().filter(|(_, e)| is_storage_event(e)).take(5).map(|(f, e)| format!("{} {}/{}: {}", t(*f), e.provider, e.id, first_line(e))));
            out.push(s(
                75 + near(ds, *ft),
                "disk",
                format!("Disk latency reached {:.0} ms", hb.vitals.disk_ms),
                "Storage stopped responding in time; anything touching disk (including paging) blocks. Causes: failing drive, controller/driver resets, cable, an I/O-heavy process, or thermal throttling of an NVMe drive.",
                Some(*ft),
                ev,
            ));
        }
    }
    let storage: Vec<&(i64, rec::EventLog)> = events.iter().filter(|(_, e)| is_storage_event(e)).collect();
    if !storage.is_empty() {
        out.push(s(
            78 + near(ds, storage[0].0),
            "storage",
            format!("{} storage/file-system error event(s)", storage.len()),
            "Windows logged disk, controller reset or file system errors.",
            Some(storage[0].0),
            storage.iter().take(8).map(|(f, e)| format!("{} {}/{}: {}", t(*f), e.provider, e.id, first_line(e))).collect(),
        ));
    }

    // ---- Disk health
    if let Some(dh) = ds.records_of(RecordType::DiskHealth).last().and_then(|r| r.parse::<rec::DiskHealth>()) {
        for d in &dh.disks {
            let mut why = Vec::new();
            if d.predict_failure == Some(true) {
                why.push("SMART predicts failure".to_string());
            }
            if let Some(h) = &d.nvme {
                if h.critical_warning != 0 {
                    why.push(format!("NVMe critical warning 0x{:02X}", h.critical_warning));
                }
                if h.media_errors > 0 {
                    why.push(format!("{} media errors", h.media_errors));
                }
                if h.used_pct >= 90 {
                    why.push(format!("{}% of rated endurance used", h.used_pct));
                }
            }
            for a in &d.ata {
                if matches!(a.id, 5 | 187 | 197 | 198) && a.raw > 0 {
                    why.push(format!("{} = {}", a.name, a.raw));
                }
                if a.id == 199 && a.raw > 0 {
                    why.push(format!("{} interface CRC errors (check SATA cable/port)", a.raw));
                }
            }
            if let (Some(tc), Some(w)) = (d.temp_c, d.warn_c) {
                if tc >= w {
                    why.push(format!("running at {tc} C (warning {w} C)"));
                }
            }
            if !why.is_empty() {
                out.push(s(82, "hardware", format!("Disk {} ({}) reports problems", d.disk, d.model), why.join("; "), None, why.clone()));
            }
        }
    }

    // ---- CPU saturation, throttling, DPC/ISR storms
    let hot: Vec<&(i64, rec::Heartbeat)> = beats.iter().filter(|(_, h)| h.vitals.cpu >= 95.0).collect();
    if hot.len() >= 30 {
        let mut by: HashMap<String, u32> = HashMap::new();
        for (_, h) in &hot {
            if let Some(tp) = &h.vitals.top {
                *by.entry(tp.split('(').next().unwrap_or(tp).to_string()).or_default() += 1;
            }
        }
        let mut v: Vec<_> = by.into_iter().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1));
        out.push(s(
            60 + near(ds, hot[0].0),
            "cpu",
            format!("CPU saturated for {} s", hot.len()),
            "The processor was pegged; the UI becomes sluggish or unresponsive.",
            Some(hot[0].0),
            v.iter().take(5).map(|(p, n)| format!("{p} was busiest for {n} s")).collect(),
        ));
    }
    let pdh: Vec<(i64, rec::PdhSample)> = ds.records_of(RecordType::PdhSample).filter_map(|r| Some((r.ft, r.parse()?))).collect();
    if let Some((ft, p)) = pdh.iter().find(|(_, p)| p.thermal.iter().any(|z| z.passive_pct < 100.0) || (p.cpu.perf > 0.0 && p.cpu.perf < 50.0 && p.cpu.utility > 70.0)) {
        out.push(s(
            65 + near(ds, *ft),
            "cpu",
            "CPU thermal or power throttling",
            format!(
                "CPU ran at {:.0}% of base performance while busy{}. Check cooling, dust, fans, power plan and power delivery.",
                p.cpu.perf,
                p.thermal.iter().filter(|z| z.passive_pct < 100.0).map(|z| format!("; zone {} at {:.0} C limited to {:.0}%", z.zone, z.celsius, z.passive_pct)).collect::<String>()
            ),
            Some(*ft),
            vec![],
        ));
    }
    if let Some((ft, p)) = pdh.iter().max_by(|a, b| (a.1.cpu.dpc_pct + a.1.cpu.intr_pct).total_cmp(&(b.1.cpu.dpc_pct + b.1.cpu.intr_pct))) {
        if p.cpu.dpc_pct + p.cpu.intr_pct >= 15.0 {
            out.push(s(
                65 + near(ds, *ft),
                "cpu",
                format!("Driver interrupt/DPC load {:.0}%", p.cpu.dpc_pct + p.cpu.intr_pct),
                "A driver spent a large share of CPU in interrupts/DPCs: causes stutter, audio dropouts, freezes. The black box (deep profile) shows which driver.",
                Some(*ft),
                vec![],
            ));
        }
    }

    // ---- GPU / display
    let gpu_ev: Vec<&(i64, rec::EventLog)> = events
        .iter()
        .filter(|(_, e)| (e.provider == "Display" && e.id == 4101) || e.message.as_deref().is_some_and(|m| m.contains("LiveKernelEvent")) || ["nvlddmkm", "amdkmdag", "amdwddmg", "igfx"].iter().any(|p| e.provider.eq_ignore_ascii_case(p)))
        .collect();
    let black: Vec<(i64, rec::UserEvent)> = ds
        .records_of(RecordType::UserEvent)
        .filter_map(|r| Some((r.ft, r.parse::<rec::UserEvent>()?)))
        .filter(|(_, u)| u.kind == "display" && u.detail == "off" && u.value < 30.0)
        .collect();
    if !gpu_ev.is_empty() || !black.is_empty() {
        let mut ev: Vec<String> = gpu_ev.iter().take(6).map(|(f, e)| format!("{} {}/{}: {}", t(*f), e.provider, e.id, first_line(e))).collect();
        ev.extend(black.iter().map(|(f, u)| format!("{} display turned off {:.0} s after the last input ({})", t(*f), u.value, u.user)));
        let at = gpu_ev.first().map(|x| x.0).or(black.first().map(|x| x.0));
        out.push(s(
            80 + at.map(|a| near(ds, a)).unwrap_or(0),
            "gpu",
            "Display / graphics driver trouble",
            "Graphics driver resets (TDR), watchdog reports, or the screen going dark while in use. Suspect the GPU driver, the GPU itself, the monitor/cable/dock, or power.",
            at,
            ev,
        ));
    }

    // ---- Hardware errors
    let whea: Vec<&(i64, rec::EventLog)> = events.iter().filter(|(_, e)| e.provider.contains("WHEA")).collect();
    if !whea.is_empty() {
        out.push(s(
            88 + near(ds, whea[0].0),
            "hardware",
            format!("{} hardware error report(s) (WHEA)", whea.len()),
            "The CPU, memory controller or PCIe bus reported an error. Even corrected errors point at failing hardware, overclocking/XMP instability or a bad PCIe device.",
            Some(whea[0].0),
            whea.iter().take(6).map(|(f, e)| format!("{} {}: {}", t(*f), e.id, first_line(e))).collect(),
        ));
    }

    // ---- Process crashes
    let mut crashes: HashMap<String, (u32, i32, i64)> = HashMap::new();
    for r in ds.records_of(RecordType::ProcessEnd) {
        if let Some(p) = r.parse::<rec::ProcessEnd>() {
            if let Some(c) = p.exit_code.filter(|c| (*c as u32) >= 0xC000_0000 && (*c as u32) != 0xC000_013A) {
                let e = crashes.entry(p.name.clone()).or_insert((0, c, r.ft));
                e.0 += 1;
            }
        }
    }
    for (_, e) in events.iter().filter(|(_, e)| e.provider == "Application Error" && e.id == 1000) {
        let app = e.data.get("AppName").or_else(|| e.data.get("0")).and_then(|v| v.as_str()).unwrap_or("app").to_string();
        crashes.entry(app).or_insert((1, 0, e.event_ft));
    }
    if !crashes.is_empty() {
        let mut v: Vec<_> = crashes.into_iter().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1 .0));
        let first = v.iter().map(|x| x.1 .2).min();
        out.push(s(
            55 + first.map(|f| near(ds, f)).unwrap_or(0),
            "crash",
            format!("{} program(s) crashed", v.len()),
            "Processes ended with error status codes.",
            first,
            v.iter().take(8).map(|(n, (c, code, f))| format!("{} {n} x{c}{}", t(*f), if *code != 0 { format!(" exit {}", exit_code(*code)) } else { String::new() })).collect(),
        ));
    }

    // ---- Hangs and stalls
    let mut hangs: Vec<String> = Vec::new();
    let mut hang_at = None;
    for r in ds.records_of(RecordType::UserEvent) {
        if let Some(u) = r.parse::<rec::UserEvent>() {
            if (u.kind == "hung_end" && u.value >= 10.0) || (u.kind == "ui_stall" && u.value >= 3000.0) {
                hang_at.get_or_insert(r.ft);
                hangs.push(if u.kind == "hung_end" { format!("{} {} not responding for {:.0} s", t(r.ft), u.proc, u.value) } else { format!("{} desktop froze for {:.1} s", t(r.ft), u.value / 1000.0) });
            }
        }
    }
    for (f, e) in events.iter().filter(|(_, e)| e.provider == "Application Hang" && e.id == 1002) {
        hang_at.get_or_insert(*f);
        hangs.push(format!("{} {}", t(*f), first_line(e)));
    }
    if !hangs.is_empty() {
        out.push(s(62 + hang_at.map(|a| near(ds, a)).unwrap_or(0), "hang", format!("{} hang(s) / UI freeze(s)", hangs.len()), "Applications or the desktop stopped responding.", hang_at, hangs.into_iter().take(10).collect()));
    }
    let stalls: Vec<&(i64, rec::Heartbeat)> = beats.iter().filter(|(_, h)| h.jitter_ms >= 3000).collect();
    let gaps: Vec<(i64, i64)> = beats
        .windows(2)
        .filter(|w| w[1].0 - w[0].0 > 10 * FT_PER_SEC && !session_boundary(ds, w[0].0, w[1].0))
        .map(|w| (w[0].0, w[1].0))
        .collect();
    if !stalls.is_empty() || !gaps.is_empty() {
        let mut ev: Vec<String> = stalls.iter().take(5).map(|(f, h)| format!("{} BlackBox heartbeat {:.1} s late", t(*f), h.jitter_ms as f64 / 1000.0)).collect();
        ev.extend(gaps.iter().take(5).map(|(a, b)| format!("{} .. {}: no heartbeat for {} s", t(*a), t(*b), (b - a) / FT_PER_SEC)));
        let at = stalls.first().map(|x| x.0).or(gaps.first().map(|g| g.0));
        out.push(s(
            75 + at.map(|a| near(ds, a)).unwrap_or(0),
            "hang",
            "Whole-system stalls",
            "Even BlackBox's own once-a-second heartbeat could not run on time: the whole machine stalled (storage, memory pressure, a driver, or firmware/SMI).",
            at,
            ev,
        ));
    }

    // ---- Devices
    let devs: Vec<(i64, rec::Device)> = ds
        .records_of(RecordType::Device)
        .filter_map(|r| Some((r.ft, r.parse::<rec::Device>()?)))
        .filter(|(_, d)| d.action == "problem" || (d.action == "removed" && !d.dev.class.eq_ignore_ascii_case("USB")))
        .collect();
    if !devs.is_empty() {
        out.push(s(
            60 + near(ds, devs[0].0),
            "device",
            format!("{} device(s) failed or disappeared", devs.len()),
            "Devices entered a problem state or dropped off the bus.",
            Some(devs[0].0),
            devs.iter().take(8).map(|(f, d)| format!("{} {} {} [{}] code {}", t(*f), d.action, d.dev.name, d.dev.class, d.dev.problem)).collect(),
        ));
    }

    // ---- Services, power, network
    let svc: Vec<&(i64, rec::EventLog)> = events.iter().filter(|(_, e)| e.provider == "Service Control Manager" && (e.id == 7031 || e.id == 7034)).collect();
    if !svc.is_empty() {
        out.push(s(50 + near(ds, svc[0].0), "crash", format!("{} service crash(es)", svc.len()), "Windows services terminated unexpectedly.", Some(svc[0].0), svc.iter().take(6).map(|(f, e)| format!("{} {}", t(*f), first_line(e))).collect()));
    }
    for r in ds.records_of(RecordType::Power) {
        if let Some(p) = r.parse::<rec::Power>() {
            if p.critical {
                out.push(s(70 + near(ds, r.ft), "power", "Battery critically low", format!("Battery at {}%; the machine may have shut off for lack of power.", p.battery_pct.unwrap_or(0)), Some(r.ft), vec![]));
                break;
            }
        }
    }
    let (mut dns_fail, mut retrans) = (0u32, 0u32);
    let mut fail_names: HashMap<String, u32> = HashMap::new();
    for r in ds.records_of(RecordType::DnsQueries) {
        for row in r.parse::<rec::DnsQueries>().map(|q| q.rows).unwrap_or_default() {
            if row.status != 0 {
                dns_fail += row.count;
                *fail_names.entry(row.name).or_default() += row.count;
            }
        }
    }
    for r in ds.records_of(RecordType::NetFlows) {
        retrans += r.parse::<rec::NetFlows>().map(|n| n.rows.iter().map(|x| x.retrans).sum::<u32>()).unwrap_or(0);
    }
    let wlan: Vec<&(i64, rec::EventLog)> = events.iter().filter(|(_, e)| e.channel.contains("WLAN") && matches!(e.id, 8003 | 11006 | 12013)).collect();
    if dns_fail >= 20 || retrans >= 100 || !wlan.is_empty() {
        let mut ev: Vec<String> = fail_names.iter().filter(|(_, n)| **n >= 3).take(6).map(|(n, c)| format!("DNS failed for {n} x{c}")).collect();
        ev.extend(wlan.iter().take(4).map(|(f, e)| format!("{} {}", t(*f), first_line(e))));
        out.push(s(40, "network", "Network trouble", format!("{dns_fail} failed DNS lookups, {retrans} TCP retransmits, {} Wi-Fi disconnects.", wlan.len()), None, ev));
    }

    // ---- Context around the moment: things that ran
    let ctx_ev: Vec<String> = events
        .iter()
        .filter(|(f, _)| (f - ds.at_ft).abs() <= 180 * FT_PER_SEC)
        .filter(|(_, e)| {
            (e.channel.contains("TaskScheduler") && (e.id == 100 || e.id == 200))
                || (e.channel.contains("Windows Defender") && matches!(e.id, 1000 | 1001 | 1116))
                || (e.channel.contains("WindowsUpdateClient") && matches!(e.id, 19 | 20 | 43 | 44))
        })
        .take(10)
        .map(|(f, e)| format!("{} {}", t(*f), first_line(e)))
        .collect();
    let drivers: Vec<String> = ds
        .records_of(RecordType::DriverLoad)
        .filter(|r| (r.ft - ds.at_ft).abs() <= 300 * FT_PER_SEC)
        .filter_map(|r| Some(format!("{} driver loaded: {}", t(r.ft), r.parse::<rec::DriverLoad>()?.path)))
        .take(5)
        .collect();
    if !ctx_ev.is_empty() || !drivers.is_empty() {
        let mut ev = ctx_ev;
        ev.extend(drivers);
        out.push(s(30, "context", "Activity right around the moment", "Scheduled tasks, Defender scans, updates and driver loads near the time of interest. Correlation, not proof.", Some(ds.at_ft), ev));
    }

    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.at_ft.cmp(&b.at_ft)));
    out
}

fn session_boundary(ds: &Dataset, a: i64, b: i64) -> bool {
    ds.in_window(a, b).iter().any(|r| r.is(RecordType::SessionStart) || r.is(RecordType::SessionEnd))
}

fn first_line(e: &rec::EventLog) -> String {
    let m = e.message.as_deref().unwrap_or("").lines().next().unwrap_or("").trim().to_string();
    if m.chars().count() > 160 { m.chars().take(160).collect::<String>() + "…" } else { m }
}

fn is_storage_event(e: &rec::EventLog) -> bool {
    let p = e.provider.to_ascii_lowercase();
    let storage = ["storahci", "stornvme", "iastora", "iastorac", "iastoravc", "nvme", "disk", "ntfs", "microsoft-windows-ntfs", "volmgr", "storport", "microsoft-windows-storport"];
    storage.contains(&p.as_str()) && (e.level <= 3 || e.id == 129 || e.id == 153)
}

fn memory_growers(ds: &Dataset, name: &dyn Fn(u32) -> String) -> Vec<String> {
    let mut first: HashMap<u32, u64> = HashMap::new();
    let mut max: HashMap<u32, u64> = HashMap::new();
    for r in ds.records_of(RecordType::ProcessSample) {
        for row in r.parse::<rec::ProcessSample>().map(|p| p.rows).unwrap_or_default() {
            first.entry(row.0).or_insert(row.3);
            let m = max.entry(row.0).or_default();
            *m = (*m).max(row.3);
        }
    }
    let mut v: Vec<(u32, u64, u64)> = max.iter().map(|(p, m)| (*p, first[p], *m)).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2 as i64 - x.1 as i64));
    let mut out: Vec<String> = v
        .iter()
        .filter(|x| x.2 > x.1 + 100 * 1024)
        .take(5)
        .map(|(p, a, b)| format!("{} grew {} MB -> {} MB private", name(*p), a / 1024, b / 1024))
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2));
    out.extend(v.iter().take(3).map(|(p, _, b)| format!("{} uses {} MB private", name(*p), b / 1024)));
    out
}

fn top_slow_io(ds: &Dataset, n: usize) -> Vec<String> {
    let mut rows: Vec<rec::DiskIoRow> = ds.records_of(RecordType::DiskActivity).flat_map(|r| r.parse::<rec::DiskActivity>().map(|d| d.rows).unwrap_or_default()).collect();
    rows.sort_by(|a, b| b.max_ms.total_cmp(&a.max_ms));
    rows.iter().take(n).filter(|r| r.max_ms >= 100.0).map(|r| format!("{:.0} ms: {} on {}", r.max_ms, r.proc, r.file)).collect()
}

/// Text block for the digest / CLI.
pub fn to_text(list: &[Suspect]) -> String {
    let mut o = String::new();
    for (i, x) in list.iter().enumerate() {
        o.push_str(&format!("{}. [{} {}] {}", i + 1, x.score, x.category, x.title));
        if let Some(a) = x.at_ft {
            o.push_str(&format!("  (at {})", fmt_local(a)));
        }
        o.push('\n');
        o.push_str(&format!("   {}\n", x.detail));
        for e in &x.evidence {
            o.push_str(&format!("   - {e}\n"));
        }
    }
    if list.is_empty() {
        o.push_str("No rule-based suspects: nothing in the recording crossed a threshold.\n");
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r(ft_s: i64, t: RecordType, data: serde_json::Value) -> Rec {
        Rec { seq: ft_s as u64, ft: ft_s * FT_PER_SEC, rtype: t as u16, data }
    }

    #[test]
    fn finds_memory_disk_gpu_and_crashes() {
        let mut ds = Dataset { at_ft: 100 * FT_PER_SEC, ..Default::default() };
        for i in 0..60 {
            ds.records.push(r(i, RecordType::Heartbeat, json!({"mono_ms": i * 1000, "boot_id": 1, "jitter_ms": if i == 50 { 9000 } else { 5 }, "cpu": 20.0, "commit_pct": 70.0 + i as f64 / 2.0, "avail_mb": 4000, "disk_ms": if i == 55 { 2500.0 } else { 2.0 }, "disk_q": 1.0})));
        }
        ds.records.push(r(1, RecordType::ProcessSample, json!({"interval_ms": 2000, "full": true, "rows": [[42, 10, 0, 100000, 10, 1, 0, 0, 0, 0]], "names": [[42, "leaky.exe"]]})));
        ds.records.push(r(59, RecordType::ProcessSample, json!({"interval_ms": 2000, "full": false, "rows": [[42, 10, 0, 3000000, 10, 1, 0, 0, 0, 0]]})));
        ds.records.push(r(56, RecordType::EventLog, json!({"channel": "System", "provider": "stornvme", "id": 129, "level": 3, "record_id": 1, "event_ft": 56 * FT_PER_SEC, "message": "Reset to device, \\Device\\RaidPort1, was issued."})));
        ds.records.push(r(57, RecordType::EventLog, json!({"channel": "System", "provider": "Display", "id": 4101, "level": 3, "record_id": 2, "event_ft": 57 * FT_PER_SEC, "message": "Display driver nvlddmkm stopped responding and has successfully recovered."})));
        ds.records.push(r(58, RecordType::ProcessEnd, json!({"pid": 7, "create_ft": 0, "name": "app.exe", "exit_code": 0xC0000005u32 as i32, "cpu_ms": 1, "peak_ws_kb": 1, "peak_private_kb": 1, "source": "etw"})));
        ds.records.sort_by_key(|x| x.ft);
        let list = analyze(&ds);
        let cats: Vec<&str> = list.iter().map(|x| x.category.as_str()).collect();
        assert!(cats.contains(&"memory"), "{cats:?}");
        assert!(cats.contains(&"disk") && cats.contains(&"storage"));
        assert!(cats.contains(&"gpu") && cats.contains(&"crash") && cats.contains(&"hang"));
        let mem = list.iter().find(|x| x.category == "memory").unwrap();
        assert!(mem.evidence.iter().any(|e| e.contains("leaky.exe grew")), "{:?}", mem.evidence);
        let crash = list.iter().find(|x| x.category == "crash").unwrap();
        assert!(crash.evidence[0].contains("access violation"));
        assert!(list.windows(2).all(|w| w[0].score >= w[1].score));
    }

    #[test]
    fn quiet_recording_has_no_suspects() {
        let mut ds = Dataset::default();
        for i in 0..30 {
            ds.records.push(r(i, RecordType::Heartbeat, json!({"mono_ms": 0, "boot_id": 1, "jitter_ms": 3, "cpu": 10.0, "commit_pct": 40.0, "avail_mb": 8000, "disk_ms": 1.0, "disk_q": 0.0})));
        }
        assert!(analyze(&ds).is_empty());
    }
}
