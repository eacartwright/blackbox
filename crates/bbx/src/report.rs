//! "What was happening around time T": a plain-text report built from the
//! journal. Used by `bbx around`, saved as summary.txt with every incident
//! and export, and (phase 4) the input digest for AI analysis.

use anyhow::Result;
use crate::dataset::Rec;
use bbx_core::paths::Paths;
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{fmt_local, FT_PER_SEC};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

#[derive(Default)]
struct ProcAgg {
    samples: u32,
    cpu_sum: f64,
    cpu_max: f64,
    private_max: u64,
    private_first: Option<u64>,
    handles_max: u32,
}

#[derive(Default)]
struct NetAgg {
    sent: u64,
    recv: u64,
    connects: u32,
    retrans: u32,
}

#[derive(Default)]
struct Collected {
    beats: Vec<(i64, rec::Heartbeat)>,
    names: HashMap<u32, String>,
    procs: HashMap<u32, ProcAgg>,
    notable: Vec<(i64, String)>,
    pdh: Vec<(i64, rec::PdhSample)>,
    pools: Vec<rec::PoolSample>,
    net: HashMap<(String, String, String), NetAgg>,
    dns_fail: BTreeMap<(String, String, u32), u32>,
    dns_top: HashMap<String, u32>,
    disk: Vec<rec::DiskIoRow>,
    files: HashMap<(String, String), rec::FileRow>,
    reg: HashMap<(String, String, String), rec::RegRow>,
    crashes: Vec<(i64, rec::ProcessEnd)>,
}

fn collect(recs: &[Rec]) -> Collected {
    let mut c = Collected::default();
    for r in recs {
        let Some(ty) = r.ty() else { continue };
        match ty {
            RecordType::Heartbeat => {
                if let Some(h) = r.parse() {
                    c.beats.push((r.ft, h));
                }
            }
            RecordType::ProcessSample => {
                if let Some(s) = r.parse::<rec::ProcessSample>() {
                    c.names.extend(s.names);
                    for row in s.rows {
                        let a = c.procs.entry(row.0).or_default();
                        let cpu = row.1 as f64 / 10.0;
                        a.samples += 1;
                        a.cpu_sum += cpu;
                        a.cpu_max = a.cpu_max.max(cpu);
                        a.private_first.get_or_insert(row.3);
                        a.private_max = a.private_max.max(row.3);
                        a.handles_max = a.handles_max.max(row.4);
                    }
                }
            }
            RecordType::PdhSample => {
                if let Some(s) = r.parse() {
                    c.pdh.push((r.ft, s));
                }
            }
            RecordType::PoolSample => {
                if let Some(s) = r.parse() {
                    c.pools.push(s);
                }
            }
            RecordType::ProcessStart => {
                if let Some(p) = r.parse::<rec::ProcessStart>() {
                    c.names.insert(p.pid, p.name.clone());
                    if p.source != "inventory" {
                        let cl = if p.cmdline.is_empty() { p.name.clone() } else { p.cmdline.clone() };
                        c.notable.push((r.ft, format!("process start  {}({}) parent {}: {}", p.name, p.pid, p.ppid, short(&cl, 160))));
                    }
                }
            }
            RecordType::ProcessEnd => {
                if let Some(p) = r.parse::<rec::ProcessEnd>() {
                    let code = p.exit_code.map(|c| format!(" exit {}", exit_code(c))).unwrap_or_default();
                    c.notable.push((r.ft, format!("process end    {}({}){code}", p.name, p.pid)));
                    if p.exit_code.is_some_and(|c| (c as u32) >= 0xC000_0000) {
                        c.crashes.push((r.ft, p));
                    }
                }
            }
            RecordType::EventLog => {
                if let Some(e) = r.parse::<rec::EventLog>() {
                    let lvl = match e.level { 1 => "CRIT", 2 => "ERR ", 3 => "WARN", _ => "info" };
                    let msg = e.message.as_deref().map(|m| short(m.lines().next().unwrap_or(""), 140)).unwrap_or_default();
                    c.notable.push((e.event_ft, format!("event {lvl}     {}/{} {} {msg}", e.channel.trim_start_matches("Microsoft-Windows-"), e.provider, e.id)));
                }
            }
            RecordType::Device => {
                if let Some(d) = r.parse::<rec::Device>() {
                    c.notable.push((r.ft, format!("device {:<8} {} [{}] problem={}", d.action, d.dev.name, d.dev.class, d.dev.problem)));
                }
            }
            RecordType::DriverLoad => {
                if let Some(d) = r.parse::<rec::DriverLoad>() {
                    c.notable.push((r.ft, format!("driver load    {}", d.path)));
                }
            }
            RecordType::UserEvent => {
                if let Some(u) = r.parse::<rec::UserEvent>() {
                    let line = match u.kind.as_str() {
                        "hung" => format!("user hung      {} stopped responding", u.proc),
                        "hung_end" => format!("user hung end  {} responding again after {:.0} s", u.proc, u.value),
                        "ui_stall" => format!("user UI STALL  desktop froze for {:.1} s", u.value / 1000.0),
                        "display" => format!("user display   {} (last input {:.0} s earlier)", u.detail, u.value),
                        "foreground" => format!("user switched  to {}", u.proc),
                        "idle" | "active" => format!("user {}", u.kind),
                        _ => format!("user {:<9} {} {}", u.kind, u.proc, u.detail),
                    };
                    c.notable.push((r.ft, format!("{line}  [{}]", u.user)));
                }
            }
            RecordType::DiskHealth => {}
            RecordType::Power => {
                if let Some(p) = r.parse::<rec::Power>() {
                    let ac = match p.ac { Some(true) => "on AC", Some(false) => "ON BATTERY", None => "power unknown" };
                    let bat = p.battery_pct.map(|b| format!(", battery {b}%{}", if p.critical { " CRITICAL" } else { "" })).unwrap_or_default();
                    c.notable.push((r.ft, format!("power          {ac}{bat}")));
                }
            }
            RecordType::Incident => {
                if let Some(i) = r.parse::<rec::Incident>() {
                    c.notable.push((r.ft, format!("INCIDENT       [{}] {}", i.kind, i.reason)));
                }
            }
            RecordType::SessionStart | RecordType::SessionEnd | RecordType::Note | RecordType::ShutdownVerdict => {
                c.notable.push((r.ft, format!("{:<14} {}", ty.name(), short(&r.data.to_string(), 160))));
            }
            RecordType::CollectorStatus => {
                if let Some(s) = r.parse::<rec::CollectorStatus>() {
                    if s.level != "info" {
                        c.notable.push((r.ft, format!("collector {:<5} [{}] {}", s.level, s.collector, s.message)));
                    }
                }
            }
            RecordType::NetFlows => {
                if let Some(n) = r.parse::<rec::NetFlows>() {
                    for row in n.rows {
                        let a = c.net.entry((row.proc.clone(), row.proto.clone(), row.remote.clone())).or_default();
                        a.sent += row.sent;
                        a.recv += row.recv;
                        a.connects += row.connects;
                        a.retrans += row.retrans;
                    }
                }
            }
            RecordType::DnsQueries => {
                if let Some(q) = r.parse::<rec::DnsQueries>() {
                    for row in q.rows {
                        *c.dns_top.entry(row.name.clone()).or_default() += row.count;
                        if row.status != 0 {
                            *c.dns_fail.entry((row.proc.clone(), row.name.clone(), row.status)).or_default() += row.count;
                        }
                    }
                }
            }
            RecordType::DiskActivity => {
                if let Some(d) = r.parse::<rec::DiskActivity>() {
                    c.disk.extend(d.rows);
                }
            }
            RecordType::FileActivity => {
                if let Some(f) = r.parse::<rec::FileActivity>() {
                    for row in f.rows {
                        let e = c.files.entry((row.proc.clone(), row.path.clone())).or_insert_with(|| rec::FileRow { proc: row.proc.clone(), path: row.path.clone(), ..Default::default() });
                        e.creates += row.creates;
                        e.writes += row.writes;
                        e.write_bytes += row.write_bytes;
                        e.deletes += row.deletes;
                        e.renames += row.renames;
                    }
                }
            }
            RecordType::RegistryActivity => {
                if let Some(g) = r.parse::<rec::RegistryActivity>() {
                    for row in g.rows {
                        let e = c.reg.entry((row.proc.clone(), row.key.clone(), row.value.clone())).or_insert_with(|| rec::RegRow {
                            proc: row.proc.clone(),
                            key: row.key.clone(),
                            value: row.value.clone(),
                            ..Default::default()
                        });
                        e.sets += row.sets;
                        e.creates += row.creates;
                        e.deletes += row.deletes;
                    }
                }
            }
            _ => {}
        }
    }
    c
}

/// Known NTSTATUS exit codes worth naming.
pub fn exit_code(c: i32) -> String {
    let u = c as u32;
    let name = match u {
        0xC0000005 => " (access violation)",
        0xC0000409 => " (stack buffer overrun / fail-fast)",
        0xC00000FD => " (stack overflow)",
        0xC0000374 => " (heap corruption)",
        0xC0000017 => " (out of memory)",
        0xC000001D => " (illegal instruction)",
        0xC0000094 => " (integer divide by zero)",
        0xC000013A => " (Ctrl+C / closed)",
        0xC0000142 => " (DLL initialization failed)",
        0xC0000135 => " (DLL not found)",
        0xC0000006 => " (in-page I/O error)",
        0xE0434352 => " (.NET exception)",
        0x40010004 => " (debugger terminated)",
        _ => "",
    };
    if u >= 0x1000 { format!("0x{u:08X}{name}") } else { format!("{c}") }
}

/// Report from this machine's journal.
pub fn around(paths: &Paths, t: i64, before_min: u64, after_min: u64) -> Result<String> {
    let from = t - before_min as i64 * 60 * FT_PER_SEC;
    let to = t + after_min as i64 * 60 * FT_PER_SEC;
    let recs = crate::dataset::load_journal(paths, from, to)?;
    around_records(&recs, t, before_min, after_min)
}

/// Report from already-loaded records (a bundle or dataset).
pub fn around_records(all: &[Rec], t: i64, before_min: u64, after_min: u64) -> Result<String> {
    let from = t - before_min as i64 * 60 * FT_PER_SEC;
    let to = t + after_min as i64 * 60 * FT_PER_SEC;
    let a = all.partition_point(|r| r.ft < from);
    let b = all.partition_point(|r| r.ft <= to);
    let c = collect(&all[a..b.max(a)]);
    let mut o = String::new();
    writeln!(o, "What was happening around {}  (window {} .. {})\n", fmt_local(t), fmt_local(from), fmt_local(to))?;
    if c.beats.is_empty() {
        writeln!(o, "No recording covers this time.")?;
        return Ok(o);
    }

    writeln!(o, "VITALS (every ~10 s)")?;
    writeln!(o, "  {:<12} {:>5} {:>7} {:>9} {:>8} {:>6} {:>7}  busiest process", "time", "cpu%", "commit%", "free MB", "disk ms", "queue", "late ms")?;
    let mut last_shown = 0i64;
    let last_ft = c.beats.last().unwrap().0;
    for (ft, h) in &c.beats {
        let v = &h.vitals;
        if (v.avail_mb == 0 && v.commit_pct == 0.0) || (*ft - last_shown < 10 * FT_PER_SEC && *ft != last_ft && h.jitter_ms < 1000) {
            continue;
        }
        last_shown = *ft;
        let mark = if (*ft - t).abs() < 5 * FT_PER_SEC { " <==" } else { "" };
        writeln!(
            o,
            "  {:<12} {:>5.0} {:>7.0} {:>9} {:>8.0} {:>6.1} {:>7}  {}{mark}",
            &fmt_local(*ft)[11..23],
            v.cpu,
            v.commit_pct,
            v.avail_mb,
            v.disk_ms,
            v.disk_q,
            h.jitter_ms,
            v.top.clone().unwrap_or_default()
        )?;
    }
    for g in c.beats.windows(2).filter(|w| (w[1].0 - w[0].0) > 5 * FT_PER_SEC) {
        writeln!(o, "  !! no heartbeat for {} s between {} and {}", (g[1].0 - g[0].0) / FT_PER_SEC, fmt_local(g[0].0), fmt_local(g[1].0))?;
    }

    if let Some((wft, worst)) = c.pdh.iter().max_by(|a, b| {
        let m = |s: &rec::PdhSample| s.disks.iter().map(|d| d.ms).fold(0.0f32, f32::max);
        m(&a.1).total_cmp(&m(&b.1))
    }) {
        writeln!(o, "\nWORST DISK MOMENT ({})", &fmt_local(*wft)[11..23])?;
        for d in &worst.disks {
            writeln!(o, "  {:<20} {:>8.1} ms  queue {:>5.1}  {:>8.1} MB/s  idle {:>5.1}%", d.disk, d.ms, d.queue, d.bps / 1048576.0, d.idle_pct)?;
        }
        if worst.cpu.perf > 0.0 {
            writeln!(o, "  CPU performance {:.0}% of base, DPC {:.1}%, interrupts {:.1}%", worst.cpu.perf, worst.cpu.dpc_pct, worst.cpu.intr_pct)?;
        }
        for z in &worst.thermal {
            writeln!(o, "  thermal {:<20} {:>5.1} °C  passive limit {:.0}%", z.zone, z.celsius, z.passive_pct)?;
        }
        if let Some(g) = &worst.gpu {
            let e: Vec<String> = g.engines.iter().take(4).map(|e| format!("{} {:.0}%", e.engine, e.pct)).collect();
            writeln!(o, "  GPU: {}; dedicated memory {:.0} MB", e.join(", "), g.dedicated_mb)?;
        }
    }

    let mut top: Vec<(&u32, &ProcAgg)> = c.procs.iter().collect();
    top.sort_by(|a, b| b.1.cpu_sum.total_cmp(&a.1.cpu_sum));
    writeln!(o, "\nTOP PROCESSES BY CPU")?;
    writeln!(o, "  {:<28} {:>7} {:>7} {:>11} {:>11} {:>8}", "process", "avg%", "max%", "private MB", "growth MB", "handles")?;
    for (pid, a) in top.iter().take(10) {
        let name = c.names.get(pid).cloned().unwrap_or_else(|| "?".into());
        writeln!(
            o,
            "  {:<28} {:>7.1} {:>7.1} {:>11} {:>11} {:>8}",
            short(&format!("{name}({pid})"), 28),
            a.cpu_sum / a.samples.max(1) as f64,
            a.cpu_max,
            a.private_max / 1024,
            (a.private_max as i64 - a.private_first.unwrap_or(0) as i64) / 1024,
            a.handles_max
        )?;
    }
    let mut mem: Vec<(&u32, &ProcAgg)> = c.procs.iter().filter(|(_, a)| a.private_max > a.private_first.unwrap_or(0) + 50 * 1024).collect();
    if !mem.is_empty() {
        mem.sort_by_key(|(_, a)| std::cmp::Reverse(a.private_max - a.private_first.unwrap_or(0)));
        writeln!(o, "\nMEMORY GROWERS (private bytes grew > 50 MB in the window)")?;
        for (pid, a) in mem.iter().take(5) {
            let name = c.names.get(pid).cloned().unwrap_or_else(|| "?".into());
            writeln!(o, "  {name}({pid}): {} MB -> {} MB", a.private_first.unwrap_or(0) / 1024, a.private_max / 1024)?;
        }
    }
    if let (Some(first), Some(last)) = (c.pools.first(), c.pools.last()) {
        let before: BTreeMap<&str, u64> = first.tags.iter().map(|t| (t.tag.as_str(), t.paged + t.nonpaged)).collect();
        let mut growth: Vec<(String, i64)> = last
            .tags
            .iter()
            .filter_map(|t| before.get(t.tag.as_str()).map(|b| (t.tag.clone(), (t.paged + t.nonpaged) as i64 - *b as i64)))
            .filter(|(_, d)| *d > 16 * 1048576)
            .collect();
        if !growth.is_empty() {
            growth.sort_by_key(|g| std::cmp::Reverse(g.1));
            writeln!(o, "\nKERNEL POOL GROWTH (possible driver leak)")?;
            for (tag, d) in growth.iter().take(5) {
                writeln!(o, "  tag '{tag}': +{} MB", d / 1048576)?;
            }
        }
    }

    if !c.crashes.is_empty() {
        writeln!(o, "\nPROCESSES THAT CRASHED (NTSTATUS error exit codes)")?;
        for (ft, p) in c.crashes.iter().take(20) {
            writeln!(o, "  {}  {}({}) exit {}", &fmt_local(*ft)[11..23], p.name, p.pid, exit_code(p.exit_code.unwrap_or(0)))?;
        }
    }

    let mut disk = c.disk.clone();
    disk.sort_by(|a, b| b.max_ms.total_cmp(&a.max_ms));
    if disk.first().is_some_and(|d| d.max_ms >= 50.0) {
        writeln!(o, "\nSLOWEST DISK I/O")?;
        writeln!(o, "  {:>8} {:>8} {:<24} file", "max ms", "avg ms", "process")?;
        for d in disk.iter().take(10).filter(|d| d.max_ms >= 50.0) {
            let n = (d.reads + d.writes).max(1) as f32;
            writeln!(o, "  {:>8.0} {:>8.1} {:<24} {}", d.max_ms, d.total_ms / n, short(&format!("{}({})", d.proc, d.pid), 24), short(&d.file, 90))?;
        }
    }

    if !c.net.is_empty() {
        let mut net: Vec<_> = c.net.iter().collect();
        net.sort_by_key(|(_, a)| std::cmp::Reverse(a.sent + a.recv));
        writeln!(o, "\nNETWORK (top by bytes)")?;
        writeln!(o, "  {:<24} {:<4} {:<28} {:>10} {:>10} {:>6} {:>7}", "process", "", "remote", "sent KB", "recv KB", "conns", "retrans")?;
        for ((p, proto, remote), a) in net.iter().take(10) {
            writeln!(o, "  {:<24} {:<4} {:<28} {:>10} {:>10} {:>6} {:>7}", short(p, 24), proto, short(remote, 28), a.sent / 1024, a.recv / 1024, a.connects, a.retrans)?;
        }
        let retrans: Vec<_> = c.net.iter().filter(|(_, a)| a.retrans >= 10).collect();
        for ((p, _, remote), a) in retrans.iter().take(5) {
            writeln!(o, "  !! {p} -> {remote}: {} TCP retransmits (packet loss / unreachable)", a.retrans)?;
        }
    }
    if !c.dns_fail.is_empty() {
        writeln!(o, "\nDNS FAILURES")?;
        for ((p, name, status), n) in c.dns_fail.iter().take(15) {
            let why = match status { 9003 => "no such name", 1460 => "timeout", 9002 => "server failure", 1214 => "invalid name", _ => "" };
            writeln!(o, "  {name} ({p}) status {status} {why} x{n}")?;
        }
    }

    if !c.files.is_empty() {
        let mut f: Vec<_> = c.files.values().collect();
        f.sort_by_key(|r| std::cmp::Reverse(r.write_bytes + 4096 * r.writes as u64));
        writeln!(o, "\nFILES WRITTEN (top by bytes)")?;
        for r in f.iter().take(12) {
            writeln!(o, "  {:<22} {:>9} KB {:>6} writes  {}", short(&r.proc, 22), r.write_bytes / 1024, r.writes, short(&r.path, 100))?;
        }
        let changed: Vec<_> = c.files.values().filter(|r| r.deletes + r.renames > 0).collect();
        if !changed.is_empty() {
            writeln!(o, "  deleted / renamed:")?;
            for r in changed.iter().take(15) {
                let what = if r.deletes > 0 { "deleted" } else { "renamed" };
                writeln!(o, "    {what:<8} by {:<20} {}", short(&r.proc, 20), short(&r.path, 100))?;
            }
        }
    }
    if !c.reg.is_empty() {
        let mut g: Vec<_> = c.reg.values().collect();
        g.sort_by_key(|r| std::cmp::Reverse(r.sets + r.creates + r.deletes));
        writeln!(o, "\nREGISTRY WRITES")?;
        for r in g.iter().take(12) {
            let v = if r.value.is_empty() { String::new() } else { format!(" : {}", r.value) };
            writeln!(o, "  {:<22} set {:>4} new {:>3} del {:>3}  {}{v}", short(&r.proc, 22), r.sets, r.creates, r.deletes, short(&r.key, 90))?;
        }
    }

    let mut notable = c.notable;
    notable.sort_by_key(|n| n.0);
    writeln!(o, "\nTIMELINE")?;
    if notable.is_empty() {
        writeln!(o, "  (no process starts/ends, events, device changes or incidents in this window)")?;
    }
    for (ft, s) in notable.iter().take(400) {
        let mark = if (*ft - t).abs() < 5 * FT_PER_SEC { "==>" } else { "   " };
        writeln!(o, "{mark} {}  {s}", &fmt_local(*ft)[11..23])?;
    }
    if notable.len() > 400 {
        writeln!(o, "    ... {} more (use `bbx dump --from ... --to ...`)", notable.len() - 400)?;
    }
    Ok(o)
}

pub fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).collect::<String>() + "…" }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exit_codes() {
        assert_eq!(super::exit_code(0), "0");
        assert_eq!(super::exit_code(0xC0000005u32 as i32), "0xC0000005 (access violation)");
    }
}
