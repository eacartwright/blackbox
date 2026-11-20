//! Read-side commands: status, around, last-shutdown, dump, mark.

use crate::agent::{self, describe_last_heartbeat, fmt_age, RunOptions, LAST_VERDICT_FILE};
use crate::service::SERVICE_NAME;
use anyhow::{anyhow, bail, Context, Result};
use bbx_collect::{blackbox, Stop};
use bbx_core::classifier::Verdict;
use bbx_core::journal;
use bbx_core::paths::Paths;
use bbx_core::records::{self as rec, type_name, RecordType};
use bbx_core::time::{fmt_local, now_ft, parse_user_time, FT_PER_SEC};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};

fn paths_readable() -> Result<Paths> {
    let p = Paths::from_env();
    if !p.root.exists() {
        bail!("no BlackBox data at {} (is it installed?)", p.root.display());
    }
    if std::fs::read_dir(p.journal()).is_err() {
        bail!("cannot read {} — run this from an elevated (Administrator) prompt", p.journal().display());
    }
    Ok(p)
}

// ---------------------------------------------------------------- run

static CONSOLE_STOP: OnceLock<Arc<Stop>> = OnceLock::new();

unsafe extern "system" fn on_ctrl(_ty: u32) -> i32 {
    if let Some(s) = CONSOLE_STOP.get() {
        s.signal();
    }
    1
}

pub fn run_console(verbose: bool, for_secs: Option<u64>) -> Result<()> {
    if !crate::install::is_elevated() {
        eprintln!("note: not elevated — the black box (ETW) and some process details will be unavailable");
    }
    let stop = Stop::new();
    CONSOLE_STOP.set(stop.clone()).ok();
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    println!("Recording to {} — Ctrl+C to stop", Paths::from_env().root.display());
    if let Some(secs) = for_secs {
        let s = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            s.signal();
        });
    }
    agent::run(stop, Arc::new(AtomicBool::new(false)), RunOptions { console: true, verbose })
}

// ---------------------------------------------------------------- status

pub fn status() -> Result<()> {
    println!("BlackBox {}", bbx_core::VERSION);
    println!("  Service:        {}", service_state());
    let bb = match blackbox::query() {
        Ok(i) if i.running => format!("recording ({} buffers written, {} lost)", i.buffers_written, i.events_lost + i.log_buffers_lost),
        Ok(_) => "NOT running".into(),
        Err(e) => format!("unknown — {e}"),
    };
    println!("  Black box:      {bb}");
    let paths = paths_readable()?;
    let files = blackbox::list_files(&paths.blackbox());
    let bb_mb: u64 = files.iter().map(|f| f.size).sum::<u64>() / 1048576;
    if let (Some(first), Some(last)) = (files.first(), files.last()) {
        println!(
            "                  {} files, {bb_mb} MB, covering {} .. {}",
            files.len(),
            fmt_local(first.created_ft),
            fmt_local(last.modified_ft)
        );
    }
    let segs = journal::list_segments(&paths.journal())?;
    let mb = segs.iter().map(|s| s.size).sum::<u64>() as f64 / 1048576.0;
    let oldest = segs.iter().filter_map(|s| s.first_ft).min();
    println!(
        "  Journal:        {} segments, {mb:.1} MB{}",
        segs.len(),
        oldest.map(|o| format!(", history since {}", fmt_local(o))).unwrap_or_default()
    );
    match describe_last_heartbeat(&paths) {
        Some((ft, hb)) => {
            println!("  Last heartbeat: {}", fmt_age(ft));
            let v = hb.vitals;
            println!(
                "                  CPU {:.0}%, commit {:.0}%, {} MB free RAM, disk {:.0} ms, busiest {}",
                v.cpu, v.commit_pct, v.avail_mb, v.disk_ms, v.top.unwrap_or_else(|| "-".into())
            );
            if (now_ft() - ft) / FT_PER_SEC > 10 {
                println!("                  WARNING: no heartbeat for over 10 s — recording may be stopped");
            }
        }
        None => println!("  Last heartbeat: none yet"),
    }
    if let Some(v) = load_verdict(&paths) {
        println!("  Last shutdown:  {:?} ({:?} confidence)", v.kind, v.confidence);
    }
    let problems = journal::tail(&paths.journal(), None, 5, |r| {
        r.rtype == RecordType::CollectorStatus as u16
            && r.parse::<rec::CollectorStatus>().is_some_and(|s| s.level != "info")
    })?;
    if !problems.is_empty() {
        println!("  Recent collector problems:");
        for r in problems.iter().rev() {
            let s: rec::CollectorStatus = r.parse().unwrap();
            println!("    {}  [{}] {}", fmt_local(r.ft), s.collector, s.message);
        }
    }
    let incidents = std::fs::read_dir(paths.incidents()).map(|d| d.count()).unwrap_or(0);
    println!("  Incidents:      {incidents} saved in {}", paths.incidents().display());
    Ok(())
}

fn service_state() -> String {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return "unknown".into();
    };
    match mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => match s.query_status() {
            Ok(st) => format!("{:?}{}", st.current_state, st.process_id.map(|p| format!(" (pid {p})")).unwrap_or_default()),
            Err(e) => format!("unknown ({e})"),
        },
        Err(_) => "not installed".into(),
    }
}

pub fn blackbox_status() -> Result<()> {
    match blackbox::query() {
        Ok(i) if i.running => {
            println!("Session {}: running", blackbox::SESSION_NAME);
            println!("  file pattern:    {}", i.file);
            println!("  buffers written: {}", i.buffers_written);
            println!("  events lost:     {}  buffers lost: {}", i.events_lost, i.log_buffers_lost);
        }
        Ok(_) => println!("Session {}: not running", blackbox::SESSION_NAME),
        Err(e) => bail!(e),
    }
    let paths = Paths::from_env();
    for f in blackbox::list_files(&paths.blackbox()) {
        println!("  {}  {:>6} MB  {} .. {}", f.path.file_name().unwrap().to_string_lossy(), f.size / 1048576, fmt_local(f.created_ft), fmt_local(f.modified_ft));
    }
    Ok(())
}

// ---------------------------------------------------------------- last-shutdown

fn load_verdict(paths: &Paths) -> Option<Verdict> {
    if let Some(v) = std::fs::read(paths.state().join(LAST_VERDICT_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
        return Some(v);
    }
    journal::tail(&paths.journal(), None, 1, |r| r.rtype == RecordType::ShutdownVerdict as u16)
        .ok()?
        .first()?
        .parse()
}

pub fn last_shutdown() -> Result<()> {
    let paths = paths_readable()?;
    let v = load_verdict(&paths).ok_or_else(|| anyhow!("no verdict yet (the service writes one within ~3 minutes of starting)"))?;
    println!("{:?}  ({:?} confidence)\n", v.kind, v.confidence);
    println!("{}\n", wrap(&v.summary, 100));
    for d in &v.details {
        println!("  - {d}");
    }
    if let Some(ev) = &v.evidence {
        if let Some(k) = &ev.kp41 {
            println!(
                "  - Kernel-Power 41 at {}: BugcheckCode=0x{:X}, SleepInProgress={}, PowerButtonTimestamp={}",
                fmt_local(k.ft),
                k.bugcheck_code,
                k.sleep_in_progress,
                if k.power_button_ft > 0 { fmt_local(k.power_button_ft) } else { "0".into() }
            );
        }
        if let Some(t) = ev.ev6008_ft {
            println!("  - EventLog 6008 (unexpected shutdown) logged at {}", fmt_local(t));
        }
    }
    Ok(())
}

fn wrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = 0;
    for w in s.split_whitespace() {
        if line + w.len() + 1 > width && line > 0 {
            out.push('\n');
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(w);
        line += w.len();
    }
    out
}

// ---------------------------------------------------------------- dump

pub fn dump(from: Option<String>, to: Option<String>, types: Option<String>, last: Option<usize>, json: bool) -> Result<()> {
    let paths = paths_readable()?;
    let from = from.map(|s| parse_user_time(&s)).transpose()?;
    let to = to.map(|s| parse_user_time(&s)).transpose()?;
    let wanted: Option<Vec<u16>> = types
        .map(|t| {
            t.split(',')
                .map(|n| RecordType::from_name(n.trim()).map(|t| t as u16).ok_or_else(|| anyhow!("unknown record type '{n}'")))
                .collect::<Result<_>>()
        })
        .transpose()?;
    let matches = |r: &journal::RawRecord| {
        wanted.as_ref().is_none_or(|w| w.contains(&r.rtype))
            && from.is_none_or(|f| r.ft >= f)
            && to.is_none_or(|t| r.ft <= t)
    };
    let print = |r: &journal::RawRecord| {
        if json {
            println!(
                "{}",
                serde_json::json!({"seq": r.seq, "time": bbx_core::time::fmt_utc(r.ft), "type": type_name(r.rtype), "data": r.json()})
            );
        } else {
            println!("{}  #{:<8} {:<16} {}", fmt_local(r.ft), r.seq, type_name(r.rtype), r.json());
        }
    };
    let n = match (last, from, to) {
        (Some(n), _, _) => Some(n),
        (None, None, None) => Some(50),
        _ => None,
    };
    if let Some(n) = n {
        let recs = journal::tail(&paths.journal(), None, n, matches)?;
        recs.iter().rev().for_each(print);
    } else {
        journal::for_each_record(&paths.journal(), from, to, |r| {
            if matches(r) {
                print(r);
            }
            true
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------- mark

pub fn mark(note: &str) -> Result<()> {
    let paths = Paths::from_env();
    let dir = paths.triggers();
    let body = serde_json::json!({
        "note": if note.is_empty() { "marked by user" } else { note },
        "user": std::env::var("USERNAME").unwrap_or_default(),
    });
    let path = dir.join(format!("mark-{}-{}.json", now_ft(), std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&body)?).with_context(|| format!("writing {}", path.display()))?;
    println!("Marked at {}.", fmt_local(now_ft()));
    println!("BlackBox will keep the black-box recording from the last few minutes together with this note.");
    Ok(())
}

// ---------------------------------------------------------------- around

#[derive(Default)]
struct ProcAgg {
    samples: u32,
    cpu_sum: f64,
    cpu_max: f64,
    private_max: u64,
    private_first: Option<u64>,
    handles_max: u32,
    io_max: u64,
}

pub fn around(time: &str, minutes: u64, after: u64) -> Result<()> {
    let paths = paths_readable()?;
    let t = parse_user_time(time)?;
    let from = t - minutes as i64 * 60 * FT_PER_SEC;
    let to = t + after as i64 * 60 * FT_PER_SEC;
    println!("What was happening around {}  (window {} .. {})\n", fmt_local(t), fmt_local(from), fmt_local(to));

    let mut beats: Vec<(i64, rec::Heartbeat)> = Vec::new();
    let mut names: HashMap<u32, String> = HashMap::new();
    let mut procs: HashMap<u32, ProcAgg> = HashMap::new();
    let mut notable: Vec<(i64, String)> = Vec::new();
    let mut pdh: Vec<(i64, rec::PdhSample)> = Vec::new();
    let mut pools: Vec<rec::PoolSample> = Vec::new();

    journal::for_each_record(&paths.journal(), Some(from), Some(to), |r| {
        let Some(ty) = r.record_type() else { return true };
        match ty {
            RecordType::Heartbeat => {
                if let Some(h) = r.parse() {
                    beats.push((r.ft, h));
                }
            }
            RecordType::ProcessSample => {
                if let Some(s) = r.parse::<rec::ProcessSample>() {
                    names.extend(s.names);
                    for row in s.rows {
                        let a = procs.entry(row.0).or_default();
                        let cpu = row.1 as f64 / 10.0;
                        a.samples += 1;
                        a.cpu_sum += cpu;
                        a.cpu_max = a.cpu_max.max(cpu);
                        a.private_first.get_or_insert(row.3);
                        a.private_max = a.private_max.max(row.3);
                        a.handles_max = a.handles_max.max(row.4);
                        a.io_max = a.io_max.max(row.6 + row.7 + row.8);
                    }
                }
            }
            RecordType::PdhSample => {
                if let Some(s) = r.parse() {
                    pdh.push((r.ft, s));
                }
            }
            RecordType::PoolSample => {
                if let Some(s) = r.parse() {
                    pools.push(s);
                }
            }
            RecordType::ProcessStart => {
                if let Some(p) = r.parse::<rec::ProcessStart>() {
                    names.insert(p.pid, p.name.clone());
                    if p.source != "inventory" {
                        let cl = if p.cmdline.is_empty() { p.name.clone() } else { p.cmdline.clone() };
                        notable.push((r.ft, format!("process start  {}({}) parent {}: {}", p.name, p.pid, p.ppid, short(&cl, 160))));
                    }
                }
            }
            RecordType::ProcessEnd => {
                if let Some(p) = r.parse::<rec::ProcessEnd>() {
                    let code = p.exit_code.map(|c| format!(" exit 0x{:X}", c as u32)).unwrap_or_default();
                    notable.push((r.ft, format!("process end    {}({}){code}, peak private {} MB", p.name, p.pid, p.peak_private_kb / 1024)));
                }
            }
            RecordType::EventLog => {
                if let Some(e) = r.parse::<rec::EventLog>() {
                    let lvl = match e.level { 1 => "CRIT", 2 => "ERR ", 3 => "WARN", _ => "info" };
                    let msg = e.message.as_deref().map(|m| short(m.lines().next().unwrap_or(""), 140)).unwrap_or_default();
                    notable.push((e.event_ft, format!("event {lvl}     {}/{} {} {msg}", short_channel(&e.channel), e.provider, e.id)));
                }
            }
            RecordType::Device => {
                if let Some(d) = r.parse::<rec::Device>() {
                    notable.push((r.ft, format!("device {:<8} {} [{}] problem={}", d.action, d.dev.name, d.dev.class, d.dev.problem)));
                }
            }
            RecordType::SessionStart | RecordType::SessionEnd | RecordType::Incident | RecordType::Note | RecordType::ShutdownVerdict => {
                notable.push((r.ft, format!("{:<14} {}", ty.name(), short(&r.json().to_string(), 160))));
            }
            RecordType::CollectorStatus => {
                if let Some(s) = r.parse::<rec::CollectorStatus>() {
                    if s.level != "info" {
                        notable.push((r.ft, format!("collector {:<5} [{}] {}", s.level, s.collector, s.message)));
                    }
                }
            }
            _ => {}
        }
        true
    })?;

    if beats.is_empty() {
        println!("No recording covers this time.");
        return Ok(());
    }

    println!("VITALS (every ~10 s)");
    println!("  {:<12} {:>5} {:>7} {:>9} {:>8} {:>6} {:>7}  busiest process", "time", "cpu%", "commit%", "free MB", "disk ms", "queue", "late ms");
    let mut last_shown = 0i64;
    for (ft, h) in &beats {
        if *ft - last_shown < 10 * FT_PER_SEC && *ft != beats.last().unwrap().0 {
            continue;
        }
        last_shown = *ft;
        let v = &h.vitals;
        if v.avail_mb == 0 && v.commit_pct == 0.0 {
            continue; // heartbeat written before the first samples
        }
        let mark = if (*ft - t).abs() < 5 * FT_PER_SEC { " <==" } else { "" };
        println!(
            "  {:<12} {:>5.0} {:>7.0} {:>9} {:>8.0} {:>6.1} {:>7}  {}{mark}",
            &fmt_local(*ft)[11..23],
            v.cpu,
            v.commit_pct,
            v.avail_mb,
            v.disk_ms,
            v.disk_q,
            h.jitter_ms,
            v.top.clone().unwrap_or_default()
        );
    }
    let gaps: Vec<_> = beats.windows(2).filter(|w| (w[1].0 - w[0].0) > 5 * FT_PER_SEC).collect();
    for g in gaps {
        println!("  !! no heartbeat for {} s between {} and {}", (g[1].0 - g[0].0) / FT_PER_SEC, fmt_local(g[0].0), fmt_local(g[1].0));
    }

    if let Some((_, worst)) = pdh.iter().max_by(|a, b| {
        let m = |s: &rec::PdhSample| s.disks.iter().map(|d| d.ms).fold(0.0f32, f32::max);
        m(&a.1).total_cmp(&m(&b.1))
    }) {
        println!("\nWORST DISK MOMENT");
        for d in &worst.disks {
            println!("  {:<20} {:>8.1} ms  queue {:>5.1}  {:>8.1} MB/s  idle {:>5.1}%", d.disk, d.ms, d.queue, d.bps / 1048576.0, d.idle_pct);
        }
        if worst.cpu.perf > 0.0 {
            println!("  CPU performance {:.0}% of base, DPC {:.1}%, interrupts {:.1}%", worst.cpu.perf, worst.cpu.dpc_pct, worst.cpu.intr_pct);
        }
        for z in &worst.thermal {
            println!("  thermal {:<20} {:>5.1} °C  passive limit {:.0}%", z.zone, z.celsius, z.passive_pct);
        }
    }

    let mut top: Vec<(&u32, &ProcAgg)> = procs.iter().collect();
    top.sort_by(|a, b| b.1.cpu_sum.total_cmp(&a.1.cpu_sum));
    println!("\nTOP PROCESSES BY CPU");
    println!("  {:<28} {:>7} {:>7} {:>11} {:>11} {:>8}", "process", "avg%", "max%", "private MB", "growth MB", "handles");
    for (pid, a) in top.iter().take(10) {
        let name = names.get(pid).cloned().unwrap_or_else(|| "?".into());
        println!(
            "  {:<28} {:>7.1} {:>7.1} {:>11} {:>11} {:>8}",
            short(&format!("{name}({pid})"), 28),
            a.cpu_sum / a.samples.max(1) as f64,
            a.cpu_max,
            a.private_max / 1024,
            (a.private_max as i64 - a.private_first.unwrap_or(0) as i64) / 1024,
            a.handles_max
        );
    }
    let mut mem: Vec<(&u32, &ProcAgg)> = procs.iter().filter(|(_, a)| a.private_max > a.private_first.unwrap_or(0) + 50 * 1024).collect();
    if !mem.is_empty() {
        mem.sort_by_key(|(_, a)| std::cmp::Reverse(a.private_max - a.private_first.unwrap_or(0)));
        println!("\nMEMORY GROWERS (private bytes grew > 50 MB in the window)");
        for (pid, a) in mem.iter().take(5) {
            let name = names.get(pid).cloned().unwrap_or_else(|| "?".into());
            println!("  {name}({pid}): {} MB -> {} MB", a.private_first.unwrap_or(0) / 1024, a.private_max / 1024);
        }
    }
    if let (Some(first), Some(last)) = (pools.first(), pools.last()) {
        let before: BTreeMap<&str, u64> = first.tags.iter().map(|t| (t.tag.as_str(), t.paged + t.nonpaged)).collect();
        let mut growth: Vec<(String, i64)> = last
            .tags
            .iter()
            .filter_map(|t| before.get(t.tag.as_str()).map(|b| (t.tag.clone(), (t.paged + t.nonpaged) as i64 - *b as i64)))
            .filter(|(_, d)| *d > 16 * 1048576)
            .collect();
        if !growth.is_empty() {
            growth.sort_by_key(|g| std::cmp::Reverse(g.1));
            println!("\nKERNEL POOL GROWTH (possible driver leak)");
            for (tag, d) in growth.iter().take(5) {
                println!("  tag '{tag}': +{} MB", d / 1048576);
            }
        }
    }

    notable.sort_by_key(|n| n.0);
    println!("\nTIMELINE");
    if notable.is_empty() {
        println!("  (no process starts/ends, events, device changes or incidents in this window)");
    }
    for (ft, s) in notable.iter().take(300) {
        let mark = if (*ft - t).abs() < 5 * FT_PER_SEC { "==>" } else { "   " };
        println!("{mark} {}  {s}", &fmt_local(*ft)[11..23]);
    }
    if notable.len() > 300 {
        println!("    ... {} more (use `bbx dump --from ... --to ...`)", notable.len() - 300);
    }
    Ok(())
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

fn short_channel(c: &str) -> String {
    c.trim_start_matches("Microsoft-Windows-").to_string()
}
