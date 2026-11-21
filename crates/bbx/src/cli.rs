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
use std::collections::BTreeMap;
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
    let svc = service_state();
    println!("  Service:        {svc}");
    if !svc.starts_with("Running") {
        if let Some((ft, msg)) = crate::service::last_reported_error() {
            println!("                  last startup error ({}): {msg}", fmt_local(ft));
        }
    }
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

pub fn around(time: &str, minutes: u64, after: u64) -> Result<()> {
    let paths = paths_readable()?;
    let t = parse_user_time(time)?;
    print!("{}", crate::report::around(&paths, t, minutes, after)?);
    Ok(())
}

// ---------------------------------------------------------------- export / incidents

#[allow(clippy::too_many_arguments)]
pub fn export(
    mut incident: Option<String>,
    latest: bool,
    mut around: Option<String>,
    from: Option<String>,
    to: Option<String>,
    mut minutes: u64,
    mut after: u64,
    out: Option<std::path::PathBuf>,
    include_etl: bool,
    recipients: Vec<String>,
) -> Result<()> {
    let paths = paths_readable()?;
    let cfg = bbx_core::config::Config::load(&paths.config());
    let recipients = crate::crypto::parse_recipients(if recipients.is_empty() { &cfg.export_recipients } else { &recipients })?;
    if latest {
        let day_ago = now_ft() - 24 * 3600 * FT_PER_SEC;
        match crate::dataset::list_incidents(&paths).into_iter().find(|i| i.at_ft > day_ago) {
            Some(i) => incident = Some(i.id),
            None => {
                (around, minutes, after) = (Some("-0m".into()), 30, 0);
            }
        }
    }
    let (from_ft, to_ft, at_ft) = if let Some(id) = &incident {
        crate::export::incident_window(&paths, id)?
    } else if let Some(a) = around {
        let t = parse_user_time(&a)?;
        (t - minutes as i64 * 60 * FT_PER_SEC, t + after as i64 * 60 * FT_PER_SEC, t)
    } else {
        let f = parse_user_time(from.as_deref().ok_or_else(|| anyhow!("give --incident, --around, or --from/--to"))?)?;
        let t = to.map(|t| parse_user_time(&t)).transpose()?.unwrap_or_else(now_ft);
        (f, t, t)
    };
    println!("Exporting {} .. {}{}", fmt_local(from_ft), fmt_local(to_ft), if include_etl { "" } else { " (without black-box files)" });
    let out = crate::export::export(
        &paths,
        crate::export::ExportOptions { from_ft, to_ft, at_ft, incident, out, include_etl },
    )?;
    let out = if recipients.is_empty() {
        out
    } else {
        let enc = std::path::PathBuf::from(format!("{}.age", out.display()));
        let r = crate::crypto::encrypt_file(&out, &enc, &recipients);
        std::fs::remove_file(&out).ok(); // never leave the plaintext behind
        r?;
        enc
    };
    let mb = std::fs::metadata(&out).map(|m| m.len() as f64 / 1048576.0).unwrap_or(0.0);
    println!("Wrote {} ({mb:.1} MB{})", out.display(), if recipients.is_empty() { "" } else { ", encrypted" });
    Ok(())
}

pub fn incidents() -> Result<()> {
    let paths = paths_readable()?;
    let mut list = crate::dataset::list_incidents(&paths);
    list.reverse(); // oldest first, newest at the bottom of the terminal
    if list.is_empty() {
        println!("No incidents saved.");
    }
    for i in list {
        let etl = blackbox::list_files(&paths.incidents().join(&i.id).join("blackbox")).len();
        println!("{}  {:<40} {} [{} black-box files]", fmt_local(i.at_ft), i.id, crate::report::short(&i.reason, 90), etl);
    }
    Ok(())
}

// ---------------------------------------------------------------- diag

/// Run the live consumer against a private session and journal, then show
/// what was decoded. Verifies kernel-event decoding on this machine.
pub fn diag_live(secs: u64) -> Result<()> {
    if !crate::install::is_elevated() {
        bail!("`bbx diag live` needs an elevated (Administrator) prompt");
    }
    let dir = std::env::temp_dir().join(format!("bbx-diag-{}", std::process::id()));
    let paths = Paths::at(&dir);
    paths.ensure()?;
    let (j, _) = journal::JournalWriter::open(&paths.journal(), Default::default())?;
    let stop = Stop::new();
    let ctx = bbx_collect::Ctx::new(Arc::new(j), Default::default(), paths.clone(), stop.clone(), 0);
    println!("Recording live ETW for {secs} s (open some files, browse a web page, change a setting)...");
    let res = std::thread::scope(|s| {
        let c = &ctx;
        let t = s.spawn(move || bbx_collect::etwlive::run_named(c, "BlackBox-Diag"));
        std::thread::sleep(std::time::Duration::from_secs(secs));
        stop.signal();
        t.join().map_err(|_| anyhow!("consumer panicked"))?
    });
    ctx.journal.commit()?;
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut samples: Vec<String> = Vec::new();
    journal::for_each_record(&paths.journal(), None, None, |r| {
        let v = r.json();
        let rows = v.get("rows").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(1);
        let e = counts.entry(type_name(r.rtype)).or_default();
        e.0 += 1;
        e.1 += rows;
        if let Some(a) = v.get("rows").and_then(|x| x.as_array()) {
            for row in a.iter().take(3) {
                samples.push(format!("{:<17} {}", type_name(r.rtype), crate::report::short(&row.to_string(), 200)));
            }
        } else if matches!(r.record_type(), Some(RecordType::ProcessStart | RecordType::ProcessEnd | RecordType::DriverLoad)) {
            samples.push(format!("{:<17} {}", type_name(r.rtype), crate::report::short(&v.to_string(), 200)));
        }
        true
    })?;
    println!("
Records produced:");
    for (k, (n, rows)) in &counts {
        println!("  {k:<18} {n:>5} records {rows:>7} rows");
    }
    println!("
Samples:");
    for s in samples.iter().take(40) {
        println!("  {s}");
    }
    std::fs::remove_dir_all(&dir).ok();
    res?;
    let expect = ["NetFlows", "DiskActivity", "FileActivity", "RegistryActivity"];
    let missing: Vec<_> = expect.iter().filter(|k| !counts.contains_key(**k)).collect();
    if missing.is_empty() {
        println!("
OK: kernel network, disk, file and registry events are being decoded.");
    } else {
        println!("
NOTE: no {missing:?} records in this run (there may simply have been no such activity).");
    }
    Ok(())
}
