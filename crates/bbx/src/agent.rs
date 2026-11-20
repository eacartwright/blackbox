//! The recording agent: opens the journal, writes session markers, runs
//! every collector under supervision, classifies the previous shutdown, and
//! performs maintenance. Used by both the Windows service and `bbx run`.

use anyhow::Result;
use bbx_collect::{blackbox, bootinfo, detect, devices, etwlive, eventlog, evidence, pdh, process, system, util, Ctx, Stop};
use bbx_core::classifier::{self, ClassifierInput, HeartbeatPoint};
use bbx_core::config::Config;
use bbx_core::journal::{self, JournalOptions, JournalWriter};
use bbx_core::paths::Paths;
use bbx_core::records::{self as rec, Heartbeat, RecordType};
use bbx_core::runstate::{write_atomic, RunState};
use bbx_core::time::{fmt_local, now_ft, FT_PER_SEC};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const LAST_VERDICT_FILE: &str = "last-verdict.json";

pub struct RunOptions {
    pub console: bool,
    pub verbose: bool,
}

pub fn run(stop: Arc<Stop>, system_shutdown: Arc<AtomicBool>, opts: RunOptions) -> Result<()> {
    let paths = Paths::from_env();
    paths.ensure()?;
    bbx_core::logging::init(paths.logs().join("bbx.log"), opts.console, opts.verbose);
    let cfg = Config::load(&paths.config());
    let boot = bootinfo::current();
    let started = Instant::now();
    log::info!("BlackBox {} starting (boot id {}, profile {})", bbx_core::VERSION, boot.boot_id, cfg.profile);

    let prev = RunState::load(&paths.run_state());
    let jopts = JournalOptions {
        max_segment_bytes: cfg.journal_segment_mb.max(1) * 1048576,
        max_segment_age: Duration::from_secs(cfg.journal_segment_minutes.max(1) * 60),
        ..Default::default()
    };
    let (journal, recovered) = JournalWriter::open(&paths.journal(), jopts)?;
    let journal = Arc::new(journal);
    let first_seq = journal.next_seq();

    journal.append(
        RecordType::SessionStart,
        &rec::SessionStart {
            version: bbx_core::VERSION.into(),
            host: bootinfo::hostname(),
            os: bootinfo::os_description(),
            boot_id: boot.boot_id,
            boot_ft: boot.boot_ft,
            pid: std::process::id(),
            profile: cfg.profile.clone(),
            console: opts.console,
        },
        true,
    )?;
    for r in &recovered {
        journal.append(RecordType::Recovery, r, true)?;
        if let Some(e) = &r.error {
            journal.append(
                RecordType::CollectorStatus,
                &rec::CollectorStatus { collector: "journal".into(), level: "error".into(), message: format!("segment {} set aside: {e}", r.segment) },
                true,
            )?;
        }
        if r.truncated_tail_bytes > 0 || r.corrupt_regions > 0 {
            log::warn!(
                "recovered {}: {} records, {} torn tail bytes dropped, {} corrupt regions skipped",
                r.segment, r.records, r.truncated_tail_bytes, r.corrupt_regions
            );
        }
    }

    let mut state = RunState {
        version: bbx_core::VERSION.into(),
        boot_id: boot.boot_id,
        boot_ft: boot.boot_ft,
        start_ft: now_ft(),
        pid: std::process::id(),
        first_seq,
        clean_stop: false,
        stop_kind: None,
        stop_ft: None,
    };
    if let Err(e) = state.save(&paths.run_state()) {
        // Without the marker the next boot can't tell clean from unclean,
        // but recording is worth more than that: keep going.
        log::error!("cannot write run marker: {e:#}");
        journal.append(
            RecordType::CollectorStatus,
            &rec::CollectorStatus { collector: "agent".into(), level: "error".into(), message: format!("cannot write run marker: {e:#}") },
            true,
        )?;
    }

    let ctx = Arc::new(Ctx::new(journal.clone(), cfg, paths.clone(), stop.clone(), boot.boot_id));

    crate::ingest::publish_agent_settings(&ctx);
    let mut threads: Vec<JoinHandle<()>> = vec![
        crate::incidents::spawn(ctx.clone()),
        spawn_heartbeat(ctx.clone()),
        spawn_supervised(ctx.clone(), "system", system::run),
        spawn_supervised(ctx.clone(), "process", process::run),
        spawn_supervised(ctx.clone(), "pdh", pdh::run),
        spawn_supervised(ctx.clone(), "devices", devices::run),
        spawn_supervised(ctx.clone(), "eventlog", eventlog::run),
        spawn_supervised(ctx.clone(), "blackbox", blackbox::run),
        spawn_supervised(ctx.clone(), "etwlive", etwlive::run),
        spawn_supervised(ctx.clone(), "hardware", bbx_collect::hardware::run),
        spawn_supervised(ctx.clone(), "pktmon", bbx_collect::pktmon::run),
        spawn_supervised(ctx.clone(), "maintenance", maintenance),
    ];
    {
        let ctx = ctx.clone();
        let prev = prev.clone();
        threads.push(
            std::thread::Builder::new()
                .name("classifier".into())
                .spawn(move || classify_previous(&ctx, prev, &boot, first_seq))?,
        );
    }

    stop.wait_forever();
    log::info!("stopping");
    let deadline = Instant::now() + Duration::from_secs(10);
    for t in threads {
        while !t.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if t.is_finished() {
            t.join().ok();
        } else {
            log::warn!("thread '{}' did not stop within 10 s", t.thread().name().unwrap_or("?"));
        }
    }

    let shutdown = system_shutdown.load(Ordering::SeqCst) || windows_shutting_down();
    let kind = if shutdown { "SystemShutdown" } else { "ServiceStop" };
    journal.append(
        RecordType::SessionEnd,
        &rec::SessionEnd { reason: kind.into(), uptime_s: started.elapsed().as_secs() },
        true,
    )?;
    journal.close()?;
    state.clean_stop = true;
    state.stop_kind = Some(kind.into());
    state.stop_ft = Some(now_ft());
    state.save(&paths.run_state())?;
    log::info!("stopped cleanly ({kind})");
    Ok(())
}

fn windows_shutting_down() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SHUTTINGDOWN};
    unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
}

/// Run a collector; restart it with backoff if it fails or panics.
fn spawn_supervised(ctx: Arc<Ctx>, name: &'static str, f: fn(&Ctx) -> Result<()>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                if ctx.stop.is_set() {
                    return;
                }
                let t0 = Instant::now();
                match catch_unwind(AssertUnwindSafe(|| f(&ctx))) {
                    Ok(Ok(())) => return,
                    Ok(Err(e)) => ctx.status(name, "error", format!("failed: {e:#}; restarting in {}s", backoff.as_secs())),
                    Err(p) => {
                        let msg = p
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown panic".into());
                        ctx.status(name, "error", format!("panicked: {msg}; restarting in {}s", backoff.as_secs()));
                    }
                }
                if t0.elapsed() > Duration::from_secs(300) {
                    backoff = Duration::from_secs(1); // it ran fine for a while
                }
                if ctx.stop.wait(backoff) {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        })
        .expect("spawn collector thread")
}

/// One heartbeat per interval, durably committed, at normal priority.
fn spawn_heartbeat(ctx: Arc<Ctx>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("heartbeat".into())
        .spawn(move || {
            let interval = Duration::from_millis(ctx.cfg.heartbeat_ms.clamp(250, 10_000));
            let start = Instant::now();
            let mut n: u32 = 0;
            let mut detector = detect::VitalsDetector::default();
            loop {
                n += 1;
                let due = start + interval * n;
                let now = Instant::now();
                if due > now && ctx.stop.wait(due - now) {
                    return;
                }
                if ctx.stop.is_set() {
                    return;
                }
                let late = Instant::now().saturating_duration_since(due);
                if late > interval {
                    // We were starved for more than one beat: resync the schedule
                    // instead of firing a burst of catch-up beats.
                    n = (start.elapsed().as_millis() / interval.as_millis()) as u32;
                }
                let hb = Heartbeat {
                    mono_ms: util::tick_ms(),
                    boot_id: ctx.boot_id,
                    jitter_ms: late.as_millis() as i64,
                    vitals: ctx.vitals.lock().unwrap().clone(),
                };
                ctx.emit_critical(RecordType::Heartbeat, &hb);
                for (kind, reason) in detector.on_heartbeat(&hb.vitals, hb.jitter_ms) {
                    ctx.request_incident(kind, reason, now_ft());
                }
            }
        })
        .expect("spawn heartbeat thread")
}

fn classify_previous(ctx: &Ctx, prev: Option<RunState>, boot: &bootinfo::BootInfo, first_seq: u64) {
    let dir = ctx.paths.journal();
    let tail: Vec<HeartbeatPoint> = journal::tail(&dir, Some(first_seq), 120, |r| r.rtype == RecordType::Heartbeat as u16)
        .unwrap_or_default()
        .into_iter()
        .rev()
        .filter_map(|r| {
            let h: Heartbeat = r.parse()?;
            Some(HeartbeatPoint {
                ft: r.ft,
                mono_ms: h.mono_ms,
                jitter_ms: h.jitter_ms,
                cpu: h.vitals.cpu,
                commit_pct: h.vitals.commit_pct,
                avail_mb: h.vitals.avail_mb,
                disk_ms: h.vitals.disk_ms,
                top: h.vitals.top,
            })
        })
        .collect();
    let last_record_ft = journal::tail(&dir, Some(first_seq), 1, |r| {
        r.rtype != RecordType::EventLog as u16 // event times can be backfilled
    })
    .ok()
    .and_then(|v| v.first().map(|r| r.ft));

    let since = last_record_ft.or(prev.as_ref().map(|p| p.start_ft)).unwrap_or(boot.boot_ft) - 600 * FT_PER_SEC;
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut input = ClassifierInput {
        prev: prev.clone(),
        current_boot_id: boot.boot_id,
        current_boot_ft: boot.boot_ft,
        tail,
        last_record_ft,
        evidence: Default::default(),
    };
    let same_boot = prev.as_ref().is_some_and(|p| classifier::same_boot(p, boot.boot_id, boot.boot_ft));
    loop {
        input.evidence = evidence::gather(since);
        let uptime_s = util::tick_ms() / 1000;
        input.evidence.complete = prev.is_none()
            || same_boot
            || prev.as_ref().is_some_and(|p| p.clean_stop)
            || input.evidence.kp41.is_some()
            || input.evidence.user1074.is_some()
            || uptime_s > 300
            || Instant::now() >= deadline;
        if input.evidence.complete || ctx.stop.wait(Duration::from_secs(15)) {
            break;
        }
    }
    let v = classifier::classify(&input);
    log::info!("previous run ended: {:?} ({:?}) - {}", v.kind, v.confidence, v.summary);
    ctx.emit_critical(RecordType::ShutdownVerdict, &v);
    if let Ok(b) = serde_json::to_vec_pretty(&v) {
        write_atomic(&ctx.paths.state().join(LAST_VERDICT_FILE), &b).ok();
    }
    // An unplanned end: keep the black box from just before it, now, before
    // pruning can reach it.
    use bbx_core::classifier::VerdictKind as K;
    if matches!(
        v.kind,
        K::Bugcheck | K::HangThenForcedOff | K::ForcedOffWhileAlive | K::DegradedThenReset | K::AbruptStop | K::SleepTransitionFailure
    ) {
        if let Some(la) = v.last_alive_ft {
            let before = ctx.cfg.incident_before_min as i64 * 60 * FT_PER_SEC;
            ctx.request_incident_window(format!("shutdown:{:?}", v.kind), v.summary.clone(), la, Some((la - before, la + 60 * FT_PER_SEC)));
        }
    }
}

/// Triggers, incidents, retention and disk-space protection.
fn maintenance(ctx: &Ctx) -> Result<()> {
    util::below_normal_priority();
    let mut last_prune = Instant::now() - Duration::from_secs(3600);
    while !ctx.stop.wait(Duration::from_secs(2)) {
        crate::ingest::pass(ctx);
        if last_prune.elapsed() >= Duration::from_secs(600) {
            last_prune = Instant::now();
            prune_all(ctx);
        }
    }
    Ok(())
}

fn prune_all(ctx: &Ctx) {
    let cfg = &ctx.cfg;
    let mut scale = 1u64;
    if let Some(free) = util::free_disk_bytes(&ctx.paths.root) {
        if free < cfg.min_free_disk_mb * 1048576 {
            scale = 4; // shrink every budget to a quarter until space recovers
            ctx.status("maintenance", "warn", format!("low disk space ({} MB free); shrinking BlackBox budgets", free / 1048576));
        }
    }
    let min_ft = now_ft() - cfg.journal_max_days as i64 * 86400 * FT_PER_SEC;
    if let Err(e) = journal::prune(&ctx.paths.journal(), cfg.journal_max_mb * 1048576 / scale, Some(min_ft)) {
        log::warn!("journal prune failed: {e:#}");
    }
    blackbox::prune(&ctx.paths.blackbox(), cfg.blackbox_max_mb * 1048576 / scale);
    prune_incidents(&ctx.paths.incidents(), cfg.incidents_max_mb * 1048576 / scale);
}

fn dir_size(p: &std::path::Path) -> u64 {
    std::fs::read_dir(p)
        .map(|rd| {
            rd.flatten()
                .map(|e| match e.metadata() {
                    Ok(m) if m.is_dir() => dir_size(&e.path()),
                    Ok(m) => m.len(),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

fn prune_incidents(dir: &std::path::Path, max_bytes: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut v: Vec<(String, std::path::PathBuf, u64)> = rd
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path(), dir_size(&e.path())))
        .collect();
    v.sort(); // names start with a timestamp: oldest first
    let mut total: u64 = v.iter().map(|x| x.2).sum();
    for (name, p, size) in v {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_dir_all(&p).is_ok() {
            log::info!("pruned incident {name}");
            total -= size;
        }
    }
}

pub fn describe_last_heartbeat(paths: &Paths) -> Option<(i64, Heartbeat)> {
    let r = journal::tail(&paths.journal(), None, 1, |r| r.rtype == RecordType::Heartbeat as u16).ok()?.pop()?;
    Some((r.ft, r.parse()?))
}

pub fn fmt_age(ft: i64) -> String {
    let s = (now_ft() - ft) / FT_PER_SEC;
    let ago = if s < 120 { format!("{s} s ago") } else if s < 7200 { format!("{} min ago", s / 60) } else { format!("{:.1} h ago", s as f64 / 3600.0) };
    format!("{} ({ago})", fmt_local(ft))
}
