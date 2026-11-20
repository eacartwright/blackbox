//! Incident manager: turns detector requests into saved incidents, with
//! per-kind cooldowns and a global rate limit so a flapping condition can't
//! fill the disk.
//!
//! An incident folder holds:
//!   incident.json            what/when/why
//!   summary.txt              the `bbx around` report for the moment
//!   blackbox\*.etl           hard links to the black-box window (survive pruning)
//!   eventlogs\*.evtx         System and Application for the window

use crate::report;
use bbx_collect::{blackbox, ctx::IncidentRequest, eventlog, Ctx};
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{fmt_local, now_ft, FT_PER_SEC};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const COOLDOWN: Duration = Duration::from_secs(600);
const MAX_PER_HOUR: usize = 6;

pub fn spawn(ctx: Arc<Ctx>) -> JoinHandle<()> {
    let (tx, rx) = channel::<IncidentRequest>();
    *ctx.incidents.lock().unwrap() = Some(tx);
    std::thread::Builder::new()
        .name("incidents".into())
        .spawn(move || {
            let mut last: HashMap<String, Instant> = HashMap::new();
            let mut recent: VecDeque<Instant> = VecDeque::new();
            let mut suppressed = 0u32;
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(req) => {
                        let manual = req.kind == "manual";
                        recent.retain(|t| t.elapsed() < Duration::from_secs(3600));
                        let cooling = last.get(&req.kind).is_some_and(|t| t.elapsed() < COOLDOWN);
                        if !manual && (cooling || recent.len() >= MAX_PER_HOUR) {
                            suppressed += 1;
                            log::debug!("incident {} suppressed (cooldown/rate limit)", req.kind);
                            continue;
                        }
                        if suppressed > 0 {
                            ctx.status("incidents", "info", format!("{suppressed} repeat incident triggers were rate-limited"));
                            suppressed = 0;
                        }
                        last.insert(req.kind.clone(), Instant::now());
                        recent.push_back(Instant::now());
                        open(&ctx, req);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                if ctx.stop.is_set() {
                    return;
                }
            }
        })
        .expect("spawn incident manager")
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(60).collect()
}

fn open(ctx: &Arc<Ctx>, req: IncidentRequest) {
    let local = bbx_core::time::ft_to_utc(req.at_ft).with_timezone(&chrono::Local);
    let id = format!("{}-{}", local.format("%Y%m%d-%H%M%S"), sanitize(&req.kind));
    let folder = ctx.paths.incidents().join(&id);
    if std::fs::create_dir_all(&folder).is_err() {
        return;
    }
    let before = ctx.cfg.incident_before_min as i64 * 60 * FT_PER_SEC;
    let after = ctx.cfg.incident_after_s as i64 * FT_PER_SEC;
    let (from, to) = req.window.unwrap_or((req.at_ft - before, req.at_ft + after));
    let inc = rec::Incident {
        id: id.clone(),
        kind: req.kind.clone(),
        reason: req.reason.clone(),
        folder: folder.display().to_string(),
        at_ft: req.at_ft,
        from_ft: from,
        to_ft: to,
    };
    ctx.emit_critical(RecordType::Incident, &inc);
    crate::ingest::signal_incident(ctx, &inc);
    if let Ok(b) = serde_json::to_vec_pretty(&inc) {
        std::fs::write(folder.join("incident.json"), b).ok();
    }
    log::info!("incident {id}: {}", req.reason);

    // Finish in the background: wait for the aftermath (unless the window is
    // entirely in the past), then gather everything.
    let ctx = ctx.clone();
    std::thread::Builder::new()
        .name("incident-gather".into())
        .spawn(move || {
            let wait = ((to - now_ft()) / FT_PER_SEC).clamp(0, 600) as u64;
            if wait > 0 && ctx.stop.wait(Duration::from_secs(wait)) {
                // Shutting down: gather what exists now rather than lose it.
            }
            gather(&ctx, &inc, &folder);
        })
        .ok();
}

fn gather(ctx: &Ctx, inc: &rec::Incident, folder: &Path) {
    let to = inc.to_ft.min(now_ft());
    if blackbox::query().is_ok_and(|i| i.running) {
        blackbox::roll().ok(); // close the file covering the end of the window
    }
    let mut notes = Vec::new();
    match blackbox::link_window(&ctx.paths.blackbox(), &folder.join("blackbox"), inc.from_ft, to) {
        Ok(n) => notes.push(format!("{n} black-box files")),
        Err(e) => notes.push(format!("black box: {e:#}")),
    }
    let ev = folder.join("eventlogs");
    std::fs::create_dir_all(&ev).ok();
    for ch in ["System", "Application"] {
        if let Err(e) = eventlog::export_range(ch, inc.from_ft - 60 * FT_PER_SEC, to, &ev.join(format!("{ch}.evtx"))) {
            notes.push(format!("{e:#}"));
        }
    }
    if ctx.cfg.packet_capture {
        match bbx_collect::pktmon::snapshot(ctx, &folder.join("packets.pcapng")) {
            Ok(()) => notes.push("packet capture saved".into()),
            Err(e) => notes.push(format!("packets: {e:#}")),
        }
    }
    ctx.journal.commit().ok();
    let before_min = ((inc.at_ft - inc.from_ft) / (60 * FT_PER_SEC)).max(1) as u64;
    let after_min = ((to - inc.at_ft) / (60 * FT_PER_SEC)).max(1) as u64;
    let summary = match report::around(&ctx.paths, inc.at_ft, before_min, after_min) {
        Ok(s) => format!("INCIDENT {}\n{}\n{}\n\n{s}", inc.id, inc.reason, fmt_local(inc.at_ft)),
        Err(e) => format!("report failed: {e:#}"),
    };
    std::fs::write(folder.join("summary.txt"), summary).ok();
    ctx.emit(
        RecordType::BlackBox,
        &rec::BlackBox { action: "incident".into(), session: inc.id.clone(), detail: notes.join("; ") },
    );
}
