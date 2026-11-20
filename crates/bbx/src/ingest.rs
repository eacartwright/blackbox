//! Takes what user agents (and `bbx mark`) drop into triggers\ and turns it
//! into journal records, incidents and incident screenshots. All of it is
//! untrusted input from unprivileged users: size-capped, parsed, clamped.

use bbx_collect::{detect, Ctx};
use bbx_core::agentproto::{
    parse_shot_name, AgentLine, IncidentSignal, MarkFile, MARK_PREFIX, MAX_MARK_FILE, MAX_SHOT_FILE, MAX_UA_FILE, SHOT_PREFIX, UA_PREFIX,
};
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{now_ft, utc_to_ft, FT_PER_SEC};
use std::path::{Path, PathBuf};

/// Files younger than this may still be being written by the agent.
const SETTLE_FT: i64 = 2 * FT_PER_SEC;
/// Screenshots that can't be matched to an incident are deleted after this.
const SHOT_TTL_FT: i64 = 600 * FT_PER_SEC;
const MAX_FILES_PER_PASS: usize = 200;

fn mtime_ft(p: &Path) -> Option<(i64, u64)> {
    let m = std::fs::metadata(p).ok()?;
    let t = m.modified().ok()?;
    Some((utc_to_ft(chrono::DateTime::<chrono::Utc>::from(t)), m.len()))
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

pub fn pass(ctx: &Ctx) {
    let Ok(rd) = std::fs::read_dir(ctx.paths.triggers()) else { return };
    let now = now_ft();
    let mut shots = Vec::new();
    for e in rd.flatten().take(MAX_FILES_PER_PASS) {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let Some((mt, size)) = mtime_ft(&p) else { continue };
        if now - mt < SETTLE_FT {
            continue;
        }
        if name.starts_with(MARK_PREFIX) {
            mark(ctx, &p, size);
            std::fs::remove_file(&p).ok();
        } else if name.starts_with(UA_PREFIX) {
            if size <= MAX_UA_FILE {
                user_events(ctx, &p);
            }
            std::fs::remove_file(&p).ok();
        } else if name.starts_with(SHOT_PREFIX) {
            shots.push((p, name, mt, size));
        } else {
            std::fs::remove_file(&p).ok(); // unknown junk
        }
    }
    if !shots.is_empty() {
        place_shots(ctx, shots);
    }
}

fn mark(ctx: &Ctx, p: &Path, size: u64) {
    let m: MarkFile = if size <= MAX_MARK_FILE {
        std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    } else {
        MarkFile::default()
    };
    let note = clip(&m.note, 500);
    ctx.emit_critical(RecordType::Note, &rec::Note { text: note.clone(), user: clip(&m.user, 100), source: "mark".into() });
    let reason = if note.is_empty() { "marked by user".to_string() } else { note };
    ctx.request_incident("manual", reason, now_ft());
}

fn user_events(ctx: &Ctx, p: &Path) {
    let Ok(text) = std::fs::read_to_string(p) else { return };
    let now = now_ft();
    for line in text.lines().take(2000) {
        let Ok(mut l) = serde_json::from_str::<AgentLine>(line) else { continue };
        // Clamp times: the agent's clock is the same machine's, but the file
        // is user-controlled.
        if l.ft > now + 60 * FT_PER_SEC || l.ft < now - 3600 * FT_PER_SEC {
            l.ft = now;
        }
        let ev = &mut l.ev;
        ev.kind = clip(&ev.kind, 32);
        ev.proc = clip(&ev.proc, 128);
        ev.user = clip(&ev.user, 100);
        ev.detail = clip(&ev.detail, 300);
        if !ev.value.is_finite() {
            ev.value = 0.0;
        }
        ctx.emit_at(RecordType::UserEvent, l.ft, &l.ev);
        if let Some((kind, reason, at)) = detect::match_user_event(&l.ev, l.ft) {
            ctx.request_incident(kind, reason, at);
        }
    }
}

fn incident_dirs(ctx: &Ctx) -> Vec<(PathBuf, rec::Incident)> {
    let Ok(rd) = std::fs::read_dir(ctx.paths.incidents()) else { return vec![] };
    rd.flatten()
        .filter_map(|e| {
            let b = std::fs::read(e.path().join("incident.json")).ok()?;
            Some((e.path(), serde_json::from_slice(&b).ok()?))
        })
        .collect()
}

fn place_shots(ctx: &Ctx, shots: Vec<(PathBuf, String, i64, u64)>) {
    let incidents = incident_dirs(ctx);
    let now = now_ft();
    for (p, name, mt, size) in shots {
        let valid = size <= MAX_SHOT_FILE && std::fs::read(&p).map(|b| b.get(1..4) == Some(b"PNG")).unwrap_or(false);
        let parsed = parse_shot_name(&name);
        if !valid || parsed.is_none() {
            std::fs::remove_file(&p).ok();
            continue;
        }
        let (tag, ft) = parsed.unwrap();
        let target = incidents
            .iter()
            .find(|(dir, _)| dir.file_name().is_some_and(|n| n.to_string_lossy() == tag))
            .or_else(|| {
                incidents
                    .iter()
                    .filter(|(_, i)| ft >= i.from_ft && ft <= i.to_ft + 120 * FT_PER_SEC)
                    .max_by_key(|(_, i)| i.at_ft)
            });
        match target {
            Some((dir, _)) => {
                let screens = dir.join("screens");
                std::fs::create_dir_all(&screens).ok();
                let local = bbx_core::time::ft_to_utc(ft).with_timezone(&chrono::Local).format("%H%M%S%.3f");
                if std::fs::rename(&p, screens.join(format!("{local}.png"))).is_err() {
                    std::fs::remove_file(&p).ok();
                }
            }
            None if now - mt > SHOT_TTL_FT => {
                std::fs::remove_file(&p).ok();
            }
            None => {} // the incident may not exist yet (mark just arrived)
        }
    }
}

/// Tell agents about a new incident so they hand over their screenshot ring.
pub fn signal_incident(ctx: &Ctx, inc: &rec::Incident) {
    let s = IncidentSignal { id: inc.id.clone(), at_ft: inc.at_ft, from_ft: inc.from_ft, to_ft: inc.to_ft };
    if let Ok(b) = serde_json::to_vec(&s) {
        bbx_core::runstate::write_atomic(&ctx.paths.public().join("incident.json"), &b).ok();
    }
}

/// Publish the agent settings from config.json.
pub fn publish_agent_settings(ctx: &Ctx) {
    let s = bbx_core::agentproto::AgentSettings::from_config(&ctx.cfg);
    if let Ok(b) = serde_json::to_vec_pretty(&s) {
        bbx_core::runstate::write_atomic(&ctx.paths.public().join("agent.json"), &b).ok();
    }
}
