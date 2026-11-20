//! Writes agent output into the service's triggers\ drop box.

use crate::screens::Ring;
use bbx_core::agentproto::{shot_name, AgentLine, MarkFile, MARK_PREFIX, UA_PREFIX};
use bbx_core::records::UserEvent;
use bbx_core::time::now_ft;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Outbox {
    dir: PathBuf,
    pub session: u32,
    pub user: String,
    pending: Vec<AgentLine>,
    last_flush: Instant,
    urgent: bool,
}

const FLUSH_EVERY: Duration = Duration::from_secs(10);

impl Outbox {
    pub fn new(dir: PathBuf, session: u32, user: String) -> Self {
        Self { dir, session, user, pending: Vec::new(), last_flush: Instant::now(), urgent: false }
    }

    pub fn push(&mut self, kind: &str, proc: &str, pid: u32, detail: &str, value: f64, urgent: bool) {
        if self.pending.len() >= 2000 {
            return; // never grow without bound if the drop box is unwritable
        }
        self.pending.push(AgentLine {
            ft: now_ft(),
            ev: UserEvent {
                session: self.session,
                user: self.user.clone(),
                kind: kind.into(),
                proc: proc.into(),
                pid,
                detail: detail.chars().take(300).collect(),
                value,
            },
        });
        self.urgent |= urgent;
    }

    pub fn maybe_flush(&mut self) {
        if self.urgent || self.last_flush.elapsed() >= FLUSH_EVERY {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        self.last_flush = Instant::now();
        self.urgent = false;
        if self.pending.is_empty() {
            return;
        }
        let path = self.dir.join(format!("{UA_PREFIX}{}-{}.jsonl", self.session, now_ft()));
        let mut body = Vec::new();
        for l in &self.pending {
            if let Ok(s) = serde_json::to_string(l) {
                body.extend_from_slice(s.as_bytes());
                body.push(b'\n');
            }
        }
        if std::fs::File::create(&path).and_then(|mut f| f.write_all(&body)).is_ok() {
            self.pending.clear();
        }
    }

    pub fn write_mark(&self, m: &MarkFile) {
        let path = self.dir.join(format!("{MARK_PREFIX}{}-{}.json", now_ft(), std::process::id()));
        if let Ok(b) = serde_json::to_vec(m) {
            let _ = std::fs::write(path, b);
        }
    }

    pub fn write_shots(&self, tag: &str, ring: &Ring) {
        for (ft, png) in ring.frames() {
            let _ = std::fs::write(self.dir.join(shot_name(tag, *ft)), png);
        }
    }
}
