use bbx_core::config::Config;
use bbx_core::journal::JournalWriter;
use bbx_core::paths::Paths;
use bbx_core::records::{CollectorStatus, RecordType, Vitals};
use bbx_core::redact::Redactor;
use serde::Serialize;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A stop signal threads can sleep on.
pub struct Stop {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Stop {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { flag: Mutex::new(false), cv: Condvar::new() })
    }
    pub fn signal(&self) {
        *self.flag.lock().unwrap() = true;
        self.cv.notify_all();
    }
    pub fn is_set(&self) -> bool {
        *self.flag.lock().unwrap()
    }
    /// Sleep up to `d`. Returns true if stop was signalled.
    pub fn wait(&self, d: Duration) -> bool {
        let g = self.flag.lock().unwrap();
        let (g, _) = self.cv.wait_timeout_while(g, d, |s| !*s).unwrap();
        *g
    }
    pub fn wait_forever(&self) {
        let g = self.flag.lock().unwrap();
        let _g = self.cv.wait_while(g, |s| !*s).unwrap();
    }
}

/// Everything a collector needs.
pub struct Ctx {
    pub journal: Arc<JournalWriter>,
    pub cfg: Config,
    pub paths: Paths,
    pub vitals: Mutex<Vitals>,
    pub stop: Arc<Stop>,
    pub redactor: Redactor,
    pub boot_id: u64,
}

impl Ctx {
    /// Append a record; failures are logged, never propagated, so one bad
    /// record can't take a collector down.
    pub fn emit<T: Serialize>(&self, t: RecordType, payload: &T) {
        if let Err(e) = self.journal.append(t, payload, false) {
            log::error!("journal append ({}) failed: {e:#}", t.name());
        }
    }

    pub fn emit_critical<T: Serialize>(&self, t: RecordType, payload: &T) {
        if let Err(e) = self.journal.append(t, payload, true) {
            log::error!("journal append ({}) failed: {e:#}", t.name());
        }
    }

    /// Append with an explicit timestamp (e.g. an event log entry's own time).
    pub fn emit_at<T: Serialize>(&self, t: RecordType, ft: i64, payload: &T) {
        let res = serde_json::to_vec(payload)
            .map_err(anyhow::Error::from)
            .and_then(|b| self.journal.append_raw(t as u16, ft, &b, false));
        if let Err(e) = res {
            log::error!("journal append ({}) failed: {e:#}", t.name());
        }
    }

    pub fn status(&self, collector: &str, level: &str, message: impl Into<String>) {
        let message = message.into();
        match level {
            "error" => log::error!("[{collector}] {message}"),
            "warn" => log::warn!("[{collector}] {message}"),
            _ => log::info!("[{collector}] {message}"),
        }
        self.emit(
            RecordType::CollectorStatus,
            &CollectorStatus { collector: collector.into(), level: level.into(), message },
        );
    }

    pub fn update_vitals(&self, f: impl FnOnce(&mut Vitals)) {
        f(&mut self.vitals.lock().unwrap());
    }
}
