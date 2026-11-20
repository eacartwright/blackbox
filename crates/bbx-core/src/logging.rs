//! Minimal diagnostic logger for BlackBox itself (not the journal): a text
//! file under logs\, rolled at 10 MB, optionally echoed to stderr.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_BYTES: u64 = 10 * 1024 * 1024;

struct FileLogger {
    path: PathBuf,
    file: Mutex<Option<File>>,
    echo: bool,
    level: log::LevelFilter,
}

impl log::Log for FileLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= self.level
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!(
            "{} {:5} [{}] {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            r.level(),
            std::thread::current().name().unwrap_or("?"),
            r.args()
        );
        if self.echo {
            eprint!("{line}");
        }
        let mut g = self.file.lock().unwrap();
        if g.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() > MAX_BYTES) {
            *g = None;
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
        }
        if g.is_none() {
            *g = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        }
        if let Some(f) = g.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = f.flush();
        }
    }
}

/// Install the logger. Safe to call once per process; later calls are ignored.
pub fn init(path: PathBuf, echo: bool, verbose: bool) {
    let level = if verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info };
    let logger = FileLogger { path, file: Mutex::new(None), echo, level };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }
}
