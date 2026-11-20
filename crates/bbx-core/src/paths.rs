//! Data directory layout. Root is `%ProgramData%\BlackBox`, overridable
//! with the `BBX_ROOT` environment variable (tests, console runs).

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        if let Some(r) = std::env::var_os("BBX_ROOT") {
            return Self { root: PathBuf::from(r) };
        }
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Self { root: base.join("BlackBox") }
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn journal(&self) -> PathBuf { self.root.join("journal") }
    pub fn blackbox(&self) -> PathBuf { self.root.join("blackbox") }
    pub fn incidents(&self) -> PathBuf { self.root.join("incidents") }
    pub fn state(&self) -> PathBuf { self.root.join("state") }
    pub fn triggers(&self) -> PathBuf { self.root.join("triggers") }
    pub fn logs(&self) -> PathBuf { self.root.join("logs") }

    pub fn run_state(&self) -> PathBuf { self.state().join("run.json") }
    pub fn config(&self) -> PathBuf { self.root.join("config.json") }
    pub fn eventlog_bookmarks(&self) -> PathBuf { self.state().join("eventlog-bookmarks.json") }

    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [self.journal(), self.blackbox(), self.incidents(), self.state(), self.triggers(), self.logs()] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}
