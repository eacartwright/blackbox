//! The run marker: a tiny file that says whether the previous run ended
//! cleanly. Written at start (clean_stop = false) and at a clean stop
//! (clean_stop = true), always via temp file + flush + write-through rename,
//! so it is either the old version or the new one, never a torn mix.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RunState {
    pub version: String,
    pub boot_id: u64,
    pub boot_ft: i64,
    pub start_ft: i64,
    pub pid: u32,
    /// First journal sequence written by this run.
    pub first_seq: u64,
    pub clean_stop: bool,
    /// "SystemShutdown" | "ServiceStop" when clean_stop.
    #[serde(default)]
    pub stop_kind: Option<String>,
    #[serde(default)]
    pub stop_ft: Option<i64>,
}

impl RunState {
    pub fn load(path: &Path) -> Option<RunState> {
        let bytes = fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_atomic(path, &serde_json::to_vec_pretty(self)?)
    }
}

/// Replace `path` with `data` atomically and durably.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    durable_rename(&tmp, path)
}

/// Rename with replace, flushed through to disk before returning.
#[cfg(windows)]
pub fn durable_rename(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let w = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    let (a, b) = (w(from), w(to));
    let ok = unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("rename {} -> {}", from.display(), to.display()));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn durable_rename(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)?;
    Ok(())
}
