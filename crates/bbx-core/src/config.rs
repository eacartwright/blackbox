//! Configuration (`%ProgramData%\BlackBox\config.json`). Every field has a
//! default, so a partial or missing file is fine.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// "standard" or "deep" (black-box ETW detail level).
    pub profile: String,

    pub heartbeat_ms: u64,
    pub system_sample_ms: u64,
    pub pool_sample_s: u64,
    pub process_sample_ms: u64,
    /// Full process table every N seconds (between those, only active rows).
    pub process_full_s: u64,
    pub pdh_sample_ms: u64,
    pub gpu_sample_ms: u64,
    pub device_poll_ms: u64,

    pub journal_max_mb: u64,
    pub journal_max_days: u64,
    pub journal_segment_mb: u64,
    pub journal_segment_minutes: u64,

    pub blackbox_enabled: bool,
    pub blackbox_max_mb: u64,
    pub blackbox_file_mb: u32,
    pub blackbox_roll_s: u64,
    pub blackbox_buffer_kb: u32,

    pub incidents_max_mb: u64,
    /// Minutes of black box before / after a trigger to keep with an incident.
    pub incident_before_min: u64,
    pub incident_after_s: u64,

    /// Stop growing data when the volume has less than this free.
    pub min_free_disk_mb: u64,

    pub eventlog_channels: Vec<ChannelConfig>,
    /// On first install, also read this much existing history per channel.
    pub eventlog_backfill_hours: u64,

    /// Extra regexes to redact from command lines (value replaced by ***).
    pub redact_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelConfig {
    pub channel: String,
    /// Condition inside `*[System[ ... ]]`; empty = everything.
    #[serde(default)]
    pub filter: String,
}

fn ch(channel: &str, filter: &str) -> ChannelConfig {
    ChannelConfig { channel: channel.into(), filter: filter.into() }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "standard".into(),
            heartbeat_ms: 1000,
            system_sample_ms: 2000,
            pool_sample_s: 30,
            process_sample_ms: 2000,
            process_full_s: 60,
            pdh_sample_ms: 2000,
            gpu_sample_ms: 5000,
            device_poll_ms: 5000,
            journal_max_mb: 1536,
            journal_max_days: 30,
            journal_segment_mb: 32,
            journal_segment_minutes: 60,
            blackbox_enabled: true,
            blackbox_max_mb: 2048,
            blackbox_file_mb: 64,
            blackbox_roll_s: 120,
            blackbox_buffer_kb: 256,
            incidents_max_mb: 1536,
            incident_before_min: 15,
            incident_after_s: 60,
            min_free_disk_mb: 2048,
            eventlog_channels: vec![
                ch("System", ""),
                ch(
                    "Application",
                    "(Level=1 or Level=2 or Level=3) or Provider[@Name='Application Hang' or \
                     @Name='Windows Error Reporting' or @Name='Application Error' or @Name='MsiInstaller']",
                ),
                ch("Microsoft-Windows-TaskScheduler/Operational", ""),
                ch("Microsoft-Windows-Kernel-PnP/Configuration", ""),
                ch("Microsoft-Windows-DriverFrameworks-UserMode/Operational", ""),
                ch("Microsoft-Windows-Diagnostics-Performance/Operational", ""),
                ch("Microsoft-Windows-Resource-Exhaustion-Detector/Operational", ""),
                ch("Microsoft-Windows-Kernel-Power/Thermal-Operational", ""),
                ch("Microsoft-Windows-Storage-Storport/Operational", ""),
                ch("Microsoft-Windows-Ntfs/Operational", "Level<=3"),
                ch("Microsoft-Windows-WindowsUpdateClient/Operational", ""),
                ch("Microsoft-Windows-Windows Defender/Operational", ""),
                ch("Microsoft-Windows-WLAN-AutoConfig/Operational", ""),
                ch("Microsoft-Windows-NetworkProfile/Operational", ""),
                ch("Microsoft-Windows-Dhcp-Client/Admin", ""),
                ch("Microsoft-Windows-Bits-Client/Operational", "Level<=3"),
                ch("Microsoft-Windows-GroupPolicy/Operational", "Level<=3"),
            ],
            eventlog_backfill_hours: 24,
            redact_patterns: vec![],
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Config {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                log::warn!("config {} is invalid ({e}); using defaults", path.display());
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }

    pub fn deep(&self) -> bool {
        self.profile.eq_ignore_ascii_case("deep")
    }
}
