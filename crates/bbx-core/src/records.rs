//! Record types and payload schemas. Payloads are JSON so that any language
//! can read a journal; field names are short because there are millions.
//!
//! Compatibility rule: fields may be added (readers ignore unknown fields,
//! writers use `#[serde(default)]` for new ones); fields are never renamed
//! or repurposed, and record type numbers are never reused.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    SessionStart = 1,
    SessionEnd = 2,
    Heartbeat = 3,
    Recovery = 4,
    ShutdownVerdict = 5,
    Note = 6,
    CollectorStatus = 7,
    SystemSample = 10,
    PoolSample = 11,
    ProcessSample = 12,
    ProcessStart = 13,
    ProcessEnd = 14,
    PdhSample = 15,
    Device = 20,
    DeviceInventory = 21,
    EventLog = 22,
    Incident = 30,
    BlackBox = 31,
}

impl RecordType {
    pub const ALL: &'static [RecordType] = &[
        Self::SessionStart, Self::SessionEnd, Self::Heartbeat, Self::Recovery,
        Self::ShutdownVerdict, Self::Note, Self::CollectorStatus, Self::SystemSample,
        Self::PoolSample, Self::ProcessSample, Self::ProcessStart, Self::ProcessEnd,
        Self::PdhSample, Self::Device, Self::DeviceInventory, Self::EventLog,
        Self::Incident, Self::BlackBox,
    ];

    pub fn from_u16(v: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|t| *t as u16 == v)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::SessionEnd => "SessionEnd",
            Self::Heartbeat => "Heartbeat",
            Self::Recovery => "Recovery",
            Self::ShutdownVerdict => "ShutdownVerdict",
            Self::Note => "Note",
            Self::CollectorStatus => "CollectorStatus",
            Self::SystemSample => "SystemSample",
            Self::PoolSample => "PoolSample",
            Self::ProcessSample => "ProcessSample",
            Self::ProcessStart => "ProcessStart",
            Self::ProcessEnd => "ProcessEnd",
            Self::PdhSample => "PdhSample",
            Self::Device => "Device",
            Self::DeviceInventory => "DeviceInventory",
            Self::EventLog => "EventLog",
            Self::Incident => "Incident",
            Self::BlackBox => "BlackBox",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|t| t.name().eq_ignore_ascii_case(s))
    }
}

pub fn type_name(v: u16) -> String {
    RecordType::from_u16(v).map(|t| t.name().to_string()).unwrap_or_else(|| format!("Type{v}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStart {
    pub version: String,
    pub host: String,
    pub os: String,
    pub boot_id: u64,
    pub boot_ft: i64,
    pub pid: u32,
    pub profile: String,
    pub console: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionEnd {
    /// "SystemShutdown" or "ServiceStop".
    pub reason: String,
    pub uptime_s: u64,
}

/// One per second. The last heartbeat before an outage is the machine's
/// last known state, so it carries a compact set of vitals.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Heartbeat {
    /// Milliseconds since boot (GetTickCount64): immune to clock changes.
    pub mono_ms: u64,
    pub boot_id: u64,
    /// Lateness of this heartbeat vs. schedule. Large values mean the
    /// collector was starved (CPU, paging, a stalled disk...).
    pub jitter_ms: i64,
    #[serde(flatten)]
    pub vitals: Vitals,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Vitals {
    /// Total CPU busy, percent.
    pub cpu: f32,
    /// Commit charge as a percentage of the commit limit.
    pub commit_pct: f32,
    pub avail_mb: u64,
    /// Worst physical-disk latency in the last PDH sample, ms.
    pub disk_ms: f32,
    /// Worst physical-disk queue length.
    pub disk_q: f32,
    /// Top CPU process: "name(pid) 37.5%".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Note {
    pub text: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectorStatus {
    pub collector: String,
    /// "info" | "warn" | "error"
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemSample {
    pub cpu: f32,
    pub cpu_kernel: f32,
    pub commit_mb: u64,
    pub commit_limit_mb: u64,
    pub commit_peak_mb: u64,
    pub phys_mb: u64,
    pub avail_mb: u64,
    pub cache_mb: u64,
    pub paged_pool_mb: u64,
    pub nonpaged_pool_mb: u64,
    pub handles: u32,
    pub processes: u32,
    pub threads: u32,
    /// BlackBox's own footprint, so its overhead is always auditable.
    pub self_cpu: f32,
    pub self_ws_mb: f32,
    pub self_private_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoolTag {
    pub tag: String,
    pub paged: u64,
    pub nonpaged: u64,
    /// Outstanding allocations (allocs - frees), paged + nonpaged.
    pub allocs: i64,
    /// Change in total bytes since the previous pool sample.
    pub delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoolSample {
    pub tags: Vec<PoolTag>,
}

/// Compact per-process row, serialized as a JSON array:
/// `[pid, cpu_permille, ws_kb, private_kb, handles, threads,
///   read_Bps, write_Bps, other_Bps, hard_faults_per_s]`
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProcRow(
    pub u32,
    pub u16,
    pub u64,
    pub u64,
    pub u32,
    pub u32,
    pub u64,
    pub u64,
    pub u64,
    pub u32,
);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessSample {
    pub interval_ms: u32,
    /// true = every process; false = only processes that did something.
    pub full: bool,
    pub rows: Vec<ProcRow>,
    /// pid -> image name, included in full samples so any window of a
    /// minute or more can be read without scanning back to process starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<(u32, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessStart {
    pub pid: u32,
    pub ppid: u32,
    pub create_ft: i64,
    pub session: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// "inventory" (running when recording started), "sampler" or "etw".
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessEnd {
    pub pid: u32,
    pub create_ft: i64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub cpu_ms: u64,
    pub peak_ws_kb: u64,
    pub peak_private_kb: u64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskRow {
    pub disk: String,
    /// Average latency per transfer, ms.
    pub ms: f32,
    pub queue: f32,
    pub bps: f64,
    pub idle_pct: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NicRow {
    pub nic: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuEngineRow {
    /// Engine type: 3D, Copy, VideoDecode, Compute_0, ...
    pub engine: String,
    pub pct: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuProcRow {
    pub pid: u32,
    pub pct: f32,
    #[serde(default)]
    pub dedicated_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuSample {
    pub engines: Vec<GpuEngineRow>,
    pub procs: Vec<GpuProcRow>,
    pub dedicated_mb: f32,
    pub shared_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThermalRow {
    pub zone: String,
    pub celsius: f32,
    /// Thermal Zone "% Passive Limit": < 100 means the zone is throttling.
    pub passive_pct: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuPdh {
    /// "% Processor Utility" (frequency-aware busy, like Task Manager).
    pub utility: f32,
    /// "% Processor Performance": below ~100 under load = throttled/parked.
    pub perf: f32,
    pub dpc_pct: f32,
    pub intr_pct: f32,
    pub queue: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdhSample {
    pub cpu: CpuPdh,
    pub disks: Vec<DiskRow>,
    pub nics: Vec<NicRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thermal: Vec<ThermalRow>,
    /// Hard page-ins per second (thrashing indicator).
    pub pages_in: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// CM_PROB_* code; 0 = working.
    pub problem: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Device {
    /// "added" | "removed" | "problem" | "recovered"
    pub action: String,
    #[serde(flatten)]
    pub dev: DeviceRow,
    #[serde(default)]
    pub old_problem: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceInventory {
    pub devices: Vec<DeviceRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventLog {
    pub channel: String,
    pub provider: String,
    pub id: u32,
    pub level: u8,
    pub record_id: u64,
    /// When Windows says the event happened (the journal frame time is when
    /// BlackBox received it; they differ for backfilled events).
    pub event_ft: i64,
    #[serde(default)]
    pub task: u16,
    #[serde(default)]
    pub opcode: u8,
    #[serde(default)]
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub data: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Incident {
    pub id: String,
    /// "manual" | detector name
    pub kind: String,
    pub reason: String,
    #[serde(default)]
    pub folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlackBox {
    /// "started" | "adopted" | "rolled" | "pruned" | "linked" | "error"
    pub action: String,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_roundtrip() {
        for t in RecordType::ALL {
            assert_eq!(RecordType::from_u16(*t as u16), Some(*t));
            assert_eq!(RecordType::from_name(t.name()), Some(*t));
        }
    }

    #[test]
    fn procrow_is_compact_array() {
        let r = ProcRow(4, 12, 1, 2, 3, 4, 5, 6, 7, 8);
        assert_eq!(serde_json::to_string(&r).unwrap(), "[4,12,1,2,3,4,5,6,7,8]");
    }
}
