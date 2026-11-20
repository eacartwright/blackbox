//! "How did the previous boot end?" — a pure function from evidence to a
//! verdict, so every rule is unit-tested. See ARCHITECTURE.md §5.

use serde::{Deserialize, Serialize};

use crate::runstate::RunState;
use crate::time::{fmt_local, secs_between, FT_PER_SEC};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerdictKind {
    FirstRun,
    CleanShutdown,
    CollectorStopped,
    CollectorCrashed,
    Bugcheck,
    HangThenForcedOff,
    ForcedOffWhileAlive,
    DegradedThenReset,
    AbruptStop,
    SleepTransitionFailure,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// One heartbeat from the end of the previous run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeartbeatPoint {
    pub ft: i64,
    pub mono_ms: u64,
    pub jitter_ms: i64,
    pub cpu: f32,
    pub commit_pct: f32,
    pub avail_mb: u64,
    pub disk_ms: f32,
    #[serde(default)]
    pub top: Option<String>,
}

/// Kernel-Power event 41 ("rebooted without cleanly shutting down").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelPower41 {
    pub ft: i64,
    pub bugcheck_code: u64,
    pub bugcheck_params: [u64; 4],
    pub sleep_in_progress: u32,
    /// FILETIME of a power-button press the OS registered, 0 if none.
    /// Windows can only record it if it was responsive enough to see it.
    pub power_button_ft: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootEvidence {
    pub kp41: Option<KernelPower41>,
    /// EventLog 6008 "previous system shutdown was unexpected".
    pub ev6008_ft: Option<i64>,
    /// User32 1074: who/what requested the shutdown or restart.
    pub user1074: Option<String>,
    /// WER-SystemErrorReporting 1001 text ("The computer has rebooted from a bugcheck...").
    pub bugcheck1001: Option<String>,
    /// Crash dumps written after the last heartbeat.
    pub dumps: Vec<String>,
    pub whea_count: u32,
    /// True once Windows has had time to log its boot-time events.
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct ClassifierInput {
    pub prev: Option<RunState>,
    pub current_boot_id: u64,
    pub current_boot_ft: i64,
    /// Heartbeats from the end of the previous run, oldest first.
    pub tail: Vec<HeartbeatPoint>,
    /// Timestamp of the very last record of the previous run.
    pub last_record_ft: Option<i64>,
    pub evidence: BootEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub confidence: Confidence,
    pub summary: String,
    #[serde(default)]
    pub last_alive_ft: Option<i64>,
    #[serde(default)]
    pub details: Vec<String>,
    #[serde(default)]
    pub evidence: Option<BootEvidence>,
    #[serde(default)]
    pub last_vitals: Option<HeartbeatPoint>,
}

/// Thresholds for "the machine was in trouble" in the final seconds.
const STRESS_WINDOW: usize = 10;
const STRESS_CPU: f32 = 95.0;
const STRESS_COMMIT: f32 = 95.0;
const STRESS_AVAIL_MB: u64 = 200;
const STRESS_DISK_MS: f32 = 2000.0;
const STRESS_JITTER_MS: i64 = 3000;
/// Same-boot detection tolerance for boot time drift.
const BOOT_FT_TOLERANCE: i64 = 5 * FT_PER_SEC;
/// Gap between last heartbeat and a power-button press above which we say
/// the collector had stopped running before the button was pressed.
const BUTTON_GAP_S: f64 = 10.0;

pub fn same_boot(prev: &RunState, boot_id: u64, boot_ft: i64) -> bool {
    // Prefer Windows' boot counter: boot time derived from the wall clock
    // shifts when the clock is corrected after boot (bad CMOS battery, NTP).
    if prev.boot_id != 0 && boot_id != 0 {
        return prev.boot_id == boot_id;
    }
    (prev.boot_ft - boot_ft).abs() <= BOOT_FT_TOLERANCE
}

impl HeartbeatPoint {
    /// False for heartbeats written before the samplers produced their first
    /// values (all-zero vitals mean "unknown", not "0 MB free").
    pub fn has_vitals(&self) -> bool {
        self.avail_mb > 0 || self.commit_pct > 0.0
    }
}

fn stress_reasons(tail: &[HeartbeatPoint]) -> Vec<String> {
    let mut why = Vec::new();
    let valid: Vec<HeartbeatPoint> = tail.iter().filter(|h| h.has_vitals()).cloned().collect();
    let recent = &valid[valid.len().saturating_sub(STRESS_WINDOW)..];
    let max_by = |f: &dyn Fn(&HeartbeatPoint) -> f64| recent.iter().map(f).fold(f64::MIN, f64::max);
    if recent.is_empty() {
        return why;
    }
    let cpu = max_by(&|h| h.cpu as f64);
    let commit = max_by(&|h| h.commit_pct as f64);
    let disk = max_by(&|h| h.disk_ms as f64);
    let jitter = max_by(&|h| h.jitter_ms as f64);
    let avail = recent.iter().map(|h| h.avail_mb).min().unwrap_or(u64::MAX);
    if cpu >= STRESS_CPU as f64 {
        why.push(format!("CPU at {cpu:.0}%"));
    }
    if commit >= STRESS_COMMIT as f64 {
        why.push(format!("commit charge at {commit:.0}% of the limit"));
    }
    if avail <= STRESS_AVAIL_MB {
        why.push(format!("only {avail} MB of physical memory available"));
    }
    if disk >= STRESS_DISK_MS as f64 {
        why.push(format!("disk latency reached {disk:.0} ms"));
    }
    if jitter >= STRESS_JITTER_MS as f64 {
        why.push(format!("BlackBox's own heartbeat ran {:.1} s late (the system was stalling)", jitter / 1000.0));
    }
    why
}

fn describe_vitals(h: &HeartbeatPoint) -> String {
    let mut s = format!(
        "CPU {:.0}%, commit {:.0}%, {} MB available, disk {:.0} ms",
        h.cpu, h.commit_pct, h.avail_mb, h.disk_ms
    );
    if let Some(t) = &h.top {
        s.push_str(&format!(", busiest: {t}"));
    }
    s
}

pub fn classify(input: &ClassifierInput) -> Verdict {
    let ev = &input.evidence;
    let last_alive = input.tail.last().map(|h| h.ft).or(input.last_record_ft);
    let last_vitals = input.tail.iter().rev().find(|h| h.has_vitals()).cloned();
    let mut v = Verdict {
        kind: VerdictKind::Unknown,
        confidence: Confidence::Low,
        summary: String::new(),
        last_alive_ft: last_alive,
        details: Vec::new(),
        evidence: Some(ev.clone()),
        last_vitals: last_vitals.clone(),
    };
    if let Some(t) = last_alive {
        v.details.push(format!("Last record from the previous run: {}", fmt_local(t)));
    }
    if let Some(h) = &last_vitals {
        v.details.push(format!("Last known state: {}", describe_vitals(h)));
    }

    let Some(prev) = &input.prev else {
        v.kind = VerdictKind::FirstRun;
        v.confidence = Confidence::High;
        v.summary = "First run of BlackBox on this machine; nothing to compare against.".into();
        return v;
    };

    let same = same_boot(prev, input.current_boot_id, input.current_boot_ft);
    if same {
        if prev.clean_stop {
            v.kind = VerdictKind::CollectorStopped;
            v.confidence = Confidence::High;
            v.summary = "BlackBox was stopped and restarted; Windows itself did not restart.".into();
        } else {
            v.kind = VerdictKind::CollectorCrashed;
            v.confidence = Confidence::High;
            v.summary = "The BlackBox service ended unexpectedly while Windows kept running \
                         (crash or killed). If the black box was running, it kept recording through the gap."
                .into();
        }
        return v;
    }

    if prev.clean_stop && prev.stop_kind.as_deref() == Some("SystemShutdown") {
        v.kind = VerdictKind::CleanShutdown;
        v.confidence = Confidence::High;
        v.summary = match &ev.user1074 {
            Some(who) => format!("Orderly shutdown/restart. {who}"),
            None => "Orderly shutdown/restart.".into(),
        };
        return v;
    }
    let collector_was_off = prev.clean_stop; // stopped manually, then Windows restarted
    if collector_was_off {
        v.details.push(
            "BlackBox had been stopped before this restart, so the last minutes before it are not recorded."
                .into(),
        );
    }

    // ---- Bugcheck
    let bc_code = ev.kp41.as_ref().map(|k| k.bugcheck_code).unwrap_or(0);
    if bc_code != 0 || ev.bugcheck1001.is_some() || !ev.dumps.is_empty() {
        v.kind = VerdictKind::Bugcheck;
        v.confidence = if bc_code != 0 || ev.bugcheck1001.is_some() { Confidence::High } else { Confidence::Medium };
        v.summary = if bc_code != 0 {
            let p = ev.kp41.as_ref().unwrap().bugcheck_params;
            format!(
                "Blue screen (bugcheck 0x{bc_code:08X}, params 0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}).",
                p[0], p[1], p[2], p[3]
            )
        } else {
            "Blue screen (bugcheck).".into()
        };
        if let Some(t) = &ev.bugcheck1001 {
            v.details.push(t.clone());
        }
        for d in &ev.dumps {
            v.details.push(format!("Dump: {d}"));
        }
        return v;
    }

    let k41 = ev.kp41.as_ref();
    if k41.is_none() && ev.user1074.is_some() {
        v.kind = VerdictKind::CleanShutdown;
        v.confidence = Confidence::Medium;
        v.summary = format!(
            "Requested shutdown/restart, but BlackBox did not get to record its own stop. {}",
            ev.user1074.as_deref().unwrap_or("")
        );
        return v;
    }
    if k41.is_none() && !ev.complete {
        v.summary = "Windows has not logged its boot evidence yet.".into();
        return v;
    }

    // ---- Sleep transition
    if k41.is_some_and(|k| k.sleep_in_progress != 0) {
        v.kind = VerdictKind::SleepTransitionFailure;
        v.confidence = Confidence::High;
        v.summary = format!(
            "The machine died while entering or leaving sleep/hibernate (SleepInProgress={}). \
             Suspect firmware, chipset/storage/GPU drivers, or power-state handling.",
            k41.unwrap().sleep_in_progress
        );
        return v;
    }

    let stress = stress_reasons(&input.tail);
    let button_ft = k41.map(|k| k.power_button_ft).unwrap_or(0);
    // Sanity-check the button time: must be within a day after the last record.
    let button_ft = match last_alive {
        Some(la) if button_ft > 0 && secs_between(la, button_ft) > -60.0 && secs_between(la, button_ft) < 86400.0 => {
            Some(button_ft)
        }
        None if button_ft > 0 => Some(button_ft),
        _ => None,
    };
    let button_pressed = k41.is_some_and(|k| k.power_button_ft != 0);

    if button_pressed {
        let gap = match (last_alive, button_ft) {
            (Some(la), Some(b)) => Some(secs_between(la, b)),
            _ => None,
        };
        match gap {
            Some(g) if g > BUTTON_GAP_S => {
                v.kind = VerdictKind::HangThenForcedOff;
                v.confidence = Confidence::High;
                v.summary = format!(
                    "The system stopped responding at {} and the power button was held {} later at {}. \
                     The kernel still registered the button, so this was a severe stall rather than a dead CPU.",
                    fmt_local(last_alive.unwrap()),
                    human_secs(g),
                    fmt_local(button_ft.unwrap())
                );
            }
            Some(_) if !stress.is_empty() => {
                v.kind = VerdictKind::HangThenForcedOff;
                v.confidence = Confidence::Medium;
                v.summary = format!(
                    "The power button was held while the machine was struggling ({}).",
                    stress.join("; ")
                );
            }
            _ => {
                v.kind = VerdictKind::ForcedOffWhileAlive;
                v.confidence = if gap.is_some() { Confidence::High } else { Confidence::Medium };
                v.summary = "The power button was held while Windows was still running normally. \
                             If the user saw a frozen or black screen, the OS was alive underneath: \
                             suspect the display/GPU driver, monitor/cable/dock, input devices, or a \
                             single hung application rather than a whole-system hang."
                    .into();
            }
        }
        if !stress.is_empty() && v.kind != VerdictKind::HangThenForcedOff {
            v.details.push(format!("Stress signs before the end: {}", stress.join("; ")));
        }
        return v;
    }

    if !stress.is_empty() {
        v.kind = VerdictKind::DegradedThenReset;
        v.confidence = Confidence::Medium;
        v.summary = format!(
            "The machine was struggling just before it went down ({}), then restarted without a \
             bugcheck or a registered power-button press (hard hang then forced off, or a watchdog/hardware reset).",
            stress.join("; ")
        );
        return v;
    }

    v.kind = VerdictKind::AbruptStop;
    v.confidence = if k41.is_some() && last_alive.is_some() { Confidence::Medium } else { Confidence::Low };
    v.summary = match last_alive {
        Some(la) => format!(
            "Everything looked normal at {}, then the machine stopped with no warning: no bugcheck, no \
             shutdown request and no power-button press that Windows could register. Most likely a loss \
             of power, the reset button, a PSU/hardware fault, or an instant total freeze followed by a \
             forced power-off. Ask: did the screen freeze first, or did it go dark/off by itself?",
            fmt_local(la)
        ),
        None => "The machine restarted without warning, but there is no recording of the moments before it.".into(),
    };
    if ev.whea_count > 0 {
        v.details.push(format!("{} WHEA (hardware error) events were logged around this boot.", ev.whea_count));
    }
    v
}

fn human_secs(s: f64) -> String {
    if s < 120.0 {
        format!("{s:.0} s")
    } else if s < 7200.0 {
        format!("{:.0} min", s / 60.0)
    } else {
        format!("{:.1} h", s / 3600.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_A: i64 = 133_000_000_000_000_000;
    const BOOT_B: i64 = BOOT_A + 3600 * FT_PER_SEC;

    fn prev(clean: bool, kind: Option<&str>) -> RunState {
        RunState {
            boot_id: 10,
            boot_ft: BOOT_A,
            clean_stop: clean,
            stop_kind: kind.map(String::from),
            ..Default::default()
        }
    }

    fn healthy_tail(end_ft: i64) -> Vec<HeartbeatPoint> {
        (0..30)
            .map(|i| HeartbeatPoint {
                ft: end_ft - (29 - i) * FT_PER_SEC,
                mono_ms: i as u64 * 1000,
                cpu: 12.0,
                commit_pct: 40.0,
                avail_mb: 8000,
                disk_ms: 3.0,
                ..Default::default()
            })
            .collect()
    }

    fn input(prev: Option<RunState>, boot_id: u64, boot_ft: i64, ev: BootEvidence) -> ClassifierInput {
        let end = BOOT_B - 120 * FT_PER_SEC;
        ClassifierInput {
            prev,
            current_boot_id: boot_id,
            current_boot_ft: boot_ft,
            tail: healthy_tail(end),
            last_record_ft: Some(end),
            evidence: BootEvidence { complete: true, ..ev },
        }
    }

    fn k41() -> KernelPower41 {
        KernelPower41 { ft: BOOT_B, ..Default::default() }
    }

    #[test]
    fn first_run() {
        let v = classify(&input(None, 11, BOOT_B, BootEvidence::default()));
        assert_eq!(v.kind, VerdictKind::FirstRun);
    }

    #[test]
    fn same_boot_crash_and_stop() {
        let v = classify(&input(Some(prev(false, None)), 10, BOOT_A, BootEvidence::default()));
        assert_eq!(v.kind, VerdictKind::CollectorCrashed);
        let v = classify(&input(Some(prev(true, Some("ServiceStop"))), 10, BOOT_A, BootEvidence::default()));
        assert_eq!(v.kind, VerdictKind::CollectorStopped);
    }

    #[test]
    fn clean_shutdown() {
        let ev = BootEvidence { user1074: Some("Restart by Windows Update".into()), ..Default::default() };
        let v = classify(&input(Some(prev(true, Some("SystemShutdown"))), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::CleanShutdown);
        assert_eq!(v.confidence, Confidence::High);
    }

    #[test]
    fn bugcheck() {
        let ev = BootEvidence {
            kp41: Some(KernelPower41 { bugcheck_code: 0x133, ..k41() }),
            ..Default::default()
        };
        let v = classify(&input(Some(prev(false, None)), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::Bugcheck);
        assert!(v.summary.contains("0x00000133"));
    }

    #[test]
    fn abrupt_stop_when_all_normal() {
        let ev = BootEvidence { kp41: Some(k41()), ..Default::default() };
        let v = classify(&input(Some(prev(false, None)), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::AbruptStop);
    }

    #[test]
    fn button_long_after_last_heartbeat_is_hang() {
        let end = BOOT_B - 120 * FT_PER_SEC;
        let ev = BootEvidence {
            kp41: Some(KernelPower41 { power_button_ft: end + 95 * FT_PER_SEC, ..k41() }),
            ..Default::default()
        };
        let v = classify(&input(Some(prev(false, None)), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::HangThenForcedOff);
        assert_eq!(v.confidence, Confidence::High);
    }

    #[test]
    fn button_while_alive() {
        let end = BOOT_B - 120 * FT_PER_SEC;
        let ev = BootEvidence {
            kp41: Some(KernelPower41 { power_button_ft: end + 2 * FT_PER_SEC, ..k41() }),
            ..Default::default()
        };
        let v = classify(&input(Some(prev(false, None)), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::ForcedOffWhileAlive);
    }

    #[test]
    fn stressed_tail_without_button() {
        let mut inp = input(Some(prev(false, None)), 11, BOOT_B, BootEvidence { kp41: Some(k41()), ..Default::default() });
        let n = inp.tail.len();
        inp.tail[n - 1].commit_pct = 99.0;
        inp.tail[n - 2].jitter_ms = 8000;
        let v = classify(&inp);
        assert_eq!(v.kind, VerdictKind::DegradedThenReset);
        assert!(v.summary.contains("commit"));
    }

    #[test]
    fn zero_vitals_are_unknown_not_stress() {
        // A run that died seconds after starting: only pre-sample heartbeats.
        let mut inp = input(Some(prev(false, None)), 11, BOOT_B, BootEvidence { kp41: Some(k41()), ..Default::default() });
        for h in inp.tail.iter_mut() {
            *h = HeartbeatPoint { ft: h.ft, mono_ms: h.mono_ms, ..Default::default() };
        }
        let v = classify(&inp);
        assert_eq!(v.kind, VerdictKind::AbruptStop);
        assert!(v.last_vitals.is_none());
    }

    #[test]
    fn sleep_failure() {
        let ev = BootEvidence { kp41: Some(KernelPower41 { sleep_in_progress: 4, ..k41() }), ..Default::default() };
        let v = classify(&input(Some(prev(false, None)), 11, BOOT_B, ev));
        assert_eq!(v.kind, VerdictKind::SleepTransitionFailure);
    }

    #[test]
    fn waits_for_evidence() {
        let mut inp = input(Some(prev(false, None)), 11, BOOT_B, BootEvidence::default());
        inp.evidence.complete = false;
        assert_eq!(classify(&inp).kind, VerdictKind::Unknown);
    }
}
