//! Gathers Windows' own evidence about how the previous boot ended, for the
//! shutdown classifier.

use crate::eventlog;
use bbx_core::classifier::{BootEvidence, KernelPower41};
use bbx_core::records::EventLog;
use bbx_core::time::{fmt_utc, utc_to_ft, FT_PER_SEC};
use std::path::Path;

fn data_u64(e: &EventLog, key: &str) -> u64 {
    let s = e.data.get(key).and_then(|v| v.as_str()).unwrap_or("0").trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

pub fn kp41_from(e: &EventLog) -> KernelPower41 {
    KernelPower41 {
        ft: e.event_ft,
        bugcheck_code: data_u64(e, "BugcheckCode"),
        bugcheck_params: [
            data_u64(e, "BugcheckParameter1"),
            data_u64(e, "BugcheckParameter2"),
            data_u64(e, "BugcheckParameter3"),
            data_u64(e, "BugcheckParameter4"),
        ],
        sleep_in_progress: data_u64(e, "SleepInProgress") as u32,
        power_button_ft: data_u64(e, "PowerButtonTimestamp") as i64,
    }
}

/// Collect evidence logged since `since_ft` (FILETIME).
pub fn gather(since_ft: i64) -> BootEvidence {
    let since = fmt_utc(since_ft);
    let xpath = format!(
        "*[System[TimeCreated[@SystemTime>='{since}'] and (\
           (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or \
           (Provider[@Name='EventLog'] and EventID=6008) or \
           (Provider[@Name='User32'] and EventID=1074) or \
           (Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001) or \
           Provider[@Name='Microsoft-Windows-WHEA-Logger'])]]"
    );
    let mut ev = BootEvidence::default();
    match eventlog::query("System", &xpath, 500) {
        Ok(events) => {
            for e in events {
                match (e.provider.as_str(), e.id) {
                    ("Microsoft-Windows-Kernel-Power", 41) => ev.kp41 = Some(kp41_from(&e)),
                    ("EventLog", 6008) => ev.ev6008_ft = Some(e.event_ft),
                    ("User32", 1074) => {
                        ev.user1074 = Some(e.message.clone().unwrap_or_else(|| format!("{:?}", e.data)));
                    }
                    ("Microsoft-Windows-WER-SystemErrorReporting", 1001) => {
                        ev.bugcheck1001 = Some(e.message.clone().unwrap_or_else(|| format!("{:?}", e.data)));
                    }
                    (p, _) if p == "Microsoft-Windows-WHEA-Logger" => ev.whea_count += 1,
                    _ => {}
                }
            }
        }
        Err(e) => log::warn!("boot evidence query failed: {e:#}"),
    }
    ev.dumps = dumps_since(since_ft - 60 * FT_PER_SEC);
    ev
}

fn dumps_since(min_ft: i64) -> Vec<String> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::new();
    let mut check = |p: &Path| {
        if let Ok(m) = std::fs::metadata(p) {
            if let Ok(t) = m.modified() {
                let ft = utc_to_ft(chrono::DateTime::<chrono::Utc>::from(t));
                if ft >= min_ft {
                    out.push(format!("{} ({} MB)", p.display(), m.len() / 1048576));
                }
            }
        }
    };
    check(&Path::new(&windir).join("MEMORY.DMP"));
    if let Ok(rd) = std::fs::read_dir(Path::new(&windir).join("Minidump")) {
        for e in rd.flatten() {
            check(&e.path());
        }
    }
    out
}
