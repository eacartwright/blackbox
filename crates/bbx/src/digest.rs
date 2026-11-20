//! The digest: a compact, self-contained text description of a dataset that
//! a person or a model can read in one go. It is exactly what `bbx analyze`
//! sends to Claude, and `bbx digest` writes it out so a technician can see
//! (and redact) what would be sent.

use crate::dataset::Dataset;
use crate::suspects::{self, Suspect};
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{fmt_local, FT_PER_SEC};
use std::fmt::Write;

/// Upper bound on digest size (characters). Roughly 50-60k tokens.
pub const MAX_CHARS: usize = 220_000;

pub fn build(ds: &Dataset, suspects: &[Suspect]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# BlackBox digest\n");
    let _ = writeln!(o, "- Machine: {} — {}", ds.host, ds.os);
    let _ = writeln!(o, "- Recording window: {} .. {}", fmt_local(ds.from_ft), fmt_local(ds.to_ft));
    let _ = writeln!(o, "- Moment of interest: {}", fmt_local(ds.at_ft));
    if let Some(i) = &ds.incident {
        let _ = writeln!(o, "- Incident: {} [{}] — {}", i.id, i.kind, i.reason);
    }
    let _ = writeln!(o, "- Black-box (kernel trace) files available for drill-down: {}", ds.etl_files.len());
    let _ = writeln!(o, "- Screenshots available: {}", ds.screens.len());

    let notes: Vec<String> = ds
        .records_of(RecordType::Note)
        .filter_map(|r| Some(format!("{}  {} ({})", fmt_local(r.ft), r.parse::<rec::Note>()?.text, r.parse::<rec::Note>()?.user)))
        .collect();
    if !notes.is_empty() {
        let _ = writeln!(o, "\n## What the user reported\n");
        for n in notes {
            let _ = writeln!(o, "- {n}");
        }
    }

    let _ = writeln!(o, "\n## How the previous boot ended\n");
    match &ds.verdict {
        Some(v) => {
            let _ = writeln!(o, "{:?} ({:?} confidence): {}", v.kind, v.confidence, v.summary);
            for d in &v.details {
                let _ = writeln!(o, "- {d}");
            }
        }
        None => {
            let _ = writeln!(o, "(no verdict in this dataset)");
        }
    }

    let _ = writeln!(o, "\n## Rule-based suspects (leads, ranked by score 0-100)\n");
    o.push_str(&suspects::to_text(suspects));

    if let Some(dh) = ds.records_of(RecordType::DiskHealth).last().and_then(|r| r.parse::<rec::DiskHealth>()) {
        let _ = writeln!(o, "\n## Disk health (latest sample)\n");
        for d in dh.disks {
            let mut line = format!("- Disk {} {} [{}]", d.disk, d.model, d.bus);
            if let Some(t) = d.temp_c {
                line += &format!(", {t} C");
            }
            if let Some(h) = d.nvme {
                line += &format!(
                    ", NVMe warning 0x{:02X}, spare {}%, used {}%, media errors {}, unsafe shutdowns {}, power-on {} h",
                    h.critical_warning, h.spare_pct, h.used_pct, h.media_errors, h.unsafe_shutdowns, h.power_on_hours
                );
            }
            for a in d.ata.iter().filter(|a| matches!(a.id, 5 | 187 | 197 | 198 | 199 | 174 | 192)) {
                line += &format!(", {}={}", a.name, a.raw);
            }
            let _ = writeln!(o, "{line}");
        }
    }

    // The situation report: vitals, top processes, disk/network/file/registry
    // activity and the event timeline around the moment.
    let before = ((ds.at_ft - ds.from_ft) / (60 * FT_PER_SEC)).clamp(1, 30) as u64;
    let after = ((ds.to_ft - ds.at_ft) / (60 * FT_PER_SEC)).clamp(1, 10) as u64;
    let report = crate::report::around_records(&ds.records, ds.at_ft, before, after).unwrap_or_default();
    let _ = writeln!(o, "\n## Situation report\n\n```");
    let budget = MAX_CHARS.saturating_sub(o.len() + 200);
    if report.len() <= budget {
        o.push_str(&report);
    } else {
        // Keep the head (vitals and summaries) and tell the reader what was cut.
        let mut cut = budget;
        while !report.is_char_boundary(cut) {
            cut -= 1;
        }
        let head = &report[..cut];
        let head = &head[..head.rfind('\n').unwrap_or(head.len())];
        let omitted = report[head.len()..].lines().count();
        o.push_str(head);
        let _ = write!(o, "\n[digest size limit: the last {omitted} lines of the timeline were omitted; see the viewer]");
    }
    let _ = writeln!(o, "\n```");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::Rec;
    use serde_json::json;

    #[test]
    fn digest_has_sections_and_respects_limit() {
        let mut ds = Dataset { host: "PC1".into(), os: "Windows 11".into(), from_ft: 0, to_ft: 600 * FT_PER_SEC, at_ft: 300 * FT_PER_SEC, ..Default::default() };
        for i in 0..600 {
            ds.records.push(Rec { seq: i, ft: i as i64 * FT_PER_SEC, rtype: RecordType::Heartbeat as u16, data: json!({"mono_ms": 0, "boot_id": 1, "jitter_ms": 1, "cpu": 5.0, "commit_pct": 40.0, "avail_mb": 8000, "disk_ms": 1.0, "disk_q": 0.0}) });
        }
        ds.records.push(Rec { seq: 999, ft: 300 * FT_PER_SEC, rtype: RecordType::Note as u16, data: json!({"text": "screen went black", "user": "bob", "source": "mark"}) });
        ds.records.sort_by_key(|r| r.ft);
        let d = build(&ds, &[]);
        for h in ["# BlackBox digest", "What the user reported", "screen went black", "Rule-based suspects", "Situation report", "VITALS"] {
            assert!(d.contains(h), "missing {h}");
        }
        assert!(d.len() < MAX_CHARS);
    }
}
