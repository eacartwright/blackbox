//! `bbx export`: one self-contained .zip for a time range or an incident,
//! readable without BlackBox installed (JSON lines, .evtx, .etl, text).
//!
//!   manifest.json     host, OS, range, record counts, BlackBox version
//!   summary.txt       the `bbx around` report
//!   records.jsonl     every journal record in the range
//!   verdict.json      the latest shutdown verdict
//!   eventlogs\*.evtx  System and Application for the range
//!   blackbox\*.etl    black-box files overlapping the range (open in WPA)
//!   dumps\*.dmp       minidumps written in the range
//!   incident\...      the incident folder (when exporting an incident)

use crate::report;
use anyhow::{anyhow, bail, Context, Result};
use bbx_collect::{blackbox, bootinfo, eventlog};
use bbx_core::journal;
use bbx_core::paths::Paths;
use bbx_core::records::{self as rec, type_name};
use bbx_core::time::{fmt_utc, now_ft, utc_to_ft, FT_PER_SEC};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub struct ExportOptions {
    pub from_ft: i64,
    pub to_ft: i64,
    pub at_ft: i64,
    pub incident: Option<String>,
    pub out: Option<PathBuf>,
    pub include_etl: bool,
}

/// Resolve `--incident ID` to its window.
pub fn incident_window(paths: &Paths, id: &str) -> Result<(i64, i64, i64)> {
    let p = paths.incidents().join(id).join("incident.json");
    let b = std::fs::read(&p).with_context(|| format!("no incident '{id}' ({})", p.display()))?;
    let inc: rec::Incident = serde_json::from_slice(&b)?;
    if inc.at_ft == 0 {
        bail!("incident {id} has no time window recorded");
    }
    Ok((inc.from_ft, inc.to_ft.max(inc.at_ft), inc.at_ft))
}

pub fn export(paths: &Paths, o: ExportOptions) -> Result<PathBuf> {
    if o.to_ft <= o.from_ft {
        bail!("empty time range");
    }
    let host = bootinfo::hostname();
    let stamp = bbx_core::time::ft_to_utc(o.at_ft).with_timezone(&chrono::Local).format("%Y%m%d-%H%M%S");
    let out = o.out.clone().unwrap_or_else(|| PathBuf::from(format!("blackbox-{host}-{stamp}.zip")));
    let file = File::create(&out).with_context(|| format!("create {}", out.display()))?;
    let mut zip = ZipWriter::new(BufWriter::new(file));
    let text = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let big = text.large_file(true);

    // records.jsonl + counts
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    zip.start_file("records.jsonl", big)?;
    journal::for_each_record(&paths.journal(), Some(o.from_ft), Some(o.to_ft), |r| {
        *counts.entry(type_name(r.rtype)).or_default() += 1;
        let line = serde_json::json!({"seq": r.seq, "ft": r.ft, "time": fmt_utc(r.ft), "type": type_name(r.rtype), "data": r.json()});
        let _ = writeln!(zip, "{line}");
        true
    })?;

    zip.start_file("summary.txt", text)?;
    let before = ((o.at_ft - o.from_ft) / (60 * FT_PER_SEC)).max(1) as u64;
    let after = ((o.to_ft - o.at_ft) / (60 * FT_PER_SEC)).max(1) as u64;
    zip.write_all(report::around(paths, o.at_ft, before, after)?.as_bytes())?;

    if let Ok(v) = std::fs::read(paths.state().join(crate::agent::LAST_VERDICT_FILE)) {
        zip.start_file("verdict.json", text)?;
        zip.write_all(&v)?;
    }

    // Event logs for the range (exported to temp files first).
    let tmp = std::env::temp_dir().join(format!("bbx-export-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    for ch in ["System", "Application"] {
        let f = tmp.join(format!("{ch}.evtx"));
        match eventlog::export_range(ch, o.from_ft, o.to_ft, &f) {
            Ok(()) => add_file(&mut zip, &f, &format!("eventlogs/{ch}.evtx"), big)?,
            Err(e) => eprintln!("warning: {e:#}"),
        }
    }
    std::fs::remove_dir_all(&tmp).ok();

    let mut added: HashSet<String> = HashSet::new();
    if let Some(id) = &o.incident {
        let dir = paths.incidents().join(id);
        for e in walk(&dir) {
            let rel = e.strip_prefix(&dir).unwrap().to_string_lossy().replace('\\', "/");
            if rel.ends_with(".etl") && !o.include_etl {
                continue;
            }
            if let Some(n) = e.file_name() {
                added.insert(n.to_string_lossy().into_owned());
            }
            add_file(&mut zip, &e, &format!("incident/{rel}"), big)?;
        }
    }
    let mut etl_bytes = 0u64;
    if o.include_etl {
        for f in blackbox::list_files(&paths.blackbox()) {
            if f.modified_ft < o.from_ft || f.created_ft > o.to_ft {
                continue;
            }
            let name = f.path.file_name().unwrap().to_string_lossy().into_owned();
            if added.contains(&name) {
                continue;
            }
            etl_bytes += f.size;
            add_file(&mut zip, &f.path, &format!("blackbox/{name}"), big)?;
        }
    }
    for d in dumps_in(o.from_ft, o.to_ft + 3600 * FT_PER_SEC) {
        let name = d.file_name().unwrap().to_string_lossy().into_owned();
        add_file(&mut zip, &d, &format!("dumps/{name}"), big)?;
    }

    zip.start_file("manifest.json", text)?;
    let manifest = serde_json::json!({
        "bbx_version": bbx_core::VERSION,
        "host": host,
        "os": bootinfo::os_description(),
        "created": fmt_utc(now_ft()),
        "from": fmt_utc(o.from_ft),
        "to": fmt_utc(o.to_ft),
        "at": fmt_utc(o.at_ft),
        "incident": o.incident,
        "record_counts": counts,
        "blackbox_etl_bytes": etl_bytes,
        "formats": "records.jsonl: one JSON object per line {seq,time,type,data}; see docs/ARCHITECTURE.md for record schemas",
    });
    zip.write_all(serde_json::to_vec_pretty(&manifest)?.as_slice())?;
    zip.finish()?.flush()?;
    Ok(out)
}

fn add_file<W: Write + std::io::Seek>(zip: &mut ZipWriter<W>, src: &Path, name: &str, opts: SimpleFileOptions) -> Result<()> {
    // .etl is written by the kernel with sharing; open read-only, shared.
    let mut f = File::open(src).map_err(|e| anyhow!("{}: {e}", src.display()))?;
    zip.start_file(name, opts)?;
    std::io::copy(&mut f, zip)?;
    Ok(())
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn dumps_in(from: i64, to: i64) -> Vec<PathBuf> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    walk(&Path::new(&windir).join("Minidump"))
        .into_iter()
        .filter(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .map(|t| {
                    let ft = utc_to_ft(chrono::DateTime::<chrono::Utc>::from(t));
                    ft >= from && ft <= to
                })
                .unwrap_or(false)
        })
        .collect()
}
