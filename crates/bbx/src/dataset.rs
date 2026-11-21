//! A dataset: every record for a time window, plus the black-box files,
//! screenshots, verdict and incident that go with it, loaded into memory
//! from an export bundle (.zip or encrypted .zip.age) or straight from the
//! local journal. The report, suspects, digest and viewer all work on this.

use anyhow::{anyhow, bail, Context, Result};
use bbx_core::classifier::Verdict;
use bbx_core::journal;
use bbx_core::paths::Paths;
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{now_ft, utc_to_ft};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Rec {
    pub seq: u64,
    pub ft: i64,
    pub rtype: u16,
    pub data: Value,
}

impl Rec {
    pub fn ty(&self) -> Option<RecordType> {
        RecordType::from_u16(self.rtype)
    }
    pub fn is(&self, t: RecordType) -> bool {
        self.rtype == t as u16
    }
    pub fn parse<T: DeserializeOwned>(&self) -> Option<T> {
        T::deserialize(&self.data).ok()
    }
}

#[derive(Debug, Default)]
pub struct Dataset {
    /// Where it came from (bundle path or "local journal").
    pub source: String,
    pub host: String,
    pub os: String,
    pub from_ft: i64,
    pub to_ft: i64,
    /// The moment of interest (incident time, --around time, or end).
    pub at_ft: i64,
    pub records: Vec<Rec>,
    pub verdict: Option<Verdict>,
    pub incident: Option<rec::Incident>,
    pub etl_files: Vec<PathBuf>,
    /// (time, png path)
    pub screens: Vec<(i64, PathBuf)>,
    /// Temp directory deleted when the dataset is dropped.
    #[allow(dead_code)]
    pub temp: TempGuard,
}

#[derive(Debug, Default)]
pub struct TempGuard(pub Option<PathBuf>);

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            std::fs::remove_dir_all(t).ok();
        }
    }
}

fn temp_dir() -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("bbx-view-{}-{}", std::process::id(), now_ft()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

impl Dataset {
    pub fn records_of(&self, t: RecordType) -> impl Iterator<Item = &Rec> {
        self.records.iter().filter(move |r| r.rtype == t as u16)
    }

    pub fn in_window(&self, from: i64, to: i64) -> &[Rec] {
        let a = self.records.partition_point(|r| r.ft < from);
        let b = self.records.partition_point(|r| r.ft <= to);
        &self.records[a..b.max(a)]
    }

    fn finish(&mut self) {
        self.records.sort_by_key(|r| (r.ft, r.seq));
        if self.from_ft == 0 {
            self.from_ft = self.records.first().map(|r| r.ft).unwrap_or(0);
        }
        if self.to_ft == 0 {
            self.to_ft = self.records.last().map(|r| r.ft).unwrap_or(0);
        }
        if self.at_ft == 0 {
            self.at_ft = self.to_ft;
        }
        if self.host.is_empty() {
            if let Some(s) = self.records_of(RecordType::SessionStart).last().and_then(|r| r.parse::<rec::SessionStart>()) {
                self.host = s.host;
                self.os = s.os;
            }
        }
    }

    /// Open an export bundle. `.age` bundles need the technician key.
    pub fn open_bundle(path: &Path, identity: Option<&Path>) -> Result<Dataset> {
        let temp = temp_dir()?;
        let mut ds = Dataset { source: path.display().to_string(), temp: TempGuard(Some(temp.clone())), ..Default::default() };
        let zip_path = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("age")) {
            let default_key = crate::crypto::default_key_path();
            let key = match identity {
                Some(k) => k,
                None if default_key.exists() => default_key.as_path(),
                None => bail!(
                    "{} is encrypted and there is no technician key at {}: run `bbx keygen` once, or pass the key with -i <key file>",
                    path.display(),
                    default_key.display()
                ),
            };
            let ids = crate::crypto::read_identities(key)?;
            let out = temp.join("bundle.zip");
            crate::crypto::decrypt_file(path, &out, &ids)?;
            out
        } else {
            path.to_path_buf()
        };
        let f = std::fs::File::open(&zip_path).with_context(|| format!("open {}", zip_path.display()))?;
        let mut z = zip::ZipArchive::new(f).with_context(|| format!("{} is not a BlackBox bundle (zip)", path.display()))?;

        let read_text = |z: &mut zip::ZipArchive<std::fs::File>, name: &str| -> Option<String> {
            let mut e = z.by_name(name).ok()?;
            let mut s = String::new();
            e.read_to_string(&mut s).ok()?;
            Some(s)
        };
        if let Some(m) = read_text(&mut z, "manifest.json").and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            let ft = |k: &str| m.get(k).and_then(|v| v.as_str()).and_then(parse_time).unwrap_or(0);
            ds.from_ft = ft("from");
            ds.to_ft = ft("to");
            ds.at_ft = ft("at");
            ds.host = m.get("host").and_then(|v| v.as_str()).unwrap_or("").into();
            ds.os = m.get("os").and_then(|v| v.as_str()).unwrap_or("").into();
        }
        ds.verdict = read_text(&mut z, "verdict.json").and_then(|s| serde_json::from_str(&s).ok());
        ds.incident = read_text(&mut z, "incident/incident.json").and_then(|s| serde_json::from_str(&s).ok());

        {
            let e = z.by_name("records.jsonl").map_err(|_| anyhow!("bundle has no records.jsonl"))?;
            for line in BufReader::new(e).lines() {
                let line = line?;
                if let Some(r) = parse_line(&line) {
                    ds.records.push(r);
                }
            }
        }

        // Extract black-box files and screenshots.
        let names: Vec<String> = z.file_names().map(String::from).collect();
        for name in names {
            let lower = name.to_ascii_lowercase();
            let is_etl = lower.ends_with(".etl");
            let is_png = lower.ends_with(".png") && lower.contains("screens/");
            if !is_etl && !is_png {
                continue;
            }
            let file_name = Path::new(&name).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            if file_name.is_empty() || file_name.contains("..") {
                continue;
            }
            let sub = if is_etl { "etl" } else { "screens" };
            let dir = temp.join(sub);
            std::fs::create_dir_all(&dir)?;
            let dest = dir.join(&file_name);
            if dest.exists() {
                continue; // same .etl both in blackbox/ and incident/blackbox/
            }
            let mut e = z.by_name(&name)?;
            let mut out = std::fs::File::create(&dest)?;
            std::io::copy(&mut e, &mut out)?;
            if is_etl {
                ds.etl_files.push(dest);
            } else if let Some(ft) = screen_time(&file_name, ds.incident.as_ref().map(|i| i.at_ft).unwrap_or(ds.at_ft)) {
                ds.screens.push((ft, dest));
            }
        }
        ds.screens.sort_by_key(|s| s.0);
        ds.finish();
        Ok(ds)
    }

    /// Read straight from this machine's journal (run elevated).
    pub fn open_local(paths: &Paths, from_ft: i64, to_ft: i64, at_ft: i64) -> Result<Dataset> {
        if std::fs::read_dir(paths.journal()).is_err() {
            bail!("cannot read {}: run from an elevated prompt", paths.journal().display());
        }
        let mut ds = Dataset { source: "local journal".into(), from_ft, to_ft, at_ft, ..Default::default() };
        ds.records = load_journal(paths, from_ft, to_ft)?;
        ds.verdict = std::fs::read(paths.state().join(crate::agent::LAST_VERDICT_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok());
        ds.etl_files = bbx_collect::blackbox::list_files(&paths.blackbox())
            .into_iter()
            .filter(|f| f.modified_ft >= from_ft && f.created_ft <= to_ft)
            .map(|f| f.path)
            .collect();
        ds.host = bbx_collect::bootinfo::hostname();
        ds.os = bbx_collect::bootinfo::os_description();
        ds.finish();
        Ok(ds)
    }

    /// One saved incident from this machine: its window, the incident
    /// itself and its screenshots (run elevated).
    pub fn open_local_incident(paths: &Paths, id: &str) -> Result<Dataset> {
        let (from_ft, to_ft, at_ft) = crate::export::incident_window(paths, id)?;
        let mut ds = Dataset::open_local(paths, from_ft, to_ft, at_ft)?;
        let dir = paths.incidents().join(id);
        ds.source = format!("incident {id}");
        ds.incident = std::fs::read(dir.join("incident.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
        if let Ok(rd) = std::fs::read_dir(dir.join("screens")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(ft) = screen_time(&name, at_ft) {
                    ds.screens.push((ft, e.path()));
                }
            }
        }
        ds.screens.sort_by_key(|s| s.0);
        Ok(ds)
    }
}

/// Saved incidents on this machine, newest first (run elevated).
pub fn list_incidents(paths: &Paths) -> Vec<rec::Incident> {
    let mut list: Vec<rec::Incident> = std::fs::read_dir(paths.incidents())
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| std::fs::read(e.path().join("incident.json")).ok())
                .filter_map(|b| serde_json::from_slice(&b).ok())
                .collect()
        })
        .unwrap_or_default();
    list.sort_by_key(|i: &rec::Incident| std::cmp::Reverse(i.at_ft));
    list
}

pub fn load_journal(paths: &Paths, from_ft: i64, to_ft: i64) -> Result<Vec<Rec>> {
    let mut v = Vec::new();
    journal::for_each_record(&paths.journal(), Some(from_ft), Some(to_ft), |r| {
        v.push(Rec { seq: r.seq, ft: r.ft, rtype: r.rtype, data: r.json() });
        true
    })?;
    v.sort_by_key(|r| (r.ft, r.seq));
    Ok(v)
}

fn parse_time(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| utc_to_ft(d.with_timezone(&chrono::Utc)))
}

/// One records.jsonl line: {"seq", "ft"?, "time", "type", "data"}.
pub fn parse_line(line: &str) -> Option<Rec> {
    let v: Value = serde_json::from_str(line).ok()?;
    let ty = v.get("type")?.as_str()?;
    let rtype = RecordType::from_name(ty).map(|t| t as u16).or_else(|| ty.strip_prefix("Type").and_then(|n| n.parse().ok()))?;
    let ft = v.get("ft").and_then(|x| x.as_i64()).or_else(|| v.get("time").and_then(|t| t.as_str()).and_then(parse_time))?;
    Some(Rec { seq: v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0), ft, rtype, data: v.get("data").cloned().unwrap_or(Value::Null) })
}

/// Screens are saved as `HHMMSS.fff.png` (local time) next to an incident.
fn screen_time(name: &str, near_ft: i64) -> Option<i64> {
    let stem = name.strip_suffix(".png")?;
    let t = chrono::NaiveTime::parse_from_str(stem, "%H%M%S%.3f").ok()?;
    let near = bbx_core::time::ft_to_utc(near_ft).with_timezone(&chrono::Local);
    let mut best: Option<i64> = None;
    for day in [-1i64, 0, 1] {
        let date = near.date_naive() + chrono::Duration::days(day);
        if let Some(dt) = chrono::TimeZone::from_local_datetime(&chrono::Local, &date.and_time(t)).earliest() {
            let ft = utc_to_ft(dt.with_timezone(&chrono::Utc));
            if best.is_none_or(|b| (b - near_ft).abs() > (ft - near_ft).abs()) {
                best = Some(ft);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_lines() {
        let r = parse_line(r#"{"seq":5,"ft":134000000000000000,"time":"x","type":"Heartbeat","data":{"cpu":3.0}}"#).unwrap();
        assert_eq!((r.seq, r.ft, r.rtype), (5, 134000000000000000, RecordType::Heartbeat as u16));
        let r = parse_line(r#"{"seq":6,"time":"2026-11-19T21:05:01.123Z","type":"Note","data":{"text":"x"}}"#).unwrap();
        assert!(r.ft > 0);
        assert!(parse_line("not json").is_none());
    }

    #[test]
    fn window_slices() {
        let mut ds = Dataset::default();
        for i in 0..10 {
            ds.records.push(Rec { seq: i, ft: i as i64 * 10, rtype: 3, data: Value::Null });
        }
        assert_eq!(ds.in_window(20, 50).len(), 4);
        assert_eq!(ds.in_window(95, 200).len(), 0);
    }
}
