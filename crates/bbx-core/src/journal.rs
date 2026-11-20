//! The journal: an append-only, crash-safe record log.
//!
//! See docs/ARCHITECTURE.md §4 for the on-disk contract. In short:
//!
//! * frames carry a magic, length, type, sequence, timestamp and CRC-32C;
//! * every append goes straight to the OS (a collector crash loses nothing),
//!   and `commit()` calls `FlushFileBuffers` (a power cut loses ≤ 1 commit
//!   interval);
//! * on open, torn tails are truncated, corrupt regions are skipped by
//!   resyncing on the next valid frame, and writing always resumes in a new
//!   segment;
//! * closed segments are sealed: zstd-compressed to a temp file, flushed,
//!   then renamed to a name that carries their sequence and time range.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::records::RecordType;
use crate::time::now_ft;

pub const SEG_MAGIC: &[u8; 8] = b"BBXJSEG1";
pub const SEG_VERSION: u32 = 1;
pub const SEG_HEADER_LEN: usize = 32;
pub const FRAME_MAGIC: u32 = 0x3158_4242; // "BBX1"
pub const FRAME_HEADER_LEN: usize = 32;
pub const MAX_PAYLOAD: usize = 1 << 20;

const OPEN_PREFIX: &str = "open-";
const OPEN_EXT: &str = "bbj";
const SEALED_EXT: &str = "bbjz";

#[derive(Debug, Clone)]
pub struct JournalOptions {
    /// Roll to a new segment after this many bytes.
    pub max_segment_bytes: u64,
    /// Roll to a new segment after this long, even if small.
    pub max_segment_age: Duration,
    pub zstd_level: i32,
}

impl Default for JournalOptions {
    fn default() -> Self {
        Self {
            max_segment_bytes: 32 * 1024 * 1024,
            max_segment_age: Duration::from_secs(3600),
            zstd_level: 6,
        }
    }
}

/// A decoded frame.
#[derive(Debug, Clone)]
pub struct RawRecord {
    pub seq: u64,
    pub ft: i64,
    pub rtype: u16,
    pub payload: Vec<u8>,
}

impl RawRecord {
    pub fn record_type(&self) -> Option<RecordType> {
        RecordType::from_u16(self.rtype)
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.payload).unwrap_or(serde_json::Value::Null)
    }
    pub fn parse<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_slice(&self.payload).ok()
    }
}

/// What recovery found in one segment that was open when the previous run ended.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RecoveryInfo {
    pub segment: String,
    pub records: usize,
    pub truncated_tail_bytes: usize,
    pub corrupt_middle_bytes: usize,
    pub corrupt_regions: usize,
    pub last_seq: Option<u64>,
    pub last_ft: Option<i64>,
    /// Set when the segment could not be read or sealed. It is left in
    /// place (renamed `.unreadable` when possible) and recording continues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Sequence numbers skipped past a segment that couldn't be read, so new
/// records can never collide with (or be confused with) the ones it holds.
pub const UNREADABLE_SEQ_GAP: u64 = 10_000_000;

// ---------------------------------------------------------------- framing

fn frame_crc(header28: &[u8], payload: &[u8]) -> u32 {
    crc32c::crc32c_append(crc32c::crc32c(header28), payload)
}

pub fn encode_frame(out: &mut Vec<u8>, rtype: u16, seq: u64, ft: i64, payload: &[u8]) {
    let start = out.len();
    out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&rtype.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&ft.to_le_bytes());
    let c = frame_crc(&out[start..start + 28], payload);
    out.extend_from_slice(&c.to_le_bytes());
    out.extend_from_slice(payload);
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Decode one frame at `pos`, returning it and its total length.
fn try_frame(buf: &[u8], pos: usize) -> Option<(RawRecord, usize)> {
    if pos + FRAME_HEADER_LEN > buf.len() || u32_at(buf, pos) != FRAME_MAGIC {
        return None;
    }
    let len = u32_at(buf, pos + 4) as usize;
    if len > MAX_PAYLOAD || pos + FRAME_HEADER_LEN + len > buf.len() {
        return None;
    }
    let payload = &buf[pos + FRAME_HEADER_LEN..pos + FRAME_HEADER_LEN + len];
    if frame_crc(&buf[pos..pos + 28], payload) != u32_at(buf, pos + 28) {
        return None;
    }
    Some((
        RawRecord {
            rtype: u16_at(buf, pos + 8),
            seq: u64_at(buf, pos + 12),
            ft: u64_at(buf, pos + 20) as i64,
            payload: payload.to_vec(),
        },
        FRAME_HEADER_LEN + len,
    ))
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub records: Vec<RawRecord>,
    /// Offset just past the last valid frame. Bytes after it are a torn tail.
    pub valid_end: usize,
    pub corrupt_middle_bytes: usize,
    pub corrupt_regions: usize,
}

/// Scan a segment image, resyncing past corrupt regions.
pub fn scan(buf: &[u8]) -> ScanResult {
    let start = if buf.len() >= SEG_HEADER_LEN && &buf[..8] == SEG_MAGIC {
        SEG_HEADER_LEN
    } else {
        0
    };
    let mut r = ScanResult { valid_end: start, ..Default::default() };
    let mut pos = start;
    let mut bad_start: Option<usize> = None;
    while pos + FRAME_HEADER_LEN <= buf.len() {
        match try_frame(buf, pos) {
            Some((rec, len)) => {
                if let Some(b) = bad_start.take() {
                    r.corrupt_middle_bytes += pos - b;
                    r.corrupt_regions += 1;
                }
                r.records.push(rec);
                pos += len;
                r.valid_end = pos;
            }
            None => {
                if bad_start.is_none() {
                    bad_start = Some(pos);
                }
                // Resync: jump to the next occurrence of the frame magic.
                let magic = FRAME_MAGIC.to_le_bytes();
                match buf[pos + 1..].windows(4).position(|w| w == magic) {
                    Some(off) => pos += 1 + off,
                    None => break,
                }
            }
        }
    }
    r
}

fn segment_header(first_seq: u64) -> [u8; SEG_HEADER_LEN] {
    let mut h = [0u8; SEG_HEADER_LEN];
    h[..8].copy_from_slice(SEG_MAGIC);
    h[8..12].copy_from_slice(&SEG_VERSION.to_le_bytes());
    h[16..24].copy_from_slice(&now_ft().to_le_bytes());
    h[24..32].copy_from_slice(&first_seq.to_le_bytes());
    h
}

// ---------------------------------------------------------------- segments

#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub path: PathBuf,
    pub first_seq: u64,
    pub last_seq: Option<u64>,
    pub first_ft: Option<i64>,
    pub last_ft: Option<i64>,
    pub sealed: bool,
    pub size: u64,
}

fn parse_segment_name(path: &Path) -> Option<SegmentInfo> {
    let name = path.file_name()?.to_str()?;
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if let Some(rest) = name.strip_prefix(OPEN_PREFIX) {
        let seq = rest.strip_suffix(&format!(".{OPEN_EXT}"))?.parse().ok()?;
        return Some(SegmentInfo {
            path: path.to_path_buf(),
            first_seq: seq,
            last_seq: None,
            first_ft: None,
            last_ft: None,
            sealed: false,
            size,
        });
    }
    let stem = name.strip_suffix(&format!(".{SEALED_EXT}"))?;
    // <first:012>-<last:012>_<firstFt:019>_<lastFt:019>
    let (seqs, fts) = stem.split_once('_')?;
    let (a, b) = seqs.split_once('-')?;
    let (fa, fb) = fts.split_once('_')?;
    Some(SegmentInfo {
        path: path.to_path_buf(),
        first_seq: a.parse().ok()?,
        last_seq: Some(b.parse().ok()?),
        first_ft: Some(fa.parse().ok()?),
        last_ft: Some(fb.parse().ok()?),
        sealed: true,
        size,
    })
}

/// All segments in the journal directory, oldest first.
pub fn list_segments(dir: &Path) -> Result<Vec<SegmentInfo>> {
    let mut v = Vec::new();
    if !dir.exists() {
        return Ok(v);
    }
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        if let Some(s) = parse_segment_name(&p) {
            v.push(s);
        }
    }
    v.sort_by_key(|s| (s.first_seq, !s.sealed));
    Ok(v)
}

fn read_shared(path: &Path) -> Result<Vec<u8>> {
    // std opens with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE on
    // Windows, so this works while the service is appending.
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read and scan one segment (sealed or open).
pub fn read_segment(seg: &SegmentInfo) -> Result<ScanResult> {
    let bytes = if seg.sealed {
        let raw = read_shared(&seg.path)?;
        zstd::decode_all(&raw[..]).with_context(|| format!("decompress {}", seg.path.display()))?
    } else {
        read_shared(&seg.path)?
    };
    Ok(scan(&bytes))
}

/// Visit every record in [from, to] (inclusive, FILETIME), oldest first.
/// The visitor returns `false` to stop early.
pub fn for_each_record(
    dir: &Path,
    from: Option<i64>,
    to: Option<i64>,
    mut visit: impl FnMut(&RawRecord) -> bool,
) -> Result<()> {
    for seg in list_segments(dir)? {
        if seg.sealed {
            if let (Some(f), Some(l)) = (seg.first_ft, seg.last_ft) {
                if to.is_some_and(|t| f > t) || from.is_some_and(|s| l < s) {
                    continue;
                }
            }
        }
        let scan = match read_segment(&seg) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("skipping unreadable segment {}: {e:#}", seg.path.display());
                continue;
            }
        };
        for r in &scan.records {
            if from.is_some_and(|s| r.ft < s) || to.is_some_and(|t| r.ft > t) {
                continue;
            }
            if !visit(r) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Newest records first, optionally only those with `seq < before_seq`,
/// stopping after `max` matches of `filter`.
pub fn tail(
    dir: &Path,
    before_seq: Option<u64>,
    max: usize,
    filter: impl Fn(&RawRecord) -> bool,
) -> Result<Vec<RawRecord>> {
    let mut out = Vec::new();
    let segs = list_segments(dir)?;
    for seg in segs.iter().rev() {
        if before_seq.is_some_and(|b| seg.first_seq >= b) {
            continue;
        }
        let Ok(scan) = read_segment(seg) else { continue };
        for r in scan.records.iter().rev() {
            if before_seq.is_some_and(|b| r.seq >= b) || !filter(r) {
                continue;
            }
            out.push(r.clone());
            if out.len() >= max {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// Seal an open segment: compress the valid prefix, write it under its final
/// name via temp + flush + rename, then delete the open file.
/// Returns `None` if the segment held no records (it is deleted).
pub fn seal_segment(open_path: &Path, zstd_level: i32) -> Result<Option<PathBuf>> {
    let dir = open_path.parent().ok_or_else(|| anyhow!("segment has no parent dir"))?;
    let bytes = read_shared(open_path)?;
    let scan = scan(&bytes);
    let (Some(first), Some(last)) = (scan.records.first(), scan.records.last()) else {
        fs::remove_file(open_path).ok();
        return Ok(None);
    };
    // Record times are not strictly monotonic (event-log records carry the
    // event's own time, and the wall clock can be adjusted), so the name
    // carries the min/max time, which is what range filtering needs.
    let min_ft = scan.records.iter().map(|r| r.ft).min().unwrap();
    let max_ft = scan.records.iter().map(|r| r.ft).max().unwrap();
    let name = format!(
        "{:012}-{:012}_{:019}_{:019}.{SEALED_EXT}",
        first.seq, last.seq, min_ft, max_ft
    );
    let final_path = dir.join(&name);
    let tmp_path = dir.join(format!("{name}.tmp"));
    let compressed = zstd::encode_all(&bytes[..scan.valid_end], zstd_level)?;
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(&compressed)?;
        f.sync_all()?;
    }
    crate::runstate::durable_rename(&tmp_path, &final_path)?;
    fs::remove_file(open_path).with_context(|| format!("remove {}", open_path.display()))?;
    Ok(Some(final_path))
}

/// Delete the oldest sealed segments until the journal fits in `max_bytes`
/// and nothing is older than `min_ft`. Returns the number of bytes freed.
pub fn prune(dir: &Path, max_bytes: u64, min_ft: Option<i64>) -> Result<u64> {
    let segs = list_segments(dir)?;
    let mut total: u64 = segs.iter().map(|s| s.size).sum();
    let mut freed = 0;
    for s in segs.iter().filter(|s| s.sealed) {
        let too_old = min_ft.is_some_and(|m| s.last_ft.is_some_and(|l| l < m));
        if total <= max_bytes && !too_old {
            break;
        }
        if fs::remove_file(&s.path).is_ok() {
            total -= s.size;
            freed += s.size;
        }
    }
    Ok(freed)
}

/// Rename a problem segment out of the way (best effort) and describe it.
fn set_aside(path: &Path, error: String) -> RecoveryInfo {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let aside = path.with_file_name(format!("{name}.unreadable"));
    let renamed = fs::rename(path, &aside).is_ok();
    log::warn!("journal segment {name} set aside ({error}){}", if renamed { "" } else { "; could not rename it" });
    RecoveryInfo {
        segment: if renamed { format!("{name}.unreadable") } else { name },
        records: 0,
        truncated_tail_bytes: 0,
        corrupt_middle_bytes: 0,
        corrupt_regions: 0,
        last_seq: None,
        last_ft: None,
        error: Some(error),
    }
}

// ---------------------------------------------------------------- writer

struct Inner {
    file: File,
    path: PathBuf,
    seg_bytes: u64,
    seg_opened: Instant,
    next_seq: u64,
    dirty: bool,
    frame_buf: Vec<u8>,
    failed: Option<String>,
}

pub struct JournalWriter {
    dir: PathBuf,
    opts: JournalOptions,
    inner: Mutex<Inner>,
    sealer: Mutex<Option<Sender<PathBuf>>>,
    sealer_thread: Mutex<Option<JoinHandle<()>>>,
}

impl JournalWriter {
    /// Open the journal, recovering anything the previous run left open.
    pub fn open(dir: &Path, opts: JournalOptions) -> Result<(Self, Vec<RecoveryInfo>)> {
        fs::create_dir_all(dir)?;

        // 1. Leftover temp files are from an interrupted seal; the open
        //    segment they came from still exists, so just drop them.
        for e in fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "tmp") {
                fs::remove_file(&p).ok();
            }
        }

        // 2. Recover open segments.
        let segs = list_segments(dir)?;
        let mut max_seq: u64 = segs.iter().filter_map(|s| s.last_seq).max().unwrap_or(0);
        let mut recovered = Vec::new();
        for s in segs.iter().filter(|s| !s.sealed) {
            // Crash between rename and delete during sealing: the sealed copy
            // is complete, so the open file is redundant.
            if segs.iter().any(|o| o.sealed && o.first_seq == s.first_seq) {
                fs::remove_file(&s.path).ok();
                continue;
            }
            // A segment we cannot read or seal must not stop recording: set it
            // aside, note it, and move on. (Seen in the field: a segment whose
            // permissions were broken by an earlier installer.)
            let bytes = match read_shared(&s.path) {
                Ok(b) => b,
                Err(e) => {
                    recovered.push(set_aside(&s.path, format!("{e:#}")));
                    max_seq = max_seq.max(s.first_seq + UNREADABLE_SEQ_GAP);
                    continue;
                }
            };
            let scan = scan(&bytes);
            let info = RecoveryInfo {
                segment: s.path.file_name().unwrap().to_string_lossy().into_owned(),
                records: scan.records.len(),
                truncated_tail_bytes: bytes.len() - scan.valid_end,
                corrupt_middle_bytes: scan.corrupt_middle_bytes,
                corrupt_regions: scan.corrupt_regions,
                last_seq: scan.records.last().map(|r| r.seq),
                last_ft: scan.records.last().map(|r| r.ft),
                error: None,
            };
            if let Some(l) = info.last_seq {
                max_seq = max_seq.max(l);
            }
            match seal_segment(&s.path, opts.zstd_level) {
                Ok(_) => recovered.push(info),
                Err(e) => {
                    let mut aside = set_aside(&s.path, format!("sealing failed: {e:#}"));
                    aside.records = info.records;
                    aside.last_seq = info.last_seq;
                    aside.last_ft = info.last_ft;
                    recovered.push(aside);
                    max_seq = max_seq.max(s.first_seq + UNREADABLE_SEQ_GAP);
                }
            }
        }

        // 3. Start a fresh segment.
        let next_seq = max_seq + 1;
        let (file, path) = Self::create_segment(dir, next_seq)?;
        let w = Self {
            dir: dir.to_path_buf(),
            opts,
            inner: Mutex::new(Inner {
                file,
                path,
                seg_bytes: SEG_HEADER_LEN as u64,
                seg_opened: Instant::now(),
                next_seq,
                dirty: false,
                frame_buf: Vec::with_capacity(4096),
                failed: None,
            }),
            sealer: Mutex::new(None),
            sealer_thread: Mutex::new(None),
        };
        w.start_sealer();
        Ok((w, recovered))
    }

    fn create_segment(dir: &Path, first_seq: u64) -> Result<(File, PathBuf)> {
        let path = dir.join(format!("{OPEN_PREFIX}{first_seq:012}.{OPEN_EXT}"));
        let mut f = OpenOptions::new().create_new(true).write(true).open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(&segment_header(first_seq))?;
        f.sync_all()?;
        Ok((f, path))
    }

    fn start_sealer(&self) {
        let (tx, rx) = channel::<PathBuf>();
        let level = self.opts.zstd_level;
        let h = std::thread::Builder::new()
            .name("journal-sealer".into())
            .spawn(move || {
                for p in rx {
                    if let Err(e) = seal_segment(&p, level) {
                        log::error!("sealing {} failed: {e:#}", p.display());
                    }
                }
            })
            .expect("spawn sealer");
        *self.sealer.lock().unwrap() = Some(tx);
        *self.sealer_thread.lock().unwrap() = Some(h);
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The sequence number the next record will get.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().unwrap().next_seq
    }

    /// Append a record. `critical` records are flushed to stable storage
    /// before this returns. Returns the record's sequence number.
    pub fn append<T: Serialize>(&self, rtype: RecordType, payload: &T, critical: bool) -> Result<u64> {
        let json = serde_json::to_vec(payload)?;
        self.append_raw(rtype as u16, now_ft(), &json, critical)
    }

    pub fn append_raw(&self, rtype: u16, ft: i64, payload: &[u8], critical: bool) -> Result<u64> {
        if payload.len() > MAX_PAYLOAD {
            return Err(anyhow!("payload of {} bytes exceeds the 1 MiB limit", payload.len()));
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(f) = &g.failed {
            return Err(anyhow!("journal is in a failed state: {f}"));
        }
        if g.seg_bytes >= self.opts.max_segment_bytes || g.seg_opened.elapsed() >= self.opts.max_segment_age {
            self.roll_locked(&mut g)?;
        }
        let seq = g.next_seq;
        let mut buf = std::mem::take(&mut g.frame_buf);
        buf.clear();
        encode_frame(&mut buf, rtype, seq, ft, payload);
        let res = g.file.write_all(&buf);
        g.frame_buf = buf;
        if let Err(e) = res {
            // A partial write leaves a torn frame; recovery handles it. Roll
            // to a fresh segment so later records aren't written after it.
            log::error!("journal write failed: {e}");
            if let Err(e2) = self.roll_locked(&mut g) {
                g.failed = Some(format!("{e}; roll failed: {e2}"));
            }
            return Err(e.into());
        }
        g.seg_bytes += g.frame_buf.len() as u64;
        g.next_seq += 1;
        g.dirty = true;
        if critical {
            g.file.sync_data()?;
            g.dirty = false;
        }
        Ok(seq)
    }

    /// Flush everything appended so far to stable storage.
    pub fn commit(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.dirty {
            g.file.sync_data()?;
            g.dirty = false;
        }
        Ok(())
    }

    fn roll_locked(&self, g: &mut Inner) -> Result<()> {
        if g.seg_bytes == SEG_HEADER_LEN as u64 {
            // Nothing written yet: keep using this segment (a new one would
            // collide with its name, which is keyed on the next sequence).
            g.seg_opened = Instant::now();
            return Ok(());
        }
        g.file.sync_data().ok();
        let (file, path) = Self::create_segment(&self.dir, g.next_seq)?;
        let old = std::mem::replace(&mut g.path, path);
        g.file = file; // drops (closes) the previous handle
        g.seg_bytes = SEG_HEADER_LEN as u64;
        g.seg_opened = Instant::now();
        g.dirty = false;
        if let Some(tx) = self.sealer.lock().unwrap().as_ref() {
            tx.send(old).ok();
        }
        Ok(())
    }

    /// Force a segment roll (used before exporting a range).
    pub fn roll(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        self.roll_locked(&mut g)
    }

    /// Commit, stop the sealer and leave the current segment open on disk.
    /// It is sealed by recovery at the next start; that's intentional, so a
    /// clean stop and a crash take the same, well-tested path.
    pub fn close(&self) -> Result<()> {
        self.commit()?;
        self.sealer.lock().unwrap().take();
        if let Some(h) = self.sealer_thread.lock().unwrap().take() {
            h.join().ok();
        }
        Ok(())
    }
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
