//! Rollups: high-rate ETW activity aggregated into one record per category
//! per window (10 s by default), keeping the top rows by weight plus any
//! rows that must never be dropped (deletes, renames, failures).

use bbx_core::records::{DiskIoRow, DnsRow, FileRow, NetRow, RegRow};
use std::collections::HashMap;
use std::hash::Hash;

pub trait Weighted {
    /// Sort key: bigger = more interesting.
    fn weight(&self) -> u64;
    /// Rows that are kept even beyond the cap.
    fn must_keep(&self) -> bool {
        false
    }
}

impl Weighted for NetRow {
    fn weight(&self) -> u64 {
        self.sent + self.recv + 4096 * (self.connects + self.retrans) as u64
    }
    fn must_keep(&self) -> bool {
        self.fails > 0 || self.retrans >= 10
    }
}
impl Weighted for DnsRow {
    fn weight(&self) -> u64 {
        self.count as u64
    }
    fn must_keep(&self) -> bool {
        self.status != 0
    }
}
impl Weighted for DiskIoRow {
    fn weight(&self) -> u64 {
        // Slow I/O matters as much as big I/O.
        self.read_bytes + self.write_bytes + (self.max_ms as u64) * 1_000_000
    }
    fn must_keep(&self) -> bool {
        self.max_ms >= 500.0
    }
}
impl Weighted for FileRow {
    fn weight(&self) -> u64 {
        self.write_bytes + 4096 * (self.writes + self.creates) as u64
    }
    fn must_keep(&self) -> bool {
        self.deletes > 0 || self.renames > 0
    }
}
impl Weighted for RegRow {
    fn weight(&self) -> u64 {
        (self.sets + self.creates + self.deletes) as u64
    }
    fn must_keep(&self) -> bool {
        self.deletes > 0 || self.creates > 0
    }
}

pub struct Rollup<K, R> {
    rows: HashMap<K, R>,
    cap: usize,
    keep_cap: usize,
    /// Distinct keys seen this window beyond `max_keys` (memory guard).
    pub overflow: u32,
    max_keys: usize,
}

impl<K: Hash + Eq, R: Weighted + Default> Rollup<K, R> {
    pub fn new(cap: usize, keep_cap: usize) -> Self {
        Self { rows: HashMap::new(), cap, keep_cap, overflow: 0, max_keys: 50_000 }
    }

    /// Get (or create) the row for `key`, initialised by `init`.
    pub fn row(&mut self, key: K, init: impl FnOnce() -> R) -> Option<&mut R> {
        if !self.rows.contains_key(&key) && self.rows.len() >= self.max_keys {
            self.overflow += 1;
            return None;
        }
        Some(self.rows.entry(key).or_insert_with(init))
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Take this window's rows: the top `cap` by weight plus up to
    /// `keep_cap` must-keep rows. Returns (rows, dropped_count).
    pub fn take(&mut self) -> (Vec<R>, u32) {
        let mut all: Vec<R> = self.rows.drain().map(|(_, r)| r).collect();
        all.sort_by_key(|r| std::cmp::Reverse(r.weight()));
        let total = all.len();
        let mut out = Vec::new();
        let mut kept_extra = 0;
        for (i, r) in all.into_iter().enumerate() {
            if i < self.cap {
                out.push(r);
            } else if r.must_keep() && kept_extra < self.keep_cap {
                kept_extra += 1;
                out.push(r);
            }
        }
        let dropped = (total - out.len()) as u32 + std::mem::take(&mut self.overflow);
        (out, dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_top_and_must_keep() {
        let mut r: Rollup<String, FileRow> = Rollup::new(2, 10);
        for i in 0..10u64 {
            let row = r.row(format!("f{i}"), FileRow::default).unwrap();
            row.path = format!("f{i}");
            row.write_bytes = i * 1000;
            row.writes = 1;
        }
        r.row("deleted".into(), FileRow::default).unwrap().deletes = 1;
        let (rows, dropped) = r.take();
        let names: Vec<_> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(&names[..2], &["f9", "f8"]);
        assert!(rows.iter().any(|r| r.deletes == 1));
        assert_eq!(rows.len(), 3);
        assert_eq!(dropped, 8);
        assert!(r.is_empty());
    }

    #[test]
    fn slow_disk_io_outranks_bulk() {
        let mut r: Rollup<u32, DiskIoRow> = Rollup::new(1, 0);
        r.row(1, DiskIoRow::default).unwrap().read_bytes = 50_000_000;
        r.row(2, DiskIoRow::default).unwrap().max_ms = 900.0;
        let (rows, _) = r.take();
        assert_eq!(rows[0].max_ms, 900.0);
    }
}
