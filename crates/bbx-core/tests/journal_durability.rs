//! Durability tests for the journal: simulate the ways a machine can die
//! mid-write and check that recovery keeps every complete record, drops only
//! the torn part, and never reuses a sequence number.

use bbx_core::journal::{self, JournalOptions, JournalWriter};
use bbx_core::records::{Note, RecordType};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

fn note(i: usize) -> Note {
    Note { text: format!("record {i} {}", "x".repeat(i % 37)), user: "t".into(), source: "test".into() }
}

fn write_n(dir: &Path, n: usize, opts: JournalOptions) -> u64 {
    let (w, _) = JournalWriter::open(dir, opts).unwrap();
    let mut last = 0;
    for i in 0..n {
        last = w.append(RecordType::Note, &note(i), false).unwrap();
    }
    w.commit().unwrap();
    last
}

fn all_seqs(dir: &Path) -> Vec<u64> {
    let mut v = Vec::new();
    journal::for_each_record(dir, None, None, |r| {
        v.push(r.seq);
        true
    })
    .unwrap();
    v
}

fn open_segment(dir: &Path) -> std::path::PathBuf {
    journal::list_segments(dir).unwrap().into_iter().find(|s| !s.sealed).unwrap().path
}

#[test]
fn clean_reopen_seals_and_continues_sequence() {
    let d = tempfile::tempdir().unwrap();
    let last = write_n(d.path(), 100, JournalOptions::default());
    assert_eq!(last, 100);

    let (w, rec) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].records, 100);
    assert_eq!(rec[0].truncated_tail_bytes, 0);
    assert_eq!(w.next_seq(), 101);
    drop(w);

    let segs = journal::list_segments(d.path()).unwrap();
    assert!(segs.iter().any(|s| s.sealed && s.first_seq == 1 && s.last_seq == Some(100)));
    assert_eq!(all_seqs(d.path()), (1..=100).collect::<Vec<_>>());
}

#[test]
fn torn_tail_is_truncated() {
    let d = tempfile::tempdir().unwrap();
    write_n(d.path(), 50, JournalOptions::default());

    // Power cut in the middle of writing record 51: only part of its frame landed.
    let mut frame = Vec::new();
    journal::encode_frame(&mut frame, RecordType::Note as u16, 51, 0, b"{\"text\":\"lost\"}");
    let seg = open_segment(d.path());
    OpenOptions::new().append(true).open(&seg).unwrap().write_all(&frame[..20]).unwrap();

    let (w, rec) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    assert_eq!(rec[0].records, 50);
    assert_eq!(rec[0].truncated_tail_bytes, 20);
    assert_eq!(rec[0].last_seq, Some(50));
    assert_eq!(w.next_seq(), 51);
}

#[test]
fn corruption_in_the_middle_is_skipped_not_fatal() {
    let d = tempfile::tempdir().unwrap();
    write_n(d.path(), 30, JournalOptions::default());
    let seg = open_segment(d.path());
    let mut bytes = fs::read(&seg).unwrap();
    // Find the 10th frame and damage its payload (bad sector / bit rot).
    let scan = journal::scan(&bytes);
    assert_eq!(scan.records.len(), 30);
    let mut pos = journal::SEG_HEADER_LEN;
    for r in &scan.records[..9] {
        pos += journal::FRAME_HEADER_LEN + r.payload.len();
    }
    bytes[pos + journal::FRAME_HEADER_LEN + 3] ^= 0xFF;
    fs::write(&seg, &bytes).unwrap();

    let (w, rec) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    assert_eq!(rec[0].records, 29);
    assert_eq!(rec[0].corrupt_regions, 1);
    assert_eq!(rec[0].last_seq, Some(30));
    assert_eq!(w.next_seq(), 31);
    drop(w);
    let seqs = all_seqs(d.path());
    assert!(!seqs.contains(&10));
    assert!(seqs.contains(&11) && seqs.contains(&30));
}

#[test]
fn power_cut_at_every_kind_of_offset() {
    let d = tempfile::tempdir().unwrap();
    write_n(d.path(), 40, JournalOptions::default());
    let seg = open_segment(d.path());
    let full = fs::read(&seg).unwrap();
    let scan = journal::scan(&full);
    // Frame end offsets, to know how many records should survive each cut.
    let mut ends = Vec::new();
    let mut pos = journal::SEG_HEADER_LEN;
    for r in &scan.records {
        pos += journal::FRAME_HEADER_LEN + r.payload.len();
        ends.push(pos);
    }

    let cuts: Vec<usize> = (0..full.len()).step_by(97).chain([full.len()]).collect();
    for cut in cuts {
        let d2 = tempfile::tempdir().unwrap();
        fs::write(d2.path().join(seg.file_name().unwrap()), &full[..cut]).unwrap();
        let (w, rec) = JournalWriter::open(d2.path(), JournalOptions::default()).unwrap();
        let expected = ends.iter().filter(|&&e| e <= cut).count();
        let got = rec.first().map(|r| r.records).unwrap_or(0);
        assert_eq!(got, expected, "cut at {cut}");
        assert_eq!(w.next_seq(), expected as u64 + 1, "cut at {cut}");
    }
}

#[test]
fn rolls_and_seals_segments_and_filters_by_time() {
    let d = tempfile::tempdir().unwrap();
    let opts = JournalOptions { max_segment_bytes: 4096, ..Default::default() };
    {
        let (w, _) = JournalWriter::open(d.path(), opts.clone()).unwrap();
        for i in 0..400 {
            w.append(RecordType::Note, &note(i), false).unwrap();
        }
        w.commit().unwrap();
        // Give the background sealer a moment.
        std::thread::sleep(Duration::from_millis(300));
    }
    let segs = journal::list_segments(d.path()).unwrap();
    assert!(segs.iter().filter(|s| s.sealed).count() >= 5, "expected several sealed segments");
    assert_eq!(all_seqs(d.path()), (1..=400).collect::<Vec<_>>());

    let t = journal::tail(d.path(), None, 5, |r| r.rtype == RecordType::Note as u16).unwrap();
    assert_eq!(t.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![400, 399, 398, 397, 396]);

    let t = journal::tail(d.path(), Some(100), 1, |_| true).unwrap();
    assert_eq!(t[0].seq, 99);
}

#[test]
fn crash_between_seal_rename_and_delete() {
    let d = tempfile::tempdir().unwrap();
    write_n(d.path(), 10, JournalOptions::default());
    let seg = open_segment(d.path());
    let copy = d.path().join("keep.bin");
    fs::copy(&seg, &copy).unwrap();
    journal::seal_segment(&seg, 3).unwrap();
    // Simulate: sealed file exists AND the open file was never deleted.
    fs::rename(&copy, &seg).unwrap();
    // Plus a stray temp file from another interrupted seal.
    fs::write(d.path().join("000000000001-000000000010_1_2.bbjz.tmp"), b"junk").unwrap();

    let (w, rec) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    assert!(rec.is_empty(), "duplicate open segment should be dropped, not re-sealed");
    assert_eq!(w.next_seq(), 11);
    drop(w);
    assert_eq!(all_seqs(d.path()), (1..=10).collect::<Vec<_>>());
}

#[test]
fn reader_sees_committed_records_while_writer_is_open() {
    let d = tempfile::tempdir().unwrap();
    let (w, _) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    for i in 0..20 {
        w.append(RecordType::Note, &note(i), false).unwrap();
    }
    w.commit().unwrap();
    assert_eq!(all_seqs(d.path()).len(), 20);
}

#[test]
fn prune_respects_budget() {
    let d = tempfile::tempdir().unwrap();
    let opts = JournalOptions { max_segment_bytes: 2048, ..Default::default() };
    {
        let (w, _) = JournalWriter::open(d.path(), opts).unwrap();
        for i in 0..300 {
            w.append(RecordType::Note, &note(i), false).unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let before: u64 = journal::list_segments(d.path()).unwrap().iter().map(|s| s.size).sum();
    let freed = journal::prune(d.path(), before / 2, None).unwrap();
    assert!(freed > 0);
    let after: u64 = journal::list_segments(d.path()).unwrap().iter().map(|s| s.size).sum();
    assert!(after <= before / 2 + 4096);
    // Oldest records went first.
    let seqs = all_seqs(d.path());
    assert!(seqs[0] > 1 && *seqs.last().unwrap() == 300);
}

#[test]
fn unreadable_segment_is_set_aside_and_recording_continues() {
    let d = tempfile::tempdir().unwrap();
    write_n(d.path(), 5, JournalOptions::default());
    // Recover the 5 records, then leave a segment that can't be opened.
    drop(JournalWriter::open(d.path(), JournalOptions::default()).unwrap());
    std::fs::create_dir(d.path().join("open-000000000009.bbj")).unwrap();

    let (w, rec) = JournalWriter::open(d.path(), JournalOptions::default()).unwrap();
    let bad = rec.iter().find(|r| r.error.is_some()).expect("problem segment reported");
    assert!(bad.segment.starts_with("open-000000000009.bbj"));
    assert!(w.next_seq() > 9 + journal::UNREADABLE_SEQ_GAP - 1, "sequence jumps past the unreadable segment");
    w.append(RecordType::Note, &note(1), true).unwrap();
    drop(w);
    let seqs = all_seqs(d.path());
    assert_eq!(&seqs[..5], &[1, 2, 3, 4, 5]);
    assert!(*seqs.last().unwrap() > journal::UNREADABLE_SEQ_GAP);
}
