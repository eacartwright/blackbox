//! FILETIME helpers. All timestamps on disk are Windows FILETIME values
//! (100 ns ticks since 1601-01-01 UTC) stored as i64.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

/// FILETIME of the Unix epoch.
pub const FT_UNIX_EPOCH: i64 = 116_444_736_000_000_000;
pub const FT_PER_SEC: i64 = 10_000_000;
pub const FT_PER_MS: i64 = 10_000;

pub fn now_ft() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    FT_UNIX_EPOCH + (d.as_nanos() / 100) as i64
}

pub fn ft_to_utc(ft: i64) -> DateTime<Utc> {
    let unix = ft - FT_UNIX_EPOCH;
    let secs = unix.div_euclid(FT_PER_SEC);
    let nanos = (unix.rem_euclid(FT_PER_SEC) * 100) as u32;
    DateTime::from_timestamp(secs, nanos).unwrap_or_default()
}

pub fn utc_to_ft(dt: DateTime<Utc>) -> i64 {
    FT_UNIX_EPOCH + dt.timestamp() * FT_PER_SEC + (dt.timestamp_subsec_nanos() / 100) as i64
}

/// `2026-11-19 16:30:01.123 -05:00` in the local time zone.
pub fn fmt_local(ft: i64) -> String {
    ft_to_utc(ft)
        .with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S%.3f %:z")
        .to_string()
}

/// RFC 3339 UTC, millisecond precision.
pub fn fmt_utc(ft: i64) -> String {
    ft_to_utc(ft).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Seconds between two FILETIMEs (b - a).
pub fn secs_between(a: i64, b: i64) -> f64 {
    (b - a) as f64 / FT_PER_SEC as f64
}

/// Parse a time the way a technician types it:
///
/// * RFC 3339: `2026-11-19T16:30:00-05:00`
/// * local date + time: `2026-11-19 16:30`, `2026-11-19 16:30:05`
/// * local time today: `16:30`, `4:30pm`
/// * relative to now: `-15m`, `-2h`, `-1d`, `-90s`
pub fn parse_user_time(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Some(rel) = s.strip_prefix('-') {
        let (num, unit) = rel.split_at(rel.find(|c: char| !c.is_ascii_digit()).unwrap_or(rel.len()));
        let n: i64 = num.parse().map_err(|_| anyhow!("bad relative time '{s}'"))?;
        let secs = match unit {
            "s" | "" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86400,
            _ => return Err(anyhow!("bad relative unit in '{s}' (use s, m, h, d)")),
        };
        return Ok(now_ft() - secs * FT_PER_SEC);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(utc_to_ft(dt.with_timezone(&Utc)));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return local_to_ft(ndt);
        }
    }
    let lower = s.to_ascii_lowercase();
    for fmt in ["%H:%M:%S", "%H:%M", "%I:%M%P", "%I:%M:%S%P", "%I:%M %P", "%I%P"] {
        if let Ok(t) = NaiveTime::parse_from_str(&lower, fmt) {
            let today: NaiveDate = Local::now().date_naive();
            return local_to_ft(today.and_time(t));
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return local_to_ft(d.and_hms_opt(0, 0, 0).unwrap());
    }
    Err(anyhow!("could not parse time '{s}'"))
}

fn local_to_ft(ndt: NaiveDateTime) -> Result<i64> {
    let local = Local
        .from_local_datetime(&ndt)
        .earliest()
        .ok_or_else(|| anyhow!("time {ndt} does not exist in the local time zone"))?;
    Ok(utc_to_ft(local.with_timezone(&Utc)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let ft = now_ft();
        let back = utc_to_ft(ft_to_utc(ft));
        assert_eq!(ft, back);
    }

    #[test]
    fn relative() {
        let t = parse_user_time("-15m").unwrap();
        let d = secs_between(t, now_ft());
        assert!((899.0..=901.0).contains(&d));
    }

    #[test]
    fn clock_formats() {
        assert!(parse_user_time("16:30").is_ok());
        assert!(parse_user_time("4:30pm").is_ok());
        assert!(parse_user_time("2026-11-19 16:30:05").is_ok());
        assert!(parse_user_time("2026-11-19T16:30:00-05:00").is_ok());
    }
}
