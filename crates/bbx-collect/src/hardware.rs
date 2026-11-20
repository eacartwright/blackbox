//! Hardware health without drivers or WMI:
//!
//! * Disks, via storage ioctls on \\.\PhysicalDriveN:
//!   - model, bus and serial (StorageDeviceProperty);
//!   - temperature with the drive's own warning/critical thresholds
//!     (StorageDeviceTemperatureProperty, NVMe and SATA);
//!   - NVMe SMART/health log page 02h: critical warning, spare, wear, media
//!     errors, power-on hours and the drive's own **unsafe shutdown** count;
//!   - ATA SMART attributes via IOCTL_STORAGE_PREDICT_FAILURE: reallocated /
//!     pending / uncorrectable sectors, cable CRC errors, power-loss counters.
//! * Power: AC/battery state and battery level (GetSystemPowerStatus).

use crate::util::{below_normal_priority, wide};
use crate::Ctx;
use anyhow::Result;
use bbx_core::journal;
use bbx_core::records::{AtaAttr, DiskHealth, DiskHealthRow, NvmeHealth, Power, RecordType};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_STORAGE_PREDICT_FAILURE: u32 = 0x002D_1100;
const STORAGE_DEVICE_PROPERTY: u32 = 0;
const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: u32 = 50;
const STORAGE_DEVICE_TEMPERATURE_PROPERTY: u32 = 52;
const PROPERTY_STANDARD_QUERY: u32 = 0;
const PROTOCOL_TYPE_NVME: u32 = 3;
const NVME_DATA_TYPE_LOG_PAGE: u32 = 2;
const NVME_LOG_PAGE_HEALTH_INFO: u32 = 2;
const BUS_NVME: u32 = 17;

struct Disk(HANDLE);
impl Drop for Disk {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn open_disk(n: u32) -> Option<Disk> {
    let path = wide(&format!(r"\\.\PhysicalDrive{n}"));
    for access in [GENERIC_READ | GENERIC_WRITE, 0] {
        let h = unsafe {
            CreateFileW(path.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut())
        };
        if h != INVALID_HANDLE_VALUE && !h.is_null() {
            return Some(Disk(h));
        }
    }
    None
}

fn ioctl(d: &Disk, code: u32, input: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let mut got = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            d.0,
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            out.as_mut_ptr().cast(),
            out.len() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    out.truncate(got as usize);
    Some(out)
}

fn query(prop: u32) -> Vec<u8> {
    let mut q = Vec::with_capacity(12);
    q.extend_from_slice(&prop.to_le_bytes());
    q.extend_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
    q.extend_from_slice(&[0u8; 4]); // AdditionalParameters[1] + padding
    q
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}
fn i16_at(b: &[u8], o: usize) -> i16 {
    u16_at(b, o) as i16
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
/// Little-endian unsigned of up to 16 bytes, saturated to u64.
fn le_u64(b: &[u8], o: usize, n: usize) -> u64 {
    let Some(s) = b.get(o..o + n) else { return 0 };
    if s[8.min(n)..].iter().any(|&x| x != 0) {
        return u64::MAX;
    }
    let mut a = [0u8; 8];
    a[..n.min(8)].copy_from_slice(&s[..n.min(8)]);
    u64::from_le_bytes(a)
}

fn cstr_at(b: &[u8], off: u32) -> String {
    if off == 0 || off as usize >= b.len() {
        return String::new();
    }
    let s = &b[off as usize..];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

fn bus_name(t: u32) -> &'static str {
    match t {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 | 15 => "Virtual",
        16 => "Spaces",
        17 => "NVMe",
        18 => "SCM",
        19 => "UFS",
        _ => "Other",
    }
}

const ATA_IDS: &[(u8, &str)] = &[
    (5, "Reallocated_Sector_Ct"),
    (9, "Power_On_Hours"),
    (12, "Power_Cycle_Count"),
    (174, "Unexpected_Power_Loss"),
    (187, "Reported_Uncorrect"),
    (188, "Command_Timeout"),
    (192, "Power_Off_Retract_Count"),
    (194, "Temperature_Celsius"),
    (196, "Reallocated_Event_Count"),
    (197, "Current_Pending_Sector"),
    (198, "Offline_Uncorrectable"),
    (199, "UDMA_CRC_Error_Count"),
];

/// Parse the 512-byte ATA SMART READ DATA block.
pub fn parse_ata_smart(v: &[u8]) -> Vec<AtaAttr> {
    let mut out = Vec::new();
    for i in 0..30 {
        let o = 2 + i * 12;
        if o + 12 > v.len() {
            break;
        }
        let id = v[o];
        let Some((_, name)) = ATA_IDS.iter().find(|(x, _)| *x == id) else { continue };
        let mut raw = le_u64(v, o + 5, 6);
        if id == 194 || id == 9 {
            raw &= if id == 194 { 0xFF } else { 0xFFFF_FFFF };
        }
        out.push(AtaAttr { id, name: (*name).into(), value: v[o + 3], worst: v[o + 4], raw });
    }
    out
}

/// Parse the 512-byte NVMe SMART / Health Information log (page 02h).
pub fn parse_nvme_health(b: &[u8]) -> Option<NvmeHealth> {
    if b.len() < 200 {
        return None;
    }
    // Data units are thousands of 512-byte units.
    let units_to_gb = |u: u64| u.saturating_mul(512_000) / 1_000_000_000;
    Some(NvmeHealth {
        critical_warning: b[0],
        temp_c: (u16_at(b, 1) as i32 - 273) as i16,
        spare_pct: b[3],
        spare_threshold_pct: b[4],
        used_pct: b[5],
        read_gb: units_to_gb(le_u64(b, 32, 16)),
        written_gb: units_to_gb(le_u64(b, 48, 16)),
        power_cycles: le_u64(b, 112, 16),
        power_on_hours: le_u64(b, 128, 16),
        unsafe_shutdowns: le_u64(b, 144, 16),
        media_errors: le_u64(b, 160, 16),
        error_log_entries: le_u64(b, 176, 16),
        warning_temp_minutes: u32_at(b, 192),
        critical_temp_minutes: u32_at(b, 196),
    })
}

fn nvme_health(d: &Disk) -> Option<NvmeHealth> {
    // STORAGE_PROPERTY_QUERY header (8) + STORAGE_PROTOCOL_SPECIFIC_DATA (40) + 512 data
    let mut q = vec![0u8; 8 + 40 + 512];
    q[0..4].copy_from_slice(&STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY.to_le_bytes());
    q[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
    let p = 8;
    q[p..p + 4].copy_from_slice(&PROTOCOL_TYPE_NVME.to_le_bytes());
    q[p + 4..p + 8].copy_from_slice(&NVME_DATA_TYPE_LOG_PAGE.to_le_bytes());
    q[p + 8..p + 12].copy_from_slice(&NVME_LOG_PAGE_HEALTH_INFO.to_le_bytes());
    q[p + 16..p + 20].copy_from_slice(&40u32.to_le_bytes()); // ProtocolDataOffset
    q[p + 20..p + 24].copy_from_slice(&512u32.to_le_bytes()); // ProtocolDataLength
    let out = ioctl(d, IOCTL_STORAGE_QUERY_PROPERTY, &q, q.len())?;
    // STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size, then the 40-byte
    // protocol data whose ProtocolDataOffset is relative to itself.
    let off = u32_at(&out, 8 + 16) as usize;
    let len = u32_at(&out, 8 + 20) as usize;
    let start = 8 + off;
    parse_nvme_health(out.get(start..start + len.min(512))?)
}

fn temperature(d: &Disk) -> (Option<i16>, Option<i16>, Option<i16>) {
    let Some(b) = ioctl(d, IOCTL_STORAGE_QUERY_PROPERTY, &query(STORAGE_DEVICE_TEMPERATURE_PROPERTY), 512) else {
        return (None, None, None);
    };
    if b.len() < 24 {
        return (None, None, None);
    }
    let crit = i16_at(&b, 8);
    let warn = i16_at(&b, 10);
    let count = u16_at(&b, 12) as usize;
    // STORAGE_TEMPERATURE_INFO[0].Temperature (index 0 = composite)
    let temp = (count > 0 && b.len() >= 24 + 16).then(|| i16_at(&b, 24 + 2));
    let nz = |v: i16| (v != 0).then_some(v);
    (temp, nz(warn), nz(crit))
}

fn predict_failure(d: &Disk) -> Option<(bool, Vec<u8>)> {
    let b = ioctl(d, IOCTL_STORAGE_PREDICT_FAILURE, &[], 4 + 512)?;
    (b.len() >= 4 + 512).then(|| (u32_at(&b, 0) != 0, b[4..4 + 512].to_vec()))
}

pub fn read_disk(n: u32) -> Option<DiskHealthRow> {
    let d = open_disk(n)?;
    let desc = ioctl(&d, IOCTL_STORAGE_QUERY_PROPERTY, &query(STORAGE_DEVICE_PROPERTY), 1024)?;
    let bus = u32_at(&desc, 28);
    let vendor = cstr_at(&desc, u32_at(&desc, 12));
    let product = cstr_at(&desc, u32_at(&desc, 16));
    let model = format!("{vendor} {product}").trim().to_string();
    let serial = cstr_at(&desc, u32_at(&desc, 24));
    let (temp_c, warn_c, crit_c) = temperature(&d);
    let mut row = DiskHealthRow {
        disk: n,
        model,
        serial,
        bus: bus_name(bus).into(),
        temp_c,
        warn_c,
        crit_c,
        ..Default::default()
    };
    if bus == BUS_NVME {
        row.nvme = nvme_health(&d);
    } else if let Some((fail, vendor_data)) = predict_failure(&d) {
        row.predict_failure = Some(fail);
        let attrs = parse_ata_smart(&vendor_data);
        if !attrs.is_empty() {
            row.ata = attrs;
        }
    }
    if row.temp_c.is_none() {
        row.temp_c = row.nvme.as_ref().map(|h| h.temp_c).or_else(|| row.ata.iter().find(|a| a.id == 194).map(|a| a.raw as i16));
    }
    Some(row)
}

pub fn read_all_disks() -> Vec<DiskHealthRow> {
    (0..32).filter_map(read_disk).collect()
}

pub fn power_status() -> Option<Power> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut s: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { GetSystemPowerStatus(&mut s) } == 0 {
        return None;
    }
    let has_battery = s.BatteryFlag != 128 && s.BatteryFlag != 255;
    Some(Power {
        ac: match s.ACLineStatus {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
        battery: has_battery,
        battery_pct: (has_battery && s.BatteryLifePercent <= 100).then_some(s.BatteryLifePercent),
        charging: has_battery && s.BatteryFlag & 8 != 0,
        critical: has_battery && s.BatteryFlag & 4 != 0,
        saver: s.SystemStatusFlag != 0,
    })
}

/// Unsafe-shutdown counters per disk serial, for the previous run's last
/// DiskHealth record vs. now.
fn unsafe_count(r: &DiskHealthRow) -> Option<u64> {
    r.nvme
        .as_ref()
        .map(|h| h.unsafe_shutdowns)
        .or_else(|| r.ata.iter().find(|a| a.id == 174 || a.id == 192).map(|a| a.raw))
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let every = Duration::from_secs(ctx.cfg.disk_health_minutes.max(5) * 60);
    let first_seq = ctx.journal.next_seq();
    let previous: Option<DiskHealth> = journal::tail(&ctx.paths.journal(), Some(first_seq), 1, |r| r.rtype == RecordType::DiskHealth as u16)
        .ok()
        .and_then(|v| v.first().and_then(|r| r.parse()));
    let mut det = crate::detect::DiskHealthDetector::default();
    let mut last_disk = Instant::now() - every;
    let mut last_power: Option<Power> = None;
    let mut first = true;
    loop {
        if last_disk.elapsed() >= every {
            last_disk = Instant::now();
            let disks = read_all_disks();
            if first {
                // Did any drive record an unsafe shutdown since the last run?
                if let Some(prev) = &previous {
                    for d in &disks {
                        let Some(p) = prev.disks.iter().find(|p| !d.serial.is_empty() && p.serial == d.serial) else { continue };
                        if let (Some(a), Some(b)) = (unsafe_count(p), unsafe_count(d)) {
                            if b > a {
                                ctx.status(
                                    "hardware",
                                    "warn",
                                    format!("disk {} ({}) recorded {} unsafe shutdown(s) since BlackBox last ran: power was lost without a clean flush", d.disk, d.model, b - a),
                                );
                            }
                        }
                    }
                }
            }
            for (kind, reason) in det.on_sample(&disks) {
                ctx.request_incident(kind, reason, bbx_core::time::now_ft());
            }
            ctx.emit(RecordType::DiskHealth, &DiskHealth { disks });
        }
        if let Some(p) = power_status() {
            let changed = last_power.as_ref().is_none_or(|l| {
                l.ac != p.ac || l.charging != p.charging || l.critical != p.critical || l.saver != p.saver || l.battery_pct.unwrap_or(0).abs_diff(p.battery_pct.unwrap_or(0)) >= 5
            });
            if changed {
                if p.critical && !last_power.as_ref().is_some_and(|l| l.critical) {
                    ctx.request_incident("battery_critical", format!("battery critically low ({}%), machine may shut off", p.battery_pct.unwrap_or(0)), bbx_core::time::now_ft());
                }
                ctx.emit(RecordType::Power, &p);
                last_power = Some(p);
            }
        }
        first = false;
        if ctx.stop.wait(Duration::from_secs(30)) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_log_parse() {
        let mut b = vec![0u8; 512];
        b[0] = 0x04; // reliability degraded
        b[1..3].copy_from_slice(&(273u16 + 45).to_le_bytes());
        b[3] = 100;
        b[4] = 10;
        b[5] = 7;
        b[48] = 0x10; // 16 * 512000 bytes written
        b[128..130].copy_from_slice(&1234u16.to_le_bytes());
        b[144] = 42;
        b[160] = 3;
        let h = parse_nvme_health(&b).unwrap();
        assert_eq!(h.critical_warning, 4);
        assert_eq!(h.temp_c, 45);
        assert_eq!(h.used_pct, 7);
        assert_eq!(h.power_on_hours, 1234);
        assert_eq!(h.unsafe_shutdowns, 42);
        assert_eq!(h.media_errors, 3);
        assert_eq!(h.written_gb, 0);
    }

    #[test]
    fn ata_smart_parse() {
        let mut v = vec![0u8; 512];
        let mut put = |slot: usize, id: u8, val: u8, raw: u64| {
            let o = 2 + slot * 12;
            v[o] = id;
            v[o + 3] = val;
            v[o + 4] = val;
            v[o + 5..o + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
        };
        put(0, 5, 100, 8);
        put(1, 194, 70, 0x0028_0012_002E); // 46 C with min/max packed above
        put(2, 199, 200, 17);
        put(3, 1, 100, 999); // not tracked
        let a = parse_ata_smart(&v);
        assert_eq!(a.len(), 3);
        assert_eq!(a.iter().find(|x| x.id == 194).unwrap().raw, 46);
        assert_eq!(a.iter().find(|x| x.id == 199).unwrap().raw, 17);
    }

    #[test]
    fn live_power_and_disks_do_not_crash() {
        let _ = power_status();
        let disks = read_all_disks();
        eprintln!("{disks:#?}");
    }
}
