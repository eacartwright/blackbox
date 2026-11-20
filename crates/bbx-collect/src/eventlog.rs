//! Event log collector: push subscriptions to System, Application and a set
//! of operational channels, resumed from persisted bookmarks so events logged
//! while BlackBox wasn't running (including during boot) are still captured.

use crate::util::{below_normal_priority, from_wide, last_error, truncate, wide};
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{EventLog, RecordType};
use bbx_core::runstate::write_atomic;
use bbx_core::time::{now_ft, utc_to_ft};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtFormatMessage, EvtNext, EvtOpenPublisherMetadata, EvtQuery, EvtRender, EvtSubscribe,
    EvtUpdateBookmark,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

pub type EvtHandle = isize;

const EVT_SUBSCRIBE_START_AT_OLDEST: u32 = 2;
const EVT_SUBSCRIBE_START_AFTER_BOOKMARK: u32 = 3;
const EVT_RENDER_EVENT_XML: u32 = 1;
const EVT_RENDER_BOOKMARK: u32 = 2;
const EVT_FORMAT_MESSAGE_EVENT: u32 = 1;
const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
const EVT_QUERY_FORWARD: u32 = 0x100;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_INVALID_OPERATION: u32 = 4317;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

const MAX_MESSAGE: usize = 2000;
const MAX_VALUE: usize = 1000;
const MAX_FIELDS: usize = 40;

/// Owned EVT_HANDLE.
pub struct Evt(pub EvtHandle);
impl Drop for Evt {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { EvtClose(self.0 as _) };
        }
    }
}

fn evt(h: impl Into<EvtRaw>) -> EvtHandle {
    h.into().0
}
/// windows-sys has used both isize and pointer types for EVT_HANDLE across
/// versions; normalise to isize.
pub struct EvtRaw(isize);
impl From<isize> for EvtRaw {
    fn from(v: isize) -> Self {
        Self(v)
    }
}
impl From<*mut std::ffi::c_void> for EvtRaw {
    fn from(v: *mut std::ffi::c_void) -> Self {
        Self(v as isize)
    }
}

/// Render an event (or bookmark) to XML.
pub fn render(h: EvtHandle, flags: u32) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    let mut buf: Vec<u16> = vec![0; 4096];
    for _ in 0..3 {
        let ok = unsafe {
            EvtRender(0 as _, h as _, flags, (buf.len() * 2) as u32, buf.as_mut_ptr().cast(), &mut used, &mut props)
        };
        if ok != 0 {
            return Some(from_wide(&buf[..(used as usize / 2).min(buf.len())]));
        }
        if last_error() != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buf = vec![0; used as usize / 2 + 1];
    }
    None
}

/// Publisher metadata handles, for rendering messages; cached per provider.
#[derive(Default)]
pub struct Publishers {
    map: HashMap<String, Evt>,
}

impl Publishers {
    pub fn message(&mut self, provider: &str, event: EvtHandle) -> Option<String> {
        let meta = self.map.entry(provider.to_string()).or_insert_with(|| {
            let w = wide(provider);
            Evt(evt(unsafe { EvtOpenPublisherMetadata(0 as _, w.as_ptr(), std::ptr::null(), 0, 0) }))
        });
        if meta.0 == 0 {
            return None;
        }
        let mut used = 0u32;
        let mut buf: Vec<u16> = vec![0; 1024];
        for _ in 0..3 {
            let ok = unsafe {
                EvtFormatMessage(meta.0 as _, event as _, 0, 0, std::ptr::null(), EVT_FORMAT_MESSAGE_EVENT, buf.len() as u32, buf.as_mut_ptr(), &mut used)
            };
            if ok != 0 {
                let s = from_wide(&buf).trim().to_string();
                return (!s.is_empty()).then(|| truncate(s, MAX_MESSAGE));
            }
            if last_error() != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
            buf = vec![0; used as usize + 1];
        }
        None
    }
}

/// The parts of an event's XML that BlackBox keeps.
#[derive(Debug, Default, Clone)]
pub struct Parsed {
    pub channel: String,
    pub provider: String,
    pub id: u32,
    pub level: u8,
    pub task: u16,
    pub opcode: u8,
    pub record_id: u64,
    pub event_ft: i64,
    pub pid: u32,
    pub data: Map<String, Value>,
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

pub fn parse_xml(xml: &str) -> Option<Parsed> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let sys = child(root, "System")?;
    let text = |name: &str| child(sys, name).and_then(|n| n.text()).unwrap_or("").trim().to_string();
    let mut p = Parsed {
        provider: child(sys, "Provider").and_then(|n| n.attribute("Name")).unwrap_or("").to_string(),
        id: text("EventID").parse().unwrap_or(0),
        level: text("Level").parse().unwrap_or(0),
        task: text("Task").parse().unwrap_or(0),
        opcode: text("Opcode").parse().unwrap_or(0),
        record_id: text("EventRecordID").parse().unwrap_or(0),
        channel: text("Channel"),
        ..Default::default()
    };
    if let Some(t) = child(sys, "TimeCreated").and_then(|n| n.attribute("SystemTime")) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t) {
            p.event_ft = utc_to_ft(dt.with_timezone(&chrono::Utc));
        }
    }
    p.pid = child(sys, "Execution").and_then(|n| n.attribute("ProcessID")).and_then(|v| v.parse().ok()).unwrap_or(0);

    let mut put = |k: String, v: &str| {
        if p.data.len() < MAX_FIELDS {
            p.data.insert(k, Value::String(truncate(v.to_string(), MAX_VALUE)));
        }
    };
    if let Some(ed) = child(root, "EventData") {
        for (i, d) in ed.children().filter(|c| c.is_element()).enumerate() {
            let k = d.attribute("Name").map(String::from).unwrap_or_else(|| i.to_string());
            put(k, d.text().unwrap_or(""));
        }
    } else if let Some(ud) = child(root, "UserData") {
        if let Some(inner) = ud.children().find(|c| c.is_element()) {
            for d in inner.children().filter(|c| c.is_element()) {
                put(d.tag_name().name().to_string(), d.text().unwrap_or(""));
            }
        }
    }
    Some(p)
}

pub fn build_query(filter: &str, backfill_hours: Option<u64>) -> String {
    let mut conds = Vec::new();
    if !filter.trim().is_empty() {
        conds.push(format!("({filter})"));
    }
    if let Some(h) = backfill_hours {
        conds.push(format!("TimeCreated[timediff(@SystemTime) <= {}]", h * 3_600_000));
    }
    if conds.is_empty() {
        "*".into()
    } else {
        format!("*[System[{}]]", conds.join(" and "))
    }
}

struct Sub {
    channel: String,
    handle: Evt,
    signal: HANDLE,
    bookmark: Evt,
    dirty: bool,
}

impl Drop for Sub {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.signal) };
    }
}

fn load_bookmarks(ctx: &Ctx) -> HashMap<String, String> {
    std::fs::read(ctx.paths.eventlog_bookmarks())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_bookmarks(ctx: &Ctx, subs: &mut [Sub], saved: &mut HashMap<String, String>) {
    let mut changed = false;
    for s in subs.iter_mut().filter(|s| s.dirty) {
        if let Some(xml) = render(s.bookmark.0, EVT_RENDER_BOOKMARK) {
            saved.insert(s.channel.clone(), xml);
            changed = true;
        }
        s.dirty = false;
    }
    if changed {
        if let Err(e) = serde_json::to_vec(saved).map_err(anyhow::Error::from).and_then(|b| write_atomic(&ctx.paths.eventlog_bookmarks(), &b)) {
            log::warn!("saving event log bookmarks failed: {e:#}");
        }
    }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let mut saved = load_bookmarks(ctx);
    let mut subs: Vec<Sub> = Vec::new();
    for chc in &ctx.cfg.eventlog_channels {
        let prior = saved.get(&chc.channel).cloned();
        let (bm, flags, query) = match &prior {
            Some(xml) => {
                let w = wide(xml);
                (Evt(evt(unsafe { EvtCreateBookmark(w.as_ptr()) })), EVT_SUBSCRIBE_START_AFTER_BOOKMARK, build_query(&chc.filter, None))
            }
            None => (
                Evt(evt(unsafe { EvtCreateBookmark(std::ptr::null()) })),
                EVT_SUBSCRIBE_START_AT_OLDEST,
                build_query(&chc.filter, Some(ctx.cfg.eventlog_backfill_hours)),
            ),
        };
        let signal = unsafe { CreateEventW(std::ptr::null(), 0, 1, std::ptr::null()) };
        let (wc, wq) = (wide(&chc.channel), wide(&query));
        let h = evt(unsafe {
            EvtSubscribe(0 as _, signal, wc.as_ptr(), wq.as_ptr(), if prior.is_some() { bm.0 as _ } else { 0 as _ }, std::ptr::null(), None, flags)
        });
        if h == 0 {
            let err = last_error();
            unsafe { CloseHandle(signal) };
            if err == ERROR_EVT_CHANNEL_NOT_FOUND {
                log::info!("event channel {} not present on this machine", chc.channel);
            } else {
                ctx.status("eventlog", "warn", format!("cannot subscribe to {} (error {err}); is the channel enabled?", chc.channel));
            }
            continue;
        }
        subs.push(Sub { channel: chc.channel.clone(), handle: Evt(h), signal, bookmark: bm, dirty: false });
    }
    if subs.is_empty() {
        return Err(anyhow!("no event log channels could be subscribed"));
    }
    ctx.status("eventlog", "info", format!("subscribed to {} channels", subs.len()));

    let mut pubs = Publishers::default();
    let mut last_save = Instant::now();
    let signals: Vec<HANDLE> = subs.iter().map(|s| s.signal).collect();
    loop {
        let rc = unsafe { WaitForMultipleObjects(signals.len() as u32, signals.as_ptr(), 0, 1000) };
        if ctx.stop.is_set() {
            break;
        }
        if rc != WAIT_TIMEOUT {
            // Drain every subscription: cheap, and avoids starving any channel.
            for s in subs.iter_mut() {
                drain(ctx, s, &mut pubs);
            }
        }
        if last_save.elapsed() >= Duration::from_secs(15) {
            save_bookmarks(ctx, &mut subs, &mut saved);
            last_save = Instant::now();
        }
    }
    save_bookmarks(ctx, &mut subs, &mut saved);
    Ok(())
}

fn drain(ctx: &Ctx, s: &mut Sub, pubs: &mut Publishers) {
    let mut batch = [0isize; 64];
    loop {
        let mut n = 0u32;
        let ok = unsafe { EvtNext(s.handle.0 as _, batch.len() as u32, batch.as_mut_ptr().cast(), 0, 0, &mut n) };
        if ok == 0 {
            let e = last_error();
            // A drained subscription reports ERROR_INVALID_OPERATION rather
            // than ERROR_NO_MORE_ITEMS; both just mean "nothing more now".
            if e != ERROR_NO_MORE_ITEMS && e != ERROR_INVALID_OPERATION {
                log::warn!("EvtNext on {} failed: {e}", s.channel);
            }
            return;
        }
        for &h in &batch[..n as usize] {
            let h = Evt(h);
            if let Some(rec) = to_record(h.0, pubs) {
                let ft = if rec.event_ft > 0 { rec.event_ft } else { now_ft() };
                ctx.emit_at(RecordType::EventLog, ft, &rec);
            }
            unsafe { EvtUpdateBookmark(s.bookmark.0 as _, h.0 as _) };
            s.dirty = true;
        }
        if ctx.stop.is_set() {
            return;
        }
    }
}

pub fn to_record(h: EvtHandle, pubs: &mut Publishers) -> Option<EventLog> {
    let xml = render(h, EVT_RENDER_EVENT_XML)?;
    let p = parse_xml(&xml)?;
    let message = pubs.message(&p.provider, h);
    Some(EventLog {
        channel: p.channel,
        provider: p.provider,
        id: p.id,
        level: p.level,
        record_id: p.record_id,
        event_ft: p.event_ft,
        task: p.task,
        opcode: p.opcode,
        pid: p.pid,
        message,
        data: p.data,
    })
}

/// One-shot query (used by the boot evidence gatherer).
pub fn query(channel: &str, xpath: &str, max: usize) -> Result<Vec<EventLog>> {
    let (wc, wq) = (wide(channel), wide(xpath));
    let q = Evt(evt(unsafe { EvtQuery(0 as _, wc.as_ptr(), wq.as_ptr(), EVT_QUERY_CHANNEL_PATH | EVT_QUERY_FORWARD) }));
    if q.0 == 0 {
        return Err(anyhow!("EvtQuery({channel}) failed: {}", last_error()));
    }
    let mut pubs = Publishers::default();
    let mut out = Vec::new();
    let mut batch = [0isize; 32];
    loop {
        let mut n = 0u32;
        if unsafe { EvtNext(q.0 as _, batch.len() as u32, batch.as_mut_ptr().cast(), 1000, 0, &mut n) } == 0 {
            break;
        }
        for &h in &batch[..n as usize] {
            let h = Evt(h);
            if out.len() < max {
                if let Some(r) = to_record(h.0, &mut pubs) {
                    out.push(r);
                }
            }
        }
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/><EventID>41</EventID><Version>9</Version><Level>1</Level><Task>63</Task><Opcode>0</Opcode><Keywords>0x8000400000000002</Keywords><TimeCreated SystemTime='2026-11-19T21:05:01.1234567Z'/><EventRecordID>98765</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>System</Channel><Computer>PC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='BugcheckCode'>0</Data><Data Name='SleepInProgress'>0</Data><Data Name='PowerButtonTimestamp'>0</Data></EventData></Event>"#;

    #[test]
    fn parses_event_xml() {
        let p = parse_xml(XML).unwrap();
        assert_eq!(p.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(p.id, 41);
        assert_eq!(p.level, 1);
        assert_eq!(p.record_id, 98765);
        assert_eq!(p.channel, "System");
        assert_eq!(p.pid, 4);
        assert_eq!(p.data["BugcheckCode"], "0");
        assert!(p.event_ft > 0);
    }

    #[test]
    fn query_shapes() {
        assert_eq!(build_query("", None), "*");
        assert_eq!(build_query("Level<=3", None), "*[System[(Level<=3)]]");
        assert_eq!(build_query("", Some(2)), "*[System[TimeCreated[timediff(@SystemTime) <= 7200000]]]");
    }

    #[test]
    fn live_system_query() {
        let r = query("System", "*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]", 5).unwrap();
        assert!(!r.is_empty(), "expected some System events in the last week");
        assert!(r.iter().all(|e| e.channel == "System" && e.event_ft > 0));
    }
}
