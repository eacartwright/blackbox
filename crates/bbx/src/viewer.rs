//! `bbx view`: a local web viewer for a dataset. Serves one embedded page
//! plus a JSON API on 127.0.0.1 only; every request needs the random token
//! printed in the URL, and the Host header must be the loopback address
//! (blocks other web pages and DNS-rebinding from reaching it).
//!
//! All data shown comes from the client machine and is treated as untrusted
//! by the page (rendered as text, never as HTML).

use crate::ai;
use crate::dataset::{Dataset, Rec};
use crate::suspects::{self, Suspect};
use anyhow::{anyhow, Result};
use bbx_collect::etlread;
use bbx_core::records::{self as rec, RecordType};
use bbx_core::time::{FT_PER_MS, FT_UNIX_EPOCH};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX_HTML: &str = include_str!("web/index.html");
const MAX_ETL_WINDOW_MS: f64 = 300_000.0;

pub struct ViewOptions {
    pub port: u16,
    pub open_browser: bool,
    pub model: String,
    /// Viewing this machine's own recordings: lets the page pick another
    /// incident or time range.
    pub local: Option<bbx_core::paths::Paths>,
    /// Quit when no page has talked to us for this long (the open page
    /// pings every minute).
    pub idle_exit: Option<std::time::Duration>,
    /// Hand the page address to whoever started us (see `write_url_file`).
    pub url_file: Option<PathBuf>,
}

/// Write one line for the tray agent: the page address, "EMPTY", or
/// "ERROR: ...". Written whole and then renamed, so the agent never reads
/// half a line.
pub fn write_url_file(path: &std::path::Path, text: &str) {
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// The running viewer. The loaded dataset can be swapped (local mode).
struct Srv {
    token: String,
    port: u16,
    model: String,
    local: Option<bbx_core::paths::Paths>,
    cur: std::sync::RwLock<Arc<State>>,
    loading: Mutex<()>,
    last_request: Mutex<std::time::Instant>,
}

/// Longest window the picker will load (records are held in memory).
const MAX_LOAD_HOURS: i64 = 48;

#[derive(Default, serde::Serialize, Clone)]
struct AiJob {
    status: String, // idle | running | done | error
    question: Option<String>,
    text: String,
    error: Option<String>,
    result: Option<ai::AiResult>,
}

struct State {
    ds: Dataset,
    model: String,
    suspects: Vec<Suspect>,
    names: HashMap<u32, String>,
    series: Value,
    events: Value,
    digest: Mutex<Option<String>>,
    ai: Mutex<AiJob>,
    etl_index: Vec<(i64, PathBuf)>,
}

pub fn ft_ms(ft: i64) -> f64 {
    (ft - FT_UNIX_EPOCH) as f64 / FT_PER_MS as f64
}
fn ms_ft(ms: f64) -> i64 {
    (ms * FT_PER_MS as f64) as i64 + FT_UNIX_EPOCH
}

fn token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut s = String::new();
    for i in 0..4u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i ^ bbx_core::time::now_ft() as u64 ^ (std::process::id() as u64) << 32);
        s.push_str(&format!("{:016x}", h.finish()));
    }
    s
}

pub fn serve(ds: Dataset, opts: ViewOptions) -> Result<()> {
    let server = Server::http(("127.0.0.1", opts.port)).map_err(|e| anyhow!("cannot listen on 127.0.0.1:{}: {e}", opts.port))?;
    let port = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(opts.port);
    let token = token();
    let st = build_state(ds, &opts.model);
    let url = format!("http://127.0.0.1:{port}/?k={token}");
    println!("BlackBox viewer for {}", st.ds.source);
    println!("  {url}");
    println!("Press Ctrl+C to stop.");
    let srv = Arc::new(Srv {
        token,
        port,
        model: opts.model,
        local: opts.local,
        cur: std::sync::RwLock::new(Arc::new(st)),
        loading: Mutex::new(()),
        last_request: Mutex::new(std::time::Instant::now()),
    });
    if let Some(f) = &opts.url_file {
        write_url_file(f, &url);
    } else if opts.open_browser {
        std::process::Command::new("explorer.exe").arg(&url).spawn().ok();
    }
    if let Some(limit) = opts.idle_exit {
        let srv = srv.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(15));
            if srv.last_request.lock().unwrap().elapsed() > limit {
                println!("No viewer page open; exiting.");
                std::process::exit(0);
            }
        });
    }
    for req in server.incoming_requests() {
        let srv = srv.clone();
        std::thread::spawn(move || handle(srv, req));
    }
    Ok(())
}

fn build_state(ds: Dataset, model: &str) -> State {
    let suspects = suspects::analyze(&ds);
    let names = process_names(&ds);
    let etl_index = index_etl(&ds.etl_files);
    State {
        series: series(&ds),
        events: events(&ds, &names),
        model: model.to_string(),
        suspects,
        names,
        digest: Mutex::new(None),
        ai: Mutex::new(AiJob { status: "idle".into(), ..Default::default() }),
        etl_index,
        ds,
    }
}

/// What the picker can offer: this machine's incidents (local mode only).
fn sources(srv: &Srv, st: &State) -> Value {
    let Some(paths) = &srv.local else { return json!({"local": false}) };
    let incidents: Vec<Value> = crate::dataset::list_incidents(paths)
        .into_iter()
        .filter(|i| i.at_ft != 0)
        .map(|i| json!({"id": i.id, "kind": i.kind, "reason": i.reason, "t": ft_ms(i.at_ft)}))
        .collect();
    json!({
        "local": true,
        "incidents": incidents,
        "current": {"incident": st.ds.incident.as_ref().map(|i| i.id.clone()), "from": ft_ms(st.ds.from_ft), "to": ft_ms(st.ds.to_ft)},
        "max_hours": MAX_LOAD_HOURS,
    })
}

/// Load another incident or time range of this machine's recordings.
fn load_view(srv: &Srv, req: &Value) -> Result<()> {
    let paths = srv.local.as_ref().ok_or_else(|| anyhow!("this viewer shows a bundle; nothing else to load"))?;
    let _one_at_a_time = srv.loading.lock().unwrap();
    let ds = if let Some(id) = req.get("incident").and_then(|v| v.as_str()) {
        // Only names from the incident list: no path separators.
        if id.is_empty() || id.contains(['/', '\\']) || id.contains("..") {
            return Err(anyhow!("bad incident id"));
        }
        Dataset::open_local_incident(paths, id)?
    } else {
        let ms = |k: &str| req.get(k).and_then(|v| v.as_f64()).ok_or_else(|| anyhow!("missing '{k}'"));
        let (from, to) = (ms_ft(ms("from")?), ms_ft(ms("to")?).min(bbx_core::time::now_ft()));
        if to <= from {
            return Err(anyhow!("the end must be after the start"));
        }
        if to - from > MAX_LOAD_HOURS * 3600 * 10_000_000 {
            return Err(anyhow!("pick at most {MAX_LOAD_HOURS} hours"));
        }
        Dataset::open_local(paths, from, to, to)?
    };
    let st = build_state(ds, &srv.model);
    *srv.cur.write().unwrap() = Arc::new(st);
    Ok(())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

fn respond(req: Request, code: u16, ctype: &str, body: Vec<u8>) {
    let mut r = Response::from_data(body).with_status_code(code);
    r.add_header(header("Content-Type", ctype));
    r.add_header(header("Cache-Control", "no-store"));
    r.add_header(header("X-Content-Type-Options", "nosniff"));
    r.add_header(header("Referrer-Policy", "no-referrer"));
    if ctype.starts_with("text/html") {
        r.add_header(header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
        ));
    }
    let _ = req.respond(r);
}

fn json_resp(req: Request, v: &impl serde::Serialize) {
    respond(req, 200, "application/json", serde_json::to_vec(v).unwrap_or_default());
}

fn query(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').map(|x| x.1).unwrap_or("");
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), percent_decode(v)))
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'+' {
            out.push(b' ');
        } else if c == b'%' && i + 2 < b.len() {
            match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 2;
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Informational events worth a marker (errors and warnings always are).
fn interesting(e: &rec::EventLog) -> bool {
    let p = e.provider.as_str();
    matches!(
        (p, e.id),
        ("Microsoft-Windows-Kernel-Power", 41 | 42 | 107 | 109 | 506 | 507)
            | ("User32", 1074)
            | ("EventLog", 6005 | 6006 | 6008)
            | ("Microsoft-Windows-Kernel-General", 12 | 13)
            | ("Microsoft-Windows-WindowsUpdateClient", 19 | 20 | 43 | 44)
            | ("Microsoft-Windows-Windows Defender", 1000 | 1001 | 1116)
            | ("Service Control Manager", 7045)
            | ("Microsoft-Windows-WLAN-AutoConfig", 8001 | 8003)
            | ("Microsoft-Windows-Resource-Exhaustion-Detector", 2004)
    )
}

fn handle(srv: Arc<Srv>, mut req: Request) {
    // Loopback Host only (DNS rebinding), and the per-run token.
    let host_ok = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| {
            let v = h.value.as_str();
            v == format!("127.0.0.1:{}", srv.port) || v == format!("localhost:{}", srv.port)
        })
        .unwrap_or(false);
    let url = req.url().to_string();
    let q = query(&url);
    if !host_ok || q.get("k") != Some(&srv.token) {
        return respond(req, 403, "text/plain", b"forbidden".to_vec());
    }
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = req.method().clone();
    *srv.last_request.lock().unwrap() = std::time::Instant::now();
    let st = srv.cur.read().unwrap().clone();
    match (method, path.as_str()) {
        (Method::Get, "/") => respond(req, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec()),
        (Method::Get, "/api/ping") => json_resp(req, &json!({"ok": true})),
        (Method::Get, "/api/sources") => json_resp(req, &sources(&srv, &st)),
        (Method::Post, "/api/load") => {
            let mut body = String::new();
            let _ = req.as_reader().take(4 * 1024).read_to_string(&mut body);
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            match load_view(&srv, &v) {
                Ok(()) => json_resp(req, &json!({"ok": true})),
                Err(e) => json_resp(req, &json!({"error": format!("{e:#}")})),
            }
        }
        (Method::Get, "/api/info") => json_resp(req, &info(&st)),
        (Method::Get, "/api/series") => json_resp(req, &st.series),
        (Method::Get, "/api/events") => json_resp(req, &st.events),
        (Method::Get, "/api/suspects") => {
            let v: Vec<Value> = st.suspects.iter().map(|s| json!({"score": s.score, "category": s.category, "title": s.title, "detail": s.detail, "t": s.at_ft.map(ft_ms), "evidence": s.evidence})).collect();
            json_resp(req, &v)
        }
        (Method::Get, "/api/moment") => {
            let t = q.get("t").and_then(|v| v.parse::<f64>().ok()).unwrap_or(ft_ms(st.ds.at_ft));
            let span = q.get("span").and_then(|v| v.parse::<f64>().ok()).unwrap_or(5.0).clamp(1.0, 300.0);
            json_resp(req, &moment(&st, ms_ft(t), (span * 10_000_000.0) as i64))
        }
        (Method::Get, "/api/report") => {
            let t = q.get("t").and_then(|v| v.parse::<f64>().ok()).map(ms_ft).unwrap_or(st.ds.at_ft);
            let text = crate::report::around_records(&st.ds.records, t, 5, 2).unwrap_or_else(|e| e.to_string());
            respond(req, 200, "text/plain; charset=utf-8", text.into_bytes())
        }
        (Method::Get, "/api/digest") => respond(req, 200, "text/plain; charset=utf-8", digest(&st).into_bytes()),
        (Method::Get, "/api/etl") => match etl(&st, &q) {
            Ok(v) => json_resp(req, &v),
            Err(e) => json_resp(req, &json!({"error": format!("{e:#}")})),
        },
        (Method::Get, "/api/screen") => {
            let i = q.get("i").and_then(|v| v.parse::<usize>().ok()).unwrap_or(usize::MAX);
            match st.ds.screens.get(i).and_then(|(_, p)| std::fs::read(p).ok()) {
                Some(b) => respond(req, 200, "image/png", b),
                None => respond(req, 404, "text/plain", b"no such screenshot".to_vec()),
            }
        }
        (Method::Get, "/api/ai") => {
            let job = st.ai.lock().unwrap().clone();
            json_resp(req, &job)
        }
        (Method::Post, "/api/ai") => {
            let mut body = String::new();
            let _ = req.as_reader().take(16 * 1024).read_to_string(&mut body);
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let question = v.get("question").and_then(|q| q.as_str()).map(|s| s.trim().chars().take(2000).collect::<String>()).filter(|s| !s.is_empty());
            let followup = v.get("followup").and_then(|f| f.as_bool()).unwrap_or(false);
            let started = start_ai(&st, question, followup);
            json_resp(req, &json!({"started": started}))
        }
        _ => respond(req, 404, "text/plain", b"not found".to_vec()),
    }
}

fn info(st: &State) -> Value {
    let ds = &st.ds;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for r in &ds.records {
        *counts.entry(bbx_core::records::type_name(r.rtype)).or_default() += 1;
    }
    json!({
        "host": ds.host, "os": ds.os, "source": ds.source,
        "from": ft_ms(ds.from_ft), "to": ft_ms(ds.to_ft), "at": ft_ms(ds.at_ft),
        "incident": ds.incident.as_ref().map(|i| json!({"id": i.id, "kind": i.kind, "reason": i.reason})),
        "verdict": ds.verdict.as_ref().map(|v| json!({"kind": format!("{:?}", v.kind), "confidence": format!("{:?}", v.confidence), "summary": v.summary})),
        "etl_files": ds.etl_files.len(),
        "screens": ds.screens.iter().map(|(t, _)| ft_ms(*t)).collect::<Vec<_>>(),
        "counts": counts,
        "model": st.model,
        "ai_available": ai::credentials().is_ok(),
        "digest_chars": st.digest.lock().unwrap().as_ref().map(|d| d.len()),
    })
}

fn process_names(ds: &Dataset) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for r in &ds.records {
        if r.is(RecordType::ProcessSample) {
            if let Some(p) = r.parse::<rec::ProcessSample>() {
                m.extend(p.names);
            }
        } else if r.is(RecordType::ProcessStart) {
            if let Some(p) = r.parse::<rec::ProcessStart>() {
                m.insert(p.pid, p.name);
            }
        }
    }
    m
}

/// Time series for the charts, bucketed to at most ~3000 points.
fn series(ds: &Dataset) -> Value {
    let hb: Vec<(i64, rec::Heartbeat)> = ds.records_of(RecordType::Heartbeat).filter_map(|r| Some((r.ft, r.parse::<rec::Heartbeat>()?))).filter(|(_, h)| h.vitals.avail_mb > 0 || h.vitals.commit_pct > 0.0).collect();
    let step = (hb.len() / 3000).max(1);
    let mut t = Vec::new();
    let (mut cpu, mut commit, mut avail, mut disk, mut queue, mut late) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    for chunk in hb.chunks(step) {
        // Keep the worst value of each bucket: spikes must survive downsampling.
        t.push(ft_ms(chunk[0].0));
        cpu.push(chunk.iter().map(|x| x.1.vitals.cpu).fold(0.0, f32::max));
        commit.push(chunk.iter().map(|x| x.1.vitals.commit_pct).fold(0.0, f32::max));
        avail.push(chunk.iter().map(|x| x.1.vitals.avail_mb).min().unwrap_or(0));
        disk.push(chunk.iter().map(|x| x.1.vitals.disk_ms).fold(0.0, f32::max));
        queue.push(chunk.iter().map(|x| x.1.vitals.disk_q).fold(0.0, f32::max));
        late.push(chunk.iter().map(|x| x.1.jitter_ms).max().unwrap_or(0));
    }
    let pdh: Vec<(i64, rec::PdhSample)> = ds.records_of(RecordType::PdhSample).filter_map(|r| Some((r.ft, r.parse()?))).collect();
    let mut pt = Vec::new();
    let (mut rx, mut tx, mut gpu, mut perf, mut dpc, mut temp) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    for (ft, p) in &pdh {
        pt.push(ft_ms(*ft));
        rx.push(p.nics.iter().map(|n| n.rx_bps).sum::<f64>() / 1024.0);
        tx.push(p.nics.iter().map(|n| n.tx_bps).sum::<f64>() / 1024.0);
        gpu.push(p.gpu.as_ref().map(|g| g.engines.iter().map(|e| e.pct).fold(0.0, f32::max)));
        perf.push(p.cpu.perf);
        dpc.push(p.cpu.dpc_pct + p.cpu.intr_pct);
        temp.push(p.thermal.iter().map(|z| z.celsius).fold(f32::NAN, f32::max));
    }
    // Carry the last GPU value forward (GPU is sampled less often).
    let mut last = None;
    let gpu: Vec<Option<f32>> = gpu.into_iter().map(|g| { if g.is_some() { last = g; } last }).collect();
    let temp: Vec<Option<f32>> = temp.into_iter().map(|t| (!t.is_nan()).then_some(t)).collect();
    json!({
        "hb": {"t": t, "cpu": cpu, "commit": commit, "avail": avail, "disk": disk, "queue": queue, "late": late},
        "pdh": {"t": pt, "rx": rx, "tx": tx, "gpu": gpu, "perf": perf, "dpc": dpc, "temp": temp},
    })
}

fn ev(ft: i64, lane: &str, sev: u8, title: impl Into<String>, detail: impl Into<String>) -> Value {
    json!({"t": ft_ms(ft), "lane": lane, "sev": sev, "title": title.into(), "detail": detail.into()})
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n).collect::<String>() + "…" }
}

/// Markers for the event lanes. sev: 0 info, 1 warning, 2 error, 3 critical.
fn events(ds: &Dataset, names: &HashMap<u32, String>) -> Value {
    let mut out = Vec::new();
    for r in &ds.records {
        let Some(ty) = r.ty() else { continue };
        match ty {
            RecordType::Incident => {
                if let Some(i) = r.parse::<rec::Incident>() {
                    out.push(ev(if i.at_ft > 0 { i.at_ft } else { r.ft }, "incident", 3, format!("Incident: {}", i.kind), i.reason));
                }
            }
            RecordType::Note => {
                if let Some(n) = r.parse::<rec::Note>() {
                    out.push(ev(r.ft, "incident", 2, format!("Note from {}", if n.user.is_empty() { "user" } else { &n.user }), n.text));
                }
            }
            RecordType::EventLog => {
                if let Some(e) = r.parse::<rec::EventLog>() {
                    let sev = match e.level { 1 => 3, 2 => 2, 3 => 1, _ => 0 };
                    let interesting = sev > 0 || interesting(&e);
                    if interesting {
                        let msg = e.message.clone().unwrap_or_default();
                        out.push(ev(e.event_ft, "event", sev, format!("{} {}", e.provider.trim_start_matches("Microsoft-Windows-"), e.id), clip(&msg, 600)));
                    }
                }
            }
            RecordType::ProcessStart => {
                if let Some(p) = r.parse::<rec::ProcessStart>() {
                    if p.source != "inventory" {
                        let parent = names.get(&p.ppid).cloned().unwrap_or_default();
                        out.push(ev(r.ft, "process", 0, format!("Start {}", p.name), clip(&format!("pid {} parent {}({})  {}", p.pid, parent, p.ppid, p.cmdline), 600)));
                    }
                }
            }
            RecordType::ProcessEnd => {
                if let Some(p) = r.parse::<rec::ProcessEnd>() {
                    let crash = p.exit_code.is_some_and(|c| (c as u32) >= 0xC000_0000 && c as u32 != 0xC000_013A);
                    let code = p.exit_code.map(crate::report::exit_code).unwrap_or_default();
                    out.push(ev(r.ft, "process", if crash { 2 } else { 0 }, format!("{} {}", if crash { "Crash" } else { "Exit" }, p.name), format!("pid {} exit {code}", p.pid)));
                }
            }
            RecordType::UserEvent => {
                if let Some(u) = r.parse::<rec::UserEvent>() {
                    let (sev, title) = match u.kind.as_str() {
                        "hung" => (1, format!("{} not responding", u.proc)),
                        "hung_end" => (if u.value >= 15.0 { 2 } else { 1 }, format!("{} responding again after {:.0} s", u.proc, u.value)),
                        "ui_stall" => (2, format!("Desktop froze {:.1} s", u.value / 1000.0)),
                        "display" => (if u.detail == "off" && u.value < 30.0 { 2 } else { 0 }, format!("Display {}", u.detail)),
                        "session" => (0, format!("Session {}", u.detail)),
                        "power" => (0, format!("Power {}", u.detail)),
                        "shell" => (2, "Explorer restarted".to_string()),
                        "foreground" => (0, format!("Switched to {}", u.proc)),
                        "idle" | "active" => (0, format!("User {}", u.kind)),
                        "mark" => (3, "User pressed It just happened".to_string()),
                        k => (0, k.to_string()),
                    };
                    out.push(ev(r.ft, "user", sev, title, format!("{} {}", u.user, u.detail)));
                }
            }
            RecordType::Device => {
                if let Some(d) = r.parse::<rec::Device>() {
                    let sev = if d.action == "problem" { 2 } else if d.action == "removed" { 1 } else { 0 };
                    out.push(ev(r.ft, "device", sev, format!("Device {}: {}", d.action, d.dev.name), format!("{} [{}] code {}", d.dev.id, d.dev.class, d.dev.problem)));
                }
            }
            RecordType::DriverLoad => {
                if let Some(d) = r.parse::<rec::DriverLoad>() {
                    out.push(ev(r.ft, "system", 0, "Driver loaded", d.path));
                }
            }
            RecordType::SessionStart => out.push(ev(r.ft, "system", 0, "Recording started", String::new())),
            RecordType::SessionEnd => out.push(ev(r.ft, "system", 0, "Recording stopped", r.data.to_string())),
            RecordType::ShutdownVerdict => {
                if let Some(v) = r.parse::<bbx_core::classifier::Verdict>() {
                    out.push(ev(r.ft, "system", 2, format!("Previous boot: {:?}", v.kind), v.summary));
                }
            }
            RecordType::CollectorStatus => {
                if let Some(c) = r.parse::<rec::CollectorStatus>() {
                    if c.level != "info" {
                        out.push(ev(r.ft, "system", 1, format!("BlackBox {}", c.collector), c.message));
                    }
                }
            }
            RecordType::Power => {
                if let Some(p) = r.parse::<rec::Power>() {
                    out.push(ev(r.ft, "system", if p.critical { 3 } else { 0 }, format!("Power: {}", match p.ac { Some(true) => "AC", Some(false) => "battery", None => "?" }), format!("battery {:?}%", p.battery_pct)));
                }
            }
            _ => {}
        }
    }
    Value::Array(out)
}

fn nearest<'a>(recs: &'a [Rec], t: RecordType, ft: i64, span: i64) -> Option<&'a Rec> {
    recs.iter().filter(|r| r.is(t) && (r.ft - ft).abs() <= span).min_by_key(|r| (r.ft - ft).abs())
}

/// Everything known about one moment (± span).
fn moment(st: &State, ft: i64, span: i64) -> Value {
    let ds = &st.ds;
    let win = ds.in_window(ft - span.max(30 * 10_000_000), ft + span.max(30 * 10_000_000));
    let near = ds.in_window(ft - span, ft + span);
    let name = |pid: u32| st.names.get(&pid).cloned().unwrap_or_else(|| "?".into());
    let vit = nearest(win, RecordType::Heartbeat, ft, span.max(5 * 10_000_000)).and_then(|r| r.parse::<rec::Heartbeat>());
    // Base: the nearest full process table (every process); overlay: the
    // nearest sample's rows (only processes that were doing something, so
    // anything not in it was idle at that moment).
    let wide = ds.in_window(ft - 90 * 10_000_000, ft + 90 * 10_000_000);
    let full = wide
        .iter()
        .filter(|r| r.is(RecordType::ProcessSample) && r.data.get("full").and_then(|f| f.as_bool()) == Some(true))
        .min_by_key(|r| (r.ft - ft).abs())
        .and_then(|r| r.parse::<rec::ProcessSample>());
    let near_sample = nearest(win, RecordType::ProcessSample, ft, span.max(10 * 10_000_000)).and_then(|r| r.parse::<rec::ProcessSample>());
    let mut table: HashMap<u32, rec::ProcRow> = HashMap::new();
    if let Some(f) = full {
        for mut r in f.rows {
            r.1 = 0;
            r.6 = 0;
            r.7 = 0;
            r.8 = 0;
            r.9 = 0;
            table.insert(r.0, r);
        }
    }
    if let Some(s) = near_sample {
        for r in s.rows {
            table.insert(r.0, r);
        }
    }
    let mut rows: Vec<rec::ProcRow> = table.into_values().collect();
    rows.sort_by_key(|r| (std::cmp::Reverse(r.1), std::cmp::Reverse(r.3)));
    let procs: Vec<Value> = rows
        .iter()
        .take(40)
        .map(|r| json!({"name": name(r.0), "pid": r.0, "cpu": r.1 as f64 / 10.0, "ws_mb": r.2 / 1024, "private_mb": r.3 / 1024, "handles": r.4, "threads": r.5, "io_kbs": (r.6 + r.7 + r.8) / 1024, "faults": r.9}))
        .collect();
    let pdh = nearest(win, RecordType::PdhSample, ft, span.max(10 * 10_000_000)).map(|r| r.data.clone());
    let rows = |t: RecordType| -> Vec<Value> {
        let mut v: Vec<Value> = near.iter().filter(|r| r.is(t)).flat_map(|r| r.data.get("rows").and_then(|x| x.as_array()).cloned().unwrap_or_default()).collect();
        v.truncate(80);
        v
    };
    let events: Vec<&Value> = st.events.as_array().map(|a| a.iter().filter(|e| (e["t"].as_f64().unwrap_or(0.0) - ft_ms(ft)).abs() <= span as f64 / 10_000.0).take(100).collect()).unwrap_or_default();
    json!({
        "t": ft_ms(ft),
        "vitals": vit.map(|h| json!({"cpu": h.vitals.cpu, "commit": h.vitals.commit_pct, "avail": h.vitals.avail_mb, "disk_ms": h.vitals.disk_ms, "queue": h.vitals.disk_q, "late": h.jitter_ms, "top": h.vitals.top})),
        "procs": procs,
        "pdh": pdh,
        "net": rows(RecordType::NetFlows),
        "dns": rows(RecordType::DnsQueries),
        "disk": rows(RecordType::DiskActivity),
        "files": rows(RecordType::FileActivity),
        "registry": rows(RecordType::RegistryActivity),
        "events": events,
    })
}

/// Black-box file start times from their names (bb-YYYYMMDD-HHMMSS-mmm.etl,
/// local time), sorted.
fn index_etl(files: &[PathBuf]) -> Vec<(i64, PathBuf)> {
    let mut v: Vec<(i64, PathBuf)> = files
        .iter()
        .filter_map(|p| {
            let stem = p.file_stem()?.to_str()?.strip_prefix("bb-")?;
            let parts: Vec<&str> = stem.split('-').collect();
            let s = format!("{}{}", parts.first()?, parts.get(1)?);
            let ndt = chrono::NaiveDateTime::parse_from_str(&s, "%Y%m%d%H%M%S").ok()?;
            let ms: i64 = parts.get(2).and_then(|m| m.parse().ok()).unwrap_or(0);
            let local = chrono::TimeZone::from_local_datetime(&chrono::Local, &ndt).earliest()?;
            Some((bbx_core::time::utc_to_ft(local.with_timezone(&chrono::Utc)) + ms * FT_PER_MS, p.clone()))
        })
        .collect();
    v.sort();
    if v.len() < files.len() {
        // Unrecognised names: let the reader sort it out.
        return files.iter().map(|p| (0, p.clone())).collect();
    }
    v
}

fn etl(st: &State, q: &HashMap<String, String>) -> Result<Value> {
    let from = q.get("from").and_then(|v| v.parse::<f64>().ok()).ok_or_else(|| anyhow!("from missing"))?;
    let to = q.get("to").and_then(|v| v.parse::<f64>().ok()).ok_or_else(|| anyhow!("to missing"))?;
    if to <= from || to - from > MAX_ETL_WINDOW_MS {
        return Err(anyhow!("choose a window of at most {} seconds", MAX_ETL_WINDOW_MS / 1000.0));
    }
    let (from_ft, to_ft) = (ms_ft(from), ms_ft(to));
    // Files whose span [start_i, start_{i+1}) overlaps the window.
    let idx = &st.etl_index;
    let files: Vec<PathBuf> = if idx.iter().all(|(t, _)| *t > 0) {
        idx.iter()
            .enumerate()
            .filter(|(i, (start, _))| *start <= to_ft && idx.get(i + 1).is_none_or(|(next, _)| *next >= from_ft))
            .map(|(_, (_, p))| p.clone())
            .collect()
    } else {
        idx.iter().map(|(_, p)| p.clone()).collect()
    };
    let kinds: Vec<String> = q.get("kinds").map(|k| k.split(',').filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default();
    let (rows, stats) = etlread::read(
        &files,
        etlread::Query {
            from_ft,
            to_ft,
            max_rows: 20_000,
            filter: q.get("q").cloned().filter(|s| !s.is_empty()),
            kinds,
            reads: q.get("reads").is_some_and(|v| v == "1"),
            names: st.names.clone(),
        },
    )?;
    let rows: Vec<Value> = rows.into_iter().map(|r| json!({"t": ft_ms(r.ft), "pid": r.pid, "tid": r.tid, "proc": r.proc, "kind": r.kind, "op": r.op, "path": r.path, "detail": r.detail})).collect();
    Ok(json!({"rows": rows, "stats": stats}))
}

fn digest(st: &State) -> String {
    let mut g = st.digest.lock().unwrap();
    if g.is_none() {
        *g = Some(crate::digest::build(&st.ds, &st.suspects));
    }
    g.clone().unwrap()
}

fn start_ai(st: &Arc<State>, question: Option<String>, followup: bool) -> bool {
    {
        let mut job = st.ai.lock().unwrap();
        if job.status == "running" {
            return false;
        }
        let previous = (followup && job.status == "done").then(|| job.text.clone());
        *job = AiJob { status: "running".into(), question: question.clone(), ..Default::default() };
        let st2 = st.clone();
        std::thread::spawn(move || {
            let d = digest(&st2);
            let res = ai::analyze(&st2.model, &d, question.as_deref(), previous.as_deref(), |chunk| {
                st2.ai.lock().unwrap().text.push_str(chunk);
            });
            let mut job = st2.ai.lock().unwrap();
            match res {
                Ok(r) => {
                    job.text = r.text.clone();
                    job.result = Some(r);
                    job.status = "done".into();
                }
                Err(e) => {
                    job.error = Some(format!("{e:#}"));
                    job.status = "error".into();
                }
            }
        });
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing() {
        let q = query("/api/etl?k=abc&q=C%3A%5CUsers+x&from=1.5");
        assert_eq!(q["q"], "C:\\Users x");
        assert_eq!(q["from"], "1.5");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn etl_names_index() {
        let v = index_etl(&[PathBuf::from("bb-20261119-221500-250.etl"), PathBuf::from("bb-20261119-221300-000.etl")]);
        assert!(v[0].0 < v[1].0);
        assert!(v[0].1.ends_with("bb-20261119-221300-000.etl"));
    }
}
