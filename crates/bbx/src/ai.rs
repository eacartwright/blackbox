//! Claude analysis of a digest via the Messages API (raw HTTPS: there is no
//! official Rust SDK). Streams the answer so long analyses don't hit HTTP
//! timeouts, retries rate limits and server errors, caches the digest so
//! follow-up questions about the same incident are cheap, and opts into
//! server-side refusal fallbacks.
//!
//! Credentials: ANTHROPIC_API_KEY (x-api-key) or ANTHROPIC_AUTH_TOKEN
//! (Bearer). ANTHROPIC_BASE_URL overrides the endpoint (tests, proxies).

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_MODEL: &str = "claude-opus-5-5";
const API_VERSION: &str = "2026-10-21";
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
const OAUTH_BETA: &str = "oauth-2025-04-20";
const MAX_TOKENS: u32 = 64_000;
const MAX_ATTEMPTS: u32 = 4;

pub const SYSTEM_PROMPT: &str = r#"You are a senior Windows support engineer. You are reading data from BlackBox, a flight recorder that was running on a user's Windows PC when something went wrong (a freeze, crash, black screen, slowdown, unexpected restart, or a moment the user marked).

The user message contains a digest of the recording:
- machine and time window, the moment of interest, and any incident or user note;
- a verdict on how the previous boot ended (clean shutdown, bugcheck, hang then forced power-off, forced off while Windows was still running, abrupt stop, ...), derived from BlackBox's own heartbeats plus Windows boot records;
- rule-based suspects: deterministic findings with scores and evidence;
- disk health (SMART / NVMe health log);
- a situation report: once-a-second vitals (CPU, commit, free RAM, disk latency and queue, heartbeat lateness, busiest process), top processes, memory and kernel-pool growth, crashed processes with exit codes, slowest disk I/O, network and DNS activity, file and registry writes, and a timeline of events (process starts and exits, Windows event logs, device changes, driver loads, user-session events such as hung windows, the display turning off, UI stalls).

Your job is to work out what most likely happened and what the technician should do next.

How to reason:
- Base every claim on the digest. Quote the times and values you rely on.
- Separate cause from symptom (a hung app is often a symptom of disk or memory starvation) and correlation from causation.
- Treat the rule-based suspects as leads to confirm, reject or re-rank, not as conclusions. Say when you disagree and why.
- Know the recorder's limits: counters are sampled every 1-2 seconds; when the verdict is an abrupt stop, software cannot tell a power loss from an instant total freeze followed by a forced power-off; the detailed kernel trace (black box) is not in the digest, but the technician can open it in the BlackBox viewer, so say which time window and which kind of activity (file, registry, disk, network, process) is worth inspecting there.
- Do not invent driver names, KB numbers or settings that the data does not support. If the evidence is thin, say so plainly and say what would settle it.

Write for an IT technician, in Markdown, with these sections:
## What happened
Two to four sentences, including when.
## Most likely cause
Ranked candidates, each with a confidence (high, medium or low) and the specific evidence.
## Ruled out or unlikely
What the data argues against, briefly.
## Gaps
What is missing from the data that would confirm or eliminate the top candidates.
## Next steps
Concrete checks, commands and fixes, most valuable first.
## For the user
Two or three sentences in plain, non-technical language that the technician can pass on."#;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct AiResult {
    pub text: String,
    pub model: String,
    pub stop_reason: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    /// Set when a fallback model answered after the primary declined.
    pub fallback: bool,
}

#[derive(Clone)]
pub struct Credentials {
    header: (&'static str, String),
    oauth: bool,
}

pub fn credentials() -> Result<Credentials> {
    if let Some(k) = std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.trim().is_empty()) {
        return Ok(Credentials { header: ("x-api-key", k.trim().to_string()), oauth: false });
    }
    if let Some(t) = std::env::var("ANTHROPIC_AUTH_TOKEN").ok().filter(|k| !k.trim().is_empty()) {
        return Ok(Credentials { header: ("authorization", format!("Bearer {}", t.trim())), oauth: true });
    }
    bail!("set ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) to use Claude analysis")
}

fn base_url() -> String {
    std::env::var("ANTHROPIC_BASE_URL").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "https://api.anthropic.com".into()).trim_end_matches('/').to_string()
}

pub fn request_body(model: &str, digest: &str, question: Option<&str>, previous: Option<&str>) -> Value {
    let mut content = vec![json!({
        "type": "text",
        "text": digest,
        // The digest is the large, stable part: cache it so follow-ups reuse it.
        "cache_control": {"type": "ephemeral"}
    })];
    let ask = match (question, previous) {
        (Some(q), Some(p)) => format!("Your earlier analysis of this digest:\n\n{p}\n\nFollow-up question from the technician: {q}\n\nAnswer the question directly; use the section structure only if it helps."),
        (Some(q), None) => format!("Analyze the digest above. The technician also asks: {q}"),
        (None, _) => "Analyze the digest above.".to_string(),
    };
    content.push(json!({"type": "text", "text": ask}));
    json!({
        "model": model,
        "max_tokens": MAX_TOKENS,
        "stream": true,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "high"},
        "fallbacks": "default",
        "system": [{"type": "text", "text": SYSTEM_PROMPT}],
        "messages": [{"role": "user", "content": content}]
    })
}

fn agent() -> Result<ureq::Agent> {
    let tls = native_tls::TlsConnector::new().map_err(|e| anyhow!("TLS setup failed: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(600))
        .try_proxy_from_env(true)
        .build())
}

/// Run an analysis. `on_text` receives the answer as it streams.
pub fn analyze(model: &str, digest: &str, question: Option<&str>, previous: Option<&str>, mut on_text: impl FnMut(&str)) -> Result<AiResult> {
    let creds = credentials()?;
    let body = request_body(model, digest, question, previous).to_string();
    let url = format!("{}/v1/messages", base_url());
    let agent = agent()?;
    let mut beta = FALLBACK_BETA.to_string();
    if creds.oauth {
        beta = format!("{beta},{OAUTH_BETA}");
    }
    let mut attempt = 0;
    loop {
        attempt += 1;
        let resp = agent
            .post(&url)
            .set(creds.header.0, &creds.header.1)
            .set("anthropic-version", API_VERSION)
            .set("anthropic-beta", &beta)
            .set("content-type", "application/json")
            .send_string(&body);
        match resp {
            Ok(r) => return read_stream(BufReader::new(r.into_reader()), &mut on_text),
            Err(ureq::Error::Status(code, r)) => {
                let retry_after = r.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok());
                let text = r.into_string().unwrap_or_default();
                let msg = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v.pointer("/error/message").and_then(|m| m.as_str()).map(String::from))
                    .unwrap_or(text);
                let retryable = matches!(code, 408 | 409 | 429 | 500 | 502 | 503 | 504 | 529);
                if retryable && attempt < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(retry_after.unwrap_or(2u64.pow(attempt)).min(60)));
                    continue;
                }
                bail!(match code {
                    401 => format!("authentication failed (401): check ANTHROPIC_API_KEY. {msg}"),
                    403 => format!("permission denied (403): {msg}"),
                    404 => format!("not found (404): is the model id '{model}' right? {msg}"),
                    413 => format!("request too large (413): {msg}"),
                    429 => format!("rate limited (429) after {attempt} attempts: {msg}"),
                    _ => format!("API error {code}: {msg}"),
                });
            }
            Err(ureq::Error::Transport(t)) => {
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                    continue;
                }
                bail!("could not reach the Claude API: {t}");
            }
        }
    }
}

/// Parse the server-sent event stream of a Messages response.
pub fn read_stream(r: impl BufRead, on_text: &mut dyn FnMut(&str)) -> Result<AiResult> {
    let mut out = AiResult::default();
    let mut refusal: Option<String> = None;
    for line in r.lines() {
        let line = line?;
        let Some(data) = line.strip_prefix("data:") else { continue };
        let Ok(v) = serde_json::from_str::<Value>(data.trim()) else { continue };
        match v.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "message_start" => {
                let m = &v["message"];
                out.model = m["model"].as_str().unwrap_or("").into();
                let u = &m["usage"];
                out.input_tokens = u["input_tokens"].as_u64().unwrap_or(0);
                out.cache_read_tokens = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                out.cache_write_tokens = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
            }
            "content_block_start" => {
                if v["content_block"]["type"] == "fallback" {
                    out.fallback = true;
                    if let Some(m) = v["content_block"]["to"]["model"].as_str() {
                        out.model = m.into();
                    }
                }
            }
            "content_block_delta" => {
                if v["delta"]["type"] == "text_delta" {
                    if let Some(t) = v["delta"]["text"].as_str() {
                        out.text.push_str(t);
                        on_text(t);
                    }
                }
            }
            "message_delta" => {
                if let Some(s) = v["delta"]["stop_reason"].as_str() {
                    out.stop_reason = s.into();
                    if s == "refusal" {
                        let d = &v["delta"]["stop_details"];
                        refusal = Some(format!(
                            "the model declined to analyze this ({}{})",
                            d["category"].as_str().unwrap_or("no category"),
                            d["explanation"].as_str().map(|e| format!(": {e}")).unwrap_or_default()
                        ));
                    }
                }
                if let Some(n) = v["usage"]["output_tokens"].as_u64() {
                    out.output_tokens = n;
                }
            }
            "error" => {
                let e = &v["error"];
                bail!("API error during streaming ({}): {}", e["type"].as_str().unwrap_or("error"), e["message"].as_str().unwrap_or(""));
            }
            _ => {}
        }
    }
    if let Some(r) = refusal {
        bail!(r);
    }
    if out.stop_reason == "max_tokens" {
        out.text.push_str("\n\n[answer cut off at the output limit]");
    }
    if out.stop_reason.is_empty() {
        bail!("the response stream ended unexpectedly");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSE: &str = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5-5\",\"usage\":{\"input_tokens\":12,\"cache_read_input_tokens\":30000,\"cache_creation_input_tokens\":0}}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"## What happened\\nThe disk \"}}\n\n\
event: ping\n\
data: {\"type\":\"ping\"}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"stalled.\"}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":321}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

    #[test]
    fn parses_stream() {
        let mut seen = String::new();
        let r = read_stream(SSE.as_bytes(), &mut |t| seen.push_str(t)).unwrap();
        assert_eq!(r.text, "## What happened\nThe disk stalled.");
        assert_eq!(seen, r.text);
        assert_eq!((r.output_tokens, r.cache_read_tokens), (321, 30000));
        assert_eq!(r.stop_reason, "end_turn");
    }

    #[test]
    fn refusal_and_errors_are_reported() {
        let refused = "data: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"usage\":{}}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\",\"stop_details\":{\"type\":\"refusal\",\"category\":\"cyber\",\"explanation\":null}},\"usage\":{\"output_tokens\":0}}\n\n";
        assert!(read_stream(refused.as_bytes(), &mut |_| {}).unwrap_err().to_string().contains("cyber"));
        let err = "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n";
        assert!(read_stream(err.as_bytes(), &mut |_| {}).unwrap_err().to_string().contains("overloaded_error"));
        assert!(read_stream("".as_bytes(), &mut |_| {}).is_err(), "a cut-off stream is an error");
    }

    #[test]
    fn body_shape() {
        let b = request_body(DEFAULT_MODEL, "DIGEST", Some("why?"), None);
        assert_eq!(b["model"], "claude-opus-5-5");
        assert_eq!(b["thinking"]["type"], "adaptive");
        assert_eq!(b["output_config"]["effort"], "high");
        assert_eq!(b["fallbacks"], "default");
        assert_eq!(b["stream"], true);
        assert_eq!(b["messages"][0]["content"][0]["cache_control"]["type"], "ephemeral");
        assert!(b.get("temperature").is_none(), "sampling params are rejected on this API version");
    }

    /// End to end against a local mock server speaking SSE.
    #[test]
    fn talks_to_a_mock_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 1 << 20];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some(h) = text.find("\r\n\r\n") {
                    let len: usize = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if got.len() >= h + 4 + len {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&got).to_string();
            let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{SSE}", SSE.len());
            s.write_all(resp.as_bytes()).unwrap();
            req
        });
        std::env::set_var("ANTHROPIC_BASE_URL", format!("http://127.0.0.1:{port}"));
        std::env::set_var("ANTHROPIC_API_KEY", "test-key");
        let r = analyze(DEFAULT_MODEL, "DIGEST", None, None, |_| {}).unwrap();
        assert!(r.text.contains("disk stalled"));
        let req = srv.join().unwrap().to_ascii_lowercase();
        assert!(req.starts_with("post /v1/messages"));
        assert!(req.contains("x-api-key: test-key"));
        assert!(req.contains("anthropic-version: 2026-10-21"));
        assert!(req.contains("anthropic-beta: server-side-fallback-2026-07-01"));
    }
}
