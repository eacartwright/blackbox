//! Contract between the per-user agent (bbx-agent.exe, runs as the user)
//! and the service (runs as SYSTEM). Communication is by files, so it
//! survives either side restarting:
//!
//! * agent -> service, in `triggers\` (users may create files there only):
//!   - `mark-<ft>-<pid>.json`   the user pressed "It just happened"
//!   - `ua-<session>-<ft>.jsonl` batches of [`AgentLine`]
//!   - `shot-<tag>-<ft>.png`     screenshot frames (tag = incident id, "mark" or "hung")
//! * service -> agent, in `public\` (readable by users):
//!   - `agent.json`    [`AgentSettings`]
//!   - `incident.json` [`IncidentSignal`] for the newest incident
//!
//! Everything the agent writes is untrusted: the service size-caps, parses
//! and clamps it, and only waits for files at least 2 s old (the agent
//! writes in place, without renaming).

use crate::records::UserEvent;
use serde::{Deserialize, Serialize};

pub const MARK_PREFIX: &str = "mark-";
pub const UA_PREFIX: &str = "ua-";
pub const SHOT_PREFIX: &str = "shot-";
pub const MAX_UA_FILE: u64 = 256 * 1024;
pub const MAX_SHOT_FILE: u64 = 2 * 1024 * 1024;
pub const MAX_MARK_FILE: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AgentSettings {
    pub screenshots: bool,
    pub screenshot_interval_s: u64,
    pub screenshot_frames: usize,
    pub screenshot_width: u32,
    pub hung_window_s: u64,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self { screenshots: false, screenshot_interval_s: 5, screenshot_frames: 24, screenshot_width: 800, hung_window_s: 5 }
    }
}

impl AgentSettings {
    pub fn from_config(c: &crate::config::Config) -> Self {
        Self {
            screenshots: c.screenshots,
            screenshot_interval_s: c.screenshot_interval_s.clamp(1, 600),
            screenshot_frames: c.screenshot_frames.clamp(1, 240),
            screenshot_width: c.screenshot_width.clamp(160, 3840),
            hung_window_s: c.hung_window_s.clamp(1, 600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct IncidentSignal {
    pub id: String,
    pub at_ft: i64,
    pub from_ft: i64,
    pub to_ft: i64,
}

/// One line of a `ua-*.jsonl` file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentLine {
    pub ft: i64,
    #[serde(flatten)]
    pub ev: UserEvent,
}

/// The mark file body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MarkFile {
    pub note: String,
    pub user: String,
    pub session: u32,
    pub foreground: String,
}

pub fn shot_name(tag: &str, ft: i64) -> String {
    let tag: String = tag.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(80).collect();
    format!("{SHOT_PREFIX}{tag}~{ft}.png")
}

/// `shot-<tag>~<ft>.png` -> (tag, ft)
pub fn parse_shot_name(name: &str) -> Option<(String, i64)> {
    let rest = name.strip_prefix(SHOT_PREFIX)?.strip_suffix(".png")?;
    let (tag, ft) = rest.rsplit_once('~')?;
    Some((tag.to_string(), ft.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shot_names_roundtrip() {
        let n = shot_name("20261119-215712-manual", 133_000_000_000_000_000);
        assert_eq!(parse_shot_name(&n), Some(("20261119-215712-manual".into(), 133_000_000_000_000_000)));
        assert_eq!(parse_shot_name(&shot_name("../../evil", 5)).unwrap().0, "evil");
        assert!(parse_shot_name("shot-x.png").is_none());
    }

    #[test]
    fn agent_line_flattens() {
        let l = AgentLine { ft: 7, ev: UserEvent { kind: "hung".into(), proc: "excel.exe".into(), value: 12.0, ..Default::default() } };
        let s = serde_json::to_string(&l).unwrap();
        assert!(s.contains("\"ft\":7") && s.contains("\"kind\":\"hung\""));
        let back: AgentLine = serde_json::from_str(&s).unwrap();
        assert_eq!(back.ev.proc, "excel.exe");
    }
}
