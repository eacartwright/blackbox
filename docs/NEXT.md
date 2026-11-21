# What's next

Status as of 2026-11-19: all four phases are built and on `main`, and 73
tests pass. The service, tray agent and both ETW sessions are installed and
running on the development machine (NOSTROMO). This file is the hand-off
list for the next session.

## 1. Finish and verify (small, do first)

- [ ] **Reinstall to apply the permissions fix.** The installer now sets the
  data folder to exactly SYSTEM + Administrators (`set_exact_dacl` in
  `crates/bbx/src/install.rs`). On NOSTROMO the folder still has an extra
  `NOSTROMO\evan:(F)` entry, probably added by Explorer's "Continue" prompt.
  Run `target\release\bbx.exe install` elevated, then check
  `icacls C:\ProgramData\BlackBox` shows only SYSTEM and Administrators.
- [ ] **A real Claude call.** The client is tested only against a mock server.
  Set `ANTHROPIC_API_KEY` and run `bbx analyze <bundle>`, or use the viewer's
  Claude tab, then judge the answer's quality on a real incident.
- [ ] **pktmon ring**, elevated: set `"packet_capture": true` in
  `C:\ProgramData\BlackBox\config.json`, restart the service, mark an
  incident, and confirm the incident folder gets a `packets.pcapng` that
  opens in Wireshark.
- [ ] **SATA SMART on real hardware.** NOSTROMO has only NVMe drives, so the
  ATA attribute parser is covered only by a unit test with made-up data.
- [ ] **Black-box drill-down on a real bundle.** Export an incident *with*
  `.etl` files (omit `--no-etl`), open it in `bbx view`, and use the Black box
  tab. Check that file and registry paths resolve and that registry value
  names look right; the kernel event layouts were inferred, not observed.

## 2. Known issues and rough edges

- **First-run backfill can open incidents.** Event-log entries up to 5
  minutes old trigger detectors (`detect::match_event`). On a first install
  that can open incidents for things that happened just before recording.
  Consider ignoring events older than the service's start time.
- **Recording gap while the service is down.** Only the kernel black box
  keeps running. A watchdog task (Task Scheduler) that alerts when the
  service is stopped would make outages visible sooner.
- **Localisation.** `takeown /D Y` in the installer's fallback assumes an
  English "Y". Replace the `icacls`/`takeown` calls with Win32 ACL code (there
  is already `set_exact_dacl`) to remove locale and parsing issues entirely.
- **Viewer black-box window** is limited to 5 minutes and 20,000 rows per
  load. Fine for drill-down, but no "search the whole trace" yet.
- **Temperatures:** CPU and GPU sensors beyond ACPI thermal zones aren't
  collected (they need vendor libraries or a kernel driver).
- **Deep profile** (`"profile": "deep"`) adds kernel flags but no stack
  walks and no DxgKrnl GPU scheduling events yet.

## 3. Next features (bigger)

1. **Code signing and release builds.** A setup exe exists
   (`installer\blackbox.iss`, built by `scripts\build-installer.ps1`). Still
   to do: sign `bbx.exe`, `bbx-agent.exe` and the setup so EDR and
   SmartScreen don't block them (needs a code-signing certificate), and add
   GitHub Actions to build, test and attach the setup to releases.
2. **Fleet use.** Optional upload of encrypted incident bundles to a
   location the technician controls (a share, S3 or Azure blob), plus a
   simple inbox in the viewer.
3. **Automatic first-pass analysis.** When an incident opens, build the
   digest; the technician's machine analyzes queued bundles with Claude and
   shows the narrative next to the incident.
4. **Tray agent polish.** A "describe what happened" note box on "It just
   happened", a status window, and localised text.
5. **Viewer.** Compare two incidents side by side, process tree view, export
   the current view as a report (HTML or PDF), and light/dark toggle.
6. **Storage.** Optionally convert sealed journal segments to a columnar
   format for faster range queries over weeks of data.

## 4. Where things live

| Area | Code |
|---|---|
| Journal format, record types, classifier, config | `crates/bbx-core/src/` |
| Collectors (samplers, event log, ETW black box and live, hardware, pktmon) | `crates/bbx-collect/src/` |
| Detector rules | `crates/bbx-collect/src/detect.rs` |
| Service, installer, CLI, incidents, export, ingest | `crates/bbx/src/` |
| Viewer server and page | `crates/bbx/src/viewer.rs`, `crates/bbx/src/web/index.html` |
| Suspects, digest, Claude client | `crates/bbx/src/suspects.rs`, `digest.rs`, `ai.rs` |
| Tray agent | `crates/bbx-agent/src/` |

### Tray icon wording

All user-facing text of the tray agent is in `crates/bbx-agent/src/main.rs`:

| Text | Where |
|---|---|
| Hover tooltip (max 127 characters) | `add_tray()`: `copy_into(&mut nid.szTip, "...")` |
| Right-click menu items | `show_menu()`: the `AppendMenuW(...)` calls |
| Tooltip when recording / stopped | `TIP_RECORDING`, `TIP_STOPPED` constants |
| "Recording stopped / started" notifications | `on_tick()`: the `balloon(...)` after the service-state check |
| "About BlackBox" dialog | `show_menu()`: the `MessageBoxW(...)` text and title |
| "Exit…" confirmation and "still running" notification | `exit()` |
| Notification after "It just happened" | `mark()`: `balloon(a.hwnd, "<title>", "<text>")` (title max 63, text max 255 characters) |
| The hotkey (Ctrl+Alt+Shift+B) | `main()`: `RegisterHotKey(...)`; update the tooltip and menu text to match |

Rebuild with `cargo build --release`, then reinstall elevated
(`target\release\bbx.exe install`); the installer replaces
`bbx-agent.exe` and restarts the agent for the current user.
