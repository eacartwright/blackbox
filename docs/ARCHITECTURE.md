# BlackBox — architecture

BlackBox is a flight recorder for Windows. It is installed on a problem machine,
records continuously with a small, fixed resource budget, and answers the
question technicians actually get asked: **"it locked up at 4:30 — what was the
machine doing just before?"**

It is built to survive the failures it is meant to explain: hard hangs, black
screens, bugchecks, collector crashes and pulled power cords.

---

## 1. Goals and non-goals

**Goals**

1. *Always on, low cost.* Target < 1% average CPU, < 20 MB resident for the
   collector, and a hard disk cap (default 5 GB across all tiers).
2. *Durable.* After a power cut, at most ~1 second of summary data is lost, the
   on-disk data is never unreadable, and the last record tells you what the
   machine looked like right before it died.
3. *Complete.* Covers resource usage (CPU, memory, commit, pool, disk, network,
   GPU, thermal), activity (processes with full command lines, file, registry,
   network, DNS, drivers, devices, services, scheduled tasks), and Windows' own
   evidence (event logs, crash dumps, shutdown reasons).
4. *One place to look.* Everything ends up in one timeline, with automatic
   "suspects" and an AI narrative on top of the raw data.

**Non-goals**

- No kernel driver. Everything uses supported user-mode interfaces (ETW, NT
  query APIs, PDH, Config Manager, the event log). This avoids driver signing,
  and a bug in BlackBox can never bugcheck the client.
- Not a security product. It records security-relevant data, but it isn't
  designed to resist a hostile administrator.

---

## 2. Components

```
 Client machine                                         Technician machine
 ┌──────────────────────────────────────────────┐     ┌─────────────────────┐
 │ bbx-svc.exe  (Windows service, LocalSystem)  │     │ Viewer (phase 4)    │
 │  ├─ Heartbeat            1 s                 │     │  timeline playback  │
 │  ├─ System sampler       2 s  (+pool 30 s)   │     │  suspects / rules   │
 │  ├─ Process sampler      2 s                 │     │  AI narrative       │
 │  ├─ PDH sampler          2–5 s (disk/net/GPU │     └──────────▲──────────┘
 │  │                       /thermal/CPU perf)  │                │
 │  ├─ Device watcher       5 s (CfgMgr diff)   │       incident bundle (.zip)
 │  ├─ Event log collector  push (EvtSubscribe) │                │
 │  ├─ Live ETW consumer    push (phase 2)      │     ┌──────────┴──────────┐
 │  ├─ Black-box ETW ctrl   kernel-written ETL  │     │ bbx.exe (CLI)       │
 │  ├─ Shutdown classifier  once per boot       │────▶│ status / export /   │
 │  └─ Incident manager     triggers (phase 2)  │     │ last-shutdown / mark│
 └──────────────────────────────────────────────┘     └─────────────────────┘
          │ writes
          ▼
 %ProgramData%\BlackBox\
   journal\     summary tier — crash-safe append-only segments
   blackbox\    detail tier — ETW .etl segments written by the kernel
   incidents\   saved windows around triggers (hard links + exports)
   state\       run marker, event-log positions, config
   triggers\    drop-box for "it just happened" marks (user-writable)
```

The collector and CLI are written in **Rust** (memory-safe, no GC, a single
static exe, ~5–15 MB resident). The viewer has none of the client-side
constraints and can be any stack. Every on-disk format is documented here and
language-neutral.

---

## 3. Data tiers

### Tier 1 — the black box (high detail, fixed budget)

An ETW session that the **kernel writes directly to disk**. BlackBox never
parses it while recording, which is why Procmon-level detail costs almost
nothing.

- Mode: `EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE`.
  The service switches the session to a fresh file (`bb-<timestamp>.etl`)
  with `ControlTrace(EVENT_TRACE_CONTROL_UPDATE)` when the current file
  reaches 64 MB or 2 minutes old, so every file except the newest is **closed
  and complete** at any moment. That's what makes the tier survive power loss.
  A single circular file would be left unfinalized. (System-logger sessions
  reject the kernel's own auto-rolling NEWFILE mode with
  `ERROR_INVALID_PARAMETER`; verified on Windows 11 25H2.) Each file is
  also capped by the kernel at 4× the roll size, so a dead service can't
  fill the disk.
- `FlushTimer = 1 s`, so buffers reach disk within a second even on an idle
  machine.
- The session belongs to the kernel, not the service. If the service crashes,
  recording continues. On restart the service finds the session by name and
  takes it over again.
- One set of files per boot. After an unexpected shutdown, the previous boot's
  files are already there, untouched.
- Retention: oldest segments are pruned to keep the tier under budget
  (default 2 GB). Segments that an incident links to survive pruning because
  they're NTFS hard links.
- Profiles:
  - **standard**: process, thread, image load, disk I/O (with file names),
    file I/O, registry, TCP/IP, hard faults, plus the Kernel-Power, Kernel-PnP,
    StorPort and DNS-Client providers.
  - **deep**: adds context switches, DPC/ISR, sampled CPU profile, stacks and
    DxgKrnl GPU scheduling. Much higher volume; use for targeted
    investigations.

Expected history in the standard profile is ~15–60 minutes on an office PC.
That's why tier 2 exists, and why incidents copy out the black-box window.

### Tier 2 — the journal (summary, days of history)

The service's own record of the machine, written with a format built for crash
safety (section 4). Roughly 50–150 MB per day before compression and
5–20 MB per day after, kept for 30 days or 1.5 GB.

| Record | Cadence | Content |
|---|---|---|
| `Heartbeat` | 1 s | monotonic clock, boot id, vitals (CPU, commit, available memory, worst disk latency and queue, top CPU process) |
| `SystemSample` | 2 s | CPU split, commit / limit, physical memory, cache, kernel paged/nonpaged pool, handle/process/thread totals |
| `PoolSample` | 30 s | top pool tags by bytes, plus any tag that's growing (driver leaks) |
| `ProcessSample` | 2 s | compact rows for *active* processes only (CPU, working set, private, handles, threads, I/O rates, hard faults); full table every 60 s |
| `ProcessStart` / `ProcessEnd` | on change | pid, create time, parent, session, user, image path, **full command line**; exit code and lifetime totals on exit |
| `PdhSample` | 2–5 s | per-disk latency / queue / throughput / idle, per-NIC rates, GPU engine use by process and engine type, GPU memory, CPU utility and **% performance (throttling)**, DPC/interrupt time, thermal zones and **passive (thermal) limit**, paging rate |
| `Device` | on change | device added/removed, device **entering or leaving a problem code** (e.g. Code 43) |
| `EventLog` | push | System (all), Application (warnings and up plus hangs/WER), and ~15 operational channels (Task Scheduler, Kernel-PnP, Storport, Defender, Windows Update, WLAN, thermal, Resource-Exhaustion…) with rendered message and event data |
| `ShutdownVerdict` | once per boot | how the previous boot ended (section 5) |
| `Incident`, `Note` | on trigger | incident markers and user-supplied notes |
| `CollectorStatus` | on change | collector errors, dropped events, budget actions; BlackBox reports on itself |

The live ETW consumer (below) adds `NetFlows`, `DnsQueries`, `DiskActivity`,
`FileActivity`, `RegistryActivity` and `DriverLoad`, and exact
`ProcessStart`/`ProcessEnd` records with exit codes.

### Live ETW consumer (phase 2)

A second kernel session, `BlackBox-Live`, runs in real-time mode and is
decoded inside the service. TDH (Windows' event schema API) is consulted
once per event type to learn property names, types and lengths; after that
each event is decoded by reading its bytes directly. Events that aren't used
(file reads, registry queries, ...) are rejected by (event class, opcode)
before any decoding, so for most of the stream the per-event cost is one
GUID comparison.

- Flags: process, thread, image load, disk I/O, disk file names, TCP/IP,
  registry, file I/O initiation; plus the DNS-Client provider.
- Kept state: thread to process, file object to path (from name/create
  events), registry KCB to key path (from KCB create/rundown events), pid to
  image name. All maps are bounded.
- Output every 10 s: `NetFlows`, `DnsQueries`, `DiskActivity`,
  `FileActivity`, `RegistryActivity` (top rows by weight plus must-keep rows
  such as deletes, renames, failures and I/O slower than 500 ms; `dropped`
  counts the rest), and immediately: `ProcessStart` (command line, user),
  `ProcessEnd` (**exit code**), `DriverLoad`.
- While the live consumer is running, the process sampler stops emitting
  start/end records (ETW's are exact and include short-lived processes) but
  keeps the inventory and per-process resource rows.
- If the service dies, the live session is replaced on the next start; it
  never outlives `bbx uninstall`.

### Tier 3 — incidents

Triggers:

- **Manual:** `bbx mark "note"` (phase 3 adds a tray button and hotkey).
- **Vitals:** CPU at or above 95% for 30 s, commit at or above 90% for 10 s,
  under 256 MB RAM free for 10 s, disk latency at or above 1 s for 5 s, a
  heartbeat more than 3 s late (the whole system stalled).
- **Events** (only if less than 5 minutes old, so backfill and boot replay
  never trigger): display TDR (Display 4101), WHEA errors, storage
  controller resets (storahci/stornvme/... 129), disk errors (7, 11, 51, 153,
  157), NTFS errors, application hangs (1002) and crashes (1000), resource
  exhaustion (2004), firmware CPU throttling (Kernel-Processor-Power 37),
  services terminating unexpectedly (7031, 7034), and live kernel events
  (driver watchdogs).
- **Devices:** a disk, display, storage or network adapter disappearing or
  entering a problem code.
- **Pool:** any kernel pool tag growing by another 1 GB since recording
  started (driver leak).
- **Unplanned shutdown:** at boot, a verdict of bugcheck, hang, forced
  power-off, degraded reset, abrupt stop or sleep failure opens an incident
  for the 15 minutes before the last heartbeat. That saves the previous
  boot's black box before pruning can reach it.

Each kind has a 10-minute cooldown, and at most 6 automatic incidents are
opened per hour (manual marks are never limited). An incident writes an
`Incident` journal record and gets a folder with `incident.json`, hard links
to the black-box files for the window, System and Application `.evtx`
exports, and `summary.txt` (the `bbx around` report). For a live trigger it
first waits `incident_after_s` (60 s) to capture the aftermath.

`bbx export` packs a time range or an incident into a self-contained zip:
`records.jsonl` (every journal record as JSON lines), `summary.txt`,
`verdict.json`, `.evtx` exports, black-box `.etl` files (optional),
minidumps, the incident folder and a `manifest.json`. This is the hand-off
format for the phase 4 viewer and AI analysis.

### User-session agent (phase 3)

`bbx-agent.exe` (a GUI-subsystem exe, no console) starts at every sign-in
from the HKLM Run key and runs as the user, one per session. It sees what a
SYSTEM service in session 0 cannot:

| Event (`UserEvent.kind`) | Source |
|---|---|
| `hung`, `hung_end` | `IsHungAppWindow` over visible top-level windows every 2 s; process and window class, never titles |
| `ui_stall` | the agent's own 2 s timer firing late: the desktop session stopped processing messages |
| `display` | `GUID_CONSOLE_DISPLAY_STATE`: off / on / dimmed, with seconds since last input |
| `session` | lock, unlock, logon, logoff, remote connect/disconnect |
| `power` | suspend / resume as seen by the session |
| `resolution` | `WM_DISPLAYCHANGE`: resolution and monitor count |
| `foreground` | foreground process changes (exe name only) |
| `idle`, `active` | no input for 120 s, and back |
| `shell` | `TaskbarCreated`: Explorer restarted |
| `mark` | tray menu **It just happened** or **Ctrl+Alt+Shift+B** |

It talks to the service only through files (`bbx_core::agentproto`):
`triggers\` (users may create files, nothing else) for marks, event batches
and screenshots; `public\` (users may read) for its settings and the newest
incident id. The service treats everything from `triggers\` as untrusted:
size caps, JSON parsing, clamped timestamps, PNG signature check.

Incidents from the agent: a window hung for 15 s or more, a UI stall of
5 s or more, **the display turning off within 30 s of user input** (the "it
just went black" case, as opposed to a power-saving timeout), and Explorer
restarting.

**Screenshots** (off by default, `"screenshots": true` in config.json): a
ring of grayscale frames, 800 px wide, one every 5 s, 24 kept (2 minutes),
held only in the agent's memory. They are written out only when an incident
opens (the service signals through `public\incident.json`), when the user
marks, or when a window hangs, and the service files them under the
incident's `screens\` folder. Unclaimed frames are deleted after 10
minutes.

### Hardware health (phase 3)

Read with storage ioctls on `\\.\PhysicalDriveN` (no WMI, no drivers), at
start and hourly (`DiskHealth`):

- model, bus, serial; temperature with the drive's own warning and critical
  thresholds (NVMe and SATA);
- NVMe SMART/Health log (page 02h): critical warning bits, spare, wear,
  media errors, error log entries, power-on hours, and the drive's own
  **unsafe shutdown** counter;
- ATA SMART attributes (via `IOCTL_STORAGE_PREDICT_FAILURE`): reallocated,
  pending and uncorrectable sectors, command timeouts, interface CRC errors
  (cables), unexpected power loss and power-off retract counts.

At startup the unsafe-shutdown counters are compared with the previous run;
an increase is reported as independent evidence that power was lost without
a clean flush. Incidents: SMART failure prediction, a new NVMe critical
warning, rising media errors or bad-sector / CRC counters, and running at or
above the drive's warning temperature (70 C if it has none).

`Power` records AC/battery state, battery level, charging and battery saver
whenever they change; a critically low battery opens an incident.

### Packet ring (phase 3, optional)

With `"packet_capture": true`, the service runs Windows' `pktmon` in
circular mode: headers only (`packet_snaplen`, 128 bytes) in a 256 MB ring.
An incident stops the ring, converts it to `packets.pcapng` in the incident
folder (open in Wireshark) and starts a new one.

### Encrypted bundles (phase 3)

`bbx keygen` creates an age (X25519) key pair for a technician. With
`export_recipients` in config.json (or `--recipient`), `bbx export` encrypts
the bundle to those keys and deletes the plaintext; `bbx decrypt` (or the
standard `age` tool) opens it.

### Viewer and analysis (phase 4)

Everything on the technician side works from a **dataset**: the records of
a time window plus the black-box files, screenshots, verdict and incident
that go with it, loaded from an export bundle (`.zip`, or `.zip.age` with
the technician key) or, with `--local`, straight from the journal.

- **Suspects** (`bbx suspects`): about twenty deterministic rules that rank
  likely causes with their evidence. They cover the shutdown verdict,
  commit and RAM exhaustion with the processes that grew, kernel-pool
  leaks, disk latency and storage errors, SMART/NVMe health, CPU
  saturation, thermal or power throttling, DPC/interrupt storms, display
  driver resets and black screens, WHEA hardware errors, crashed processes
  with named NTSTATUS codes, hangs and whole-system stalls (late or missing
  heartbeats), failing devices, service crashes, battery, network/DNS/Wi-Fi
  trouble, and what ran around the moment (tasks, Defender, Windows Update,
  driver loads). Findings within 5 minutes of the moment of interest score
  higher.
- **Digest** (`bbx digest`): a self-contained Markdown summary (machine,
  window, user notes, verdict, suspects, disk health, and the full
  situation report), capped at about 220k characters with an explicit note
  if the timeline had to be shortened. It is exactly what `bbx analyze`
  sends, so a technician can review or redact it first.
- **Claude analysis** (`bbx analyze`, or the viewer's Claude tab): one
  streamed Messages API request (`claude-opus-5-5` by default, adaptive
  thinking, effort `high`) with a fixed system prompt that asks for what
  happened, ranked causes with confidence and evidence, what is ruled out,
  gaps, next steps and a plain-language note for the user. The digest is
  sent with prompt caching, so follow-up questions about the same incident
  reuse it. Server-side refusal fallbacks are enabled (`fallbacks:
  "default"`); refusals, rate limits, 5xx and transport errors are retried
  or reported clearly. Credentials come from `ANTHROPIC_API_KEY` (or
  `ANTHROPIC_AUTH_TOKEN`) on the technician's machine; nothing is sent
  unless the technician asks.
- **Black-box drill-down**: an offline ETW reader replays the `.etl` files
  for a window of up to 5 minutes and returns Procmon-style rows: process
  start/exit with command lines, image loads, file create/write/delete/
  rename (and optionally reads), registry writes (and optionally queries),
  TCP/UDP, disk I/O with latency, DNS, plus a generic decoding of every
  other provider. It needs no admin rights, and file and registry names are
  resolved from the trace's own name and rundown events.
- **Viewer** (`bbx view`): a local web app served from `bbx.exe` on
  127.0.0.1 only. Every request needs a random per-run token, and requests
  whose `Host` isn't the loopback address are refused. The page is one
  embedded HTML file with no external resources and a strict
  Content-Security-Policy, and everything from the bundle is rendered as
  text. It has stacked charts (CPU, commit, free RAM, disk latency,
  network, GPU, heartbeat lateness), event lanes (incidents, event logs,
  user session, processes, devices, BlackBox) with drag-to-zoom, a
  playhead and timed playback, the suspects list, and tabs for the moment
  under the playhead, the filterable timeline, black-box rows, screenshots,
  Claude analysis and the text report.

---

## 4. Journal format (crash-safety contract)

Directory: `journal\`. Two kinds of files:

- `open-<firstSeq:012>.bbj`: the active, uncompressed segment. Only one is
  open at a time.
- `<firstSeq:012>-<lastSeq:012>_<firstFt:019>_<lastFt:019>.bbjz`: a sealed
  segment, zstd-compressed, written to a temp name, flushed, then renamed.
  Readers can pick a time range from the file names alone.

### Segment header (32 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `BBXJSEG1` |
| 8 | 4 | format version (1) |
| 12 | 4 | reserved (0) |
| 16 | 8 | created, FILETIME UTC |
| 24 | 8 | first sequence number |

### Record frame (32-byte header + payload, little-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `0x31584242` (`"BBX1"`) |
| 4 | 4 | payload length (≤ 1 MiB) |
| 8 | 2 | record type |
| 10 | 2 | flags (0) |
| 12 | 8 | sequence number (strictly increasing, never reused) |
| 20 | 8 | timestamp, FILETIME UTC |
| 28 | 4 | CRC-32C over bytes 0–27 + payload |
| 32 | n | payload, UTF-8 JSON |

### Rules

- **Commit cadence.** Records are buffered and the file is flushed with
  `FlushFileBuffers` every second, and immediately for critical records
  (session start/end, verdicts, incidents). After power loss, at most ~1 s of
  data is lost.
- **Recovery on open.** Every `open-*.bbj` is scanned. Valid frames are kept,
  the file is **truncated at the first torn or corrupt frame at the tail**,
  sealed, and a `Recovery` record notes how many bytes were dropped and the
  last good sequence and time. Writing always resumes in a *new* segment.
- **Corruption in the middle** (bad sector, not a torn tail): readers resync
  by scanning for the next magic whose CRC checks out, so one bad record
  never hides everything after it.
- **Sequence continuity.** The next sequence number is one more than the last
  valid one seen across all segments, so gaps show exactly what was lost.
- **Run marker.** `state\run.json` is replaced atomically with
  `MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)` at service start and at clean
  stop.

---

## 5. How did the last boot end? (shutdown classifier)

Runs once, shortly after the service starts. It retries for up to 3 minutes
because Windows writes Kernel-Power 41 a little after boot.

**Evidence used:**

- The previous run marker: whether the service stopped cleanly, and whether
  that was a system shutdown or a plain service stop.
- Whether the boot changed (BootId plus boot time).
- The tail of the journal: last record time, and heartbeat regularity and
  vitals over the final 60 s.
- System log for the current boot:
  - Kernel-Power 41: `BugcheckCode`, `PowerButtonTimestamp`, `SleepInProgress`
  - EventLog 6008 (unexpected shutdown)
  - User32 1074 (who requested the shutdown or restart)
  - WER-SystemErrorReporting 1001 (bugcheck)
  - WHEA
- Crash dumps newer than the last heartbeat.

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `CleanShutdown` | Orderly shutdown or restart (with the 1074 initiator if known). |
| `CollectorStopped` / `CollectorCrashed` | Same boot; BlackBox stopped or died but Windows kept running. |
| `Bugcheck` | BSOD; stop code and parameters, plus the dump path. |
| `HangThenForcedOff` | Heartbeats stopped at T1 and the power button was held at T2 > T1. **The whole OS was frozen.** |
| `ForcedOffWhileAlive` | The power button was held while heartbeats were still regular. **Windows was running**, so suspect the display, GPU, input or a single app: the "it just goes black" class. |
| `DegradedThenReset` | Vitals were extreme or heartbeats jittered just before the end, then the machine reset without a bugcheck or button press. |
| `AbruptStop` | Everything looked normal on the last heartbeat; no bugcheck, no registered button press, no shutdown. Total power loss, reset button, PSU or other instant hardware fault, **or** an instant total freeze followed by a forced power-off. Windows can only record a power-button press while it's responsive, so software can't tell those apart. The verdict says so and tells the technician what to ask the user. |
| `SleepTransitionFailure` | Died while entering or leaving sleep or hibernate. |
| `Unknown` | Not enough evidence; the classifier says what's missing. |

Each verdict carries a confidence level, a one-line summary, and the evidence
behind it, so a technician can check its reasoning.

---

## 6. Hard-freeze and worst-case strategy

| Failure | What survives |
|---|---|
| Collector crash | The black box keeps recording (it belongs to the kernel), SCM restarts the service after 5 s, and the next start records `CollectorCrashed`. |
| Hard reboot or power cut | Journal up to ~1 s before; all closed black-box segments plus most of the open one; `AbruptStop` or `HangThenForcedOff` at the next boot. |
| Bugcheck | Same as above, plus the dump; the verdict carries the stop code. |
| Full OS freeze (nothing runs) | Data up to the freeze. `bbx install` enables **CrashOnCtrlScroll**: hold Right Ctrl and press Scroll Lock twice to force a bugcheck. The kernel dump then contains the in-memory ETW buffers, which `!wmitrace.logsave` can extract, so the last seconds are recovered too. |
| Disk full | Every tier has a budget, and the service stops expanding before the system volume drops below 2 GB free. |

---

## 7. Resource budget and self-protection

- Each collector runs in its own thread with panic isolation: a failing
  collector is restarted with backoff and reported, never takes the service
  down.
- Below-normal process priority, except the heartbeat and journal commit
  thread, which runs at normal priority so the "last alive" signal stays
  accurate under load.
- Disk budget (defaults, configurable): journal 1.5 GB, black box 2 GB,
  incidents 1.5 GB.
- BlackBox measures its own CPU, memory and I/O in every `SystemSample`, so
  its overhead can always be checked from the data.
- Measured (phase 1, release build, Windows 11 25H2, 60 s run, black box not
  included): 0.10% average CPU (0.19% peak), 11.8 MB private memory, 22 MB
  working set (mostly shared system DLL pages), about 100 KB/min of journal
  before compression.

---

## 8. Privacy

Command lines, file paths, DNS names and (later) screenshots are sensitive.

- Redaction rules run before anything is written: argument patterns such as
  `password=`, `/p:`, bearer tokens and connection strings.
- `%ProgramData%\BlackBox` is ACL'd to SYSTEM and Administrators, except
  `triggers\`, which only accepts small marker files from users.
- Exported bundles can be encrypted to a technician key (phase 3).
- `bbx install` shows what is collected and asks for confirmation.

---

## 9. Phases

1. **Foundation (this phase).** Journal; heartbeat; system, pool, process,
   PDH and device samplers; event log collector; black-box ETW controller;
   shutdown classifier; Windows service; `bbx` CLI (install, uninstall,
   status, run, dump, last-shutdown, mark).
2. **Live ETW and incidents (built).** Real-time ETW consumer with TDH
   decoding; process start/stop with exit codes, including short-lived
   processes; network, DNS, disk, file and registry rollups; detectors and
   incidents; `bbx export` bundles; `bbx diag live`.
3. **User session and hardware (built).** Tray agent (hung windows, display
   state, UI stalls, sessions, foreground/idle, "It just happened" button and
   hotkey, optional screenshot ring); disk health from NVMe/ATA SMART and
   temperature; power/battery; optional `pktmon` packet ring; encrypted
   bundles. Not covered: CPU/GPU temperatures beyond ACPI thermal zones
   (those need vendor libraries or a kernel driver).
4. **Viewer and AI (built).** `bbx view` timeline playback across all tiers,
   black-box drill-down, rule-based suspects, the digest, and Claude analysis
   (`bbx analyze`). Startup failures of the service are also written to the
   Application event log and shown by `bbx status`.
