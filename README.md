# BlackBox

A flight recorder for Windows. Install it on a machine that "just freezes",
"goes black" or "reboots by itself", leave it running, and when it happens
again you can see what the machine was doing right before, and how it went
down.

- **Always recording, small fixed budget.** About 0.1% CPU and ~12 MB of
  private memory, with hard disk caps per tier.
- **Survives what it's investigating.** A crash-safe journal loses at most
  ~1 second on a power cut. The ETW black box keeps recording even if the
  service dies.
- **Says how the last boot ended:** clean shutdown, bugcheck, hang then forced
  off, forced off while Windows was still alive (the "black screen" case),
  degraded then reset, sleep transition failure, or an abrupt stop with no
  warning.

The design and on-disk formats are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What's recorded (phase 1)

| | |
|---|---|
| Every second | heartbeat with vitals: CPU, commit, free RAM, worst disk latency/queue, busiest process |
| Every 2 s | system totals (commit, pools, handles), per-process CPU / memory / handles / I/O / hard faults (active processes; full table every minute), disk / NIC / CPU-throttling / DPC / thermal counters |
| Every 5 s | GPU engine and memory use per process; device add / remove / problem codes |
| Every 30 s | kernel pool usage by tag (driver leaks) |
| As they happen | process start/end with full command line, user and image path (secrets redacted); System, Application and ~15 operational event logs; incidents and notes |
| Black box | kernel ETW: process, thread, image load, disk, file and registry I/O, TCP/IP, hard faults, plus Kernel-Power, Kernel-PnP, StorPort, DNS-Client, in rolling `.etl` files (open them with Windows Performance Analyzer) |

## Build

Requires Rust (MSVC toolchain) and the Visual Studio C++ Build Tools.

```bash
cargo build --release
```

The result is a single self-contained `target\release\bbx.exe` with no runtime
dependencies.

```bash
cargo test --workspace
```

## Use

From an elevated (Administrator) prompt on the machine to watch:

```bash
bbx install
```

This copies `bbx.exe` to `C:\Program Files\BlackBox`, registers the
`BlackBox` service (automatic start, restarts on failure), stores data under
`C:\ProgramData\BlackBox`, and turns on extra Windows evidence:

- the Task Scheduler operational log
- larger System and Application logs
- automatic memory dumps
- CrashOnCtrlScroll

Pass `--no-system-changes` to skip that last part.

When the user says "it froze at 4:30":

```bash
bbx around 16:30
```

```bash
bbx last-shutdown
```

Other commands:

| Command | What it does |
|---|---|
| `bbx status` | Is it healthy? Service, black box, journal, last heartbeat, last verdict |
| `bbx around <time> [-m 10] [-a 2]` | Vitals, worst disk moment, top processes, memory and pool growth, timeline |
| `bbx last-shutdown` | How the previous boot ended, with the evidence behind it |
| `bbx dump --from 16:20 --to 16:35 -t EventLog,Device` | Raw records (`--json` for JSON lines) |
| `bbx mark "screen went black"` | Users can run this right after it happens; keeps the black-box window with the note |
| `bbx blackbox status` | ETW session state and files |
| `bbx run --for-secs 60` | Record in the foreground (testing; no black box unless elevated) |
| `bbx uninstall [--purge]` | Remove the service and black box (and optionally all data) |

For a total freeze where nothing responds, once CrashOnCtrlScroll is enabled
(it takes effect after the next reboot), hold **Right Ctrl** and press **Scroll
Lock** twice. Windows bugchecks deliberately and writes a dump that also
contains the in-memory ETW buffers.

## Status

Phase 1 (foundation) is built and tested. Phases 2–4 (live ETW rollups and
detectors, tray agent and hardware health, viewer and AI analysis) are
described in the architecture doc.

**Not yet verified elevated:** the black-box ETW session and
`bbx install` need administrator rights. The development session ran
unelevated, so those paths are tested only up to "parameters accepted".
