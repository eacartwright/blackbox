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
What's left to do, known issues and where things live (including the tray icon text) are in [docs/NEXT.md](docs/NEXT.md).

## What's recorded

| | |
|---|---|
| Every second | heartbeat with vitals: CPU, commit, free RAM, worst disk latency/queue, busiest process |
| Every 2 s | system totals (commit, pools, handles), per-process CPU / memory / handles / I/O / hard faults (active processes; full table every minute), disk / NIC / CPU-throttling / DPC / thermal counters |
| Every 5 s | GPU engine and memory use per process; device add / remove / problem codes |
| Every 30 s | kernel pool usage by tag (driver leaks) |
| As they happen | process start/end with full command line, user and image path (secrets redacted); System, Application and ~15 operational event logs; incidents and notes |
| Every 10 s (live ETW) | network bytes / connects / retransmits per process and remote address, DNS queries and failures, disk I/O per process and file with worst latency, file writes / creates / deletes / renames, registry writes |
| Instantly (live ETW) | every process start and exit with **exit code** (even ones that live milliseconds), kernel driver loads |
| In each user session (tray agent) | hung windows, desktop stalls, **display turning off**, lock/unlock, foreground app, idle/active, Explorer restarts; optional screenshot ring kept only for incidents |
| Hourly | disk health: NVMe/SATA SMART, temperature, wear, media errors, the drive's own unsafe-shutdown count |
| On change | AC / battery state |
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

### Setup program

```powershell
.\scripts\build-installer.ps1
```

Builds, tests and packages `dist\BlackBox-Setup-<version>.exe` (needs
[Inno Setup 6](https://jrsoftware.org/isinfo.php): `winget install JRSoftware.InnoSetup`).
The setup asks for administrator rights and offers two types:

- **Record this PC**: the service, tray icon and tools. It asks for the
  technician's public key (from `bbx keygen`) so every export is encrypted for
  you, and whether to turn on the extra Windows evidence listed below.
- **Technician tools only**: `bbx` for opening, viewing and analyzing bundles
  on your own computer, with no recording.

Either way `bbx` is added to the system PATH. Upgrading is running a newer
setup over the old one; uninstalling (Settings > Apps) asks whether to keep
the recordings. The binaries and setup aren't code-signed yet; see
[docs/SIGNING.md](docs/SIGNING.md).

The icons are drawn by `assets/make_icons.py` (run it after changing the
design); `build.rs` in `bbx` and `bbx-agent` embeds them.

Unattended, e.g. from Intune or a script:

```powershell
BlackBox-Setup-0.1.0.exe /VERYSILENT /RECIPIENT=age1...
```

Add `/MERGETASKS="!evidence"` to leave Windows logging settings alone, or
`/TYPE=technician /MERGETASKS="assoc"` for the tools only with double-click to
open bundles. The double-click option is on the tasks page for either type
(ticked by default for technician installs), so a PC can record and open
bundles too.

## Use

The setup program above does this for you. By hand, from an elevated
(Administrator) prompt on the machine to watch:

```bash
bbx install [--recipient age1...]
```

This copies `bbx.exe` and `bbx-agent.exe` to `C:\Program Files\BlackBox`,
registers the `BlackBox` service (automatic start, restarts on failure),
starts the tray agent at every sign-in, stores data under
`C:\ProgramData\BlackBox`, and turns on extra Windows evidence:

- the Task Scheduler operational log
- larger System and Application logs
- automatic memory dumps
- CrashOnCtrlScroll

Pass `--no-system-changes` to skip that last part.

### Getting the evidence

**On the client PC**, from the tray icon (each asks for administrator approval,
because the recordings are readable only by administrators):

- **View recordings…** opens the viewer in the browser. The picker at the top
  switches between the last 30 minutes / 2 hours / 24 hours, any saved incident,
  or a custom range of up to 48 hours. The hidden viewer quits 10 minutes after
  the page is closed.
- **Send to technician…** saves the newest incident from the last 24 hours (or
  else the last 30 minutes) to the user's Desktop as `BlackBox-<PC>-<time>.zip.age`,
  encrypted for the technician key set during setup, and shows it in Explorer.
  The user emails it or shares it from there. With black-box files included it's
  typically tens of MB.

**On the technician's PC** (setup type **Technician tools only**):

1. Run `bbx keygen` once. The key is saved in `%APPDATA%\BlackBox\blackbox-tech.key`
   (back it up: bundles can't be opened without it), and it prints the public
   key to paste into each client's setup. Running it again shows the same public key.
2. Double-click a `.zip.age` bundle, or use **BlackBox Viewer** in the Start menu
   to pick one. The key is found automatically; `-i <key>` still works.

That opens the viewer in your browser. For reading room, drag the bar under
the chart, press **C** for a compact strip of event markers, or **S** to hide
the suspects; **←/→** step the playhead 5 seconds (**Shift** for 1 minute). It has the timeline with playback, ranked suspects, black-box drill-down and screenshots. Its **Claude analysis** tab explains what happened once it has an Anthropic API
key: put the key (from console.anthropic.com) on one line in
`%APPDATA%\BlackBox\anthropic.key`, next to the technician key, or set
`ANTHROPIC_API_KEY`, which takes precedence. The same analysis from the command line:

```bash
bbx analyze bundle.zip --question "why did the screen go black?"
```

From an elevated prompt on the client, the same viewer without exporting:

```bash
bbx view --local --around 16:30
```

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
| `bbx mark "screen went black"` | Users can run this right after it happens; opens an incident with the note |
| `bbx incidents` | List saved incidents (manual marks and automatic detections) |
| `bbx export --incident <id>` | One .zip with records, report, event logs, black-box files and dumps (`--latest`, `--around 16:30`, `--from/--to`, `--no-etl`, `-o <file>`) |
| `bbx diag live` | Elevated: run the live ETW decoder for 15 s and show what it captured |
| `bbx view [bundle] [-i key]` | Viewer: charts, event lanes, playback, suspects, moment details, black-box rows, screenshots, Claude analysis. No bundle: asks for one. `--local --around 16:30` reads this machine (with the incident and range picker); `--idle-exit <secs>` quits once the page is closed |
| `bbx suspects <bundle>` | Rule-based ranked causes with evidence |
| `bbx digest <bundle> [-o file]` | The text that `analyze` would send, to review first |
| `bbx analyze <bundle> [-q question]` | Ask Claude (`claude-opus-5-5`) what happened; needs the API key in `%APPDATA%\BlackBox\anthropic.key` or `ANTHROPIC_API_KEY` |
| `bbx keygen` | Create the technician key in `%APPDATA%\BlackBox` (or show its public key if it exists); the `age1...` public key goes in the client setup or `config.json` `export_recipients` |
| `bbx decrypt <bundle.age> [-i key]` | Decrypt a bundle to a plain .zip |
| `bbx blackbox status` | ETW session state and files |
| `bbx run --for-secs 60` | Record in the foreground (testing; no black box unless elevated) |
| `bbx stop` / `bbx start` | Stop recording (service and both ETW sessions) / start again; elevated. Also in the tray menu, behind a UAC prompt. Tray **Exit…** stops recording and closes the tray icon; both return at the next restart, or from **BlackBox** in the Start menu |
| `bbx uninstall [--purge]` | Remove the service and black box (and optionally all data) |

Users can also press **Ctrl+Alt+Shift+B**, or right-click the tray icon >
**Capture Incident**, the moment something goes wrong.

Optional settings in `C:\ProgramData\BlackBox\config.json` (restart the service after changing):

| Setting | Default | |
|---|---|---|
| `screenshots` | `false` | Keep a 2-minute ring of grayscale screenshots in the agent's memory; saved only with incidents |
| `packet_capture` | `false` | pktmon header capture ring (256 MB), saved as `.pcapng` with incidents |
| `export_recipients` | `[]` | age public keys; bundles are then always encrypted |
| `profile` | `standard` | `deep` adds context switches, DPCs, interrupts and CPU sampling to the black box |

For a total freeze where nothing responds, once CrashOnCtrlScroll is enabled
(it takes effect after the next reboot), hold **Right Ctrl** and press **Scroll
Lock** twice. Windows bugchecks deliberately and writes a dump that also
contains the in-memory ETW buffers.

## Status

All four phases are built and tested: 1 (foundation), 2 (live ETW,
detectors, incidents, export), 3 (tray agent, disk and power health, packet
ring, encrypted bundles) and 4 (viewer, suspects, black-box drill-down,
Claude analysis).

Incidents open automatically for sustained CPU / memory / disk trouble,
system stalls, display driver resets, WHEA hardware errors, storage resets,
app hangs and crashes, critical devices disappearing, kernel pool leaks, and
any unplanned shutdown.

**Elevated-only paths:** kernel-event decoding in the live consumer runs only
with administrator rights; `bbx diag live` checks it on a given machine. The
DNS half of the same pipeline is covered by an automated test that runs
unelevated.
