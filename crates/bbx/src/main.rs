//! bbx — BlackBox flight recorder for Windows.

mod agent;
mod ai;
mod cli;
mod crypto;
mod dataset;
mod digest;
mod export;
mod incidents;
mod ingest;
mod install;
mod report;
mod service;
mod suspects;
mod viewer;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bbx", version, about = "BlackBox: a flight recorder for Windows", long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install (or update) and start the BlackBox service. Run elevated.
    Install {
        /// Black-box detail: "standard" (default) or "deep".
        #[arg(long)]
        profile: Option<String>,
        /// Don't change event log sizes, crash-dump or CrashOnCtrlScroll settings.
        #[arg(long)]
        no_system_changes: bool,
        /// Register the service but don't start it.
        #[arg(long)]
        no_start: bool,
        /// Technician public key (age1...) that exports are encrypted for.
        /// Added to export_recipients in config.json. Repeatable.
        #[arg(long = "recipient")]
        recipients: Vec<String>,
    },
    /// Stop recording: stops the service and both ETW sessions. Run elevated.
    Stop,
    /// Start recording again. Run elevated.
    Start,
    /// Stop and remove the service and the black-box session. Run elevated.
    Uninstall {
        /// Also delete all recorded data.
        #[arg(long)]
        purge: bool,
    },
    /// Show whether recording is healthy.
    Status,
    /// Record in the foreground (for testing). Ctrl+C to stop.
    Run {
        #[arg(short, long)]
        verbose: bool,
        /// Stop automatically after this many seconds.
        #[arg(long)]
        for_secs: Option<u64>,
    },
    /// Show what the machine was doing around a moment, e.g. `bbx around 16:30`.
    Around {
        /// When: "16:30", "4:30pm", "2026-11-19 16:30", "-15m".
        #[arg(allow_hyphen_values = true)]
        time: String,
        /// Minutes before the moment to show.
        #[arg(short, long, default_value_t = 5)]
        minutes: u64,
        /// Minutes after the moment to show.
        #[arg(short, long, default_value_t = 1)]
        after: u64,
    },
    /// How did the last boot end? (power loss, freeze, bugcheck, clean...)
    LastShutdown,
    /// Print raw journal records.
    Dump {
        #[arg(long, allow_hyphen_values = true)]
        from: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        to: Option<String>,
        /// Comma-separated record types, e.g. Heartbeat,EventLog.
        #[arg(long, short = 't')]
        types: Option<String>,
        /// Only the newest N matching records.
        #[arg(long, short = 'n')]
        last: Option<usize>,
        /// JSON lines output.
        #[arg(long)]
        json: bool,
    },
    /// Mark "it just happened": saves the black-box window with a note.
    Mark {
        /// What the user saw.
        note: Vec<String>,
    },
    /// Package a time range or incident into one .zip for analysis elsewhere.
    Export {
        /// An incident id (folder name under incidents\).
        #[arg(long)]
        incident: Option<String>,
        /// The newest incident from the last 24 hours, or else the last
        /// 30 minutes (used by the tray's "Send to technician").
        #[arg(long)]
        latest: bool,
        /// Centre time, e.g. "16:30" (with --minutes / --after).
        #[arg(long, allow_hyphen_values = true)]
        around: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        from: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        to: Option<String>,
        #[arg(short, long, default_value_t = 15)]
        minutes: u64,
        #[arg(short, long, default_value_t = 2)]
        after: u64,
        /// Output .zip path.
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
        /// Leave out black-box .etl files (much smaller).
        #[arg(long)]
        no_etl: bool,
        /// Encrypt to this age public key (repeatable). Defaults to
        /// export_recipients from config.json.
        #[arg(long = "recipient")]
        recipients: Vec<String>,
    },
    /// Create a technician key pair for encrypted bundles.
    /// Saved in %APPDATA%\BlackBox, where `view` and `decrypt` find it.
    Keygen {
        /// Save the key somewhere else instead.
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
    },
    /// Decrypt a bundle made with --recipient / export_recipients.
    Decrypt {
        file: std::path::PathBuf,
        /// Technician key (default: the one `bbx keygen` saved).
        #[arg(short, long)]
        identity: Option<std::path::PathBuf>,
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
    },
    /// List saved incidents.
    Incidents,
    /// Diagnostics. `bbx diag live` checks live ETW decoding (elevated).
    Diag {
        #[command(subcommand)]
        what: DiagCmd,
    },
    /// Open the viewer: timeline playback, suspects, black-box drill-down
    /// and Claude analysis, in the browser.
    View {
        #[command(flatten)]
        src: Source,
        /// Port on 127.0.0.1 (0 = any free port).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Print the URL but don't open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Claude model for analysis.
        #[arg(long, default_value = ai::DEFAULT_MODEL)]
        model: String,
        /// Quit after this many seconds with the page closed (the tray's
        /// "View recordings" runs it hidden). 0 = keep running.
        #[arg(long, default_value_t = 0)]
        idle_exit: u64,
    },
    /// Print the rule-based suspects for a bundle.
    Suspects {
        #[command(flatten)]
        src: Source,
    },
    /// Write the digest that `analyze` sends to Claude (to review it first).
    Digest {
        #[command(flatten)]
        src: Source,
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
    },
    /// Ask Claude what happened (needs ANTHROPIC_API_KEY).
    Analyze {
        #[command(flatten)]
        src: Source,
        /// An optional question to focus the analysis.
        #[arg(short, long)]
        question: Option<String>,
        #[arg(long, default_value = ai::DEFAULT_MODEL)]
        model: String,
        /// Also save the answer (Markdown).
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
    },
    /// Black-box ETW session control.
    Blackbox {
        #[command(subcommand)]
        action: BlackboxCmd,
    },
    /// Entry point used by the Windows service manager.
    #[command(hide = true)]
    Service,
}

/// Where the data comes from: a bundle, or this machine's own journal.
#[derive(clap::Args)]
struct Source {
    /// Export bundle (.zip, or .zip.age with -i).
    bundle: Option<std::path::PathBuf>,
    /// Technician key for encrypted bundles.
    #[arg(short, long)]
    identity: Option<std::path::PathBuf>,
    /// Read this machine's journal instead of a bundle (elevated).
    #[arg(long)]
    local: bool,
    /// With --local: centre time, e.g. "16:30" or "-20m".
    #[arg(long, allow_hyphen_values = true)]
    around: Option<String>,
    /// With --local: minutes before / after the centre time.
    #[arg(short, long, default_value_t = 30)]
    minutes: u64,
    #[arg(short, long, default_value_t = 5)]
    after: u64,
}

#[derive(Subcommand)]
enum DiagCmd {
    /// Run the live ETW consumer for a few seconds and show what it decoded.
    Live {
        #[arg(long, default_value_t = 15)]
        secs: u64,
    },
}

#[derive(Subcommand)]
enum BlackboxCmd {
    /// Show the session state and files.
    Status,
    /// Close the current .etl file and start the next.
    Roll,
    /// Stop the session (the service restarts it unless stopped too).
    Stop,
}

/// The Windows "Open" dialog, for a bundle from a client.
fn pick_bundle() -> Option<std::path::PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW};
    let filter: Vec<u16> = "BlackBox bundles (*.zip.age, *.zip)\0*.age;*.zip\0All files\0*.*\0\0".encode_utf16().collect();
    let title: Vec<u16> = "Open a BlackBox bundle\0".encode_utf16().collect();
    let mut buf = vec![0u16; 4096];
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = buf.as_mut_ptr();
    ofn.nMaxFile = buf.len() as u32;
    ofn.lpstrTitle = title.as_ptr();
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if unsafe { GetOpenFileNameW(&mut ofn) } == 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
    Some(String::from_utf16_lossy(&buf[..len]).into())
}

fn load(src: &Source) -> Result<dataset::Dataset> {
    use bbx_core::time::{now_ft, parse_user_time, FT_PER_SEC};
    if src.local {
        let paths = bbx_core::paths::Paths::from_env();
        let at = src.around.as_deref().map(parse_user_time).transpose()?.unwrap_or_else(now_ft);
        let from = at - src.minutes as i64 * 60 * FT_PER_SEC;
        let to = (at + src.after as i64 * 60 * FT_PER_SEC).min(now_ft());
        return dataset::Dataset::open_local(&paths, from, to, at);
    }
    // No bundle given (the Start menu "BlackBox Viewer"): ask for one.
    let picked = if src.bundle.is_none() { pick_bundle() } else { None };
    let b = src.bundle.as_ref().or(picked.as_ref()).ok_or_else(|| anyhow::anyhow!("no bundle chosen: give a bundle path, or --local"))?;
    let ds = dataset::Dataset::open_bundle(b, src.identity.as_deref())?;
    eprintln!("Loaded {} records from {}", ds.records.len(), b.display());
    Ok(ds)
}

fn main() {
    let args = Args::parse();
    let res: Result<()> = match args.cmd {
        Cmd::Install { profile, no_system_changes, no_start, recipients } => install::install(install::InstallOptions {
            profile,
            system_changes: !no_system_changes,
            start: !no_start,
            recipients,
        }),
        Cmd::Uninstall { purge } => install::uninstall(purge),
        Cmd::Stop => install::stop_recording(),
        Cmd::Start => install::start_recording(),
        Cmd::Status => cli::status(),
        Cmd::Run { verbose, for_secs } => cli::run_console(verbose, for_secs),
        Cmd::Around { time, minutes, after } => cli::around(&time, minutes, after),
        Cmd::LastShutdown => cli::last_shutdown(),
        Cmd::Dump { from, to, types, last, json } => cli::dump(from, to, types, last, json),
        Cmd::Mark { note } => cli::mark(&note.join(" ")),
        Cmd::Export { incident, latest, around, from, to, minutes, after, out, no_etl, recipients } => {
            cli::export(incident, latest, around, from, to, minutes, after, out, !no_etl, recipients)
        }
        Cmd::Keygen { out } => {
            let out = out.unwrap_or_else(crypto::default_key_path);
            if out.exists() {
                // Already set up: show the public key again instead of failing.
                crypto::public_key_of(&out).map(|public| {
                    println!("You already have a technician key: {}", out.display());
                    println!("Its public key, for the client setup or --recipient:");
                    println!("  {public}");
                })
            } else {
                crypto::keygen(&out).map(|public| {
                    println!("Wrote {} (keep it private, and back it up: bundles can't be opened without it).", out.display());
                    println!("Public key, for the client setup or --recipient:");
                    println!("  {public}");
                })
            }
        }
        Cmd::Decrypt { file, identity, out } => {
            let identity = identity.unwrap_or_else(crypto::default_key_path);
            let out = out.unwrap_or_else(|| file.with_extension(""));
            crypto::read_identities(&identity).and_then(|ids| crypto::decrypt_file(&file, &out, &ids)).map(|_| println!("Wrote {}", out.display()))
        }
        Cmd::Incidents => cli::incidents(),
        Cmd::View { src, port, no_browser, model, idle_exit } => {
            let local = src.local.then(bbx_core::paths::Paths::from_env);
            let idle_exit = (idle_exit > 0).then(|| std::time::Duration::from_secs(idle_exit));
            load(&src).and_then(|ds| viewer::serve(ds, viewer::ViewOptions { port, open_browser: !no_browser, model, local, idle_exit }))
        }
        Cmd::Suspects { src } => load(&src).map(|ds| print!("{}", suspects::to_text(&suspects::analyze(&ds)))),
        Cmd::Digest { src, out } => load(&src).and_then(|ds| {
            let d = digest::build(&ds, &suspects::analyze(&ds));
            match out {
                Some(p) => std::fs::write(&p, &d).map(|_| println!("Wrote {} ({} KB)", p.display(), d.len() / 1024)).map_err(Into::into),
                None => {
                    print!("{d}");
                    Ok(())
                }
            }
        }),
        Cmd::Analyze { src, question, model, out } => load(&src).and_then(|ds| {
            let d = digest::build(&ds, &suspects::analyze(&ds));
            eprintln!("Sending a {} KB digest to {model}...", d.len() / 1024);
            let r = ai::analyze(&model, &d, question.as_deref(), None, |t| {
                use std::io::Write;
                print!("{t}");
                std::io::stdout().flush().ok();
            })?;
            println!();
            eprintln!(
                "[{}: {} input tokens ({} cached), {} output tokens{}]",
                r.model,
                r.input_tokens + r.cache_read_tokens + r.cache_write_tokens,
                r.cache_read_tokens,
                r.output_tokens,
                if r.fallback { ", answered by the fallback model" } else { "" }
            );
            if let Some(p) = out {
                std::fs::write(&p, &r.text)?;
                eprintln!("Saved {}", p.display());
            }
            Ok(())
        }),
        Cmd::Diag { what: DiagCmd::Live { secs } } => cli::diag_live(secs),
        Cmd::Blackbox { action } => match action {
            BlackboxCmd::Status => cli::blackbox_status(),
            BlackboxCmd::Roll => bbx_collect::blackbox::roll(),
            BlackboxCmd::Stop => bbx_collect::blackbox::stop(),
        },
        Cmd::Service => service::run_dispatcher(),
    };
    if let Err(e) = res {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
