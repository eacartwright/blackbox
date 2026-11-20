//! bbx — BlackBox flight recorder for Windows.

mod agent;
mod cli;
mod install;
mod service;

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
    },
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
    /// Black-box ETW session control.
    Blackbox {
        #[command(subcommand)]
        action: BlackboxCmd,
    },
    /// Entry point used by the Windows service manager.
    #[command(hide = true)]
    Service,
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

fn main() {
    let args = Args::parse();
    let res: Result<()> = match args.cmd {
        Cmd::Install { profile, no_system_changes, no_start } => install::install(install::InstallOptions {
            profile,
            system_changes: !no_system_changes,
            start: !no_start,
        }),
        Cmd::Uninstall { purge } => install::uninstall(purge),
        Cmd::Status => cli::status(),
        Cmd::Run { verbose, for_secs } => cli::run_console(verbose, for_secs),
        Cmd::Around { time, minutes, after } => cli::around(&time, minutes, after),
        Cmd::LastShutdown => cli::last_shutdown(),
        Cmd::Dump { from, to, types, last, json } => cli::dump(from, to, types, last, json),
        Cmd::Mark { note } => cli::mark(&note.join(" ")),
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
