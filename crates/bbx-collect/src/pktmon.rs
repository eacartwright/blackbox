//! Optional packet ring using Windows' built-in pktmon (Windows 10 2004+):
//! a circular capture of packet headers (default 128 bytes per packet,
//! 256 MB ring) that incidents convert to .pcapng for Wireshark.
//! Off by default (`packet_capture` in config.json).

use crate::Ctx;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn pktmon(args: &[&str]) -> Result<String> {
    let o = Command::new("pktmon").args(args).output().map_err(|e| anyhow!("cannot run pktmon: {e}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if o.status.success() {
        Ok(text)
    } else {
        Err(anyhow!("pktmon {} failed: {}", args.join(" "), text.trim()))
    }
}

pub fn ring_file(ctx: &Ctx) -> PathBuf {
    ctx.paths.blackbox().join("packets.etl")
}

fn start(file: &Path, mb: u64, snaplen: u32) -> Result<()> {
    let _ = pktmon(&["stop"]);
    pktmon(&[
        "start",
        "--capture",
        "--pkt-size",
        &snaplen.to_string(),
        "--file-name",
        &file.display().to_string(),
        "--file-size",
        &mb.max(16).to_string(),
        "--log-mode",
        "circular",
    ])
    .map(|_| ())
}

pub fn stop() {
    let _ = pktmon(&["stop"]);
}

/// Stop the ring, convert it to `dest` (.pcapng), and start a fresh ring.
pub fn snapshot(ctx: &Ctx, dest: &Path) -> Result<()> {
    let _g = LOCK.lock().unwrap();
    let file = ring_file(ctx);
    pktmon(&["stop"])?;
    let conv = pktmon(&["etl2pcap", &file.display().to_string(), "--out", &dest.display().to_string()])
        .or_else(|_| pktmon(&["pcapng", &file.display().to_string(), "-o", &dest.display().to_string()]));
    let restart = start(&file, ctx.cfg.packet_capture_mb, ctx.cfg.packet_snaplen);
    conv?;
    restart
}

pub fn run(ctx: &Ctx) -> Result<()> {
    if !ctx.cfg.packet_capture {
        return Ok(());
    }
    {
        let _g = LOCK.lock().unwrap();
        start(&ring_file(ctx), ctx.cfg.packet_capture_mb, ctx.cfg.packet_snaplen)?;
    }
    ctx.status("pktmon", "info", format!("packet ring running ({} MB, {} bytes per packet)", ctx.cfg.packet_capture_mb, ctx.cfg.packet_snaplen));
    ctx.stop.wait_forever();
    let _g = LOCK.lock().unwrap();
    stop();
    Ok(())
}
