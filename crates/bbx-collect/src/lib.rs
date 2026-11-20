//! Windows collectors. Each collector is a function that loops until the
//! shared stop signal is set, writing records through the `Ctx`.

pub mod blackbox;
pub mod bootinfo;
pub mod ctx;
pub mod detect;
pub mod devices;
pub mod devpath;
pub mod etwlive;
pub mod eventlog;
pub mod evidence;
pub mod hardware;
pub mod ntapi;
pub mod pdh;
pub mod pktmon;
pub mod process;
pub mod rollup;
pub mod system;
pub mod tdh;
pub mod util;

pub use ctx::{Ctx, Stop};
