//! Windows collectors. Each collector is a function that loops until the
//! shared stop signal is set, writing records through the `Ctx`.

pub mod blackbox;
pub mod bootinfo;
pub mod ctx;
pub mod devices;
pub mod eventlog;
pub mod evidence;
pub mod ntapi;
pub mod pdh;
pub mod process;
pub mod system;
pub mod util;

pub use ctx::{Ctx, Stop};
