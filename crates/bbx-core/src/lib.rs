//! Platform-neutral core of BlackBox: the crash-safe journal, record schema,
//! run marker, configuration, redaction and the shutdown classifier.
//!
//! Everything here is pure logic plus file I/O so it can be unit-tested
//! without administrator rights or ETW.

pub mod classifier;
pub mod config;
pub mod journal;
pub mod logging;
pub mod paths;
pub mod records;
pub mod redact;
pub mod runstate;
pub mod time;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
