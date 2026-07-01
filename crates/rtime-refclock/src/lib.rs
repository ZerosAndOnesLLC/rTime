//! Reference clock drivers for the [rTime](https://github.com/ZerosAndOnesLLC/rTime)
//! NTP/PTP time synchronization daemon.
//!
//! Reference clocks — a local GPS receiver or a PPS pulse-per-second source — provide a
//! stratum-0 time reference so a host can serve time without an upstream network peer.
//! Drivers are gated behind cargo features so the dependency and syscall surface is only
//! compiled when needed.
//!
//! # Features
//!
//! - `gps` — enables the `gps` NMEA/serial GPS driver.
//! - `pps` — enables the `pps` pulse-per-second ([RFC 2783](https://www.rfc-editor.org/rfc/rfc2783)) driver.
//!
//! The crate error type is [`RefClockError`].

#[cfg(feature = "gps")]
pub mod gps;
#[cfg(feature = "pps")]
pub mod pps;

#[derive(Debug, thiserror::Error)]
pub enum RefClockError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PPS: no edge detected within timeout")]
    PpsTimeout,
}
