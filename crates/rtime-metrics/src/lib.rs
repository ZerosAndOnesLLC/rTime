//! Prometheus metrics for the [rTime](https://github.com/ZerosAndOnesLLC/rTime)
//! NTP/PTP time synchronization daemon.
//!
//! Defines the daemon's metric instruments (clock offset/jitter/frequency, per-source
//! statistics, packet counters, selection results) and an HTTP exporter that serves them in
//! Prometheus text format at `/metrics`.
//!
//! # Modules
//!
//! - [`instruments`] — metric definitions and update helpers.
//! - [`exporter`] — the Axum-based `/metrics` HTTP endpoint.
//!
//! The [`metrics`] facade crate is re-exported for convenience.

pub mod exporter;
pub mod instruments;

// Re-export metrics macros for convenience
pub use metrics;
