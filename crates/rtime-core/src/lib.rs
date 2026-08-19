//! Core types, traits, and algorithms shared across the
//! [rTime](https://github.com/ZerosAndOnesLLC/rTime) NTP/PTP time synchronization daemon.
//!
//! This crate is protocol-agnostic: it defines timestamp arithmetic, clock abstractions,
//! the configuration model, and the source-selection and clock-discipline algorithms that
//! the transport crates (`rtime-ntp`, `rtime-ptp`, `rtime-nts`) and the daemon build on.
//!
//! # Modules
//!
//! - [`timestamp`] — NTP/PTP timestamp and duration types with fixed-point arithmetic.
//! - [`clock`] — clock traits, stratum, and leap-indicator types.
//! - [`config`] — the `rtime.toml` configuration model ([`config::RtimeConfig`]).
//! - [`filter`] — the clock filter that selects the best sample from a poll burst.
//! - [`marzullo`] — Marzullo's interval-intersection algorithm.
//! - [`selection`] — truechimer/falseticker source selection and clustering.
//! - [`servo`] — the PI servo loop that drives clock discipline.
//! - [`source`] — per-source measurement and identity types.
//! - [`steps`] — ledger reconciling cached measurements with applied clock steps.

pub mod clock;
pub mod config;
pub mod filter;
pub mod marzullo;
pub mod selection;
pub mod servo;
pub mod source;
pub mod steps;
pub mod timestamp;
