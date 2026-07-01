//! System clock interfaces for the [rTime](https://github.com/ZerosAndOnesLLC/rTime)
//! NTP/PTP time synchronization daemon.
//!
//! Abstracts the platform primitives used to read and steer the system clock — slewing
//! (`adjtime`/`adjtimex`), stepping (`clock_settime`), and reading PTP hardware clocks —
//! behind a common interface, with a [`mock`] backend for tests.
//!
//! # Modules
//!
//! - [`unix`] — the Unix system-clock backend.
//! - [`adjtime`] — `adjtime`/`adjtimex` slew and frequency adjustment.
//! - [`phc`] — PTP hardware clock (PHC) access.
//! - [`mock`] — an in-memory clock for testing.

pub mod adjtime;
pub mod mock;
pub mod phc;
pub mod unix;
