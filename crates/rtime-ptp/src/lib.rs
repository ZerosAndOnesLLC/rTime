//! PTP / IEEE 1588 (Precision Time Protocol) implementation for the
//! [rTime](https://github.com/ZerosAndOnesLLC/rTime) time synchronization daemon.
//!
//! Covers the message codec, the Best Master Clock Algorithm (BMCA), the datasets that
//! describe a PTP port and clock, and the end-to-end delay computation used to derive offset
//! from `Sync`/`Follow_Up`/`Delay_Req`/`Delay_Resp` exchanges.
//!
//! # Modules
//!
//! - [`message`] — PTP message header and body codec.
//! - [`announce`] — `Announce` message handling.
//! - [`bmca`] — Best Master Clock Algorithm (dataset comparison and master selection).
//! - [`dataset`] — default/current/parent/time-properties datasets.
//! - [`delay`] — end-to-end delay and offset computation.
//! - [`port`] — PTP port state machine.
//! - [`tlv`] — TLV (type-length-value) extension encoding.

pub mod announce;
pub mod bmca;
pub mod dataset;
pub mod delay;
pub mod message;
pub mod port;
pub mod tlv;
