//! Network I/O with packet timestamping for the
//! [rTime](https://github.com/ZerosAndOnesLLC/rTime) NTP/PTP time synchronization daemon.
//!
//! Wraps UDP sockets with software and (where available) hardware receive/transmit
//! timestamping — essential for accurate offset measurement — plus multicast join/leave and
//! network-interface discovery.
//!
//! # Modules
//!
//! - [`udp`] — timestamped UDP socket wrappers.
//! - [`multicast`] — multicast group membership (used by PTP).
//! - [`interface`] — network interface enumeration and capability queries.

pub mod interface;
pub mod multicast;
pub mod udp;
