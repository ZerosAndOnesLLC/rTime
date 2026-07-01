//! NTPv4 ([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)) protocol implementation for the
//! [rTime](https://github.com/ZerosAndOnesLLC/rTime) time synchronization daemon.
//!
//! Provides the packet codec plus the client- and server-side logic, poll-interval control,
//! and Kiss-o'-Death handling needed to both query upstream servers and answer downstream
//! clients.
//!
//! # Modules
//!
//! - [`packet`] — NTP packet layout, parsing, and serialization ([`packet::NtpPacket`]).
//! - [`client`] — client-side request building and response validation.
//! - [`server`] — server-side request validation and response construction.
//! - [`poll`] — adaptive poll-interval management.
//! - [`extension`] — NTP extension-field framing (used by NTS).
//! - [`kiss_code`] — Kiss-o'-Death (KoD) codes such as `RATE` and `DENY`.

pub mod client;
pub mod extension;
pub mod kiss_code;
pub mod packet;
pub mod poll;
pub mod server;
