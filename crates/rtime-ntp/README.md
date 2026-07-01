# rtime-ntp

[![crates.io](https://img.shields.io/crates/v/rtime-ntp.svg)](https://crates.io/crates/rtime-ntp)
[![docs.rs](https://docs.rs/rtime-ntp/badge.svg)](https://docs.rs/rtime-ntp)

NTPv4 ([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)) protocol implementation for
[rTime](https://github.com/ZerosAndOnesLLC/rTime), a high-performance NTP/PTP time
synchronization daemon written in Rust.

Provides the packet codec plus the client- and server-side logic, poll-interval control,
and Kiss-o'-Death handling needed to both query upstream servers and answer downstream
clients.

## Contents

| Module | Purpose |
|--------|---------|
| `packet` | NTP packet layout, parsing, and serialization (`NtpPacket`) |
| `client` | Client-side request building and response validation |
| `server` | Server-side request validation and response construction |
| `poll` | Adaptive poll-interval management |
| `extension` | NTP extension-field framing (used by NTS) |
| `kiss_code` | Kiss-o'-Death (KoD) codes such as `RATE` and `DENY` |

## License

Licensed under the [MIT license](LICENSE).
