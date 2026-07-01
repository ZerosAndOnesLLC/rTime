# rtime-refclock

[![crates.io](https://img.shields.io/crates/v/rtime-refclock.svg)](https://crates.io/crates/rtime-refclock)
[![docs.rs](https://docs.rs/rtime-refclock/badge.svg)](https://docs.rs/rtime-refclock)

Reference clock drivers for [rTime](https://github.com/ZerosAndOnesLLC/rTime),
a high-performance NTP/PTP time synchronization daemon written in Rust.

Reference clocks — a local GPS receiver or a PPS pulse-per-second source — provide a
stratum-0 time reference so a host can serve time without an upstream network peer.
Drivers are gated behind cargo features so the dependency and syscall surface is only
compiled when needed.

## Features

| Feature | Enables |
|---------|---------|
| `gps` | The `gps` NMEA/serial GPS driver |
| `pps` | The `pps` pulse-per-second ([RFC 2783](https://www.rfc-editor.org/rfc/rfc2783)) driver |

Both features are off by default. The crate error type is `RefClockError`.

## License

Licensed under the [MIT license](LICENSE).
