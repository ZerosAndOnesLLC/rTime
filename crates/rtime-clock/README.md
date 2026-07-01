# rtime-clock

[![crates.io](https://img.shields.io/crates/v/rtime-clock.svg)](https://crates.io/crates/rtime-clock)
[![docs.rs](https://docs.rs/rtime-clock/badge.svg)](https://docs.rs/rtime-clock)

System clock interfaces for [rTime](https://github.com/ZerosAndOnesLLC/rTime),
a high-performance NTP/PTP time synchronization daemon written in Rust.

Abstracts the platform primitives used to read and steer the system clock — slewing
(`adjtime`/`adjtimex`), stepping (`clock_settime`), and reading PTP hardware clocks —
behind a common interface, with a mock backend for tests.

## Contents

| Module | Purpose |
|--------|---------|
| `unix` | Unix system-clock backend |
| `adjtime` | `adjtime`/`adjtimex` slew and frequency adjustment |
| `phc` | PTP hardware clock (PHC) access |
| `mock` | In-memory clock for testing |

## License

Licensed under the [MIT license](LICENSE).
