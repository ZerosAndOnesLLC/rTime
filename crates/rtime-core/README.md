# rtime-core

[![crates.io](https://img.shields.io/crates/v/rtime-core.svg)](https://crates.io/crates/rtime-core)
[![docs.rs](https://docs.rs/rtime-core/badge.svg)](https://docs.rs/rtime-core)

Core types, traits, and algorithms shared across [rTime](https://github.com/ZerosAndOnesLLC/rTime),
a high-performance NTP/PTP time synchronization daemon written in Rust.

This crate is protocol-agnostic. It defines the timestamp arithmetic, clock
abstractions, configuration model, and the source-selection and clock-discipline
algorithms that the transport crates (`rtime-ntp`, `rtime-ptp`, `rtime-nts`) and the
daemon build on.

## Contents

| Module | Purpose |
|--------|---------|
| `timestamp` | NTP/PTP timestamp and duration types with fixed-point arithmetic |
| `clock` | Clock traits, stratum, and leap-indicator types |
| `config` | The `rtime.toml` configuration model (`RtimeConfig`) |
| `filter` | Clock filter that selects the best sample from a poll burst |
| `marzullo` | Marzullo's interval-intersection algorithm |
| `selection` | Truechimer/falseticker source selection and clustering |
| `servo` | PI servo loop that drives clock discipline |
| `source` | Per-source measurement and identity types |

## License

Licensed under the [MIT license](LICENSE).
