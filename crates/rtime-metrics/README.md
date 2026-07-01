# rtime-metrics

[![crates.io](https://img.shields.io/crates/v/rtime-metrics.svg)](https://crates.io/crates/rtime-metrics)
[![docs.rs](https://docs.rs/rtime-metrics/badge.svg)](https://docs.rs/rtime-metrics)

Prometheus metrics for [rTime](https://github.com/ZerosAndOnesLLC/rTime),
a high-performance NTP/PTP time synchronization daemon written in Rust.

Defines the daemon's metric instruments (clock offset/jitter/frequency, per-source
statistics, packet counters, selection results) and an HTTP exporter that serves them in
Prometheus text format at `/metrics`.

## Contents

| Module | Purpose |
|--------|---------|
| `instruments` | Metric definitions and update helpers |
| `exporter` | Axum-based `/metrics` HTTP endpoint |

The [`metrics`](https://crates.io/crates/metrics) facade crate is re-exported for
convenience.

## License

Licensed under the [MIT license](LICENSE).
