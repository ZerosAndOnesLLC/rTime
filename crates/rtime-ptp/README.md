# rtime-ptp

[![crates.io](https://img.shields.io/crates/v/rtime-ptp.svg)](https://crates.io/crates/rtime-ptp)
[![docs.rs](https://docs.rs/rtime-ptp/badge.svg)](https://docs.rs/rtime-ptp)

PTP / IEEE 1588 (Precision Time Protocol) implementation for
[rTime](https://github.com/ZerosAndOnesLLC/rTime), a high-performance NTP/PTP time
synchronization daemon written in Rust.

Covers the message codec, the Best Master Clock Algorithm (BMCA), the datasets that
describe a PTP port and clock, and the end-to-end delay computation used to derive offset
from `Sync`/`Follow_Up`/`Delay_Req`/`Delay_Resp` exchanges.

## Contents

| Module | Purpose |
|--------|---------|
| `message` | PTP message header and body codec |
| `announce` | `Announce` message handling |
| `bmca` | Best Master Clock Algorithm (dataset comparison and master selection) |
| `dataset` | Default/current/parent/time-properties datasets |
| `delay` | End-to-end delay and offset computation |
| `port` | PTP port state machine |
| `tlv` | TLV (type-length-value) extension encoding |

## License

Licensed under the [MIT license](LICENSE).
