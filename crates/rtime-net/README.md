# rtime-net

[![crates.io](https://img.shields.io/crates/v/rtime-net.svg)](https://crates.io/crates/rtime-net)
[![docs.rs](https://docs.rs/rtime-net/badge.svg)](https://docs.rs/rtime-net)

Network I/O with packet timestamping for
[rTime](https://github.com/ZerosAndOnesLLC/rTime), a high-performance NTP/PTP time
synchronization daemon written in Rust.

Wraps UDP sockets with software and (where available) hardware receive/transmit
timestamping — essential for accurate offset measurement — plus multicast join/leave and
network-interface discovery.

## Contents

| Module | Purpose |
|--------|---------|
| `udp` | Timestamped UDP socket wrappers |
| `multicast` | Multicast group membership (used by PTP) |
| `interface` | Network interface enumeration and capability queries |

## License

Licensed under the [MIT license](LICENSE).
