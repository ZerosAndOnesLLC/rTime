# rtime-nts

[![crates.io](https://img.shields.io/crates/v/rtime-nts.svg)](https://crates.io/crates/rtime-nts)
[![docs.rs](https://docs.rs/rtime-nts/badge.svg)](https://docs.rs/rtime-nts)

Network Time Security (NTS, [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915)) for
[rTime](https://github.com/ZerosAndOnesLLC/rTime), a high-performance NTP/PTP time
synchronization daemon written in Rust.

NTS adds authentication and replay protection to NTPv4 without per-packet asymmetric
crypto: a TLS 1.3 handshake (NTS-KE) establishes keys and issues opaque cookies, and each
subsequent NTP exchange is protected with AEAD (`AEAD_AES_SIV_CMAC_256`).

## Contents

| Module | Purpose |
|--------|---------|
| `ke` | NTS-KE (key establishment) record exchange over TLS |
| `records` | NTS-KE record framing and parsing |
| `aead` | AEAD encryption/decryption of NTP extension fields |
| `cookie` | Cookie issuance, storage, and rotation |

Protocol constants (algorithm ids, ports, key lengths) and the crate error type
`NtsError` are defined at the crate root.

## License

Licensed under the [MIT license](LICENSE).
