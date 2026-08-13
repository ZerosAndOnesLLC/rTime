# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.2]

### Changed

- Updated all dependencies to the latest stable versions.
- `aes-siv` 0.7 → 0.8 (RustCrypto `aead` 0.6 stack); internal AEAD code in
  `rtime-nts` migrated off the removed `GenericArray` type. No wire-format or
  API changes.

## [0.14.1]

### Changed

- Updated all dependencies to the latest compatible versions.

## [0.14.0]

### Added

- Full crates.io publishing metadata for the workspace: descriptions, keywords,
  categories, `readme`, `documentation`, `homepage`, and a verified MSRV
  (`rust-version = "1.88"`, the floor required by the let-chains used in the daemon).
- Crate-level (`//!`) documentation and per-crate `README.md` for every library crate.

### Changed

- The binary crate is now published as `rtimed` (the installed binary remains `rtime`),
  because the `rtime` crate name is already taken on crates.io.
- Internal path dependencies now carry version requirements so they resolve from the
  registry when published.
- Updated all dependencies to the latest stable, compatible versions.

[0.14.2]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.2
[0.14.1]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.1
[0.14.0]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.0
