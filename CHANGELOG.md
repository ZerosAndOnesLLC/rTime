# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.15.0]

### Fixed

- **Clock steps no longer snowball.** Source selection re-ran over the cached
  latest measurement from every source, including measurements taken *before*
  the servo's most recent step. Each stale entry re-elected the old offset and
  the servo stepped again, so with three sources every correction was applied
  ~3× and the error doubled each round (130 ms → −252 ms → 513 ms → … → 18 min)
  until it exceeded the panic threshold and the clock was stranded. The
  discipline task now records every step in a `StepLedger` (`rtime_core::steps`)
  keyed on the monotonic clock, and selection reconciles each cached
  measurement against it: measurements completed before a step have the step
  removed from their offset, measurements whose exchange straddled a step are
  discarded.
- Every offset the selection loop publishes is tagged with the step-ledger
  sequence it was reconciled against; the discipline task ignores an offset
  computed before a step it has since applied, closing the small window in
  which a selection racing the step syscall could still re-apply it.
- **Negative sub-second clock steps failed with `EINVAL` on Linux.** The
  `ADJ_SETOFFSET` timespec was built with `nanos / 1e9, nanos % 1e9`, which
  truncates toward zero and produced a negative `tv_nsec` for any
  backward step that was not a whole number of seconds (e.g. −250 ms →
  `(0, −250000000)`); the kernel rejects that, so a clock that ran ahead by
  more than `step_threshold_ms` could never be stepped back. The timespec is
  now normalised with `div_euclid`/`rem_euclid` (FreeBSD path simplified to
  match).
- `UnixClock::is_adjustable()` reported `true` without `CAP_SYS_TIME`. The
  probe was a read-only `adjtimex`/`ntp_adjtime` query, which needs no
  privilege, so the daemon never entered read-only mode and instead logged
  "Failed to step clock: insufficient privileges" on every poll. The probe now
  issues a privileged no-op (`ADJ_SETOFFSET` of zero on Linux; rewriting the
  current frequency on FreeBSD).
- A source that stops answering no longer keeps voting with its last
  measurement forever: NTP measurements expire after eight missed polls
  (mirrors the NTP reachability register).

### Added

- `clock.panic_restart_after` (default `8`): after that many consecutive
  offsets refused by the panic clamp the daemon exits with an error so its
  supervisor (`daemon -R`, systemd `Restart=`) restarts it and
  `allow_initial_step` can step the clock back into range, instead of logging
  "Refused implausible offset" forever. `0` restores the old behaviour.
- `PiServo::consecutive_rejects()`.

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

[0.15.0]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.15.0
[0.14.2]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.2
[0.14.1]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.1
[0.14.0]: https://github.com/ZerosAndOnesLLC/rTime/releases/tag/v0.14.0
