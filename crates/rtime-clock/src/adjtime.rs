//! Safe wrappers over the POSIX / Linux NTP kernel clock-adjustment APIs:
//! `adjtimex(2)` (Linux), `clock_adjtime(2)` (Linux), and `ntp_adjtime(3)`
//! (FreeBSD).
//!
//! These kernel APIs are not wrapped by `nix` or any other maintained
//! crate. Consolidating them into this module contains every `unsafe`
//! involved in NTP clock discipline to a single audited surface: four
//! functions total. Every call site elsewhere in this crate can then use
//! the wrappers without writing `unsafe` themselves.

use std::io;

/// A safe wrapper over `libc::timex`.
///
/// `Default` returns a fully zero-initialized struct, which is the
/// documented way to prepare a `timex` before calling `adjtimex` or
/// similar (a zero `modes` field means a read-only query).
#[repr(transparent)]
pub struct Timex(pub libc::timex);

impl Default for Timex {
    fn default() -> Self {
        // SAFETY: `libc::timex` is `#[repr(C)]` and contains only integer
        // fields and a `timeval`. An all-zero bit pattern is a valid
        // inhabitant of every field, and is also the documented "unset"
        // state that the kernel interprets as a read-only query.
        Self(unsafe { std::mem::zeroed() })
    }
}

impl Timex {
    /// Create a fresh zero-initialized `Timex`.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Call `adjtimex(2)` on Linux.
///
/// Returns the kernel clock state on success (a non-negative integer).
/// Callers set fields on `tx.0` before calling, and read fields from it
/// afterwards for queries like frequency offset.
#[cfg(target_os = "linux")]
pub fn adjtimex(tx: &mut Timex) -> io::Result<libc::c_int> {
    // SAFETY: `libc::adjtimex` requires a pointer to a valid, writable
    // `libc::timex`. `tx.0` is owned by `tx` and we hold a `&mut`, so
    // the pointer is valid, aligned, and exclusive for the duration of
    // the call.
    let ret = unsafe { libc::adjtimex(&mut tx.0 as *mut _) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

/// Call `clock_adjtime(2)` on Linux for the given `clockid_t`.
///
/// Used for adjusting dynamic clocks (e.g. PTP hardware clocks) with the
/// same `timex` interface as `adjtimex`.
#[cfg(target_os = "linux")]
pub fn clock_adjtime(clockid: libc::clockid_t, tx: &mut Timex) -> io::Result<libc::c_int> {
    // SAFETY: `libc::clock_adjtime` requires a clockid and a pointer to
    // a valid, writable `libc::timex`. The clockid is passed by value
    // and `tx.0` is owned via `&mut`, so both requirements are met.
    let ret = unsafe { libc::clock_adjtime(clockid, &mut tx.0 as *mut _) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

/// Call `ntp_adjtime(3)` on FreeBSD (equivalent to Linux `adjtimex`).
#[cfg(target_os = "freebsd")]
pub fn ntp_adjtime(tx: &mut Timex) -> io::Result<libc::c_int> {
    // SAFETY: `libc::ntp_adjtime` requires a pointer to a valid,
    // writable `libc::timex`. `tx.0` is owned by `tx` and we hold
    // `&mut`.
    let ret = unsafe { libc::ntp_adjtime(&mut tx.0 as *mut _) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}
