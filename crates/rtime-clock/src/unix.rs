use rtime_core::clock::{Clock, ClockError};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

use crate::adjtime::Timex;

/// FreeBSD MOD_FREQUENCY constant for ntp_adjtime().
#[cfg(target_os = "freebsd")]
const MOD_FREQUENCY: u32 = 0x0002;

/// Real system clock using POSIX clock_gettime(CLOCK_REALTIME).
pub struct UnixClock {
    adjustable: bool,
}

impl UnixClock {
    /// Create a new UnixClock. Probes whether clock adjustment is available.
    pub fn new() -> Self {
        let adjustable = Self::probe_adjustable();
        Self { adjustable }
    }

    fn read_clock() -> Result<nix::sys::time::TimeSpec, ClockError> {
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME)
            .map_err(|e| ClockError::Os(e.into()))
    }

    // --- probe_adjustable ---

    /// A read-only `adjtimex` query (modes = 0) succeeds for any user, so it
    /// cannot tell us whether we hold `CAP_SYS_TIME`. Instead inject a
    /// zero-length offset: any non-zero `modes` requires the capability and
    /// fails with `EPERM` without it, while a zero offset leaves the clock
    /// untouched when it does succeed.
    #[cfg(target_os = "linux")]
    fn probe_adjustable() -> bool {
        let mut tx = Timex::new();
        tx.0.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;
        tx.0.time.tv_sec = 0;
        tx.0.time.tv_usec = 0;
        crate::adjtime::adjtimex(&mut tx).is_ok()
    }

    /// Like Linux, a modes = 0 `ntp_adjtime` query needs no privilege.
    /// Read the current frequency and write the same value back: a
    /// non-zero `modes` requires root and fails with `EPERM` otherwise.
    #[cfg(target_os = "freebsd")]
    fn probe_adjustable() -> bool {
        let mut tx = Timex::new(); // modes = 0 => read-only query
        if crate::adjtime::ntp_adjtime(&mut tx).is_err() {
            return false;
        }
        tx.0.modes = MOD_FREQUENCY as u32;
        crate::adjtime::ntp_adjtime(&mut tx).is_ok()
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    fn probe_adjustable() -> bool {
        false
    }

    // --- step (platform-specific helpers) ---

    #[cfg(target_os = "linux")]
    fn step_impl(&self, offset: NtpDuration) -> Result<(), ClockError> {
        let (secs, nanos) = split_timespec(offset.to_nanos());
        let mut tx = Timex::new();
        tx.0.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;
        tx.0.time.tv_sec = secs;
        tx.0.time.tv_usec = nanos;

        crate::adjtime::adjtimex(&mut tx).map_err(|err| {
            if err.raw_os_error() == Some(libc::EPERM) {
                ClockError::PermissionDenied
            } else {
                ClockError::Os(err)
            }
        })?;
        Ok(())
    }

    #[cfg(target_os = "freebsd")]
    fn step_impl(&self, offset: NtpDuration) -> Result<(), ClockError> {
        use nix::sys::time::TimeSpec;
        // FreeBSD lacks ADJ_SETOFFSET. Read current time, add offset, set.
        let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME)
            .map_err(|e| ClockError::Os(e.into()))?;

        let (secs, nanos) = split_timespec(offset.to_nanos());
        let mut tv_sec = ts.tv_sec() + secs;
        let mut tv_nsec = ts.tv_nsec() + nanos as libc::c_long;

        // Both parts are normalized, so at most one carry is needed.
        if tv_nsec >= 1_000_000_000 {
            tv_sec += 1;
            tv_nsec -= 1_000_000_000;
        }

        let new_ts = TimeSpec::new(tv_sec, tv_nsec);
        nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, new_ts).map_err(|e| {
            let err: std::io::Error = e.into();
            if err.raw_os_error() == Some(libc::EPERM) {
                ClockError::PermissionDenied
            } else {
                ClockError::Os(err)
            }
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    fn step_impl(&self, _offset: NtpDuration) -> Result<(), ClockError> {
        Err(ClockError::NotSupported)
    }

    // --- adjust_frequency (platform-specific helpers) ---

    #[cfg(target_os = "linux")]
    fn adjust_frequency_impl(&self, ppm: f64) -> Result<(), ClockError> {
        // adjtimex freq is in units of 2^-16 ppm (scaled ppm)
        let freq = (ppm * 65536.0) as i64;

        let mut tx = Timex::new();
        tx.0.modes = libc::ADJ_FREQUENCY;
        tx.0.freq = freq;

        crate::adjtime::adjtimex(&mut tx).map_err(|err| {
            if err.raw_os_error() == Some(libc::EPERM) {
                ClockError::PermissionDenied
            } else {
                ClockError::Os(err)
            }
        })?;
        Ok(())
    }

    #[cfg(target_os = "freebsd")]
    fn adjust_frequency_impl(&self, ppm: f64) -> Result<(), ClockError> {
        let freq = (ppm * 65536.0) as i64;

        let mut tx = Timex::new();
        tx.0.modes = MOD_FREQUENCY as u32;
        tx.0.freq = freq;

        crate::adjtime::ntp_adjtime(&mut tx).map_err(|err| {
            if err.raw_os_error() == Some(libc::EPERM) {
                ClockError::PermissionDenied
            } else {
                ClockError::Os(err)
            }
        })?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    fn adjust_frequency_impl(&self, _ppm: f64) -> Result<(), ClockError> {
        Err(ClockError::NotSupported)
    }

    // --- frequency_offset (platform-specific helpers) ---

    #[cfg(target_os = "linux")]
    fn frequency_offset_impl(&self) -> Result<f64, ClockError> {
        let mut tx = Timex::new(); // modes = 0 => query
        crate::adjtime::adjtimex(&mut tx).map_err(ClockError::Os)?;
        Ok(tx.0.freq as f64 / 65536.0)
    }

    #[cfg(target_os = "freebsd")]
    fn frequency_offset_impl(&self) -> Result<f64, ClockError> {
        let mut tx = Timex::new(); // modes = 0 => query
        crate::adjtime::ntp_adjtime(&mut tx).map_err(ClockError::Os)?;
        Ok(tx.0.freq as f64 / 65536.0)
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    fn frequency_offset_impl(&self) -> Result<f64, ClockError> {
        Err(ClockError::NotSupported)
    }
}

impl Default for UnixClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for UnixClock {
    fn now(&self) -> Result<NtpTimestamp, ClockError> {
        let ts = Self::read_clock()?;
        let st = std::time::UNIX_EPOCH
            + std::time::Duration::new(ts.tv_sec() as u64, ts.tv_nsec() as u32);
        Ok(NtpTimestamp::from_system_time(st))
    }

    fn step(&self, offset: NtpDuration) -> Result<(), ClockError> {
        if !self.adjustable {
            return Err(ClockError::PermissionDenied);
        }
        self.step_impl(offset)
    }

    fn adjust_frequency(&self, ppm: f64) -> Result<(), ClockError> {
        if !self.adjustable {
            return Err(ClockError::PermissionDenied);
        }
        self.adjust_frequency_impl(ppm)
    }

    fn frequency_offset(&self) -> Result<f64, ClockError> {
        self.frequency_offset_impl()
    }

    fn resolution(&self) -> NtpDuration {
        // CLOCK_REALTIME typically has ~1ns resolution
        NtpDuration::from_nanos(1)
    }

    fn max_frequency_adjustment(&self) -> f64 {
        // Kernel limit: +/-500 ppm (both Linux and FreeBSD)
        500.0
    }

    fn is_adjustable(&self) -> bool {
        self.adjustable
    }
}

/// Split a signed nanosecond duration into a normalized `(tv_sec, tv_nsec)`
/// pair with `0 <= tv_nsec < 1_000_000_000`, as the kernel requires.
///
/// A naive `nanos / 1e9, nanos % 1e9` truncates toward zero, so a negative
/// sub-second step such as −250 ms became `(0, −250_000_000)`, which Linux's
/// `ADJ_SETOFFSET` rejects with `EINVAL` (`timekeeping_inject_offset` insists
/// on a non-negative `tv_nsec`). The clock could then never be stepped
/// backwards by anything other than a whole number of seconds.
#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
fn split_timespec(nanos: i64) -> (i64, i64) {
    (
        nanos.div_euclid(1_000_000_000),
        nanos.rem_euclid(1_000_000_000),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_timespec_normalizes_negative_subsecond() {
        assert_eq!(split_timespec(0), (0, 0));
        assert_eq!(split_timespec(1_500_000_000), (1, 500_000_000));
        assert_eq!(split_timespec(-250_000_000), (-1, 750_000_000));
        assert_eq!(split_timespec(-1_000_000_000), (-1, 0));
        assert_eq!(split_timespec(-1_250_000_000), (-2, 750_000_000));
        assert_eq!(split_timespec(999_999_999), (0, 999_999_999));
    }

    #[test]
    fn split_timespec_roundtrips() {
        for n in [-3_000_000_001i64, -1, 0, 1, 2_999_999_999, i64::MIN / 2] {
            let (s, ns) = split_timespec(n);
            assert!((0..1_000_000_000).contains(&ns));
            assert_eq!(s * 1_000_000_000 + ns, n);
        }
    }
}
