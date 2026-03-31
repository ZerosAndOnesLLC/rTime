use rtime_core::clock::{Clock, ClockError};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

/// Real system clock using POSIX clock_gettime(CLOCK_REALTIME).
pub struct UnixClock {
    adjustable: bool,
}

impl UnixClock {
    /// Create a new UnixClock. Probes whether clock adjustment is available.
    pub fn new() -> Self {
        // Check if we can adjust the clock by reading current adjtime status
        let adjustable = unsafe {
            let mut tx: libc::timex = std::mem::zeroed();
            tx.modes = 0; // read-only query
            libc::adjtimex(&mut tx) >= 0
        };

        Self { adjustable }
    }

    fn read_clock() -> Result<libc::timespec, ClockError> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        if ret != 0 {
            return Err(ClockError::Os(std::io::Error::last_os_error()));
        }
        Ok(ts)
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
            + std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        Ok(NtpTimestamp::from_system_time(st))
    }

    fn step(&self, offset: NtpDuration) -> Result<(), ClockError> {
        if !self.adjustable {
            return Err(ClockError::PermissionDenied);
        }

        let nanos = offset.to_nanos();
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        tx.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;
        tx.time.tv_sec = nanos / 1_000_000_000;
        tx.time.tv_usec = nanos % 1_000_000_000;

        let ret = unsafe { libc::adjtimex(&mut tx) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(ClockError::PermissionDenied);
            }
            return Err(ClockError::Os(err));
        }
        Ok(())
    }

    fn adjust_frequency(&self, ppm: f64) -> Result<(), ClockError> {
        if !self.adjustable {
            return Err(ClockError::PermissionDenied);
        }

        // adjtimex freq is in units of 2^-16 ppm (scaled ppm)
        let freq = (ppm * 65536.0) as i64;

        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        tx.modes = libc::ADJ_FREQUENCY;
        tx.freq = freq;

        let ret = unsafe { libc::adjtimex(&mut tx) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(ClockError::PermissionDenied);
            }
            return Err(ClockError::Os(err));
        }
        Ok(())
    }

    fn frequency_offset(&self) -> Result<f64, ClockError> {
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        tx.modes = 0;
        let ret = unsafe { libc::adjtimex(&mut tx) };
        if ret < 0 {
            return Err(ClockError::Os(std::io::Error::last_os_error()));
        }
        Ok(tx.freq as f64 / 65536.0)
    }

    fn resolution(&self) -> NtpDuration {
        // Linux CLOCK_REALTIME typically has ~1ns resolution
        NtpDuration::from_nanos(1)
    }

    fn max_frequency_adjustment(&self) -> f64 {
        // Linux kernel limit: ±500 ppm
        500.0
    }

    fn is_adjustable(&self) -> bool {
        self.adjustable
    }
}
