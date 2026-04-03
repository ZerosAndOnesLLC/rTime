#[cfg(target_os = "linux")]
mod linux_phc {
    use std::ffi::CString;
    use std::sync::Mutex;

    use rtime_core::clock::{Clock, ClockError};
    use rtime_core::timestamp::{NtpDuration, NtpTimestamp, PtpTimestamp};

    /// Dynamic clock ID base used by the kernel for `/dev/ptpN`.
    ///
    /// The kernel maps `/dev/ptpN` file descriptors to clockid_t values using:
    ///     clockid = ~(fd << 3) | 3
    /// This allows `clock_gettime` to read PTP hardware clocks directly.
    const CLOCKFD: libc::clockid_t = 3;

    /// Convert a raw file descriptor to a `clockid_t` that can be passed to
    /// `clock_gettime` / `clock_settime` / `clock_adjtime`.
    fn fd_to_clockid(fd: libc::c_int) -> libc::clockid_t {
        (!(fd as libc::clockid_t) << 3) | CLOCKFD
    }

    /// PTP Hardware Clock (PHC) accessed via `/dev/ptpN`.
    ///
    /// This provides direct access to the NIC's hardware clock through the Linux
    /// PTP subsystem. The PHC can be read with nanosecond precision and disciplined
    /// independently of the system clock.
    ///
    /// The internal Mutex ensures that read-modify-write operations like `step()`
    /// are atomic with respect to concurrent callers.
    pub struct PhcClock {
        fd: libc::c_int,
        clockid: libc::clockid_t,
        device_path: String,
        /// Guards clock mutation operations (step, adjust_frequency) to prevent
        /// TOCTOU races from concurrent calls via &self.
        discipline_lock: Mutex<()>,
    }

    impl std::fmt::Debug for PhcClock {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PhcClock")
                .field("fd", &self.fd)
                .field("clockid", &self.clockid)
                .field("device_path", &self.device_path)
                .finish()
        }
    }

    // SAFETY: The file descriptor is owned and mutation operations are
    // serialized through the discipline_lock Mutex.
    unsafe impl Send for PhcClock {}
    unsafe impl Sync for PhcClock {}

    impl PhcClock {
        /// Open a PTP hardware clock device.
        ///
        /// `device` should be a path like `/dev/ptp0`. The device must exist and be
        /// readable by the current process.
        pub fn open(device: &str) -> Result<Self, ClockError> {
            let c_path = CString::new(device).map_err(|_| ClockError::DeviceNotFound)?;

            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::ENOENT) | Some(libc::ENXIO) => Err(ClockError::DeviceNotFound),
                    Some(libc::EACCES) | Some(libc::EPERM) => Err(ClockError::PermissionDenied),
                    _ => Err(ClockError::Os(err)),
                };
            }

            let clockid = fd_to_clockid(fd);

            Ok(Self {
                fd,
                clockid,
                device_path: device.to_string(),
                discipline_lock: Mutex::new(()),
            })
        }

        /// Read the PHC time as a `PtpTimestamp`.
        ///
        /// Uses `clock_gettime` with the dynamic clockid derived from the PHC file
        /// descriptor.
        pub fn read_time(&self) -> Result<PtpTimestamp, ClockError> {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            let ret = unsafe { libc::clock_gettime(self.clockid, &mut ts) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EINVAL) => Err(ClockError::DeviceNotFound),
                    _ => Err(ClockError::Os(err)),
                };
            }

            Ok(PtpTimestamp::new(ts.tv_sec as u64, ts.tv_nsec as u32))
        }

        /// Get the device path this clock was opened from.
        pub fn device_path(&self) -> &str {
            &self.device_path
        }

        /// Get the raw file descriptor (for advanced ioctl operations).
        pub fn as_raw_fd(&self) -> libc::c_int {
            self.fd
        }

        /// Get the dynamic clockid for this PHC.
        pub fn clockid(&self) -> libc::clockid_t {
            self.clockid
        }
    }

    impl Drop for PhcClock {
        fn drop(&mut self) {
            if self.fd >= 0 {
                unsafe {
                    libc::close(self.fd);
                }
            }
        }
    }

    impl Clock for PhcClock {
        fn now(&self) -> Result<NtpTimestamp, ClockError> {
            let ptp_ts = self.read_time()?;
            Ok(ptp_ts.to_ntp_timestamp())
        }

        fn step(&self, offset: NtpDuration) -> Result<(), ClockError> {
            // Hold lock to prevent TOCTOU race in read-modify-write.
            let _guard = self.discipline_lock.lock().map_err(|_| {
                ClockError::Os(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "discipline lock poisoned",
                ))
            })?;

            // Read current time, apply offset, and set.
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            let ret = unsafe { libc::clock_gettime(self.clockid, &mut ts) };
            if ret < 0 {
                return Err(ClockError::Os(std::io::Error::last_os_error()));
            }

            let nanos = offset.to_nanos();
            let total_ns = ts.tv_sec * 1_000_000_000 + ts.tv_nsec + nanos;

            if total_ns < 0 {
                return Err(ClockError::Os(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "step would set clock to negative time",
                )));
            }

            ts.tv_sec = (total_ns / 1_000_000_000) as libc::time_t;
            ts.tv_nsec = (total_ns % 1_000_000_000) as libc::c_long;

            let ret = unsafe { libc::clock_settime(self.clockid, &ts) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EPERM) => Err(ClockError::PermissionDenied),
                    _ => Err(ClockError::Os(err)),
                };
            }

            Ok(())
        }

        fn adjust_frequency(&self, ppm: f64) -> Result<(), ClockError> {
            let _guard = self.discipline_lock.lock().map_err(|_| {
                ClockError::Os(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "discipline lock poisoned",
                ))
            })?;

            // Use clock_adjtime to adjust the PHC frequency.
            let freq = (ppm * 65536.0) as i64;

            let mut tx: libc::timex = unsafe { std::mem::zeroed() };
            tx.modes = libc::ADJ_FREQUENCY;
            tx.freq = freq;

            let ret = unsafe { libc::clock_adjtime(self.clockid, &mut tx) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EPERM) => Err(ClockError::PermissionDenied),
                    Some(libc::EOPNOTSUPP) => Err(ClockError::NotSupported),
                    _ => Err(ClockError::Os(err)),
                };
            }

            Ok(())
        }

        fn frequency_offset(&self) -> Result<f64, ClockError> {
            let mut tx: libc::timex = unsafe { std::mem::zeroed() };
            tx.modes = 0; // read-only query

            let ret = unsafe { libc::clock_adjtime(self.clockid, &mut tx) };
            if ret < 0 {
                return Err(ClockError::Os(std::io::Error::last_os_error()));
            }

            Ok(tx.freq as f64 / 65536.0)
        }

        fn resolution(&self) -> NtpDuration {
            // PHC resolution varies by hardware; assume 1ns as a reasonable default.
            NtpDuration::from_nanos(1)
        }

        fn max_frequency_adjustment(&self) -> f64 {
            // Most PHCs support wider adjustments than the system clock.
            // Common NICs (Intel i210, etc.) support up to ~1000 ppm.
            1000.0
        }

        fn is_adjustable(&self) -> bool {
            // If we could open it O_RDWR, it's likely adjustable (with CAP_SYS_TIME).
            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fd_to_clockid_formula() {
            // The formula is: clockid = (~fd << 3) | 3
            // For fd=0: (~0 << 3) | 3 = (-1 << 3) | 3 = -8 | 3 = -5
            let cid = fd_to_clockid(0);
            assert_eq!(cid, -5);

            // For fd=3: (~3 << 3) | 3 = (-4 << 3) | 3 = -32 | 3 = -29
            let cid = fd_to_clockid(3);
            assert_eq!(cid, (-4i32 << 3) | 3);
            assert_eq!(cid, -29);
        }

        #[test]
        fn open_nonexistent_device() {
            let result = PhcClock::open("/dev/ptp_nonexistent_999");
            assert!(result.is_err());
            match result.unwrap_err() {
                ClockError::DeviceNotFound => {}
                ClockError::PermissionDenied => {
                    // In some environments, /dev/ access might be denied entirely.
                }
                other => panic!("expected DeviceNotFound or PermissionDenied, got: {other}"),
            }
        }

        #[test]
        fn open_ptp0_if_available() {
            // This test only runs meaningfully on systems with a PHC.
            match PhcClock::open("/dev/ptp0") {
                Ok(phc) => {
                    // If we can open it, try reading.
                    match phc.read_time() {
                        Ok(ts) => {
                            assert!(ts.seconds > 0, "PHC time should be non-zero");
                        }
                        Err(e) => {
                            eprintln!("read_time failed (may be expected): {e}");
                        }
                    }
                }
                Err(_) => {
                    // No PHC available -- that's fine.
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_phc::PhcClock;

/// Stub PhcClock for non-Linux platforms (PTP hardware clocks are Linux-specific).
#[cfg(not(target_os = "linux"))]
pub struct PhcClock;

#[cfg(not(target_os = "linux"))]
impl PhcClock {
    /// PTP hardware clocks are not supported on this platform.
    pub fn open(_device: &str) -> Result<Self, rtime_core::clock::ClockError> {
        Err(rtime_core::clock::ClockError::NotSupported)
    }
}
