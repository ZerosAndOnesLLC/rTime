use crate::timestamp::{NtpDuration, NtpTimestamp};

/// Abstraction over system clock access.
///
/// Implementations:
/// - `UnixClock` (real system clock via clock_gettime/clock_adjtime)
/// - `PhcClock` (PTP hardware clock via /dev/ptpN ioctl) -- Phase 7
/// - `MockClock` (deterministic testing)
pub trait Clock: Send + Sync {
    /// Read current time from this clock.
    fn now(&self) -> Result<NtpTimestamp, ClockError>;

    /// Apply a step adjustment (instant offset). Requires privilege.
    fn step(&self, offset: NtpDuration) -> Result<(), ClockError>;

    /// Apply a slew adjustment (frequency change in PPM). Requires privilege.
    fn adjust_frequency(&self, ppm: f64) -> Result<(), ClockError>;

    /// Read current frequency offset in PPM.
    fn frequency_offset(&self) -> Result<f64, ClockError>;

    /// Get clock resolution as a duration.
    fn resolution(&self) -> NtpDuration;

    /// Maximum allowed frequency adjustment in PPM.
    fn max_frequency_adjustment(&self) -> f64;

    /// Whether this clock supports discipline (has CAP_SYS_TIME or equivalent).
    fn is_adjustable(&self) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("insufficient privileges for clock adjustment")]
    PermissionDenied,

    #[error("clock device not found")]
    DeviceNotFound,

    #[error("operation not supported")]
    NotSupported,

    #[error("OS error: {0}")]
    Os(#[from] std::io::Error),
}

/// Status of clock synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockStatus {
    /// Not synchronized to any source.
    Unsynchronized,
    /// Synchronizing (converging).
    Synchronizing,
    /// Synchronized and stable.
    Synchronized,
}

/// Leap indicator values per NTPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LeapIndicator {
    #[default]
    NoWarning = 0,
    LastMinute61Seconds = 1,
    LastMinute59Seconds = 2,
    AlarmUnsynchronized = 3,
}

impl LeapIndicator {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::NoWarning,
            1 => Self::LastMinute61Seconds,
            2 => Self::LastMinute59Seconds,
            _ => Self::AlarmUnsynchronized,
        }
    }
}
