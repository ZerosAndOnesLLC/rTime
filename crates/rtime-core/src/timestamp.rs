use std::fmt;
use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_UNIX_EPOCH_DIFF: u64 = 2_208_988_800;

/// NTP uses a 64-bit timestamp: 32-bit seconds since 1900-01-01 + 32-bit fraction.
/// Stored as a single u64 for arithmetic efficiency.
/// Upper 32 bits = seconds, lower 32 bits = fractional seconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    pub const ZERO: Self = Self(0);

    /// Create from separate seconds (since NTP epoch) and fraction parts.
    pub fn new(seconds: u32, fraction: u32) -> Self {
        Self(((seconds as u64) << 32) | (fraction as u64))
    }

    /// Create from the current system time.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// Convert from a SystemTime.
    pub fn from_system_time(time: SystemTime) -> Self {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let ntp_seconds = duration.as_secs() + NTP_UNIX_EPOCH_DIFF;
        let fraction =
            ((duration.subsec_nanos() as u64) << 32) / 1_000_000_000;
        Self::new(ntp_seconds as u32, fraction as u32)
    }

    /// Convert to a SystemTime.
    pub fn to_system_time(self) -> SystemTime {
        let secs = self.seconds() as u64;
        let unix_secs = secs.saturating_sub(NTP_UNIX_EPOCH_DIFF);
        let nanos = ((self.fraction() as u64) * 1_000_000_000) >> 32;
        UNIX_EPOCH + Duration::new(unix_secs, nanos as u32)
    }

    /// Seconds since NTP epoch (upper 32 bits).
    pub fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Fractional seconds (lower 32 bits).
    pub fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// Raw 64-bit value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Create from raw 64-bit value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Serialize to 8-byte big-endian wire format.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Deserialize from 8-byte big-endian wire format.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

impl fmt::Debug for NtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NtpTimestamp({}.{:010})",
            self.seconds(),
            self.fraction()
        )
    }
}

impl fmt::Display for NtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nanos = ((self.fraction() as u64) * 1_000_000_000) >> 32;
        write!(f, "{}.{:09}", self.seconds(), nanos)
    }
}

/// PTP uses an 80-bit timestamp: 48-bit seconds + 32-bit nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PtpTimestamp {
    /// Seconds since PTP epoch (TAI, 1970-01-01). Only lower 48 bits used on wire.
    pub seconds: u64,
    /// Nanoseconds [0, 999_999_999].
    pub nanoseconds: u32,
}

impl PtpTimestamp {
    pub const ZERO: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };

    pub fn new(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }

    /// Convert to NtpTimestamp (approximate, ignores TAI-UTC offset).
    pub fn to_ntp_timestamp(self) -> NtpTimestamp {
        let ntp_secs = self.seconds + NTP_UNIX_EPOCH_DIFF;
        let fraction = ((self.nanoseconds as u64) << 32) / 1_000_000_000;
        NtpTimestamp::new(ntp_secs as u32, fraction as u32)
    }

    /// Serialize the 10-byte wire format (6 bytes seconds + 4 bytes nanos).
    pub fn to_bytes(self) -> [u8; 10] {
        let mut buf = [0u8; 10];
        let sec_bytes = self.seconds.to_be_bytes();
        buf[0..6].copy_from_slice(&sec_bytes[2..8]);
        buf[6..10].copy_from_slice(&self.nanoseconds.to_be_bytes());
        buf
    }

    /// Deserialize from 10-byte wire format.
    pub fn from_bytes(bytes: [u8; 10]) -> Self {
        let mut sec_buf = [0u8; 8];
        sec_buf[2..8].copy_from_slice(&bytes[0..6]);
        let seconds = u64::from_be_bytes(sec_buf);
        let nanoseconds =
            u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        Self {
            seconds,
            nanoseconds,
        }
    }
}

impl fmt::Display for PtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.seconds, self.nanoseconds)
    }
}

/// High-resolution signed duration for offset/delay calculations.
/// Stored as signed nanoseconds in i128 for sub-nanosecond precision
/// with the lower 32 bits representing fractional nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtpDuration(i128);

impl NtpDuration {
    pub const ZERO: Self = Self(0);

    /// Number of fractional bits in the fixed-point representation.
    const FRAC_BITS: u32 = 32;

    /// Create from whole nanoseconds.
    pub fn from_nanos(nanos: i64) -> Self {
        Self((nanos as i128) << Self::FRAC_BITS)
    }

    /// Create from seconds as f64.
    pub fn from_seconds_f64(secs: f64) -> Self {
        let nanos = secs * 1_000_000_000.0;
        Self((nanos as i128) << Self::FRAC_BITS)
    }

    /// Create from milliseconds.
    pub fn from_millis(ms: i64) -> Self {
        Self::from_nanos(ms * 1_000_000)
    }

    /// Convert to nanoseconds (truncating fractional part).
    pub fn to_nanos(self) -> i64 {
        (self.0 >> Self::FRAC_BITS) as i64
    }

    /// Convert to seconds as f64.
    pub fn to_seconds_f64(self) -> f64 {
        (self.0 as f64) / ((1i128 << Self::FRAC_BITS) as f64) / 1_000_000_000.0
    }

    /// Convert to milliseconds as f64.
    pub fn to_millis_f64(self) -> f64 {
        self.to_seconds_f64() * 1_000.0
    }

    /// Absolute value.
    pub fn abs(self) -> Self {
        Self(self.0.abs())
    }

    /// Create from NTP short format (16.16 fixed-point, in seconds).
    pub fn from_ntp_short(raw: u32) -> Self {
        let seconds = (raw >> 16) as i64;
        let fraction = (raw & 0xFFFF) as i64;
        let nanos = seconds * 1_000_000_000 + (fraction * 1_000_000_000) / 65536;
        Self::from_nanos(nanos)
    }

    /// Convert to NTP short format (16.16 fixed-point, in seconds).
    /// Only works for non-negative durations.
    pub fn to_ntp_short(self) -> u32 {
        let nanos = self.to_nanos().max(0) as u64;
        let seconds = nanos / 1_000_000_000;
        let frac_nanos = nanos % 1_000_000_000;
        let frac = (frac_nanos * 65536) / 1_000_000_000;
        ((seconds as u32) << 16) | (frac as u32)
    }

    /// Compute the difference between two NTP timestamps as a duration.
    pub fn between(a: NtpTimestamp, b: NtpTimestamp) -> Self {
        let diff = (b.0 as i128) - (a.0 as i128);
        // Convert from NTP fixed-point (32.32 seconds) to our format (nanos with 32 frac bits)
        // NTP: upper 32 = seconds, lower 32 = fractional seconds
        // We need nanoseconds << 32
        // diff is in 32.32 seconds format
        // nanos = diff * 1_000_000_000 / (1 << 32)
        // But we want nanos << 32, so: diff * 1_000_000_000
        Self(diff * 1_000_000_000 / (1i128 << 32) * (1i128 << Self::FRAC_BITS))
    }

    /// Raw internal value for serialization.
    pub fn raw(self) -> i128 {
        self.0
    }

    /// Create from raw internal value (inverse of `raw()`).
    pub fn from_raw(raw: i128) -> Self {
        Self(raw)
    }
}

impl Add for NtpDuration {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for NtpDuration {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::Div<i64> for NtpDuration {
    type Output = Self;
    fn div(self, rhs: i64) -> Self {
        Self(self.0 / rhs as i128)
    }
}

impl std::ops::Neg for NtpDuration {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl fmt::Debug for NtpDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtpDuration({:.9}s)", self.to_seconds_f64())
    }
}

impl fmt::Display for NtpDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.to_seconds_f64();
        if secs.abs() < 0.001 {
            write!(f, "{:.3}us", secs * 1_000_000.0)
        } else if secs.abs() < 1.0 {
            write!(f, "{:.3}ms", secs * 1_000.0)
        } else {
            write!(f, "{:.6}s", secs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_timestamp_roundtrip_bytes() {
        let ts = NtpTimestamp::new(3_900_000_000, 2_147_483_648);
        let bytes = ts.to_bytes();
        let ts2 = NtpTimestamp::from_bytes(bytes);
        assert_eq!(ts, ts2);
    }

    #[test]
    fn ntp_timestamp_system_time_roundtrip() {
        let now = SystemTime::now();
        let ts = NtpTimestamp::from_system_time(now);
        let back = ts.to_system_time();
        let diff = now
            .duration_since(back)
            .or_else(|e| Ok::<_, std::convert::Infallible>(e.duration()))
            .unwrap();
        // Should be within 1 microsecond (NTP fraction precision)
        assert!(diff < Duration::from_micros(1));
    }

    #[test]
    fn ntp_timestamp_zero() {
        let ts = NtpTimestamp::ZERO;
        assert_eq!(ts.seconds(), 0);
        assert_eq!(ts.fraction(), 0);
    }

    #[test]
    fn ptp_timestamp_roundtrip_bytes() {
        let ts = PtpTimestamp::new(1_000_000, 500_000_000);
        let bytes = ts.to_bytes();
        let ts2 = PtpTimestamp::from_bytes(bytes);
        assert_eq!(ts, ts2);
    }

    #[test]
    fn ptp_timestamp_48bit_seconds() {
        // Verify only lower 48 bits are used in wire format
        let ts = PtpTimestamp::new(0x0000_FFFF_FFFF_FFFF, 0);
        let bytes = ts.to_bytes();
        let ts2 = PtpTimestamp::from_bytes(bytes);
        assert_eq!(ts2.seconds, 0x0000_FFFF_FFFF_FFFF);
    }

    #[test]
    fn ntp_duration_from_nanos() {
        let d = NtpDuration::from_nanos(1_000_000_000); // 1 second
        assert!((d.to_seconds_f64() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ntp_duration_from_seconds_f64() {
        let d = NtpDuration::from_seconds_f64(0.5);
        assert!((d.to_seconds_f64() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ntp_duration_arithmetic() {
        let a = NtpDuration::from_nanos(100);
        let b = NtpDuration::from_nanos(50);
        assert_eq!((a + b).to_nanos(), 150);
        assert_eq!((a - b).to_nanos(), 50);
        assert_eq!((a / 2).to_nanos(), 50);
        assert_eq!((-a).to_nanos(), -100);
    }

    #[test]
    fn ntp_duration_abs() {
        let d = NtpDuration::from_nanos(-500);
        assert_eq!(d.abs().to_nanos(), 500);
    }

    #[test]
    fn ntp_duration_between_timestamps() {
        let t1 = NtpTimestamp::new(1000, 0);
        let t2 = NtpTimestamp::new(1001, 0);
        let diff = NtpDuration::between(t1, t2);
        assert!((diff.to_seconds_f64() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn ntp_duration_ntp_short_roundtrip() {
        let d = NtpDuration::from_millis(500);
        let short = d.to_ntp_short();
        let d2 = NtpDuration::from_ntp_short(short);
        assert!((d.to_millis_f64() - d2.to_millis_f64()).abs() < 0.1);
    }

    #[test]
    fn ntp_duration_display() {
        let d = NtpDuration::from_nanos(500);
        assert!(format!("{}", d).contains("us"));

        let d = NtpDuration::from_millis(50);
        assert!(format!("{}", d).contains("ms"));

        let d = NtpDuration::from_seconds_f64(2.5);
        assert!(format!("{}", d).contains("s"));
    }
}
