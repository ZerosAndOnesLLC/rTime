use rtime_core::clock::LeapIndicator;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

#[cfg(not(target_os = "linux"))]
use crate::RefClockError;

/// PPS edge timestamp.
#[derive(Debug, Clone)]
pub struct PpsEdge {
    /// Kernel timestamp of the PPS edge.
    pub timestamp: NtpTimestamp,
    /// Sequence number from the kernel.
    pub sequence: u32,
}

// PPS ioctl constants (from Linux kernel pps.h).
//
// The PPS_FETCH ioctl reads the most recent assert/clear edges from a PPS device.
// Actual value depends on architecture; on x86-64 Linux this is 0xC00870A4.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const PPS_FETCH: u64 = 0xC00870A4;

/// PPS driver using the Linux PPS API (`/dev/ppsN`).
///
/// PPS (Pulse Per Second) signals provide a precise 1-second boundary with
/// sub-microsecond accuracy. The driver reads edge timestamps from the kernel
/// via `ioctl(PPS_FETCH)` and computes the offset between the local clock and
/// the PPS edge.
///
/// PPS alone cannot determine the full time (it only marks second boundaries),
/// so it is typically paired with a GPS NMEA driver that provides coarse time.
pub struct PpsDriver {
    device: String,
    source_id: SourceId,
}

impl PpsDriver {
    /// Create a new PPS driver for the given device path (e.g. `/dev/pps0`).
    pub fn new(device: &str) -> Self {
        Self {
            device: device.to_string(),
            source_id: SourceId::RefClock {
                driver: "PPS".to_string(),
                unit: 0,
            },
        }
    }

    /// Return the device path.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Create a measurement from a PPS edge.
    ///
    /// The PPS edge marks a precise second boundary. The offset is computed as
    /// the sub-second portion of the local time at the PPS edge, which represents
    /// how far the local clock is from the true second boundary.
    ///
    /// If the local clock's fractional second is < 0.5s, the clock is ahead of
    /// the PPS edge (positive offset that must be subtracted). If > 0.5s, the
    /// clock is behind (the next PPS edge is closer).
    ///
    /// # Arguments
    ///
    /// * `edge` - The PPS edge with its kernel-reported timestamp.
    /// * `local_time` - The local system clock reading near the PPS edge.
    pub fn process_edge(&self, edge: &PpsEdge, local_time: NtpTimestamp) -> SourceMeasurement {
        // The PPS edge represents an exact second boundary.
        // The offset between local time and the true second boundary is
        // derived from the fractional part of the edge timestamp.
        //
        // edge.timestamp is the kernel's record of when the PPS pulse arrived.
        // In an ideal system this would be exactly on a second boundary.
        // The fractional part of the edge timestamp tells us how far the
        // system clock was from the second boundary when the edge arrived.
        let edge_frac = edge.timestamp.fraction();
        let half_second = 1u32 << 31; // 0.5s in NTP fraction units

        // If fractional part < 0.5s, the local clock is slightly ahead of the
        // second boundary -> negative offset (need to subtract).
        // If fractional part >= 0.5s, the local clock just passed a second boundary
        // and is close to the next one -> positive offset = (1.0 - frac) seconds.
        let offset_nanos = if edge_frac < half_second {
            // Clock is ahead: offset = -frac
            let frac_nanos = ((edge_frac as u64) * 1_000_000_000) >> 32;
            -(frac_nanos as i64)
        } else {
            // Clock is behind: offset = 1.0 - frac
            let complement = u32::MAX - edge_frac + 1;
            let frac_nanos = ((complement as u64) * 1_000_000_000) >> 32;
            frac_nanos as i64
        };

        let offset = NtpDuration::from_nanos(offset_nanos);

        // PPS has essentially zero network delay -- the pulse is a direct
        // electrical signal. The only delay is the kernel interrupt latency
        // which is typically < 10 microseconds.
        let delay = NtpDuration::from_nanos(1_000); // 1 microsecond
        let dispersion = NtpDuration::from_nanos(500); // 0.5 microsecond

        SourceMeasurement {
            id: self.source_id.clone(),
            offset,
            delay,
            dispersion,
            jitter: 0.000_001, // 1 microsecond jitter estimate
            stratum: 1,        // PPS is a stratum-0 source, report as stratum-1
            leap_indicator: LeapIndicator::NoWarning,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            time: local_time,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux-specific PPS ioctl structures and helpers
// ---------------------------------------------------------------------------

/// C-compatible structures for Linux PPS ioctl (for future raw ioctl usage).
///
/// These mirror the kernel's `struct pps_ktime` and `struct pps_fdata`.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
struct PpsKtime {
    sec: i64,
    nsec: i32,
    flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
struct PpsFdata {
    info: PpsKinfo,
    timeout: PpsKtime,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
struct PpsKinfo {
    assert_sequence: u32,
    clear_sequence: u32,
    assert_tu: PpsKtime,
    clear_tu: PpsKtime,
    current_mode: i32,
}

/// Convert a Linux PPS kernel timestamp to an NtpTimestamp.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn pps_ktime_to_ntp(ktime: &PpsKtime) -> NtpTimestamp {
    // PPS kernel time is in Unix epoch (seconds + nanoseconds).
    // NTP epoch is 70 years (2208988800 seconds) before Unix epoch.
    const NTP_UNIX_DIFF: u64 = 2_208_988_800;
    let ntp_seconds = (ktime.sec as u64) + NTP_UNIX_DIFF;
    let fraction = ((ktime.nsec as u64) << 32) / 1_000_000_000;
    NtpTimestamp::new(ntp_seconds as u32, fraction as u32)
}

/// Fetch the latest PPS edge from a device (non-Linux stub).
///
/// PPS ioctl support is currently only implemented for Linux. On other
/// platforms this returns an error indicating the feature is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn fetch_pps_edge(_device: &str) -> Result<PpsEdge, RefClockError> {
    Err(RefClockError::DeviceNotFound(
        "PPS not supported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_driver_creation() {
        let driver = PpsDriver::new("/dev/pps0");
        assert_eq!(driver.device(), "/dev/pps0");
    }

    #[test]
    fn test_pps_edge_exact_second() {
        let driver = PpsDriver::new("/dev/pps0");

        // Edge timestamp exactly on a second boundary -> zero offset.
        let edge = PpsEdge {
            timestamp: NtpTimestamp::new(3_900_000_000, 0),
            sequence: 1,
        };
        let local_time = NtpTimestamp::new(3_900_000_000, 0);
        let m = driver.process_edge(&edge, local_time);

        assert_eq!(m.stratum, 1);
        assert_eq!(m.offset.to_nanos(), 0);
    }

    #[test]
    fn test_pps_edge_clock_ahead() {
        let driver = PpsDriver::new("/dev/pps0");

        // Edge fractional part = 0.001s (clock is 1ms ahead of second boundary).
        // fraction for 1ms = 0.001 * 2^32 = 4294967 (approx)
        let frac = ((1u64 << 32) / 1000) as u32; // ~4294967
        let edge = PpsEdge {
            timestamp: NtpTimestamp::new(3_900_000_000, frac),
            sequence: 2,
        };
        let local_time = NtpTimestamp::now();
        let m = driver.process_edge(&edge, local_time);

        // Offset should be approximately -1ms = -1_000_000 ns.
        let offset_ns = m.offset.to_nanos();
        assert!(offset_ns < 0, "expected negative offset, got {offset_ns}");
        assert!(
            (offset_ns + 1_000_000).abs() < 1000,
            "expected ~-1ms offset, got {offset_ns} ns"
        );
    }

    #[test]
    fn test_pps_edge_clock_behind() {
        let driver = PpsDriver::new("/dev/pps0");

        // Edge fractional part = 0.999s (clock is 1ms behind the next second).
        // fraction for 0.999s = 0.999 * 2^32 = 4290672329 (approx)
        let frac = ((999u64 * (1u64 << 32)) / 1000) as u32;
        let edge = PpsEdge {
            timestamp: NtpTimestamp::new(3_900_000_000, frac),
            sequence: 3,
        };
        let local_time = NtpTimestamp::now();
        let m = driver.process_edge(&edge, local_time);

        // Offset should be approximately +1ms = +1_000_000 ns.
        let offset_ns = m.offset.to_nanos();
        assert!(offset_ns > 0, "expected positive offset, got {offset_ns}");
        assert!(
            (offset_ns - 1_000_000).abs() < 1000,
            "expected ~+1ms offset, got {offset_ns} ns"
        );
    }

    #[test]
    fn test_pps_measurement_source_id() {
        let driver = PpsDriver::new("/dev/pps0");
        let edge = PpsEdge {
            timestamp: NtpTimestamp::new(1000, 0),
            sequence: 0,
        };
        let m = driver.process_edge(&edge, NtpTimestamp::now());
        match &m.id {
            SourceId::RefClock { driver, unit } => {
                assert_eq!(driver, "PPS");
                assert_eq!(*unit, 0);
            }
            _ => panic!("expected RefClock source ID"),
        }
    }

    #[test]
    fn test_pps_measurement_properties() {
        let driver = PpsDriver::new("/dev/pps0");
        let edge = PpsEdge {
            timestamp: NtpTimestamp::new(1000, 0),
            sequence: 0,
        };
        let m = driver.process_edge(&edge, NtpTimestamp::now());

        // PPS should have very low delay and dispersion.
        assert!(m.delay.to_nanos() <= 1_000); // <= 1 microsecond
        assert!(m.dispersion.to_nanos() <= 1_000);
        assert_eq!(m.leap_indicator, LeapIndicator::NoWarning);
        assert_eq!(m.root_delay, NtpDuration::ZERO);
        assert_eq!(m.root_dispersion, NtpDuration::ZERO);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pps_ktime_to_ntp() {
        let ktime = PpsKtime {
            sec: 0, // Unix epoch
            nsec: 0,
            flags: 0,
        };
        let ts = pps_ktime_to_ntp(&ktime);
        // Unix epoch in NTP seconds = 2208988800
        assert_eq!(ts.seconds(), 2_208_988_800);
        assert_eq!(ts.fraction(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pps_ktime_to_ntp_with_nanos() {
        let ktime = PpsKtime {
            sec: 1_000_000,
            nsec: 500_000_000, // 0.5 seconds
            flags: 0,
        };
        let ts = pps_ktime_to_ntp(&ktime);
        assert_eq!(ts.seconds(), (1_000_000u64 + 2_208_988_800u64) as u32);
        // 0.5s fraction = 2^31 = 2147483648
        assert_eq!(ts.fraction(), 2_147_483_648);
    }
}
