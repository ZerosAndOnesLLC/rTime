//! PTP datasets per IEEE 1588-2019 Section 8.2.
//!
//! These datasets hold the current state of the PTP clock and are used
//! by the BMCA, state machines, and protocol engine.

use crate::message::{ClockQuality, PortIdentity};
use rtime_core::timestamp::NtpDuration;

/// Default dataset (IEEE 1588-2019 Section 8.2.1).
///
/// Contains the clock's own properties that are used by the BMCA to
/// determine whether this clock should be grandmaster.
#[derive(Debug, Clone)]
pub struct DefaultDS {
    /// Whether this clock is a two-step clock.
    pub two_step_flag: bool,
    /// The identity of this clock (derived from MAC or EUI-64).
    pub clock_identity: [u8; 8],
    /// Number of PTP ports on this clock.
    pub number_ports: u16,
    /// Clock quality of this clock.
    pub clock_quality: ClockQuality,
    /// Priority1 value (0-255, lower is better).
    pub priority1: u8,
    /// Priority2 value (0-255, lower is better).
    pub priority2: u8,
    /// PTP domain number.
    pub domain_number: u8,
    /// Whether this clock is slave-only.
    pub slave_only: bool,
}

impl DefaultDS {
    /// Create a new DefaultDS with the given clock identity and domain.
    pub fn new(clock_identity: [u8; 8], domain_number: u8) -> Self {
        Self {
            two_step_flag: true,
            clock_identity,
            number_ports: 1,
            clock_quality: ClockQuality {
                clock_class: 248, // Default: slave-only clock
                clock_accuracy: 0xFE, // Unknown
                offset_scaled_log_variance: 0xFFFF, // Maximum uncertainty
            },
            priority1: 128,
            priority2: 128,
            domain_number,
            slave_only: false,
        }
    }

    /// Get this clock's port identity for port number `port_number`.
    pub fn port_identity(&self, port_number: u16) -> PortIdentity {
        PortIdentity {
            clock_identity: self.clock_identity,
            port_number,
        }
    }
}

/// Current dataset (IEEE 1588-2019 Section 8.2.2).
///
/// Contains the current synchronization state of the clock.
#[derive(Debug, Clone)]
pub struct CurrentDS {
    /// Number of steps removed from the grandmaster.
    pub steps_removed: u16,
    /// Current measured offset from master (as NtpDuration for precision).
    pub offset_from_master: NtpDuration,
    /// Current computed mean path delay.
    pub mean_delay: NtpDuration,
}

impl CurrentDS {
    pub fn new() -> Self {
        Self {
            steps_removed: 0,
            offset_from_master: NtpDuration::ZERO,
            mean_delay: NtpDuration::ZERO,
        }
    }

    /// Update the offset and delay from a new measurement.
    pub fn update(&mut self, offset: NtpDuration, delay: NtpDuration) {
        self.offset_from_master = offset;
        self.mean_delay = delay;
    }
}

impl Default for CurrentDS {
    fn default() -> Self {
        Self::new()
    }
}

/// Parent dataset (IEEE 1588-2019 Section 8.2.3).
///
/// Describes the parent clock (the clock this node is synchronized to)
/// and the grandmaster at the top of the hierarchy.
#[derive(Debug, Clone)]
pub struct ParentDS {
    /// Port identity of the master port this clock is synchronized to.
    pub parent_port_identity: PortIdentity,
    /// Whether the parent port's statistics are valid.
    pub parent_stats: bool,
    /// Observed parent offset scaled log variance.
    pub observed_parent_offset_scaled_log_variance: u16,
    /// Observed parent clock phase change rate (ns/s).
    pub observed_parent_clock_phase_change_rate: i32,
    /// Identity of the grandmaster clock.
    pub grandmaster_identity: [u8; 8],
    /// Clock quality of the grandmaster.
    pub grandmaster_clock_quality: ClockQuality,
    /// Priority1 of the grandmaster.
    pub grandmaster_priority1: u8,
    /// Priority2 of the grandmaster.
    pub grandmaster_priority2: u8,
}

impl ParentDS {
    /// Create a new ParentDS with the local clock as parent (self-referencing).
    pub fn new(default_ds: &DefaultDS) -> Self {
        Self {
            parent_port_identity: default_ds.port_identity(0),
            parent_stats: false,
            observed_parent_offset_scaled_log_variance: 0xFFFF,
            observed_parent_clock_phase_change_rate: 0,
            grandmaster_identity: default_ds.clock_identity,
            grandmaster_clock_quality: default_ds.clock_quality,
            grandmaster_priority1: default_ds.priority1,
            grandmaster_priority2: default_ds.priority2,
        }
    }

    /// Update from an announce message's fields.
    pub fn update_from_announce(
        &mut self,
        parent_port: PortIdentity,
        grandmaster_identity: [u8; 8],
        grandmaster_quality: ClockQuality,
        grandmaster_priority1: u8,
        grandmaster_priority2: u8,
    ) {
        self.parent_port_identity = parent_port;
        self.grandmaster_identity = grandmaster_identity;
        self.grandmaster_clock_quality = grandmaster_quality;
        self.grandmaster_priority1 = grandmaster_priority1;
        self.grandmaster_priority2 = grandmaster_priority2;
    }
}

/// Time properties dataset (IEEE 1588-2019 Section 8.2.4).
///
/// Describes the timescale and traceability properties of the grandmaster.
#[derive(Debug, Clone)]
pub struct TimePropertiesDS {
    /// Current UTC offset (TAI - UTC) in seconds.
    pub current_utc_offset: i16,
    /// Whether `current_utc_offset` is valid.
    pub current_utc_offset_valid: bool,
    /// Whether a positive leap second is pending.
    pub leap59: bool,
    /// Whether a negative leap second is pending.
    pub leap61: bool,
    /// Whether the timescale is traceable to a primary reference.
    pub time_traceable: bool,
    /// Whether the frequency is traceable to a primary reference.
    pub frequency_traceable: bool,
    /// Whether the clock uses PTP (TAI) timescale.
    pub ptp_timescale: bool,
    /// Time source enumeration (IEEE 1588-2019 Table 6).
    pub time_source: u8,
}

impl TimePropertiesDS {
    pub fn new() -> Self {
        Self {
            current_utc_offset: 37, // As of 2017-01-01
            current_utc_offset_valid: false,
            leap59: false,
            leap61: false,
            time_traceable: false,
            frequency_traceable: false,
            ptp_timescale: true,
            time_source: 0xA0, // INTERNAL_OSCILLATOR
        }
    }
}

impl Default for TimePropertiesDS {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> [u8; 8] {
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
    }

    #[test]
    fn default_ds_creation() {
        let ds = DefaultDS::new(test_identity(), 0);
        assert_eq!(ds.clock_identity, test_identity());
        assert_eq!(ds.domain_number, 0);
        assert_eq!(ds.priority1, 128);
        assert_eq!(ds.priority2, 128);
        assert!(ds.two_step_flag);
        assert!(!ds.slave_only);
    }

    #[test]
    fn default_ds_port_identity() {
        let ds = DefaultDS::new(test_identity(), 0);
        let pi = ds.port_identity(1);
        assert_eq!(pi.clock_identity, test_identity());
        assert_eq!(pi.port_number, 1);
    }

    #[test]
    fn current_ds_update() {
        let mut ds = CurrentDS::new();
        assert_eq!(ds.offset_from_master, NtpDuration::ZERO);
        assert_eq!(ds.mean_delay, NtpDuration::ZERO);

        let offset = NtpDuration::from_nanos(500);
        let delay = NtpDuration::from_nanos(1000);
        ds.update(offset, delay);
        assert_eq!(ds.offset_from_master.to_nanos(), 500);
        assert_eq!(ds.mean_delay.to_nanos(), 1000);
    }

    #[test]
    fn parent_ds_self_referencing() {
        let default_ds = DefaultDS::new(test_identity(), 0);
        let parent_ds = ParentDS::new(&default_ds);
        assert_eq!(parent_ds.grandmaster_identity, test_identity());
        assert_eq!(
            parent_ds.parent_port_identity.clock_identity,
            test_identity()
        );
        assert_eq!(parent_ds.grandmaster_priority1, 128);
    }

    #[test]
    fn parent_ds_update_from_announce() {
        let default_ds = DefaultDS::new(test_identity(), 0);
        let mut parent_ds = ParentDS::new(&default_ds);

        let remote_identity = [0xAA; 8];
        let remote_port = PortIdentity {
            clock_identity: remote_identity,
            port_number: 1,
        };
        let quality = ClockQuality {
            clock_class: 6,
            clock_accuracy: 0x21,
            offset_scaled_log_variance: 0x4E5D,
        };

        parent_ds.update_from_announce(remote_port, remote_identity, quality, 100, 128);

        assert_eq!(parent_ds.grandmaster_identity, remote_identity);
        assert_eq!(parent_ds.parent_port_identity, remote_port);
        assert_eq!(parent_ds.grandmaster_priority1, 100);
        assert_eq!(parent_ds.grandmaster_clock_quality.clock_class, 6);
    }

    #[test]
    fn time_properties_defaults() {
        let tp = TimePropertiesDS::new();
        assert_eq!(tp.current_utc_offset, 37);
        assert!(tp.ptp_timescale);
        assert!(!tp.current_utc_offset_valid);
        assert_eq!(tp.time_source, 0xA0);
    }
}
