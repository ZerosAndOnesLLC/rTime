use std::net::SocketAddr;

use crate::clock::LeapIndicator;
use crate::timestamp::{NtpDuration, NtpTimestamp};

/// Unique identifier for a time source.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SourceId {
    Ntp {
        address: SocketAddr,
        reference_id: u32,
    },
    Ptp {
        clock_identity: [u8; 8],
        port_number: u16,
    },
    RefClock {
        driver: String,
        unit: u8,
    },
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ntp { address, .. } => write!(f, "NTP:{}", address),
            Self::Ptp {
                clock_identity,
                port_number,
            } => {
                write!(
                    f,
                    "PTP:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-{}",
                    clock_identity[0],
                    clock_identity[1],
                    clock_identity[2],
                    clock_identity[3],
                    clock_identity[4],
                    clock_identity[5],
                    clock_identity[6],
                    clock_identity[7],
                    port_number
                )
            }
            Self::RefClock { driver, unit } => write!(f, "REF:{}({})", driver, unit),
        }
    }
}

/// Measurement from a single time source after filtering.
#[derive(Clone, Debug)]
pub struct SourceMeasurement {
    pub id: SourceId,
    /// Offset from local clock.
    pub offset: NtpDuration,
    /// Round-trip delay.
    pub delay: NtpDuration,
    /// Error bound.
    pub dispersion: NtpDuration,
    /// RMS jitter estimate.
    pub jitter: f64,
    /// Stratum of this source.
    pub stratum: u8,
    /// Leap indicator from source.
    pub leap_indicator: LeapIndicator,
    /// Root delay to primary reference.
    pub root_delay: NtpDuration,
    /// Root dispersion.
    pub root_dispersion: NtpDuration,
    /// When this measurement was taken.
    pub time: NtpTimestamp,
}

impl SourceMeasurement {
    /// Root distance: total error budget from this source to the primary reference.
    /// root_distance = root_delay/2 + root_dispersion + |delay|/2 + dispersion
    pub fn root_distance(&self) -> NtpDuration {
        self.root_delay.abs() / 2 + self.root_dispersion + self.delay.abs() / 2 + self.dispersion
    }
}
