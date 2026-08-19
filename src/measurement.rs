//! Measurements as they travel from the source tasks to the selection loop.
//!
//! A [`SourceMeasurement`] only knows the wall-clock time it was taken, and the
//! wall clock is exactly what the discipline task moves when it steps. The
//! selection loop needs to know whether a cached measurement was taken before
//! or after a step, so every measurement is wrapped with monotonic instants
//! bracketing its exchange. See [`rtime_core::steps`].

use std::time::{Duration, Instant};

use rtime_core::source::SourceMeasurement;
use rtime_core::timestamp::NtpDuration;

/// A system offset elected by the selection loop, handed to the discipline
/// task.
///
/// `ledger_sequence` is the step-ledger sequence number the measurements were
/// reconciled against. If the discipline task has recorded a step since then,
/// the offset was computed from a cache that did not yet know about that step
/// and must not be applied — it would re-apply the step. The selection loop
/// will publish a fresh, reconciled offset on its next measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedOffset {
    pub offset: NtpDuration,
    pub ledger_sequence: u64,
}

/// A source measurement plus the monotonic window in which it was taken.
#[derive(Clone, Debug)]
pub struct StampedMeasurement {
    /// Monotonic instant just before the exchange began (request sent).
    pub started_at: Instant,
    /// Monotonic instant just after the exchange completed (reply processed).
    pub finished_at: Instant,
    /// How long after `finished_at` the selection loop may keep using this
    /// measurement when no fresher one arrives from the same source. `None`
    /// means it never expires (the source has no fixed cadence).
    pub valid_for: Option<Duration>,
    pub measurement: SourceMeasurement,
}

impl StampedMeasurement {
    /// Whether the measurement has outlived its validity window at `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        match self.valid_for {
            Some(ttl) => now.saturating_duration_since(self.finished_at) > ttl,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtime_core::clock::LeapIndicator;
    use rtime_core::source::SourceId;
    use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

    fn stamped(valid_for: Option<Duration>) -> StampedMeasurement {
        let now = Instant::now();
        StampedMeasurement {
            started_at: now,
            finished_at: now,
            valid_for,
            measurement: SourceMeasurement {
                id: SourceId::RefClock {
                    driver: "test".into(),
                    unit: 0,
                },
                offset: NtpDuration::ZERO,
                delay: NtpDuration::ZERO,
                dispersion: NtpDuration::ZERO,
                jitter: 0.0,
                stratum: 1,
                leap_indicator: LeapIndicator::NoWarning,
                root_delay: NtpDuration::ZERO,
                root_dispersion: NtpDuration::ZERO,
                time: NtpTimestamp::ZERO,
            },
        }
    }

    #[test]
    fn expiry_honours_validity_window() {
        let m = stamped(Some(Duration::from_secs(10)));
        assert!(!m.is_expired(m.finished_at + Duration::from_secs(5)));
        assert!(m.is_expired(m.finished_at + Duration::from_secs(11)));
    }

    #[test]
    fn no_window_never_expires() {
        let m = stamped(None);
        assert!(!m.is_expired(m.finished_at + Duration::from_secs(86_400)));
    }
}
