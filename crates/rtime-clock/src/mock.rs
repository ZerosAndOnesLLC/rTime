use std::sync::{Arc, Mutex};

use rtime_core::clock::{Clock, ClockError};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

/// Deterministic mock clock for testing.
/// Time advances only when explicitly set or stepped.
#[derive(Clone)]
pub struct MockClock {
    state: Arc<Mutex<MockClockState>>,
}

struct MockClockState {
    current_time: NtpTimestamp,
    frequency_ppm: f64,
    adjustable: bool,
}

impl MockClock {
    pub fn new(initial_time: NtpTimestamp) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockClockState {
                current_time: initial_time,
                frequency_ppm: 0.0,
                adjustable: true,
            })),
        }
    }

    /// Set the current time directly.
    pub fn set_time(&self, time: NtpTimestamp) {
        self.state.lock().unwrap().current_time = time;
    }

    /// Advance time by a duration (in nanoseconds).
    pub fn advance(&self, nanos: i64) {
        let mut state = self.state.lock().unwrap();
        let raw = state.current_time.raw() as i128;
        // Convert nanos to NTP fraction: nanos * 2^32 / 1_000_000_000
        let ntp_delta = (nanos as i128) * (1i128 << 32) / 1_000_000_000;
        state.current_time = NtpTimestamp::from_raw((raw + ntp_delta) as u64);
    }

    /// Set whether this clock can be adjusted.
    pub fn set_adjustable(&self, adjustable: bool) {
        self.state.lock().unwrap().adjustable = adjustable;
    }

    /// Get current frequency offset.
    pub fn get_frequency(&self) -> f64 {
        self.state.lock().unwrap().frequency_ppm
    }
}

impl Clock for MockClock {
    fn now(&self) -> Result<NtpTimestamp, ClockError> {
        Ok(self.state.lock().unwrap().current_time)
    }

    fn step(&self, offset: NtpDuration) -> Result<(), ClockError> {
        let mut state = self.state.lock().unwrap();
        if !state.adjustable {
            return Err(ClockError::PermissionDenied);
        }
        let raw = state.current_time.raw() as i128;
        let ntp_delta = (offset.to_nanos() as i128) * (1i128 << 32) / 1_000_000_000;
        state.current_time = NtpTimestamp::from_raw((raw + ntp_delta) as u64);
        Ok(())
    }

    fn adjust_frequency(&self, ppm: f64) -> Result<(), ClockError> {
        let mut state = self.state.lock().unwrap();
        if !state.adjustable {
            return Err(ClockError::PermissionDenied);
        }
        state.frequency_ppm = ppm;
        Ok(())
    }

    fn frequency_offset(&self) -> Result<f64, ClockError> {
        Ok(self.state.lock().unwrap().frequency_ppm)
    }

    fn resolution(&self) -> NtpDuration {
        NtpDuration::from_nanos(1)
    }

    fn max_frequency_adjustment(&self) -> f64 {
        500.0
    }

    fn is_adjustable(&self) -> bool {
        self.state.lock().unwrap().adjustable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_basic() {
        let clock = MockClock::new(NtpTimestamp::new(1000, 0));
        let t = clock.now().unwrap();
        assert_eq!(t.seconds(), 1000);
    }

    #[test]
    fn mock_clock_advance() {
        let clock = MockClock::new(NtpTimestamp::new(1000, 0));
        clock.advance(1_000_000_000); // 1 second
        let t = clock.now().unwrap();
        assert_eq!(t.seconds(), 1001);
    }

    #[test]
    fn mock_clock_step() {
        let clock = MockClock::new(NtpTimestamp::new(1000, 0));
        clock.step(NtpDuration::from_nanos(2_000_000_000)).unwrap();
        let t = clock.now().unwrap();
        assert_eq!(t.seconds(), 1002);
    }

    #[test]
    fn mock_clock_not_adjustable() {
        let clock = MockClock::new(NtpTimestamp::new(1000, 0));
        clock.set_adjustable(false);
        assert!(!clock.is_adjustable());
        assert!(clock.step(NtpDuration::from_nanos(1000)).is_err());
        assert!(clock.adjust_frequency(1.0).is_err());
    }

    #[test]
    fn mock_clock_frequency() {
        let clock = MockClock::new(NtpTimestamp::new(1000, 0));
        clock.adjust_frequency(10.5).unwrap();
        assert!((clock.frequency_offset().unwrap() - 10.5).abs() < f64::EPSILON);
    }
}
