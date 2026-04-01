/// Adaptive poll interval manager per NTPv4 (RFC 5905).
///
/// Poll interval is expressed as log2(seconds):
///   poll=6 -> 64 seconds
///   poll=10 -> 1024 seconds
#[derive(Debug, Clone)]
pub struct PollInterval {
    /// Current poll exponent (log2 seconds).
    current: i8,
    /// Minimum allowed poll exponent.
    min: i8,
    /// Maximum allowed poll exponent.
    max: i8,
}

impl PollInterval {
    /// Default: minpoll=6 (64s), maxpoll=10 (1024s).
    pub fn new() -> Self {
        Self {
            current: 6,
            min: 4,   // 16 seconds
            max: 10,  // 1024 seconds
        }
    }

    /// Create with custom min/max bounds.
    pub fn with_bounds(min: i8, max: i8) -> Self {
        let min = min.clamp(4, 17);
        let max = max.clamp(min, 17);
        Self {
            current: min,
            min,
            max,
        }
    }

    /// Current poll interval in seconds.
    pub fn interval_secs(&self) -> u64 {
        1u64 << self.current as u64
    }

    /// Current poll exponent (for NTP packet field).
    pub fn exponent(&self) -> i8 {
        self.current
    }

    /// Increase poll interval (clock is stable).
    pub fn increase(&mut self) {
        if self.current < self.max {
            self.current += 1;
        }
    }

    /// Decrease poll interval (clock needs faster updates).
    pub fn decrease(&mut self) {
        if self.current > self.min {
            self.current -= 1;
        }
    }

    /// Reset to minimum poll interval.
    pub fn reset(&mut self) {
        self.current = self.min;
    }
}

impl Default for PollInterval {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_poll_interval() {
        let pi = PollInterval::new();
        assert_eq!(pi.interval_secs(), 64);
        assert_eq!(pi.exponent(), 6);
    }

    #[test]
    fn increase_decrease() {
        let mut pi = PollInterval::new();
        pi.increase();
        assert_eq!(pi.interval_secs(), 128);
        pi.decrease();
        assert_eq!(pi.interval_secs(), 64);
    }

    #[test]
    fn respects_bounds() {
        let mut pi = PollInterval::with_bounds(6, 8);
        assert_eq!(pi.interval_secs(), 64);

        pi.increase();
        pi.increase();
        pi.increase(); // should be clamped at max
        assert_eq!(pi.exponent(), 8);
        assert_eq!(pi.interval_secs(), 256);

        pi.decrease();
        pi.decrease();
        pi.decrease(); // should be clamped at min
        assert_eq!(pi.exponent(), 6);
    }

    #[test]
    fn reset() {
        let mut pi = PollInterval::with_bounds(4, 10);
        pi.increase();
        pi.increase();
        pi.increase();
        pi.reset();
        assert_eq!(pi.exponent(), 4);
    }
}
