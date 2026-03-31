use crate::timestamp::NtpDuration;

/// Number of samples in the clock filter window (RFC 5905 Section 10).
const FILTER_SIZE: usize = 8;

/// Result of adding a sample to the clock filter.
#[derive(Clone, Debug)]
pub struct FilterResult {
    /// Best offset estimate (from minimum-delay sample).
    pub offset: NtpDuration,
    /// Minimum delay observed in the window.
    pub delay: NtpDuration,
    /// Dispersion of the best sample.
    pub dispersion: NtpDuration,
    /// RMS jitter: root-mean-square of successive offset differences.
    pub jitter: f64,
}

/// A single sample stored in the filter window.
#[derive(Clone, Copy, Debug)]
struct FilterSample {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
}

impl Default for FilterSample {
    fn default() -> Self {
        Self {
            offset: NtpDuration::ZERO,
            // RFC 5905: uninitialized delay slots are set to MAXDISP (16 seconds).
            delay: NtpDuration::from_seconds_f64(16.0),
            dispersion: NtpDuration::from_seconds_f64(16.0),
        }
    }
}

/// Per-source clock filter as described in RFC 5905 Section 10.
///
/// Maintains a sliding window of the last 8 (offset, delay, dispersion)
/// samples, selects the minimum-delay sample as best estimate, and computes
/// jitter from successive offset differences.
///
/// Also tracks an 8-bit reachability register: each poll shifts left and
/// sets bit 0 on a successful sample; `timeout()` shifts without setting.
pub struct ClockFilter {
    /// Circular buffer of samples (newest at `head`).
    samples: [FilterSample; FILTER_SIZE],
    /// Index where the next sample will be written.
    head: usize,
    /// Number of samples received so far (saturates at FILTER_SIZE).
    count: usize,
    /// 8-bit reachability shift register.
    reach: u8,
    /// Previous best offset, used for jitter calculation.
    prev_offset: Option<NtpDuration>,
    /// Running jitter estimate (seconds, RMS).
    jitter: f64,
}

impl ClockFilter {
    /// Create a new clock filter with empty window.
    pub fn new() -> Self {
        Self {
            samples: [FilterSample::default(); FILTER_SIZE],
            head: 0,
            count: 0,
            reach: 0,
            prev_offset: None,
            jitter: 0.0,
        }
    }

    /// Add a new sample to the filter and return the best estimate.
    ///
    /// The sample with minimum delay in the window is selected as the best
    /// estimate. Jitter is computed as the RMS of successive offset differences.
    pub fn add_sample(
        &mut self,
        offset: NtpDuration,
        delay: NtpDuration,
        dispersion: NtpDuration,
    ) -> FilterResult {
        // Update reachability: shift left, set bit 0.
        self.reach = (self.reach << 1) | 1;

        // Store sample in circular buffer.
        self.samples[self.head] = FilterSample {
            offset,
            delay,
            dispersion,
        };
        self.head = (self.head + 1) % FILTER_SIZE;
        if self.count < FILTER_SIZE {
            self.count += 1;
        }

        // Find the sample with minimum delay in the window.
        let best = self.min_delay_sample();

        // Update jitter using exponential moving average of offset differences.
        // RFC 5905: jitter = sqrt( sum(offset_i - offset_{i-1})^2 / (n-1) )
        // We use a simple RMS approach on successive best offsets.
        if let Some(prev) = self.prev_offset {
            let diff = (best.offset - prev).to_seconds_f64();
            // Exponential weighted moving average with phi = 1/FILTER_SIZE.
            // First approximation: use simple RMS accumulation.
            self.jitter = ((self.jitter * self.jitter + diff * diff) / 2.0).sqrt();
        }
        self.prev_offset = Some(best.offset);

        FilterResult {
            offset: best.offset,
            delay: best.delay,
            dispersion: best.dispersion,
            jitter: self.jitter,
        }
    }

    /// Record a timeout (no response). Shifts reachability register left
    /// without setting bit 0.
    pub fn timeout(&mut self) {
        self.reach <<= 1;
    }

    /// Return the 8-bit reachability register.
    pub fn reachability(&self) -> u8 {
        self.reach
    }

    /// Whether the source is considered reachable (any bit set).
    pub fn is_reachable(&self) -> bool {
        self.reach != 0
    }

    /// Find the sample in the window with the smallest delay.
    fn min_delay_sample(&self) -> FilterSample {
        let mut best = self.samples[0];
        for i in 1..self.count {
            if self.samples[i].delay < best.delay {
                best = self.samples[i];
            }
        }
        best
    }
}

impl Default for ClockFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_filter_is_unreachable() {
        let filter = ClockFilter::new();
        assert_eq!(filter.reachability(), 0);
        assert!(!filter.is_reachable());
    }

    #[test]
    fn single_sample_returns_that_sample() {
        let mut filter = ClockFilter::new();
        let offset = NtpDuration::from_millis(10);
        let delay = NtpDuration::from_millis(20);
        let dispersion = NtpDuration::from_millis(5);

        let result = filter.add_sample(offset, delay, dispersion);

        assert_eq!(result.offset.to_nanos(), offset.to_nanos());
        assert_eq!(result.delay.to_nanos(), delay.to_nanos());
        assert_eq!(result.dispersion.to_nanos(), dispersion.to_nanos());
        // First sample: no prior offset, jitter should be 0.
        assert_eq!(result.jitter, 0.0);
    }

    #[test]
    fn selects_minimum_delay_sample() {
        let mut filter = ClockFilter::new();

        // Add samples with varying delays; the one with min delay should be selected.
        filter.add_sample(
            NtpDuration::from_millis(100),
            NtpDuration::from_millis(50),
            NtpDuration::from_millis(5),
        );
        filter.add_sample(
            NtpDuration::from_millis(90),
            NtpDuration::from_millis(10), // minimum delay
            NtpDuration::from_millis(5),
        );
        let result = filter.add_sample(
            NtpDuration::from_millis(110),
            NtpDuration::from_millis(30),
            NtpDuration::from_millis(5),
        );

        // Best sample should be the one with delay=10ms, offset=90ms.
        assert_eq!(result.delay.to_nanos(), NtpDuration::from_millis(10).to_nanos());
        assert_eq!(result.offset.to_nanos(), NtpDuration::from_millis(90).to_nanos());
    }

    #[test]
    fn reachability_register_shifts_correctly() {
        let mut filter = ClockFilter::new();

        // Add a sample -> reach = 0b00000001
        filter.add_sample(
            NtpDuration::ZERO,
            NtpDuration::from_millis(10),
            NtpDuration::from_millis(1),
        );
        assert_eq!(filter.reachability(), 0b0000_0001);
        assert!(filter.is_reachable());

        // Add another sample -> reach = 0b00000011
        filter.add_sample(
            NtpDuration::ZERO,
            NtpDuration::from_millis(10),
            NtpDuration::from_millis(1),
        );
        assert_eq!(filter.reachability(), 0b0000_0011);

        // Timeout -> reach = 0b00000110 (shifted, bit 0 not set)
        filter.timeout();
        assert_eq!(filter.reachability(), 0b0000_0110);
        assert!(filter.is_reachable());
    }

    #[test]
    fn reachability_becomes_zero_after_8_timeouts() {
        let mut filter = ClockFilter::new();

        filter.add_sample(
            NtpDuration::ZERO,
            NtpDuration::from_millis(10),
            NtpDuration::from_millis(1),
        );
        assert!(filter.is_reachable());

        // 8 timeouts should shift the bit out.
        for _ in 0..8 {
            filter.timeout();
        }
        assert_eq!(filter.reachability(), 0);
        assert!(!filter.is_reachable());
    }

    #[test]
    fn jitter_increases_with_varying_offsets() {
        let mut filter = ClockFilter::new();

        // First sample: jitter = 0.
        let r1 = filter.add_sample(
            NtpDuration::from_millis(0),
            NtpDuration::from_millis(10),
            NtpDuration::from_millis(1),
        );
        assert_eq!(r1.jitter, 0.0);

        // Second sample with different offset and lower delay so it becomes the new best.
        let r2 = filter.add_sample(
            NtpDuration::from_millis(50),
            NtpDuration::from_millis(5),
            NtpDuration::from_millis(1),
        );
        assert!(r2.jitter > 0.0);
    }

    #[test]
    fn jitter_zero_for_constant_offsets() {
        let mut filter = ClockFilter::new();

        let offset = NtpDuration::from_millis(10);
        let delay = NtpDuration::from_millis(5);
        let disp = NtpDuration::from_millis(1);

        // First sample sets the baseline.
        filter.add_sample(offset, delay, disp);
        // Subsequent identical samples: jitter converges to 0.
        for _ in 0..20 {
            let r = filter.add_sample(offset, delay, disp);
            // With identical offsets, the diff is always 0, so jitter decays to 0.
            assert!(r.jitter >= 0.0);
        }
        let final_result = filter.add_sample(offset, delay, disp);
        assert!(final_result.jitter < 1e-9, "jitter should converge to ~0 for constant offsets");
    }

    #[test]
    fn window_wraps_around() {
        let mut filter = ClockFilter::new();

        // Fill beyond FILTER_SIZE to ensure wrap-around works.
        for i in 0..16 {
            let delay = NtpDuration::from_millis(100 - i);
            filter.add_sample(NtpDuration::from_millis(i), delay, NtpDuration::from_millis(1));
        }

        // After 16 samples, only last 8 are in the window (i=8..15).
        // Their delays are 92..85 ms. Minimum is 85 ms (i=15).
        let result = filter.add_sample(
            NtpDuration::from_millis(50),
            NtpDuration::from_millis(200), // large delay
            NtpDuration::from_millis(1),
        );
        // The min delay should be from one of the recent samples, not the new one.
        assert!(result.delay.to_nanos() < NtpDuration::from_millis(200).to_nanos());
    }
}
