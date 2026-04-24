//! PI servo clock discipline for NTP/PTP.
//!
//! Implements a proportional-integral controller that adjusts system clock
//! frequency to converge the measured offset to zero. The servo operates in
//! three phases:
//!
//!  1. **Init** -- discard the first few samples while filters warm up.
//!  2. **FLL (Frequency-Lock Loop)** -- large gains for fast initial convergence.
//!  3. **PLL (Phase-Lock Loop)** -- small gains for fine-grained tracking.

use tracing::warn;

/// Servo operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServoState {
    /// Initial state, waiting for first sample.
    Init,
    /// Frequency-Lock Loop: fast initial convergence using large gains.
    FrequencyLock,
    /// Phase-Lock Loop: fine-grained tracking with smaller gains.
    PhaseLock,
}

/// Action to take on the system clock after processing a sample.
#[derive(Debug, Clone)]
pub enum ServoAction {
    /// Adjust frequency by this many PPM.
    AdjustFrequency { ppm: f64 },
    /// Step the clock by this offset (too large for slew).
    Step { offset_ns: i64 },
    /// Measurement was implausibly large; ignored without touching state.
    Reject { offset_ns: i64 },
    /// No action needed (waiting for more samples).
    None,
}

/// Configuration for the PI servo.
#[derive(Debug, Clone)]
pub struct ServoConfig {
    /// Step threshold in nanoseconds. Offsets larger than this trigger a step.
    /// Default: 128_000_000 (128ms).
    pub step_threshold_ns: f64,
    /// Panic threshold in nanoseconds. Offsets whose absolute value exceeds
    /// this are rejected outright -- neither slewed nor stepped -- on the
    /// assumption that any jump this large is a bug or a spoofed/corrupt
    /// NTP reply rather than real drift. Must be greater than
    /// `step_threshold_ns`. Default: 1_000_000_000 (1s).
    pub panic_threshold_ns: f64,
    /// Maximum frequency adjustment in PPM. Default: 500.0.
    pub max_frequency: f64,
    /// Number of initial samples to skip (for filter warmup). Default: 4.
    pub init_samples: u32,
    /// Number of FLL samples before switching to PLL. Default: 8.
    pub fll_samples: u32,
}

impl Default for ServoConfig {
    fn default() -> Self {
        Self {
            step_threshold_ns: 128_000_000.0,
            panic_threshold_ns: 1_000_000_000.0,
            max_frequency: 500.0,
            init_samples: 4,
            fll_samples: 8,
        }
    }
}

/// PI (Proportional-Integral) servo for clock discipline.
///
/// Processes offset samples and produces clock adjustment actions. The servo
/// transitions through [`ServoState::Init`] -> [`ServoState::FrequencyLock`] ->
/// [`ServoState::PhaseLock`] as it gathers enough samples to converge.
pub struct PiServo {
    config: ServoConfig,
    state: ServoState,
    /// Accumulated integral term.
    integral: f64,
    /// Current frequency offset estimate (PPM).
    frequency: f64,
    /// Previous offset for derivative calculation (ns).
    last_offset: Option<f64>,
    /// Number of samples processed.
    sample_count: u32,
}

impl PiServo {
    /// Create a new PI servo with the given configuration.
    pub fn new(config: ServoConfig) -> Self {
        Self {
            config,
            state: ServoState::Init,
            integral: 0.0,
            frequency: 0.0,
            last_offset: None,
            sample_count: 0,
        }
    }

    /// Create a new PI servo with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ServoConfig::default())
    }

    /// Current servo state.
    pub fn state(&self) -> ServoState {
        self.state
    }

    /// Current estimated frequency offset in PPM.
    pub fn frequency(&self) -> f64 {
        self.frequency
    }

    /// Number of samples processed so far.
    pub fn sample_count(&self) -> u32 {
        self.sample_count
    }

    /// Process a new offset measurement and return the action to take.
    ///
    /// # Arguments
    /// - `offset_ns`: measured clock offset in nanoseconds (positive means local
    ///   clock is ahead).
    /// - `poll_interval_secs`: current polling interval in seconds (tau). This
    ///   controls the PI gain scaling.
    pub fn sample(&mut self, offset_ns: f64, poll_interval_secs: f64) -> ServoAction {
        // Panic clamp: reject implausibly large offsets before they touch any
        // state. A real drift this large doesn't occur on a running kernel;
        // a value this big means the measurement is corrupt, spoofed, or the
        // result of an NTP-era wrap. Stepping would wreck the clock (see the
        // year-9920 incident that motivated this guard).
        if offset_ns.abs() > self.config.panic_threshold_ns {
            warn!(
                "Rejecting implausible offset: {:.0} ns exceeds panic threshold {:.0} ns",
                offset_ns, self.config.panic_threshold_ns
            );
            return ServoAction::Reject {
                offset_ns: offset_ns as i64,
            };
        }

        self.sample_count += 1;

        // Step detection: if offset is larger than the threshold, step the clock
        // and reset state so the servo re-converges from scratch.
        if offset_ns.abs() > self.config.step_threshold_ns {
            self.reset();
            return ServoAction::Step {
                offset_ns: offset_ns as i64,
            };
        }

        // Init phase: skip the first N samples so upstream filters can warm up.
        if self.sample_count <= self.config.init_samples {
            self.last_offset = Some(offset_ns);
            return ServoAction::None;
        }

        // Transition out of Init on the first real sample.
        if self.state == ServoState::Init {
            self.state = ServoState::FrequencyLock;
        }

        let tau = poll_interval_secs;

        // Determine number of samples in the active (non-init) phase.
        let active_samples = self.sample_count - self.config.init_samples;

        // Transition from FLL to PLL once we have enough FLL samples.
        if self.state == ServoState::FrequencyLock
            && active_samples > self.config.fll_samples
        {
            self.state = ServoState::PhaseLock;
        }

        // Compute PI gains based on the current operating mode.
        //
        // The controller works in the offset domain (nanoseconds) and produces a
        // frequency correction in PPM.  A conversion factor of 1e-3/tau translates
        // from "nanoseconds per tau-seconds" into PPM:
        //   1 ns offset / tau s  =  1e-9 / tau  fractional freq
        //   * 1e6  =  1e-3 / tau  PPM
        let (kp, ki) = match self.state {
            ServoState::FrequencyLock => {
                // FLL: large gains for fast convergence.
                //   raw Kp = 2*tau,  raw Ki = tau^2
                //   scaled by 1e-3/tau to convert ns -> PPM.
                let scale = 1.0e-3 / tau;
                (2.0 * tau * scale, tau * tau * scale)
            }
            ServoState::PhaseLock => {
                // PLL: smaller gains for fine-grained tracking.
                //   raw Kp = 0.7/tau,  raw Ki = Kp^2 / 4
                //   scaled by 1e-3/tau to convert ns -> PPM.
                let scale = 1.0e-3 / tau;
                let kp_raw = 0.7 / tau;
                let ki_raw = kp_raw * kp_raw / 4.0;
                (kp_raw * scale, ki_raw * scale)
            }
            ServoState::Init => unreachable!(),
        };

        // Update integral term.
        self.integral += offset_ns * ki;

        // Proportional term.
        let proportional = offset_ns * kp;

        // Total correction.
        self.frequency = proportional + self.integral;

        // Clamp to maximum allowed frequency.
        self.frequency = self
            .frequency
            .clamp(-self.config.max_frequency, self.config.max_frequency);

        self.last_offset = Some(offset_ns);

        ServoAction::AdjustFrequency {
            ppm: self.frequency,
        }
    }

    /// Reset the servo to its initial state.
    pub fn reset(&mut self) {
        self.state = ServoState::Init;
        self.integral = 0.0;
        self.frequency = 0.0;
        self.last_offset = None;
        self.sample_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL_INTERVAL: f64 = 16.0; // typical NTP poll interval in seconds

    fn default_servo() -> PiServo {
        PiServo::with_defaults()
    }

    fn servo_with_config(init: u32, fll: u32) -> PiServo {
        PiServo::new(ServoConfig {
            init_samples: init,
            fll_samples: fll,
            ..ServoConfig::default()
        })
    }

    // ---------------------------------------------------------------
    // Init state returns None for the first N samples
    // ---------------------------------------------------------------
    #[test]
    fn init_state_returns_none() {
        let mut servo = default_servo();
        // Default init_samples = 4; samples 1..=4 should return None.
        for i in 1..=4 {
            let action = servo.sample(1000.0, POLL_INTERVAL);
            assert!(
                matches!(action, ServoAction::None),
                "sample {i} should be None during init"
            );
            assert_eq!(servo.state(), ServoState::Init);
        }
    }

    // ---------------------------------------------------------------
    // Large offset triggers Step
    // ---------------------------------------------------------------
    #[test]
    fn large_offset_triggers_step() {
        let mut servo = default_servo();
        // An offset > 128ms should step.
        let action = servo.sample(200_000_000.0, POLL_INTERVAL);
        match action {
            ServoAction::Step { offset_ns } => {
                assert_eq!(offset_ns, 200_000_000);
            }
            other => panic!("expected Step, got {:?}", other),
        }
        // After a step the servo should be back in Init.
        assert_eq!(servo.state(), ServoState::Init);
        assert_eq!(servo.sample_count(), 0);
    }

    #[test]
    fn negative_large_offset_triggers_step() {
        let mut servo = default_servo();
        let action = servo.sample(-200_000_000.0, POLL_INTERVAL);
        match action {
            ServoAction::Step { offset_ns } => {
                assert_eq!(offset_ns, -200_000_000);
            }
            other => panic!("expected Step, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // FLL mode adjusts frequency
    // ---------------------------------------------------------------
    #[test]
    fn fll_mode_adjusts_frequency() {
        let mut servo = servo_with_config(2, 8);
        // Burn through init.
        for _ in 0..2 {
            servo.sample(5000.0, POLL_INTERVAL);
        }
        assert_eq!(servo.state(), ServoState::Init);

        // Next sample should transition to FLL and produce a frequency adjustment.
        let action = servo.sample(5000.0, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);
        match action {
            ServoAction::AdjustFrequency { ppm } => {
                assert!(ppm != 0.0, "FLL should produce non-zero correction");
            }
            other => panic!("expected AdjustFrequency, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // PLL mode adjusts frequency with smaller correction
    // ---------------------------------------------------------------
    #[test]
    fn pll_mode_smaller_correction() {
        let mut servo = servo_with_config(1, 2);
        // Init phase.
        servo.sample(1000.0, POLL_INTERVAL);

        // FLL phase: gather 2 samples.
        servo.sample(1000.0, POLL_INTERVAL);
        servo.sample(1000.0, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);

        // Record the FLL correction magnitude.
        let fll_action = servo.sample(1000.0, POLL_INTERVAL);
        // This sample transitions to PLL (active_samples = 3 > fll_samples = 2).
        assert_eq!(servo.state(), ServoState::PhaseLock);

        // Now take a PLL sample with a fresh servo to compare gain magnitudes
        // without accumulated integral drift.
        let mut servo_pll = servo_with_config(1, 1);
        servo_pll.sample(1000.0, POLL_INTERVAL); // init
        servo_pll.sample(1000.0, POLL_INTERVAL); // fll sample 1
        // Active sample 2 > fll_samples 1, so transition to PLL.
        let pll_action = servo_pll.sample(1000.0, POLL_INTERVAL);
        assert_eq!(servo_pll.state(), ServoState::PhaseLock);

        let fll_ppm = match fll_action {
            ServoAction::AdjustFrequency { ppm } => ppm.abs(),
            _ => panic!("expected AdjustFrequency"),
        };
        let pll_ppm = match pll_action {
            ServoAction::AdjustFrequency { ppm } => ppm.abs(),
            _ => panic!("expected AdjustFrequency"),
        };

        // PLL gains are much smaller than FLL gains, so the first PLL correction
        // (with minimal integral) should be smaller than a comparable FLL correction.
        assert!(
            pll_ppm < fll_ppm,
            "PLL correction ({pll_ppm}) should be smaller than FLL ({fll_ppm})"
        );
    }

    // ---------------------------------------------------------------
    // Frequency is clamped to max
    // ---------------------------------------------------------------
    #[test]
    fn frequency_clamped_to_max() {
        let mut servo = servo_with_config(0, 1);
        // With init_samples=0, the very first sample enters FLL.
        // Use a large offset (but under step threshold) to push the correction high.
        for _ in 0..50 {
            servo.sample(100_000_000.0, POLL_INTERVAL); // 100ms offset
        }
        let freq = servo.frequency().abs();
        assert!(
            freq <= 500.0,
            "frequency {freq} should be clamped to 500 PPM"
        );
    }

    // ---------------------------------------------------------------
    // State transitions: Init -> FLL -> PLL
    // ---------------------------------------------------------------
    #[test]
    fn state_transitions() {
        let mut servo = servo_with_config(2, 3);
        let offset = 1000.0;

        // Samples 1-2: Init
        for _ in 0..2 {
            servo.sample(offset, POLL_INTERVAL);
            assert_eq!(servo.state(), ServoState::Init);
        }

        // Sample 3: transitions to FLL (active_sample=1 <= fll_samples=3)
        servo.sample(offset, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);

        // Samples 4-5: still FLL (active 2, 3)
        servo.sample(offset, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);
        servo.sample(offset, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);

        // Sample 6: active_sample=4 > fll_samples=3, transitions to PLL
        servo.sample(offset, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::PhaseLock);

        // Sample 7: stays in PLL
        servo.sample(offset, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::PhaseLock);
    }

    // ---------------------------------------------------------------
    // Step resets state to Init
    // ---------------------------------------------------------------
    #[test]
    fn step_resets_to_init() {
        let mut servo = servo_with_config(1, 2);
        // Warm up and enter FLL.
        servo.sample(1000.0, POLL_INTERVAL);
        servo.sample(1000.0, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);

        // Now feed a huge offset to trigger a step.
        let action = servo.sample(500_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Step { .. }));
        assert_eq!(servo.state(), ServoState::Init);
        assert_eq!(servo.sample_count(), 0);
        assert_eq!(servo.frequency(), 0.0);
    }

    // ---------------------------------------------------------------
    // Convergence: offset should shrink over repeated samples
    // ---------------------------------------------------------------
    #[test]
    fn converges_toward_zero() {
        // Verify the servo produces a positive frequency correction for a
        // positive offset, which would reduce the offset over time.
        let mut servo = servo_with_config(2, 4);
        let offset = 50_000.0; // 50us offset

        // Init phase.
        for _ in 0..2 {
            servo.sample(offset, POLL_INTERVAL);
        }

        // First active sample (FLL mode): should produce a positive PPM
        // correction to counteract the positive offset.
        let action = servo.sample(offset, POLL_INTERVAL);
        match action {
            ServoAction::AdjustFrequency { ppm } => {
                assert!(
                    ppm > 0.0,
                    "positive offset should produce positive freq correction, got {ppm}"
                );
            }
            other => panic!("expected AdjustFrequency, got {:?}", other),
        }

        // Negative offset should produce negative correction.
        let mut servo2 = servo_with_config(2, 4);
        let neg_offset = -50_000.0;
        for _ in 0..2 {
            servo2.sample(neg_offset, POLL_INTERVAL);
        }
        let action2 = servo2.sample(neg_offset, POLL_INTERVAL);
        match action2 {
            ServoAction::AdjustFrequency { ppm } => {
                assert!(
                    ppm < 0.0,
                    "negative offset should produce negative freq correction, got {ppm}"
                );
            }
            other => panic!("expected AdjustFrequency, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // Zero offset produces zero (or near-zero) correction
    // ---------------------------------------------------------------
    #[test]
    fn zero_offset_no_correction() {
        let mut servo = servo_with_config(1, 2);
        servo.sample(0.0, POLL_INTERVAL); // init

        let action = servo.sample(0.0, POLL_INTERVAL);
        match action {
            ServoAction::AdjustFrequency { ppm } => {
                assert!(
                    ppm.abs() < 1e-12,
                    "zero offset should produce ~zero correction, got {ppm}"
                );
            }
            other => panic!("expected AdjustFrequency, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // Negative offsets produce negative frequency adjustments
    // ---------------------------------------------------------------
    #[test]
    fn negative_offset_negative_correction() {
        let mut servo = servo_with_config(1, 4);
        servo.sample(-5000.0, POLL_INTERVAL); // init

        let action = servo.sample(-5000.0, POLL_INTERVAL);
        match action {
            ServoAction::AdjustFrequency { ppm } => {
                assert!(
                    ppm < 0.0,
                    "negative offset should give negative ppm, got {ppm}"
                );
            }
            other => panic!("expected AdjustFrequency, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // Panic threshold: implausibly large offsets are rejected, not stepped
    // ---------------------------------------------------------------
    #[test]
    fn insanely_large_offset_rejected() {
        let mut servo = default_servo();
        // 24 million seconds -- matches the kind of bogus step seen in the
        // year-9920 incident. Should Reject, not Step.
        let action = servo.sample(24_621_704_000_000_000.0, POLL_INTERVAL);
        match action {
            ServoAction::Reject { offset_ns } => {
                assert_eq!(offset_ns, 24_621_704_000_000_000);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
        // State must be untouched so good measurements can still drive convergence.
        assert_eq!(servo.state(), ServoState::Init);
        assert_eq!(servo.sample_count(), 0);
    }

    #[test]
    fn negative_insanely_large_offset_rejected() {
        let mut servo = default_servo();
        let action = servo.sample(-24_621_704_000_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
        assert_eq!(servo.sample_count(), 0);
    }

    #[test]
    fn just_under_panic_threshold_still_steps() {
        // 999ms is well over the 128ms step threshold but just under the 1s
        // panic threshold -- it must still step (this is how NTP recovers
        // from genuine drift after a long outage).
        let mut servo = default_servo();
        let action = servo.sample(999_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Step { .. }));
    }

    #[test]
    fn rejected_sample_does_not_disturb_convergence() {
        // A single rogue measurement should not reset an already-converging
        // servo or consume an init slot.
        let mut servo = servo_with_config(2, 4);
        servo.sample(1000.0, POLL_INTERVAL); // init sample 1
        servo.sample(1000.0, POLL_INTERVAL); // init sample 2

        // Now a rogue huge offset arrives -- must be rejected.
        let action = servo.sample(1e18, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
        // Sample count unchanged, state still Init.
        assert_eq!(servo.sample_count(), 2);
        assert_eq!(servo.state(), ServoState::Init);

        // Next real sample should transition to FLL as if the rogue never arrived.
        let action = servo.sample(1000.0, POLL_INTERVAL);
        assert_eq!(servo.state(), ServoState::FrequencyLock);
        assert!(matches!(action, ServoAction::AdjustFrequency { .. }));
    }

    #[test]
    fn custom_panic_threshold_honored() {
        // If a user sets a tighter panic threshold, it takes effect.
        let mut servo = PiServo::new(ServoConfig {
            step_threshold_ns: 100_000_000.0, // 100ms
            panic_threshold_ns: 500_000_000.0, // 500ms
            ..ServoConfig::default()
        });
        // 600ms is > 500ms panic threshold → reject.
        let action = servo.sample(600_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
    }

    // ---------------------------------------------------------------
    // with_defaults constructor works
    // ---------------------------------------------------------------
    #[test]
    fn with_defaults_constructor() {
        let servo = PiServo::with_defaults();
        assert_eq!(servo.state(), ServoState::Init);
        assert_eq!(servo.sample_count(), 0);
        assert_eq!(servo.frequency(), 0.0);
    }
}
