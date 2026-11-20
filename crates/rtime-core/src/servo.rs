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
    /// Allow a single unrestricted step the first time the servo sees a
    /// measurement, bypassing `panic_threshold_ns` on that first sample only.
    /// Matches `ntpd -g` semantics: after a cold boot or long VM suspend the
    /// real-world offset can legitimately exceed any sane steady-state panic
    /// guard, and refusing to step would strand the clock forever. Once the
    /// first step is performed, the panic clamp engages for all subsequent
    /// samples. Default: true.
    pub allow_initial_step: bool,
    /// Maximum frequency adjustment in PPM. Default: 500.0.
    pub max_frequency: f64,
    /// Number of initial samples to skip (for filter warmup). Default: 4.
    pub init_samples: u32,
    /// Number of FLL samples before switching to PLL. Default: 8.
    pub fll_samples: u32,
    /// Loop time constant in seconds. The proportional term removes an
    /// offset over roughly this long in FLL (twice as long in PLL), and the
    /// integral term (the frequency estimate) settles over a few multiples
    /// of it. Default: 64.
    pub time_constant_secs: f64,
}

impl Default for ServoConfig {
    fn default() -> Self {
        Self {
            step_threshold_ns: 128_000_000.0,
            panic_threshold_ns: 1_000_000_000.0,
            allow_initial_step: true,
            max_frequency: 500.0,
            init_samples: 4,
            fll_samples: 8,
            time_constant_secs: 64.0,
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
    /// Integral term: the servo's estimate (PPM) of the frequency correction
    /// the oscillator needs. Kept across steps; bounded by `max_frequency`.
    integral: f64,
    /// Frequency correction most recently commanded (PPM): integral plus
    /// the proportional phase term.
    frequency: f64,
    /// Previous offset for derivative calculation (ns).
    last_offset: Option<f64>,
    /// Number of samples processed.
    sample_count: u32,
    /// Whether a Step has ever been performed by this servo instance. Used
    /// together with `config.allow_initial_step` to permit one unrestricted
    /// step at startup; subsequent samples are clamped by the panic threshold.
    /// Not cleared by `reset()` — once we've stepped, we trust the clamp.
    has_stepped: bool,
    /// Number of consecutive samples rejected by the panic clamp. Reset to
    /// zero by any sample that passes the clamp.
    consecutive_rejects: u32,
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
            has_stepped: false,
            consecutive_rejects: 0,
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

    /// Number of consecutive samples the panic clamp has rejected. A sample
    /// that passes the clamp resets this to zero. Callers use it to decide
    /// when a stranded clock should give up and restart (see
    /// `clock.panic_restart_after`).
    pub fn consecutive_rejects(&self) -> u32 {
        self.consecutive_rejects
    }

    /// Process a new offset measurement and return the action to take.
    ///
    /// # Arguments
    /// - `offset_ns`: measured clock offset in nanoseconds (reference minus
    ///   local: positive means the local clock is behind and must speed up or
    ///   be stepped forward).
    /// - `interval_secs`: seconds since the previous sample, i.e. how long the
    ///   previously commanded frequency has been acting. Values outside
    ///   `0..=time constant` (or non-finite) are clamped.
    pub fn sample(&mut self, offset_ns: f64, interval_secs: f64) -> ServoAction {
        // Panic clamp: reject implausibly large offsets before they touch any
        // state. A real drift this large doesn't occur on a running kernel;
        // a value this big means the measurement is corrupt, spoofed, or the
        // result of an NTP-era wrap. Stepping would wreck the clock (see the
        // year-9920 incident that motivated this guard).
        //
        // Exception: if `allow_initial_step` is set and we have never stepped,
        // permit one unrestricted step. After a cold boot or long VM suspend
        // the real-world offset can legitimately exceed any sane steady-state
        // panic guard; without this bypass the clock is stranded forever.
        // Equivalent to `ntpd -g`.
        if offset_ns.abs() > self.config.panic_threshold_ns {
            if self.config.allow_initial_step && !self.has_stepped {
                warn!(
                    "Initial offset {:.0} ns exceeds panic threshold {:.0} ns; \
                     performing one-shot startup step (allow_initial_step=true).",
                    offset_ns, self.config.panic_threshold_ns
                );
                self.has_stepped = true;
                self.restart_after_step();
                return ServoAction::Step {
                    offset_ns: offset_ns as i64,
                };
            }
            self.consecutive_rejects = self.consecutive_rejects.saturating_add(1);
            warn!(
                "Rejecting implausible offset: {:.0} ns exceeds panic threshold {:.0} ns \
                 (consecutive rejects: {})",
                offset_ns, self.config.panic_threshold_ns, self.consecutive_rejects
            );
            return ServoAction::Reject {
                offset_ns: offset_ns as i64,
            };
        }

        self.consecutive_rejects = 0;
        self.sample_count += 1;

        // Step detection: if offset is larger than the threshold, step the clock
        // and restart the phase loop. The frequency estimate survives: a step
        // fixes the phase, not the oscillator, and throwing the estimate away
        // only makes the clock drift straight back out (#73).
        if offset_ns.abs() > self.config.step_threshold_ns {
            self.has_stepped = true;
            self.restart_after_step();
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

        // Determine number of samples in the active (non-init) phase.
        let active_samples = self.sample_count - self.config.init_samples;

        // Transition from FLL to PLL once we have enough FLL samples.
        if self.state == ServoState::FrequencyLock && active_samples > self.config.fll_samples {
            self.state = ServoState::PhaseLock;
        }

        // Continuous-time PI loop on the phase offset theta (seconds), where
        // the local clock runs at (natural error + commanded frequency):
        //
        //   freq = theta / Tp + I,      dI/dt = theta / Ti^2
        //
        // which gives theta'' + theta'/Tp + theta/Ti^2 = 0 -- critically
        // damped for Ti = 2 Tp, settling with I equal to minus the
        // oscillator's natural error and theta at zero. Gains are expressed
        // per second and integrated over the real sample interval, so they
        // do not depend on how often the selection loop publishes offsets.
        //
        // FLL uses the short time constant to capture the frequency quickly;
        // PLL doubles it to filter measurement jitter while tracking.
        let tau = self.config.time_constant_secs.max(1.0);
        let tp = match self.state {
            ServoState::FrequencyLock => tau,
            ServoState::PhaseLock => 2.0 * tau,
            ServoState::Init => unreachable!(),
        };
        let ti = 2.0 * tp;
        let dt = if interval_secs.is_finite() {
            interval_secs.clamp(0.0, tp)
        } else {
            0.0
        };

        // ns -> fractional frequency -> PPM: x ns / y s = x * 1e-9 / y = x * 1e-3 / y PPM.
        let max = self.config.max_frequency;
        // Anti-windup: the integral is the frequency estimate and can never
        // usefully exceed what the kernel will accept. An unbounded integral
        // (as before #73) wound up to millions of PPM, pinned the frequency at
        // the clamp and walked the clock into the step threshold forever.
        self.integral = (self.integral + offset_ns * 1.0e-3 * dt / (ti * ti)).clamp(-max, max);
        let proportional = offset_ns * 1.0e-3 / tp;

        self.frequency = (proportional + self.integral).clamp(-max, max);

        self.last_offset = Some(offset_ns);

        ServoAction::AdjustFrequency {
            ppm: self.frequency,
        }
    }

    /// Restart the phase loop after a step: back to `Init` so filters see
    /// post-step measurements before the loop acts again, but keep the
    /// frequency estimate and command only that (the proportional term
    /// referred to the pre-step offset).
    fn restart_after_step(&mut self) {
        self.state = ServoState::Init;
        self.last_offset = None;
        self.sample_count = 0;
        self.frequency = self.integral;
    }

    /// Reset the servo to its initial state, discarding the frequency
    /// estimate.
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
        // The frequency estimate (integral) survives the step; only the
        // proportional term is dropped.
        assert_eq!(servo.frequency(), servo.integral);
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
        // With the initial-step bypass disabled, a panic-exceeding offset must
        // be rejected even on the very first sample.
        let mut servo = PiServo::new(ServoConfig {
            allow_initial_step: false,
            ..ServoConfig::default()
        });
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
        let mut servo = PiServo::new(ServoConfig {
            allow_initial_step: false,
            ..ServoConfig::default()
        });
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
        // servo or consume an init slot. The bypass is disabled here so we're
        // exercising the steady-state panic path -- the bypass only ever fires
        // before the first step, not in the middle of a converged session.
        let mut servo = PiServo::new(ServoConfig {
            init_samples: 2,
            fll_samples: 4,
            allow_initial_step: false,
            ..ServoConfig::default()
        });
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
            step_threshold_ns: 100_000_000.0,  // 100ms
            panic_threshold_ns: 500_000_000.0, // 500ms
            allow_initial_step: false,
            ..ServoConfig::default()
        });
        // 600ms is > 500ms panic threshold → reject.
        let action = servo.sample(600_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
    }

    // ---------------------------------------------------------------
    // allow_initial_step: cold-boot bypass of the panic clamp
    // ---------------------------------------------------------------
    #[test]
    fn initial_step_bypasses_panic_when_enabled() {
        // Mirrors the real-world appliance case: VM suspended for ~47 min,
        // measured offset ~2.84e12 ns, panic threshold 1s. Default config has
        // allow_initial_step=true so the first sample must Step, not Reject.
        let mut servo = default_servo();
        let huge = 2_844_849_653_081.0;
        let action = servo.sample(huge, POLL_INTERVAL);
        match action {
            ServoAction::Step { offset_ns } => {
                assert_eq!(offset_ns, huge as i64);
            }
            other => panic!("expected Step, got {:?}", other),
        }
    }

    #[test]
    fn initial_step_only_fires_once() {
        // After the cold-boot bypass has fired, the panic clamp re-engages
        // for all subsequent oversized samples.
        let mut servo = default_servo();
        // First huge offset: bypass fires, returns Step.
        let action = servo.sample(2_844_849_653_081.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Step { .. }));
        // Second huge offset: bypass already spent → Reject.
        let action = servo.sample(2_844_849_653_081.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
    }

    #[test]
    fn initial_step_bypass_disabled_rejects() {
        // Opting out of the bypass restores the strict steady-state semantic
        // (Reject even on first sample).
        let mut servo = PiServo::new(ServoConfig {
            allow_initial_step: false,
            ..ServoConfig::default()
        });
        let action = servo.sample(2_844_849_653_081.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
    }

    #[test]
    fn normal_step_also_arms_panic_clamp() {
        // A normal in-threshold Step (e.g., legitimate drift recovery during
        // steady state) also flips `has_stepped`, so a later huge measurement
        // can't sneak through under the cold-boot bypass.
        let mut servo = default_servo();
        // 999ms is over the 128ms step threshold but under the 1s panic
        // threshold → normal Step, has_stepped flips true.
        let action = servo.sample(999_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Step { .. }));
        // Now a huge offset should be Rejected, not Stepped via bypass.
        let action = servo.sample(2_844_849_653_081.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Reject { .. }));
    }

    // ---------------------------------------------------------------
    // Consecutive panic rejects are counted and cleared
    // ---------------------------------------------------------------
    #[test]
    fn consecutive_rejects_count_and_reset() {
        let mut servo = PiServo::new(ServoConfig {
            allow_initial_step: false,
            ..ServoConfig::default()
        });
        assert_eq!(servo.consecutive_rejects(), 0);
        for expected in 1..=3 {
            let action = servo.sample(5_000_000_000.0, POLL_INTERVAL);
            assert!(matches!(action, ServoAction::Reject { .. }));
            assert_eq!(servo.consecutive_rejects(), expected);
        }
        // A sample that passes the clamp clears the streak.
        let action = servo.sample(1_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::None));
        assert_eq!(servo.consecutive_rejects(), 0);
    }

    // ---------------------------------------------------------------
    // Closed-loop simulation (#73)
    // ---------------------------------------------------------------

    /// Outcome of [`simulate`].
    struct SimRun {
        /// (time s, step ns) for every step the servo ordered.
        steps: Vec<(f64, i64)>,
        /// Largest |true offset| (ns) seen after `settle_secs`.
        max_abs_offset_after_settle: f64,
        /// Frequency the servo commanded at the end (PPM).
        final_frequency: f64,
    }

    /// Run the servo in closed loop against a simulated clock, the way the
    /// daemon drives it: `SOURCES` NTP sources each polled every
    /// `POLL_SECS` (staggered), the selection loop publishing the mean of
    /// the latest measurement from each source whenever one arrives, every
    /// measurement carrying deterministic noise of up to +/- `noise_ns`.
    ///
    /// The local oscillator runs fast by `natural_ppm`; the commanded
    /// frequency adds to that. Offsets are reference minus local, so
    /// d(offset)/dt = -(natural + commanded) * 1e-6. A step moves the local
    /// clock by the stepped amount, and cached measurements are shifted by it
    /// as the step ledger does.
    fn simulate(
        natural_ppm: f64,
        initial_offset_ns: f64,
        noise_ns: f64,
        duration_secs: f64,
        settle_secs: f64,
    ) -> SimRun {
        const SOURCES: usize = 4;
        const POLL_SECS: f64 = 16.0;
        const TICK: f64 = POLL_SECS / SOURCES as f64;

        let mut servo = PiServo::new(ServoConfig::default());
        let mut theta = initial_offset_ns; // true offset, ns
        let mut commanded = 0.0; // kernel frequency, PPM
        let mut cache = [None::<f64>; SOURCES];
        let mut rng: u64 = 0x2545_f491_4f6c_dd1d;
        let mut noise = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            ((rng >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0) * noise_ns
        };

        let mut run = SimRun {
            steps: Vec::new(),
            max_abs_offset_after_settle: 0.0,
            final_frequency: 0.0,
        };
        let mut t = 0.0;
        let mut tick = 0usize;
        while t < duration_secs {
            t += TICK;
            theta -= (natural_ppm + commanded) * 1.0e-6 * TICK * 1.0e9;
            if t >= settle_secs {
                run.max_abs_offset_after_settle = run.max_abs_offset_after_settle.max(theta.abs());
            }

            cache[tick % SOURCES] = Some(theta + noise());
            tick += 1;
            let fresh: Vec<f64> = cache.iter().flatten().copied().collect();
            let system_offset = fresh.iter().sum::<f64>() / fresh.len() as f64;

            match servo.sample(system_offset, TICK) {
                ServoAction::AdjustFrequency { ppm } => commanded = ppm,
                ServoAction::Step { offset_ns } => {
                    theta -= offset_ns as f64;
                    for m in cache.iter_mut().flatten() {
                        *m -= offset_ns as f64;
                    }
                    commanded = servo.frequency();
                    run.steps.push((t, offset_ns));
                }
                ServoAction::Reject { .. } | ServoAction::None => {}
            }
        }
        run.final_frequency = commanded;
        run
    }

    /// The #73 field case: a clock several hundred PPM off, a 128 ms step
    /// threshold and a few ms of measurement jitter. The servo must capture
    /// the frequency without ever stepping, then hold the offset far inside
    /// the threshold for the rest of the 12 hours. Before the fix the
    /// integral wound up to millions of PPM, pinned the frequency at
    /// +/-500 PPM and stepped by ~128 ms every few minutes (76 steps in 12 h
    /// at +250 PPM).
    #[test]
    fn closed_loop_converges_without_repeated_steps() {
        for natural_ppm in [-400.0, -250.0, -70.0, 0.0, 70.0, 250.0, 400.0] {
            let run = simulate(natural_ppm, 2_000_000.0, 3_000_000.0, 12.0 * 3600.0, 3600.0);
            assert!(
                run.steps.is_empty(),
                "natural {natural_ppm} PPM: servo stepped {} times, first {:?}",
                run.steps.len(),
                &run.steps[..run.steps.len().min(4)]
            );
            assert!(
                run.max_abs_offset_after_settle < 2_000_000.0,
                "natural {natural_ppm} PPM: offset still {:.3} ms after settling",
                run.max_abs_offset_after_settle / 1e6
            );
            assert!(
                (run.final_frequency + natural_ppm).abs() < 5.0,
                "natural {natural_ppm} PPM: frequency settled at {:.3} PPM",
                run.final_frequency
            );
        }
    }

    /// A start-up offset above the step threshold is stepped exactly once,
    /// and the loop then settles instead of drifting back out and stepping
    /// the other way.
    #[test]
    fn closed_loop_single_initial_step_then_settles() {
        for natural_ppm in [-250.0, 70.0, 250.0] {
            let run = simulate(
                natural_ppm,
                300_000_000.0,
                3_000_000.0,
                12.0 * 3600.0,
                3600.0,
            );
            assert_eq!(
                run.steps.len(),
                1,
                "natural {natural_ppm} PPM: expected one initial step, got {:?}",
                &run.steps[..run.steps.len().min(4)]
            );
            assert!(
                run.max_abs_offset_after_settle < 2_000_000.0,
                "natural {natural_ppm} PPM: offset still {:.3} ms after settling",
                run.max_abs_offset_after_settle / 1e6
            );
        }
    }

    /// A step fixes the phase, not the oscillator: the learned frequency
    /// must survive it.
    #[test]
    fn step_keeps_frequency_estimate() {
        let mut servo = servo_with_config(0, 1);
        for _ in 0..200 {
            servo.sample(5_000_000.0, POLL_INTERVAL);
        }
        let learned = servo.integral;
        assert!(learned > 0.0);
        let action = servo.sample(200_000_000.0, POLL_INTERVAL);
        assert!(matches!(action, ServoAction::Step { .. }));
        assert_eq!(servo.frequency(), learned);
        assert_eq!(servo.state(), ServoState::Init);
    }

    #[test]
    fn integral_is_bounded_by_max_frequency() {
        let mut servo = servo_with_config(0, 1);
        for _ in 0..10_000 {
            servo.sample(100_000_000.0, POLL_INTERVAL);
        }
        assert!(servo.integral <= servo.config.max_frequency);
        // A bounded integral unwinds: sustained opposite offsets flip it.
        for _ in 0..10_000 {
            servo.sample(-100_000_000.0, POLL_INTERVAL);
        }
        assert!(servo.frequency() < 0.0);
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
