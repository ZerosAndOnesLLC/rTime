//! Step ledger: reconciling cached measurements with clock steps.
//!
//! Source selection runs over the *latest* measurement from every source. When
//! the servo steps the clock, every measurement taken before the step is now
//! wrong by exactly the step amount — but it is still cached, and the next
//! selection will happily re-elect the stale offset and step the clock again.
//! With three sources this applied each step three times, so every correction
//! overshot by ~2x and the error doubled on each round until it blew past the
//! panic threshold and stranded the clock.
//!
//! The discipline task records every step it applies in a [`StepLedger`]
//! (keyed on the monotonic clock, which a step does not disturb). Selection
//! then asks the ledger to [`correct`](StepLedger::correct) each cached
//! measurement:
//!
//! - a measurement whose exchange finished before a step has the step amount
//!   removed from its offset (the residual is exactly `offset - step`);
//! - a measurement whose exchange *spanned* a step is unusable and is dropped;
//! - a measurement taken after every recorded step is used as-is.

use std::collections::VecDeque;
use std::time::Instant;

use crate::timestamp::NtpDuration;

/// Maximum number of steps retained. Older entries are pruned and the ledger
/// horizon advances so that measurements predating them are refused rather
/// than silently left uncorrected.
const MAX_STEPS: usize = 512;

/// One applied clock step.
#[derive(Clone, Debug)]
pub struct StepRecord {
    /// Monotonic instant read immediately before the step syscall.
    pub before: Instant,
    /// Monotonic instant read immediately after the step syscall returned.
    pub after: Instant,
    /// Amount the clock was moved by (positive = clock advanced).
    pub amount: NtpDuration,
}

/// Ledger of clock steps applied by the discipline task.
#[derive(Clone, Debug, Default)]
pub struct StepLedger {
    steps: VecDeque<StepRecord>,
    /// Measurements that started before this instant may predate a pruned
    /// step and cannot be vouched for.
    horizon: Option<Instant>,
    /// Total number of steps ever recorded (monotonic sequence number).
    sequence: u64,
}

impl StepLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a step that moved the clock by `amount`, bracketed by the
    /// monotonic instants read around the step syscall.
    pub fn record(&mut self, before: Instant, after: Instant, amount: NtpDuration) {
        self.steps.push_back(StepRecord {
            before,
            after,
            amount,
        });
        self.sequence = self.sequence.wrapping_add(1);
        while self.steps.len() > MAX_STEPS {
            if let Some(pruned) = self.steps.pop_front() {
                self.horizon = Some(pruned.after);
            }
        }
    }

    /// Number of steps ever recorded.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Number of steps currently retained.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether no steps are retained.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Reconcile a measurement with the steps applied since it was taken.
    ///
    /// `started` / `finished` bracket the measurement exchange on the
    /// monotonic clock; `offset` is the offset as measured. Returns the offset
    /// that is still outstanding *now*, or `None` if the measurement can no
    /// longer be trusted (its exchange spanned a step, or it predates the
    /// ledger horizon).
    pub fn correct(
        &self,
        started: Instant,
        finished: Instant,
        offset: NtpDuration,
    ) -> Option<NtpDuration> {
        if let Some(horizon) = self.horizon
            && started < horizon
        {
            return None;
        }

        let mut applied = NtpDuration::ZERO;
        for step in &self.steps {
            if finished <= step.before {
                // Exchange completed before the clock moved: the step has
                // since consumed that much of the measured offset.
                applied = applied + step.amount;
            } else if started >= step.after {
                // Exchange started after the clock moved: already reflects it.
            } else {
                // Exchange straddled the step: the offset mixes pre- and
                // post-step timestamps and cannot be repaired.
                return None;
            }
        }
        Some(offset - applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ms(v: i64) -> NtpDuration {
        NtpDuration::from_millis(v)
    }

    #[test]
    fn empty_ledger_passes_through() {
        let ledger = StepLedger::new();
        let t = Instant::now();
        assert_eq!(ledger.correct(t, t, ms(130)), Some(ms(130)));
        assert!(ledger.is_empty());
        assert_eq!(ledger.sequence(), 0);
    }

    #[test]
    fn measurement_before_step_is_corrected() {
        let t0 = Instant::now();
        let m_start = t0;
        let m_end = t0 + Duration::from_millis(10);
        let step_before = t0 + Duration::from_millis(100);
        let step_after = step_before + Duration::from_micros(50);

        let mut ledger = StepLedger::new();
        ledger.record(step_before, step_after, ms(130));

        // The measurement said "local is 130ms behind"; we stepped +130ms, so
        // nothing is outstanding any more.
        assert_eq!(ledger.correct(m_start, m_end, ms(130)), Some(ms(0)));
        // A source that disagreed slightly keeps only its disagreement.
        assert_eq!(ledger.correct(m_start, m_end, ms(134)), Some(ms(4)));
    }

    #[test]
    fn measurement_after_step_is_untouched() {
        let t0 = Instant::now();
        let step_before = t0;
        let step_after = t0 + Duration::from_micros(50);
        let m_start = t0 + Duration::from_millis(500);
        let m_end = m_start + Duration::from_millis(10);

        let mut ledger = StepLedger::new();
        ledger.record(step_before, step_after, ms(130));
        assert_eq!(ledger.correct(m_start, m_end, ms(2)), Some(ms(2)));
    }

    #[test]
    fn measurement_spanning_step_is_dropped() {
        let t0 = Instant::now();
        let m_start = t0;
        let m_end = t0 + Duration::from_millis(30);
        let step_before = t0 + Duration::from_millis(10);
        let step_after = step_before + Duration::from_micros(50);

        let mut ledger = StepLedger::new();
        ledger.record(step_before, step_after, ms(130));
        assert_eq!(ledger.correct(m_start, m_end, ms(130)), None);

        // Touching either edge of the step window also counts as spanning.
        assert_eq!(
            ledger.correct(step_before, step_after, ms(130)),
            None,
            "exchange that begins exactly at the step and ends exactly after it"
        );
    }

    #[test]
    fn multiple_steps_accumulate() {
        let t0 = Instant::now();
        let m_start = t0;
        let m_end = t0 + Duration::from_millis(5);

        let mut ledger = StepLedger::new();
        let s1 = t0 + Duration::from_millis(100);
        ledger.record(s1, s1 + Duration::from_micros(10), ms(130));
        let s2 = t0 + Duration::from_millis(200);
        ledger.record(s2, s2 + Duration::from_micros(10), ms(-20));

        assert_eq!(ledger.correct(m_start, m_end, ms(130)), Some(ms(20)));
        assert_eq!(ledger.sequence(), 2);
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn stale_cache_cannot_double_the_correction() {
        // Reproduces the production failure: three sources all report +130ms,
        // the servo steps +130ms on the first, and the other two cached
        // measurements are re-selected afterwards. They must now read ~0, not
        // +130ms again.
        let t0 = Instant::now();
        let taken = [
            (t0, t0 + Duration::from_millis(8)),
            (t0 + Duration::from_millis(1), t0 + Duration::from_millis(9)),
            (
                t0 + Duration::from_millis(2),
                t0 + Duration::from_millis(12),
            ),
        ];
        let mut ledger = StepLedger::new();
        let step_at = t0 + Duration::from_millis(50);
        ledger.record(step_at, step_at + Duration::from_micros(20), ms(130));

        for (start, end) in taken {
            let residual = ledger.correct(start, end, ms(130)).expect("not spanning");
            assert_eq!(residual, ms(0));
        }
    }

    #[test]
    fn pruning_advances_horizon() {
        let t0 = Instant::now();
        let mut ledger = StepLedger::new();
        for i in 0..(MAX_STEPS + 3) {
            let at = t0 + Duration::from_secs(i as u64 + 1);
            ledger.record(at, at + Duration::from_micros(1), ms(1));
        }
        assert_eq!(ledger.len(), MAX_STEPS);
        assert_eq!(ledger.sequence(), (MAX_STEPS + 3) as u64);

        // A measurement older than the pruned steps is refused outright.
        assert_eq!(ledger.correct(t0, t0, ms(5)), None);

        // A measurement newer than every retained step passes through.
        let late = t0 + Duration::from_secs(MAX_STEPS as u64 + 10);
        assert_eq!(ledger.correct(late, late, ms(5)), Some(ms(5)));
    }
}
