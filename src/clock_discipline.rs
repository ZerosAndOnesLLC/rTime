use std::sync::Arc;
use std::time::Instant;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use rtime_core::clock::Clock;
use rtime_core::servo::{PiServo, ServoAction, ServoConfig};
use rtime_core::steps::StepLedger;
use rtime_core::timestamp::NtpDuration;
use rtime_metrics::instruments;

/// Why the discipline task stopped.
#[derive(Debug)]
pub enum DisciplineExit {
    /// Shutdown was requested; nothing is wrong.
    Shutdown,
    /// The panic clamp rejected `rejects` consecutive offsets, the last one
    /// being `last_offset_ns`. The clock is stranded out of range and the
    /// daemon should exit so its supervisor restarts it with the
    /// `allow_initial_step` bypass armed.
    PanicStranded { rejects: u32, last_offset_ns: i64 },
}

/// Async task that disciplines the system clock based on offset measurements.
///
/// Receives `NtpDuration` offsets from the selection task via a watch channel,
/// feeds them into the PI servo, and applies the resulting actions to the clock.
/// Every step it applies is recorded in `step_tx` so the selection loop can
/// reconcile measurements taken before the clock moved (see
/// [`rtime_core::steps`]).
///
/// When the clock is not adjustable (no CAP_SYS_TIME), offsets are logged but
/// no adjustments are made.
///
/// `panic_restart_after` > 0 makes the task return
/// [`DisciplineExit::PanicStranded`] once that many consecutive offsets have
/// been refused by the panic clamp; `0` keeps the old behaviour of logging
/// forever.
#[allow(clippy::too_many_arguments)]
pub async fn run_clock_discipline(
    clock: Arc<dyn Clock>,
    mut offset_rx: watch::Receiver<Option<NtpDuration>>,
    step_tx: watch::Sender<StepLedger>,
    poll_interval_secs: f64,
    config: ServoConfig,
    panic_restart_after: u32,
    mut shutdown: watch::Receiver<bool>,
    metrics_enabled: bool,
) -> DisciplineExit {
    let mut servo = PiServo::new(config);

    if !clock.is_adjustable() {
        info!("Clock is not adjustable (no CAP_SYS_TIME) -- running in read-only mode");
    }

    loop {
        tokio::select! {
            Ok(()) = offset_rx.changed() => {
                let Some(offset) = *offset_rx.borrow() else { continue };
                let offset_ns = offset.to_nanos() as f64;
                let action = servo.sample(offset_ns, poll_interval_secs);

                // Record clock offset and frequency metrics.
                if metrics_enabled {
                    instruments::record_clock_offset(offset.to_seconds_f64());
                    instruments::record_clock_frequency(servo.frequency());
                }

                match action {
                    ServoAction::AdjustFrequency { ppm } => {
                        if clock.is_adjustable() {
                            if let Err(e) = clock.adjust_frequency(ppm) {
                                warn!("Failed to adjust frequency: {}", e);
                            }
                            debug!(
                                "Clock frequency adjusted: {:.3} PPM, offset: {}",
                                ppm, offset
                            );
                        } else {
                            info!(
                                "Clock offset: {} (read-only mode, would adjust {:.3} PPM)",
                                offset, ppm
                            );
                        }
                    }
                    ServoAction::Step { offset_ns } => {
                        let step = NtpDuration::from_nanos(offset_ns);
                        if clock.is_adjustable() {
                            let before = Instant::now();
                            match clock.step(step) {
                                Ok(()) => {
                                    let after = Instant::now();
                                    // Publish the step before logging so the
                                    // selection loop sees it as early as possible.
                                    step_tx.send_modify(|ledger| ledger.record(before, after, step));
                                    info!("Clock stepped by {}", step);
                                }
                                Err(e) => warn!("Failed to step clock: {}", e),
                            }
                        } else {
                            info!(
                                "Clock offset: {} (read-only mode, would step by {})",
                                offset, step
                            );
                        }
                    }
                    ServoAction::Reject { offset_ns } => {
                        let rejects = servo.consecutive_rejects();
                        warn!(
                            "Refused implausible offset {} ns (panic threshold exceeded); \
                             clock NOT stepped. Check upstream time sources for spoofing, \
                             corruption, or NTP-era handling bugs.",
                            offset_ns
                        );
                        if panic_restart_after > 0 && rejects >= panic_restart_after {
                            error!(
                                "Clock is stranded: {} consecutive offsets exceeded the panic \
                                 threshold (last {} ns). Exiting so the supervisor can restart \
                                 the daemon with allow_initial_step armed \
                                 (clock.panic_restart_after={}).",
                                rejects, offset_ns, panic_restart_after
                            );
                            return DisciplineExit::PanicStranded {
                                rejects,
                                last_offset_ns: offset_ns,
                            };
                        }
                    }
                    ServoAction::None => {
                        debug!(
                            "Servo warming up ({} samples), offset: {}",
                            servo.sample_count(),
                            offset
                        );
                    }
                }
            }
            Ok(()) = shutdown.changed() => {
                info!("Clock discipline shutting down");
                return DisciplineExit::Shutdown;
            }
        }
    }
}
