use std::sync::Arc;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use rtime_core::clock::Clock;
use rtime_core::servo::{PiServo, ServoAction, ServoConfig};
use rtime_core::timestamp::NtpDuration;
use rtime_metrics::instruments;

/// Async task that disciplines the system clock based on offset measurements.
///
/// Receives `NtpDuration` offsets from the selection task via a watch channel,
/// feeds them into the PI servo, and applies the resulting actions to the clock.
///
/// When the clock is not adjustable (no CAP_SYS_TIME), offsets are logged but
/// no adjustments are made.
pub async fn run_clock_discipline(
    clock: Arc<dyn Clock>,
    mut offset_rx: watch::Receiver<Option<NtpDuration>>,
    poll_interval_secs: f64,
    config: ServoConfig,
    mut shutdown: watch::Receiver<bool>,
    metrics_enabled: bool,
) -> anyhow::Result<()> {
    let mut servo = PiServo::new(config);

    if !clock.is_adjustable() {
        info!("Clock is not adjustable (no CAP_SYS_TIME) -- running in read-only mode");
    }

    loop {
        tokio::select! {
            Ok(()) = offset_rx.changed() => {
                if let Some(offset) = *offset_rx.borrow() {
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
                                if let Err(e) = clock.step(step) {
                                    warn!("Failed to step clock: {}", e);
                                }
                                info!("Clock stepped by {}", step);
                            } else {
                                info!(
                                    "Clock offset: {} (read-only mode, would step by {})",
                                    offset, step
                                );
                            }
                        }
                        ServoAction::Reject { offset_ns } => {
                            warn!(
                                "Refused implausible offset {} ns (panic threshold exceeded); \
                                 clock NOT stepped. Check upstream time sources for spoofing, \
                                 corruption, or NTP-era handling bugs.",
                                offset_ns
                            );
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
            }
            Ok(()) = shutdown.changed() => {
                info!("Clock discipline shutting down");
                break;
            }
        }
    }

    Ok(())
}
