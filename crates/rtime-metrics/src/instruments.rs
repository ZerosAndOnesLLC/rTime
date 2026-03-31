//! Convenience functions for recording rTime metrics.
//!
//! These functions use the `metrics` crate macros (`gauge!`, `counter!`) to record
//! values. If no metrics recorder is installed (e.g., metrics are disabled), the
//! calls are effectively no-ops.

use metrics::{counter, gauge};

// ─── Clock state ────────────────────────────────────────────────────────────

/// Record the current clock offset in seconds.
pub fn record_clock_offset(offset_seconds: f64) {
    gauge!("rtime_clock_offset_seconds").set(offset_seconds);
}

/// Record the current clock jitter in seconds.
pub fn record_clock_jitter(jitter_seconds: f64) {
    gauge!("rtime_clock_jitter_seconds").set(jitter_seconds);
}

/// Record the current clock frequency adjustment in PPM.
pub fn record_clock_frequency(ppm: f64) {
    gauge!("rtime_clock_frequency_ppm").set(ppm);
}

/// Record the current stratum of this clock.
pub fn record_clock_stratum(stratum: u8) {
    gauge!("rtime_clock_stratum").set(stratum as f64);
}

// ─── NTP source (labeled by peer) ──────────────────────────────────────────

/// Record the offset of a specific NTP source in seconds.
pub fn record_ntp_source_offset(peer: &str, offset_seconds: f64) {
    gauge!("rtime_ntp_source_offset_seconds", "peer" => peer.to_string())
        .set(offset_seconds);
}

/// Record the round-trip delay of a specific NTP source in seconds.
pub fn record_ntp_source_delay(peer: &str, delay_seconds: f64) {
    gauge!("rtime_ntp_source_delay_seconds", "peer" => peer.to_string())
        .set(delay_seconds);
}

// ─── NTP packets ───────────────────────────────────────────────────────────

/// Increment the count of NTP packets sent.
pub fn increment_ntp_packets_sent() {
    counter!("rtime_ntp_packets_sent_total").increment(1);
}

/// Increment the count of NTP packets received.
pub fn increment_ntp_packets_received() {
    counter!("rtime_ntp_packets_received_total").increment(1);
}

/// Increment the count of NTP packets dropped (invalid, timeout, etc.).
pub fn increment_ntp_packets_dropped() {
    counter!("rtime_ntp_packets_dropped_total").increment(1);
}

/// Increment the count of NTP requests that were rate-limited (KoD RATE sent).
pub fn increment_ntp_rate_limited() {
    counter!("rtime_ntp_rate_limited_total").increment(1);
}

// ─── Selection ─────────────────────────────────────────────────────────────

/// Record the number of truechimers from the latest selection round.
pub fn record_selection_truechimers(count: usize) {
    gauge!("rtime_selection_truechimers").set(count as f64);
}

/// Record the number of falsetickers from the latest selection round.
pub fn record_selection_falsetickers(count: usize) {
    gauge!("rtime_selection_falsetickers").set(count as f64);
}

// ─── Process ───────────────────────────────────────────────────────────────

/// Record the daemon uptime in seconds.
pub fn record_uptime(seconds: f64) {
    gauge!("rtime_uptime_seconds").set(seconds);
}
