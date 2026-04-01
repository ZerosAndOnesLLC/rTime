//! End-to-end (E2E) delay measurement per IEEE 1588-2019 Section 11.3.
//!
//! The E2E delay mechanism uses four timestamps from a Sync/DelayReq exchange:
//! - T1: Sync departure time at master (from FollowUp or one-step Sync)
//! - T2: Sync arrival time at slave (local receive timestamp)
//! - T3: Delay_Req departure time at slave (local send timestamp)
//! - T4: Delay_Req arrival time at master (from Delay_Resp)
//!
//! From these, we compute:
//! - offset  = ((T2 - T1) - (T4 - T3)) / 2
//! - delay   = ((T2 - T1) + (T4 - T3)) / 2

use rtime_core::timestamp::{NtpDuration, PtpTimestamp};

/// Convert a PtpTimestamp difference to NtpDuration.
/// This computes (a - b) as a signed duration in nanoseconds.
fn ptp_diff(a: PtpTimestamp, b: PtpTimestamp) -> NtpDuration {
    let a_nanos = a.seconds as i128 * 1_000_000_000 + a.nanoseconds as i128;
    let b_nanos = b.seconds as i128 * 1_000_000_000 + b.nanoseconds as i128;
    let diff_nanos = a_nanos - b_nanos;
    NtpDuration::from_nanos(diff_nanos.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
}

/// Compute clock offset and mean path delay from E2E delay mechanism timestamps.
///
/// # Arguments
/// - `t1`: Sync departure time at master
/// - `t2`: Sync arrival time at slave
/// - `t3`: Delay_Req departure time at slave
/// - `t4`: Delay_Req arrival time at master
///
/// # Returns
/// `(offset, delay)` where:
/// - `offset` = ((T2 - T1) - (T4 - T3)) / 2  (positive means slave is ahead)
/// - `delay`  = ((T2 - T1) + (T4 - T3)) / 2  (one-way network delay)
pub fn compute_e2e(
    t1: PtpTimestamp,
    t2: PtpTimestamp,
    t3: PtpTimestamp,
    t4: PtpTimestamp,
) -> (NtpDuration, NtpDuration) {
    let forward = ptp_diff(t2, t1);  // T2 - T1
    let reverse = ptp_diff(t4, t3);  // T4 - T3

    let offset = (forward - reverse) / 2;
    let delay = (forward + reverse) / 2;

    (offset, delay)
}

/// State tracker for collecting E2E delay measurement timestamps.
///
/// Collects timestamps as they arrive from the protocol exchange and
/// computes offset/delay when all four are available.
#[derive(Debug, Default)]
pub struct E2eDelayState {
    /// T1: Sync departure (from master, via FollowUp or one-step).
    pub t1: Option<PtpTimestamp>,
    /// T2: Sync arrival (local receive timestamp).
    pub t2: Option<PtpTimestamp>,
    /// T3: Delay_Req departure (local send timestamp).
    pub t3: Option<PtpTimestamp>,
    /// T4: Delay_Req arrival (from Delay_Resp).
    pub t4: Option<PtpTimestamp>,
}

impl E2eDelayState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all timestamps for a new measurement cycle.
    pub fn reset(&mut self) {
        self.t1 = None;
        self.t2 = None;
        self.t3 = None;
        self.t4 = None;
    }

    /// Record the Sync departure time (T1, from master).
    pub fn set_sync_departure(&mut self, t1: PtpTimestamp) {
        self.t1 = Some(t1);
    }

    /// Record the Sync arrival time (T2, local).
    pub fn set_sync_arrival(&mut self, t2: PtpTimestamp) {
        self.t2 = Some(t2);
    }

    /// Record the Delay_Req departure time (T3, local).
    pub fn set_delay_req_departure(&mut self, t3: PtpTimestamp) {
        self.t3 = Some(t3);
    }

    /// Record the Delay_Req arrival time (T4, from master).
    pub fn set_delay_resp_arrival(&mut self, t4: PtpTimestamp) {
        self.t4 = Some(t4);
    }

    /// Try to compute offset and delay. Returns None if not all timestamps are set.
    pub fn compute(&self) -> Option<(NtpDuration, NtpDuration)> {
        match (self.t1, self.t2, self.t3, self.t4) {
            (Some(t1), Some(t2), Some(t3), Some(t4)) => Some(compute_e2e(t1, t2, t3, t4)),
            _ => None,
        }
    }

    /// Whether all four timestamps have been collected.
    pub fn is_complete(&self) -> bool {
        self.t1.is_some() && self.t2.is_some() && self.t3.is_some() && self.t4.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_delay_zero_offset() {
        // Symmetric path with zero offset:
        // Master sends at T1=100.0, slave receives at T2=100.001 (1ms delay)
        // Slave sends at T3=100.002, master receives at T4=100.003 (1ms delay)
        let t1 = PtpTimestamp::new(100, 0);
        let t2 = PtpTimestamp::new(100, 1_000_000); // +1ms
        let t3 = PtpTimestamp::new(100, 2_000_000); // +2ms
        let t4 = PtpTimestamp::new(100, 3_000_000); // +3ms

        let (offset, delay) = compute_e2e(t1, t2, t3, t4);

        // offset should be ~0 (clocks are aligned)
        assert!(
            offset.to_nanos().abs() < 10,
            "expected ~0 offset, got {} ns",
            offset.to_nanos()
        );
        // delay should be ~1ms
        assert!(
            (delay.to_nanos() - 1_000_000).abs() < 10,
            "expected ~1ms delay, got {} ns",
            delay.to_nanos()
        );
    }

    #[test]
    fn symmetric_delay_with_offset() {
        // Slave clock is 500us ahead of master.
        // Master sends at T1=100.000000000, arrives at T2=100.001500000
        //   (1ms network delay + 0.5ms offset)
        // Slave sends at T3=100.002500000 (slave's clock), arrives at T4=100.003000000
        //   (0.5ms network delay ... wait, let me be more careful)
        //
        // Real scenario: network delay = 1ms each way.
        // Slave offset = +500us (slave reads 500us ahead).
        // T1 (master) = 100.000 000 000
        // T2 (slave)  = 100.001 500 000  (arrived after 1ms, but slave clock is +500us)
        // T3 (slave)  = 100.002 500 000  (slave sends 1ms after T2 in slave time)
        // T4 (master) = 100.002 000 000  (T3 in master time is 100.002, +1ms delay)
        let t1 = PtpTimestamp::new(100, 0);
        let t2 = PtpTimestamp::new(100, 1_500_000); // slave sees +1ms delay + 500us offset
        let t3 = PtpTimestamp::new(100, 2_500_000); // slave sends
        // Redo with clearer math:
        // True offset = +500us (slave ahead)
        // True one-way delay = 1ms
        // T1 = 100.000 (master clock)
        // T2 = T1 + delay + offset = 100.000 + 0.001 + 0.0005 = 100.0015 (slave clock)
        // T3 = T2 + some_gap(slave) = 100.0025 (slave clock, 1ms after T2)
        // T4 = T3 - offset + delay = 100.0025 - 0.0005 + 0.001 = 100.003 (master clock)
        let t4_fixed = PtpTimestamp::new(100, 3_000_000);

        let (offset, delay) = compute_e2e(t1, t2, t3, t4_fixed);

        // offset should be ~500us
        assert!(
            (offset.to_nanos() - 500_000).abs() < 10,
            "expected ~500us offset, got {} ns",
            offset.to_nanos()
        );
        // delay should be ~1ms
        assert!(
            (delay.to_nanos() - 1_000_000).abs() < 10,
            "expected ~1ms delay, got {} ns",
            delay.to_nanos()
        );
    }

    #[test]
    fn negative_offset() {
        // Slave is 200us behind master.
        // True delay = 500us each way, offset = -200us.
        // T1 = 100.000 000 000
        // T2 = T1 + delay + offset = 100.000 + 0.0005 - 0.0002 = 100.000 300 000
        // T3 = T2 + 1ms (gap) = 100.001 300 000
        // T4 = T3 - offset + delay = 100.001300 + 0.0002 + 0.0005 = 100.002 000 000
        let t1 = PtpTimestamp::new(100, 0);
        let t2 = PtpTimestamp::new(100, 300_000);
        let t3 = PtpTimestamp::new(100, 1_300_000);
        let t4 = PtpTimestamp::new(100, 2_000_000);

        let (offset, delay) = compute_e2e(t1, t2, t3, t4);

        assert!(
            (offset.to_nanos() - (-200_000)).abs() < 10,
            "expected ~-200us offset, got {} ns",
            offset.to_nanos()
        );
        assert!(
            (delay.to_nanos() - 500_000).abs() < 10,
            "expected ~500us delay, got {} ns",
            delay.to_nanos()
        );
    }

    #[test]
    fn e2e_state_tracker() {
        let mut state = E2eDelayState::new();
        assert!(!state.is_complete());
        assert!(state.compute().is_none());

        state.set_sync_departure(PtpTimestamp::new(100, 0));
        state.set_sync_arrival(PtpTimestamp::new(100, 1_000_000));
        state.set_delay_req_departure(PtpTimestamp::new(100, 2_000_000));
        assert!(!state.is_complete());
        assert!(state.compute().is_none());

        state.set_delay_resp_arrival(PtpTimestamp::new(100, 3_000_000));
        assert!(state.is_complete());

        let (offset, delay) = state.compute().unwrap();
        assert!(offset.to_nanos().abs() < 10);
        assert!((delay.to_nanos() - 1_000_000).abs() < 10);
    }

    #[test]
    fn e2e_state_reset() {
        let mut state = E2eDelayState::new();
        state.set_sync_departure(PtpTimestamp::new(100, 0));
        state.set_sync_arrival(PtpTimestamp::new(100, 1_000_000));
        state.reset();
        assert!(!state.is_complete());
        assert!(state.t1.is_none());
        assert!(state.t2.is_none());
    }
}
