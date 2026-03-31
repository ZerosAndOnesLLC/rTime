//! Best Master Clock Algorithm (BMCA) per IEEE 1588-2019 Section 9.3.
//!
//! Determines which clock should be grandmaster based on announce message
//! comparison. The comparison uses a strict priority ordering of fields.

use crate::message::AnnounceBody;

/// Result of comparing two announce messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BmcaResult {
    /// This clock is better (should be preferred).
    ThisBetter,
    /// The other clock is better (should be preferred).
    OtherBetter,
    /// Equal quality (should not happen with unique clock identities).
    Equal,
}

/// Compare two announce messages to determine the better master clock.
///
/// Priority order per IEEE 1588-2019 Section 9.3.4 (data set comparison):
/// 1. `grandmaster_priority1` (lower is better)
/// 2. `clock_class` (lower is better)
/// 3. `clock_accuracy` (lower is better)
/// 4. `offset_scaled_log_variance` (lower is better)
/// 5. `grandmaster_priority2` (lower is better)
/// 6. `grandmaster_identity` (lower is better, tiebreaker)
pub fn compare_announce(this: &AnnounceBody, other: &AnnounceBody) -> BmcaResult {
    // 1. Priority1
    match this.grandmaster_priority1.cmp(&other.grandmaster_priority1) {
        std::cmp::Ordering::Less => return BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => return BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => {}
    }

    // 2. Clock class
    match this
        .grandmaster_clock_quality
        .clock_class
        .cmp(&other.grandmaster_clock_quality.clock_class)
    {
        std::cmp::Ordering::Less => return BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => return BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => {}
    }

    // 3. Clock accuracy
    match this
        .grandmaster_clock_quality
        .clock_accuracy
        .cmp(&other.grandmaster_clock_quality.clock_accuracy)
    {
        std::cmp::Ordering::Less => return BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => return BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => {}
    }

    // 4. Offset scaled log variance
    match this
        .grandmaster_clock_quality
        .offset_scaled_log_variance
        .cmp(
            &other
                .grandmaster_clock_quality
                .offset_scaled_log_variance,
        )
    {
        std::cmp::Ordering::Less => return BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => return BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => {}
    }

    // 5. Priority2
    match this
        .grandmaster_priority2
        .cmp(&other.grandmaster_priority2)
    {
        std::cmp::Ordering::Less => return BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => return BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => {}
    }

    // 6. Clock identity (tiebreaker)
    match this
        .grandmaster_identity
        .cmp(&other.grandmaster_identity)
    {
        std::cmp::Ordering::Less => BmcaResult::ThisBetter,
        std::cmp::Ordering::Greater => BmcaResult::OtherBetter,
        std::cmp::Ordering::Equal => BmcaResult::Equal,
    }
}

/// Determine the best master from a slice of announce bodies.
/// Returns the index of the best announce, or `None` if the slice is empty.
pub fn select_best_master(announces: &[AnnounceBody]) -> Option<usize> {
    if announces.is_empty() {
        return None;
    }
    let mut best_idx = 0;
    for (i, candidate) in announces.iter().enumerate().skip(1) {
        if compare_announce(candidate, &announces[best_idx]) == BmcaResult::ThisBetter {
            best_idx = i;
        }
    }
    Some(best_idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ClockQuality;
    use rtime_core::timestamp::PtpTimestamp;

    fn make_announce(
        priority1: u8,
        clock_class: u8,
        clock_accuracy: u8,
        variance: u16,
        priority2: u8,
        identity: [u8; 8],
    ) -> AnnounceBody {
        AnnounceBody {
            origin_timestamp: PtpTimestamp::ZERO,
            current_utc_offset: 37,
            grandmaster_priority1: priority1,
            grandmaster_clock_quality: ClockQuality {
                clock_class,
                clock_accuracy,
                offset_scaled_log_variance: variance,
            },
            grandmaster_priority2: priority2,
            grandmaster_identity: identity,
            steps_removed: 0,
            time_source: 0x20,
        }
    }

    #[test]
    fn priority1_wins() {
        let better = make_announce(100, 6, 0x21, 0x4E5D, 128, [0; 8]);
        let worse = make_announce(200, 6, 0x21, 0x4E5D, 128, [0; 8]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
        assert_eq!(compare_announce(&worse, &better), BmcaResult::OtherBetter);
    }

    #[test]
    fn clock_class_wins() {
        let better = make_announce(128, 6, 0x21, 0x4E5D, 128, [0; 8]);
        let worse = make_announce(128, 7, 0x21, 0x4E5D, 128, [0; 8]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
        assert_eq!(compare_announce(&worse, &better), BmcaResult::OtherBetter);
    }

    #[test]
    fn clock_accuracy_wins() {
        let better = make_announce(128, 6, 0x20, 0x4E5D, 128, [0; 8]);
        let worse = make_announce(128, 6, 0x21, 0x4E5D, 128, [0; 8]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
    }

    #[test]
    fn variance_wins() {
        let better = make_announce(128, 6, 0x21, 0x1000, 128, [0; 8]);
        let worse = make_announce(128, 6, 0x21, 0x4E5D, 128, [0; 8]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
    }

    #[test]
    fn priority2_wins() {
        let better = make_announce(128, 6, 0x21, 0x4E5D, 100, [0; 8]);
        let worse = make_announce(128, 6, 0x21, 0x4E5D, 200, [0; 8]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
    }

    #[test]
    fn identity_tiebreaker() {
        let better = make_announce(128, 6, 0x21, 0x4E5D, 128, [0, 0, 0, 0, 0, 0, 0, 1]);
        let worse = make_announce(128, 6, 0x21, 0x4E5D, 128, [0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(compare_announce(&better, &worse), BmcaResult::ThisBetter);
        assert_eq!(compare_announce(&worse, &better), BmcaResult::OtherBetter);
    }

    #[test]
    fn equal_clocks() {
        let a = make_announce(128, 6, 0x21, 0x4E5D, 128, [1; 8]);
        let b = make_announce(128, 6, 0x21, 0x4E5D, 128, [1; 8]);
        assert_eq!(compare_announce(&a, &b), BmcaResult::Equal);
    }

    #[test]
    fn select_best_from_multiple() {
        let announces = vec![
            make_announce(200, 6, 0x21, 0x4E5D, 128, [3; 8]),
            make_announce(100, 6, 0x21, 0x4E5D, 128, [2; 8]), // best: priority1=100
            make_announce(150, 6, 0x21, 0x4E5D, 128, [1; 8]),
        ];
        assert_eq!(select_best_master(&announces), Some(1));
    }

    #[test]
    fn select_best_empty() {
        let announces: Vec<AnnounceBody> = vec![];
        assert_eq!(select_best_master(&announces), None);
    }

    #[test]
    fn select_best_single() {
        let announces = vec![make_announce(128, 6, 0x21, 0x4E5D, 128, [1; 8])];
        assert_eq!(select_best_master(&announces), Some(0));
    }
}
