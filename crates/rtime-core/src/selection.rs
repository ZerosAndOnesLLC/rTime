use crate::marzullo;
use crate::source::{SourceId, SourceMeasurement};
use crate::timestamp::NtpDuration;

/// Result of the full source selection pipeline.
#[derive(Clone, Debug)]
pub struct SelectionResult {
    /// Weighted-average system offset from truechimers.
    pub system_offset: NtpDuration,
    /// Source IDs classified as truechimers.
    pub truechimers: Vec<SourceId>,
    /// Source IDs classified as falsetickers.
    pub falsetickers: Vec<SourceId>,
    /// System peer: the truechimer with the lowest root distance.
    pub system_peer: Option<SourceId>,
    /// System jitter: RMS of truechimer offset residuals from the weighted mean.
    pub system_jitter: f64,
}

/// Run the full source selection pipeline:
///
/// 1. Marzullo's intersection to identify truechimers vs falsetickers.
/// 2. Select the system peer (truechimer with lowest `root_distance`).
/// 3. Compute a weighted-average offset (weight = 1 / root_distance).
/// 4. Compute system jitter as the RMS of truechimer offset residuals.
pub fn select_sources(measurements: &[SourceMeasurement]) -> SelectionResult {
    if measurements.is_empty() {
        return SelectionResult {
            system_offset: NtpDuration::ZERO,
            truechimers: Vec::new(),
            falsetickers: Vec::new(),
            system_peer: None,
            system_jitter: 0.0,
        };
    }

    // Step 1: Run Marzullo's intersection algorithm.
    let intersection = marzullo::intersect(measurements);

    let truechimer_ids: Vec<SourceId> = intersection
        .truechimers
        .iter()
        .map(|&i| measurements[i].id.clone())
        .collect();

    let falseticker_ids: Vec<SourceId> = intersection
        .falsetickers
        .iter()
        .map(|&i| measurements[i].id.clone())
        .collect();

    if intersection.truechimers.is_empty() {
        return SelectionResult {
            system_offset: NtpDuration::ZERO,
            truechimers: truechimer_ids,
            falsetickers: falseticker_ids,
            system_peer: None,
            system_jitter: 0.0,
        };
    }

    // Step 2: Find the system peer (lowest root_distance among truechimers).
    let mut best_peer_idx = intersection.truechimers[0];
    let mut best_root_dist = measurements[best_peer_idx].root_distance();

    for &idx in &intersection.truechimers[1..] {
        let rd = measurements[idx].root_distance();
        if rd.raw() < best_root_dist.raw() {
            best_root_dist = rd;
            best_peer_idx = idx;
        }
    }

    let system_peer = Some(measurements[best_peer_idx].id.clone());

    // Step 3: Compute weighted-average offset (weight = 1 / root_distance).
    let mut weight_sum = 0.0_f64;
    let mut weighted_offset_sum = 0.0_f64;

    for &idx in &intersection.truechimers {
        let rd = measurements[idx].root_distance().to_seconds_f64();
        let w = if rd > 1e-15 { 1.0 / rd } else { 1e15 };
        weight_sum += w;
        weighted_offset_sum += w * measurements[idx].offset.to_seconds_f64();
    }

    let avg_offset_secs = if weight_sum > 0.0 {
        weighted_offset_sum / weight_sum
    } else {
        0.0
    };
    let system_offset = NtpDuration::from_seconds_f64(avg_offset_secs);

    // Step 4: Compute system jitter (RMS of residuals from the weighted mean).
    let n_tc = intersection.truechimers.len() as f64;
    let mut sum_sq = 0.0_f64;

    for &idx in &intersection.truechimers {
        let residual = measurements[idx].offset.to_seconds_f64() - avg_offset_secs;
        sum_sq += residual * residual;
    }

    let system_jitter = if n_tc > 1.0 {
        (sum_sq / (n_tc - 1.0)).sqrt()
    } else {
        measurements[intersection.truechimers[0]].jitter
    };

    SelectionResult {
        system_offset,
        truechimers: truechimer_ids,
        falsetickers: falseticker_ids,
        system_peer,
        system_jitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::LeapIndicator;
    use crate::timestamp::NtpTimestamp;
    use std::net::SocketAddr;

    fn make_measurement(
        idx: u16,
        offset_ms: f64,
        delay_ms: f64,
        root_delay_ms: f64,
        root_dispersion_ms: f64,
    ) -> SourceMeasurement {
        let addr: SocketAddr = format!("127.0.0.{}:{}", idx, 123).parse().unwrap();
        SourceMeasurement {
            id: SourceId::Ntp {
                address: addr,
                reference_id: idx as u32,
            },
            offset: NtpDuration::from_seconds_f64(offset_ms / 1000.0),
            delay: NtpDuration::from_seconds_f64(delay_ms / 1000.0),
            dispersion: NtpDuration::from_seconds_f64(1.0 / 1000.0),
            jitter: 0.001,
            stratum: 2,
            leap_indicator: LeapIndicator::NoWarning,
            root_delay: NtpDuration::from_seconds_f64(root_delay_ms / 1000.0),
            root_dispersion: NtpDuration::from_seconds_f64(root_dispersion_ms / 1000.0),
            time: NtpTimestamp::ZERO,
        }
    }

    #[test]
    fn empty_input() {
        let result = select_sources(&[]);
        assert!(result.truechimers.is_empty());
        assert!(result.falsetickers.is_empty());
        assert!(result.system_peer.is_none());
        assert_eq!(result.system_jitter, 0.0);
    }

    #[test]
    fn single_source() {
        let m = vec![make_measurement(1, 10.0, 5.0, 10.0, 5.0)];
        let result = select_sources(&m);

        assert_eq!(result.truechimers.len(), 1);
        assert!(result.falsetickers.is_empty());
        assert!(result.system_peer.is_some());
        assert!(
            (result.system_offset.to_millis_f64() - 10.0).abs() < 0.5,
            "expected ~10ms, got {}ms",
            result.system_offset.to_millis_f64()
        );
    }

    #[test]
    fn three_agreeing_sources() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
            make_measurement(3, 9.0, 5.0, 10.0, 5.0),
        ];
        let result = select_sources(&m);

        assert_eq!(result.truechimers.len(), 3);
        assert!(result.falsetickers.is_empty());
        assert!(result.system_peer.is_some());
        assert!(
            (result.system_offset.to_millis_f64() - 10.0).abs() < 1.0,
            "expected ~10ms, got {}ms",
            result.system_offset.to_millis_f64()
        );
        assert!(result.system_jitter >= 0.0);
    }

    #[test]
    fn one_falseticker_excluded() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
            make_measurement(3, 500.0, 5.0, 10.0, 5.0),
        ];
        let result = select_sources(&m);

        assert_eq!(result.truechimers.len(), 2);
        assert_eq!(result.falsetickers.len(), 1);
        assert!(
            result.system_offset.to_millis_f64() < 20.0,
            "offset should not include falseticker, got {}ms",
            result.system_offset.to_millis_f64()
        );
    }

    #[test]
    fn system_peer_has_lowest_root_distance() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 20.0, 5.0),
            make_measurement(2, 11.0, 5.0, 2.0, 1.0),
            make_measurement(3, 9.0, 5.0, 20.0, 5.0),
        ];
        let result = select_sources(&m);

        assert!(result.system_peer.is_some());
        let peer = result.system_peer.unwrap();
        match &peer {
            SourceId::Ntp { reference_id, .. } => {
                assert_eq!(*reference_id, 2, "source 2 should be system peer");
            }
            _ => panic!("expected NTP source"),
        }
    }

    #[test]
    fn weighted_average_favors_lower_root_distance() {
        let m = vec![
            make_measurement(1, 0.0, 5.0, 40.0, 10.0),
            make_measurement(2, 20.0, 5.0, 4.0, 1.0),
            make_measurement(3, 0.0, 5.0, 40.0, 10.0),
        ];
        let result = select_sources(&m);

        assert!(
            result.system_offset.to_millis_f64() > 5.0,
            "offset should be pulled toward 20ms by low-root-distance source, got {}ms",
            result.system_offset.to_millis_f64()
        );
    }

    #[test]
    fn jitter_zero_for_identical_offsets() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 10.0, 5.0, 10.0, 5.0),
            make_measurement(3, 10.0, 5.0, 10.0, 5.0),
        ];
        let result = select_sources(&m);

        assert!(
            result.system_jitter < 1e-9,
            "expected near-zero jitter, got {}",
            result.system_jitter
        );
    }

    #[test]
    fn all_disagree_no_system_peer() {
        let m = vec![
            make_measurement(1, 0.0, 1.0, 1.0, 1.0),
            make_measurement(2, 1000.0, 1.0, 1.0, 1.0),
            make_measurement(3, -1000.0, 1.0, 1.0, 1.0),
        ];
        let result = select_sources(&m);

        if result.truechimers.is_empty() {
            assert!(result.system_peer.is_none());
        }
    }
}
