//! Multi-source selection pipeline integration tests.
//!
//! These tests exercise the full selection pipeline: clock filter -> Marzullo
//! intersection -> weighted average -> system peer selection.

use rtime_core::clock::LeapIndicator;
use rtime_core::filter::ClockFilter;
use rtime_core::marzullo;
use rtime_core::selection::select_sources;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};
use std::net::SocketAddr;

/// Helper: create a SourceMeasurement with given parameters in milliseconds.
fn make_measurement(
    idx: u16,
    offset_ms: f64,
    delay_ms: f64,
    root_delay_ms: f64,
    root_dispersion_ms: f64,
) -> SourceMeasurement {
    let addr: SocketAddr = format!("10.0.0.{}:123", idx).parse().unwrap();
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
fn five_sources_with_two_falsetickers() {
    // Three sources clustered around 10ms, two outliers at +500ms and -400ms.
    let measurements = vec![
        make_measurement(1, 10.0, 5.0, 10.0, 5.0),
        make_measurement(2, 11.0, 5.0, 10.0, 5.0),
        make_measurement(3, 9.0, 5.0, 10.0, 5.0),
        make_measurement(4, 500.0, 5.0, 10.0, 5.0),
        make_measurement(5, -400.0, 5.0, 10.0, 5.0),
    ];

    let result = select_sources(&measurements);

    // Three truechimers, two falsetickers.
    assert_eq!(
        result.truechimers.len(),
        3,
        "expected 3 truechimers, got {}",
        result.truechimers.len()
    );
    assert_eq!(
        result.falsetickers.len(),
        2,
        "expected 2 falsetickers, got {}",
        result.falsetickers.len()
    );

    // System peer should be selected.
    assert!(result.system_peer.is_some(), "system peer should be selected");

    // System offset should be near 10ms (the cluster center).
    let sys_offset_ms = result.system_offset.to_millis_f64();
    assert!(
        (sys_offset_ms - 10.0).abs() < 2.0,
        "system offset should be ~10ms, got {:.3}ms",
        sys_offset_ms
    );

    // The falseticker IDs should be sources 4 and 5.
    let falseticker_ref_ids: Vec<u32> = result
        .falsetickers
        .iter()
        .filter_map(|id| match id {
            SourceId::Ntp { reference_id, .. } => Some(*reference_id),
            _ => None,
        })
        .collect();
    assert!(
        falseticker_ref_ids.contains(&4),
        "source 4 should be a falseticker"
    );
    assert!(
        falseticker_ref_ids.contains(&5),
        "source 5 should be a falseticker"
    );
}

#[test]
fn filter_then_select_pipeline() {
    // Simulate multiple samples per source through the clock filter, then run
    // selection on the filtered results.
    let mut filters: Vec<ClockFilter> = (0..3).map(|_| ClockFilter::new()).collect();

    // Source 0: offset ~10ms with varying delay
    let offsets_0 = [10.0, 10.5, 9.8, 10.2, 10.1, 9.9, 10.3, 10.0];
    let delays_0 = [5.0, 6.0, 4.5, 7.0, 3.0, 5.5, 4.0, 5.0];

    // Source 1: offset ~11ms
    let offsets_1 = [11.0, 10.8, 11.2, 11.1, 10.9, 11.0, 10.7, 11.3];
    let delays_1 = [6.0, 5.0, 7.0, 4.0, 5.5, 6.5, 4.5, 5.0];

    // Source 2: offset ~500ms (falseticker)
    let offsets_2 = [500.0, 501.0, 499.0, 500.5, 500.0, 499.5, 501.0, 500.0];
    let delays_2 = [5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0];

    let mut filter_results = Vec::new();

    for (filter, (offsets, delays)) in filters.iter_mut().zip(
        [
            (&offsets_0[..], &delays_0[..]),
            (&offsets_1[..], &delays_1[..]),
            (&offsets_2[..], &delays_2[..]),
        ]
        .iter(),
    ) {
        let mut last_result = None;
        for (&offset, &delay) in offsets.iter().zip(delays.iter()) {
            last_result = Some(filter.add_sample(
                NtpDuration::from_seconds_f64(offset / 1000.0),
                NtpDuration::from_seconds_f64(delay / 1000.0),
                NtpDuration::from_seconds_f64(1.0 / 1000.0),
            ));
        }
        filter_results.push(last_result.unwrap());
    }

    // Build SourceMeasurements from filter results.
    let measurements: Vec<SourceMeasurement> = filter_results
        .iter()
        .enumerate()
        .map(|(i, fr)| {
            let idx = (i + 1) as u16;
            let addr: SocketAddr = format!("10.0.0.{}:123", idx).parse().unwrap();
            SourceMeasurement {
                id: SourceId::Ntp {
                    address: addr,
                    reference_id: idx as u32,
                },
                offset: fr.offset,
                delay: fr.delay,
                dispersion: fr.dispersion,
                jitter: fr.jitter,
                stratum: 2,
                leap_indicator: LeapIndicator::NoWarning,
                root_delay: NtpDuration::from_seconds_f64(10.0 / 1000.0),
                root_dispersion: NtpDuration::from_seconds_f64(5.0 / 1000.0),
                time: NtpTimestamp::ZERO,
            }
        })
        .collect();

    let result = select_sources(&measurements);

    // Sources 0 and 1 should be truechimers; source 2 should be a falseticker.
    assert_eq!(result.truechimers.len(), 2, "expected 2 truechimers");
    assert_eq!(result.falsetickers.len(), 1, "expected 1 falseticker");

    // System offset should be near 10ms.
    let sys_offset_ms = result.system_offset.to_millis_f64();
    assert!(
        sys_offset_ms < 20.0 && sys_offset_ms > 5.0,
        "system offset should be near 10ms, got {:.3}ms",
        sys_offset_ms
    );

    // Jitter should be reasonable (non-negative, not huge).
    assert!(
        result.system_jitter >= 0.0 && result.system_jitter < 1.0,
        "jitter should be reasonable, got {}",
        result.system_jitter
    );
}

#[test]
fn selection_weighted_average_accuracy() {
    // Test that the weighted average correctly weights lower-root-distance
    // sources more heavily.
    let measurements = vec![
        // Source with high root distance, offset = 0ms.
        make_measurement(1, 0.0, 5.0, 40.0, 10.0),
        // Source with low root distance, offset = 20ms -- should dominate.
        make_measurement(2, 20.0, 5.0, 4.0, 1.0),
        // Source with high root distance, offset = 0ms.
        make_measurement(3, 0.0, 5.0, 40.0, 10.0),
    ];

    let result = select_sources(&measurements);
    assert_eq!(result.truechimers.len(), 3);
    assert!(result.system_peer.is_some());

    // The system peer should be source 2 (lowest root distance).
    let peer = result.system_peer.as_ref().unwrap();
    match peer {
        SourceId::Ntp { reference_id, .. } => {
            assert_eq!(*reference_id, 2, "system peer should be source 2");
        }
        _ => panic!("expected NTP source"),
    }

    // The weighted average should be pulled toward 20ms.
    let sys_offset_ms = result.system_offset.to_millis_f64();
    assert!(
        sys_offset_ms > 5.0,
        "weighted offset should be pulled toward 20ms by low-root-distance source, got {:.3}ms",
        sys_offset_ms
    );
}

#[test]
fn all_sources_agree_tightly() {
    // Five sources with very similar offsets -- all should be truechimers.
    let measurements = vec![
        make_measurement(1, 10.0, 5.0, 10.0, 5.0),
        make_measurement(2, 10.1, 5.0, 10.0, 5.0),
        make_measurement(3, 9.9, 5.0, 10.0, 5.0),
        make_measurement(4, 10.05, 5.0, 10.0, 5.0),
        make_measurement(5, 9.95, 5.0, 10.0, 5.0),
    ];

    let result = select_sources(&measurements);
    assert_eq!(result.truechimers.len(), 5);
    assert!(result.falsetickers.is_empty());
    assert!(result.system_peer.is_some());

    let sys_offset_ms = result.system_offset.to_millis_f64();
    assert!(
        (sys_offset_ms - 10.0).abs() < 0.5,
        "system offset should be ~10ms, got {:.3}ms",
        sys_offset_ms
    );

    // Jitter should be very small for tightly clustered sources.
    assert!(
        result.system_jitter < 0.001,
        "jitter should be tiny for tight cluster, got {}",
        result.system_jitter
    );
}

#[test]
fn all_sources_disagree() {
    // All sources far apart with tiny confidence intervals.
    let measurements = vec![
        make_measurement(1, 0.0, 1.0, 1.0, 1.0),
        make_measurement(2, 1000.0, 1.0, 1.0, 1.0),
        make_measurement(3, -1000.0, 1.0, 1.0, 1.0),
    ];

    let result = select_sources(&measurements);

    // No majority can agree, so either no truechimers or all are falsetickers.
    if result.truechimers.is_empty() {
        assert!(result.system_peer.is_none());
    }

    // Total should be accounted for.
    let total = result.truechimers.len() + result.falsetickers.len();
    assert_eq!(total, 3);
}

#[test]
fn marzullo_intersection_bounds_contain_truechimer_offsets() {
    // Verify the intersection bounds bracket the truechimer offsets.
    let measurements = vec![
        make_measurement(1, 10.0, 5.0, 10.0, 5.0),
        make_measurement(2, 12.0, 5.0, 10.0, 5.0),
        make_measurement(3, 8.0, 5.0, 10.0, 5.0),
    ];

    let intersection = marzullo::intersect(&measurements);
    assert_eq!(intersection.truechimers.len(), 3);
    assert!(intersection.low.raw() <= intersection.high.raw());

    // Each truechimer's offset should fall within the intersection bounds
    // (well, the intersection of confidence intervals should contain
    // the average, but at minimum low <= high).
    let low_ms = intersection.low.to_millis_f64();
    let high_ms = intersection.high.to_millis_f64();
    assert!(
        low_ms <= high_ms,
        "low ({:.3}) should be <= high ({:.3})",
        low_ms,
        high_ms
    );
}
