use crate::source::SourceMeasurement;
use crate::timestamp::NtpDuration;

/// Result of Marzullo's intersection algorithm.
#[derive(Clone, Debug)]
pub struct IntersectionResult {
    /// Indices of sources whose intervals overlap the intersection (truechimers).
    pub truechimers: Vec<usize>,
    /// Indices of sources whose intervals do not overlap (falsetickers).
    pub falsetickers: Vec<usize>,
    /// Lower bound of the final intersection interval.
    pub low: NtpDuration,
    /// Upper bound of the final intersection interval.
    pub high: NtpDuration,
}

/// Type tag for interval endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointType {
    /// Lower bound of a confidence interval (contributes +1 when entered).
    Low,
    /// Upper bound of a confidence interval (contributes -1 when exited).
    High,
}

/// A tagged interval endpoint for the sweep.
#[derive(Clone, Copy, Debug)]
struct Endpoint {
    value: i128,
    kind: EndpointType,
}

/// Marzullo's intersection algorithm as described in RFC 5905 Section 11.2.1.
///
/// For each source measurement the confidence interval is:
///   `[offset - lambda, offset + lambda]`  where `lambda = root_distance()`.
///
/// The algorithm creates a sorted list of interval endpoints, then sweeps
/// through them tracking the overlap count. It finds the largest interval
/// that contains points from at least `n - f` sources, starting with
/// `f = 0` falsetickers and increasing until `f < n/2`.
///
/// Sources whose intervals do not overlap the final intersection are
/// classified as falsetickers; the rest are truechimers.
pub fn intersect(measurements: &[SourceMeasurement]) -> IntersectionResult {
    let n = measurements.len();

    if n == 0 {
        return IntersectionResult {
            truechimers: Vec::new(),
            falsetickers: Vec::new(),
            low: NtpDuration::ZERO,
            high: NtpDuration::ZERO,
        };
    }

    // Build interval endpoints using root_distance as lambda.
    let mut endpoints = Vec::with_capacity(n * 2);
    for m in measurements {
        let lambda = m.root_distance();
        let lo = (m.offset - lambda).raw();
        let hi = (m.offset + lambda).raw();
        endpoints.push(Endpoint {
            value: lo,
            kind: EndpointType::Low,
        });
        endpoints.push(Endpoint {
            value: hi,
            kind: EndpointType::High,
        });
    }

    // Sort by value; break ties with Low before High so a point exactly at
    // a boundary is counted as inside.
    endpoints.sort_by(|a, b| {
        a.value.cmp(&b.value).then_with(|| match (&a.kind, &b.kind) {
            (EndpointType::Low, EndpointType::High) => std::cmp::Ordering::Less,
            (EndpointType::High, EndpointType::Low) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        })
    });

    // Try increasing numbers of allowed falsetickers.
    // With f falsetickers we require overlap of at least (n - f) sources.
    // f can be at most floor((n-1)/2) to maintain a strict majority.
    let max_f = (n - 1) / 2;
    let mut best_low = 0i128;
    let mut best_high = 0i128;
    let mut found = false;

    for f in 0..=max_f {
        let required = (n - f) as i32;
        let mut count: i32 = 0;
        let mut candidate_low = 0i128;
        let mut have_low = false;

        for ep in &endpoints {
            match ep.kind {
                EndpointType::Low => {
                    count += 1;
                    if count >= required && !have_low {
                        candidate_low = ep.value;
                        have_low = true;
                    }
                }
                EndpointType::High => {
                    if count >= required && have_low {
                        // Found valid intersection for this f.
                        best_low = candidate_low;
                        best_high = ep.value;
                        found = true;
                        break;
                    }
                    count -= 1;
                }
            }
        }

        if found {
            break;
        }
    }

    if !found {
        // No valid intersection -- all sources are falsetickers.
        return IntersectionResult {
            truechimers: Vec::new(),
            falsetickers: (0..n).collect(),
            low: NtpDuration::ZERO,
            high: NtpDuration::ZERO,
        };
    }

    // Classify each source: truechimer if its interval overlaps [best_low, best_high].
    let mut truechimers = Vec::new();
    let mut falsetickers = Vec::new();

    for (i, m) in measurements.iter().enumerate() {
        let lambda = m.root_distance();
        let src_lo = (m.offset - lambda).raw();
        let src_hi = (m.offset + lambda).raw();

        if src_lo <= best_high && src_hi >= best_low {
            truechimers.push(i);
        } else {
            falsetickers.push(i);
        }
    }

    IntersectionResult {
        truechimers,
        falsetickers,
        low: NtpDuration::from_raw(best_low),
        high: NtpDuration::from_raw(best_high),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::LeapIndicator;
    use crate::source::SourceId;
    use crate::timestamp::NtpTimestamp;
    use std::net::SocketAddr;

    /// Helper: create a SourceMeasurement with given parameters in milliseconds.
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
        let result = intersect(&[]);
        assert!(result.truechimers.is_empty());
        assert!(result.falsetickers.is_empty());
    }

    #[test]
    fn single_source_is_truechimer() {
        let m = vec![make_measurement(1, 10.0, 5.0, 10.0, 5.0)];
        let result = intersect(&m);
        assert_eq!(result.truechimers, vec![0]);
        assert!(result.falsetickers.is_empty());
    }

    #[test]
    fn three_sources_all_agree() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
            make_measurement(3, 9.0, 5.0, 10.0, 5.0),
        ];
        let result = intersect(&m);
        assert_eq!(result.truechimers.len(), 3);
        assert!(result.falsetickers.is_empty());
        assert!(result.low.raw() <= result.high.raw());
    }

    #[test]
    fn one_falseticker_out_of_three() {
        // Two sources near 10ms, one outlier at 500ms.
        // root_distance ~ root_delay/2 + root_disp + delay/2 + disp
        //              = 5 + 5 + 2.5 + 1 = 13.5ms
        // Sources 0 and 1 overlap; source 2 at 500ms does not.
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
            make_measurement(3, 500.0, 5.0, 10.0, 5.0),
        ];
        let result = intersect(&m);

        assert!(result.truechimers.contains(&0));
        assert!(result.truechimers.contains(&1));
        assert!(result.falsetickers.contains(&2));
    }

    #[test]
    fn five_sources_two_falsetickers() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
            make_measurement(3, 9.0, 5.0, 10.0, 5.0),
            make_measurement(4, 500.0, 5.0, 10.0, 5.0),
            make_measurement(5, -400.0, 5.0, 10.0, 5.0),
        ];
        let result = intersect(&m);

        assert!(result.truechimers.contains(&0));
        assert!(result.truechimers.contains(&1));
        assert!(result.truechimers.contains(&2));
        assert!(result.falsetickers.contains(&3));
        assert!(result.falsetickers.contains(&4));
    }

    #[test]
    fn intersection_bounds_are_ordered() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 12.0, 5.0, 10.0, 5.0),
            make_measurement(3, 8.0, 5.0, 10.0, 5.0),
        ];
        let result = intersect(&m);
        assert!(result.low.raw() <= result.high.raw());
    }

    #[test]
    fn all_completely_disagree() {
        // Intervals so far apart that no majority intersection is possible.
        let m = vec![
            make_measurement(1, 0.0, 1.0, 1.0, 1.0),
            make_measurement(2, 1000.0, 1.0, 1.0, 1.0),
            make_measurement(3, -1000.0, 1.0, 1.0, 1.0),
        ];
        let result = intersect(&m);

        // With 3 sources, max 1 falseticker needed for 2 to agree.
        // But none of these pairs overlap, so all should be falsetickers.
        let total = result.truechimers.len() + result.falsetickers.len();
        assert_eq!(total, 3);
    }

    #[test]
    fn two_sources_agree() {
        let m = vec![
            make_measurement(1, 10.0, 5.0, 10.0, 5.0),
            make_measurement(2, 11.0, 5.0, 10.0, 5.0),
        ];
        let result = intersect(&m);
        assert_eq!(result.truechimers.len(), 2);
        assert!(result.falsetickers.is_empty());
    }

    #[test]
    fn two_sources_disagree() {
        // Two sources far apart -- with n=2, max f=0, need both to agree.
        let m = vec![
            make_measurement(1, 0.0, 1.0, 1.0, 1.0),
            make_measurement(2, 1000.0, 1.0, 1.0, 1.0),
        ];
        let result = intersect(&m);
        // With 2 sources and f=0, need both to overlap.
        // These don't overlap, so both are falsetickers.
        assert!(result.truechimers.is_empty());
        assert_eq!(result.falsetickers.len(), 2);
    }
}
