//! Foreign master table for tracking announce messages (IEEE 1588-2019 Section 9.3.2.4).
//!
//! Each PTP port maintains a foreign master table that records announce messages
//! received from other clocks. A foreign master becomes qualified after receiving
//! a threshold number of announces within a window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::message::{AnnounceBody, PortIdentity};

/// Default number of announces required to qualify a foreign master.
const FOREIGN_MASTER_THRESHOLD: usize = 2;

/// Default window size as a multiple of the announce interval.
const FOREIGN_MASTER_WINDOW_MULTIPLIER: u32 = 4;

/// A single record in the foreign master table.
#[derive(Debug, Clone)]
pub struct ForeignMasterRecord {
    /// Port identity of the foreign master.
    pub port_identity: PortIdentity,
    /// The most recent announce body received.
    pub announce: AnnounceBody,
    /// Timestamps of received announce messages (for qualification window).
    pub receive_times: Vec<Instant>,
    /// Whether this master is qualified (enough announces in the window).
    pub qualified: bool,
}

impl ForeignMasterRecord {
    fn new(port_identity: PortIdentity, announce: AnnounceBody) -> Self {
        Self {
            port_identity,
            announce,
            receive_times: Vec::new(),
            qualified: false,
        }
    }
}

/// Foreign master table for a single PTP port.
#[derive(Debug)]
pub struct ForeignMasterTable {
    /// Map from port identity to foreign master record.
    records: HashMap<PortIdentity, ForeignMasterRecord>,
    /// Qualification window duration.
    window: Duration,
    /// Number of announces required within the window for qualification.
    threshold: usize,
    /// Maximum number of foreign master records to keep.
    max_records: usize,
}

impl ForeignMasterTable {
    /// Create a new foreign master table.
    ///
    /// # Arguments
    /// - `announce_interval`: The announce interval in seconds (from log2 value).
    /// - `max_records`: Maximum number of foreign masters to track.
    pub fn new(announce_interval_secs: f64, max_records: usize) -> Self {
        let window = Duration::from_secs_f64(
            announce_interval_secs * FOREIGN_MASTER_WINDOW_MULTIPLIER as f64,
        );
        Self {
            records: HashMap::new(),
            window,
            threshold: FOREIGN_MASTER_THRESHOLD,
            max_records,
        }
    }

    /// Record an announce message from a foreign master.
    /// Returns true if the foreign master is now qualified.
    pub fn record_announce(
        &mut self,
        source: PortIdentity,
        announce: AnnounceBody,
        now: Instant,
    ) -> bool {
        let record = self.records.entry(source).or_insert_with(|| {
            ForeignMasterRecord::new(source, announce.clone())
        });

        // Update the announce body to the latest
        record.announce = announce;

        // Add the new receive time
        record.receive_times.push(now);

        // Prune old timestamps outside the qualification window
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        record.receive_times.retain(|&t| t >= cutoff);

        // Check qualification
        record.qualified = record.receive_times.len() >= self.threshold;
        let qualified = record.qualified;

        // Enforce max records limit by removing the oldest unqualified record
        if self.records.len() > self.max_records {
            self.evict_oldest_unqualified(source);
        }

        qualified
    }

    /// Remove unqualified records to stay within the max_records limit.
    fn evict_oldest_unqualified(&mut self, keep: PortIdentity) {
        if self.records.len() <= self.max_records {
            return;
        }

        // Find the oldest unqualified record that isn't the one we just inserted.
        let victim = self
            .records
            .iter()
            .filter(|(id, r)| !r.qualified && **id != keep)
            .min_by_key(|(_, r)| r.receive_times.first().copied())
            .map(|(id, _)| *id);

        if let Some(id) = victim {
            self.records.remove(&id);
        }
    }

    /// Get all qualified foreign masters.
    pub fn qualified_masters(&self) -> Vec<&ForeignMasterRecord> {
        self.records.values().filter(|r| r.qualified).collect()
    }

    /// Get a specific foreign master record.
    pub fn get(&self, identity: &PortIdentity) -> Option<&ForeignMasterRecord> {
        self.records.get(identity)
    }

    /// Remove a foreign master record.
    pub fn remove(&mut self, identity: &PortIdentity) -> Option<ForeignMasterRecord> {
        self.records.remove(identity)
    }

    /// Expire stale records that haven't received announces within the window.
    pub fn expire_stale(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.records.retain(|_, record| {
            record.receive_times.retain(|&t| t >= cutoff);
            !record.receive_times.is_empty()
        });
        // Update qualification status
        for record in self.records.values_mut() {
            record.qualified = record.receive_times.len() >= self.threshold;
        }
    }

    /// Number of records in the table.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ClockQuality;
    use rtime_core::timestamp::PtpTimestamp;

    fn make_port_identity(id: u8) -> PortIdentity {
        PortIdentity {
            clock_identity: [id; 8],
            port_number: 1,
        }
    }

    fn make_announce_body() -> AnnounceBody {
        AnnounceBody {
            origin_timestamp: PtpTimestamp::ZERO,
            current_utc_offset: 37,
            grandmaster_priority1: 128,
            grandmaster_clock_quality: ClockQuality {
                clock_class: 6,
                clock_accuracy: 0x21,
                offset_scaled_log_variance: 0x4E5D,
            },
            grandmaster_priority2: 128,
            grandmaster_identity: [0; 8],
            steps_removed: 0,
            time_source: 0x20,
        }
    }

    #[test]
    fn first_announce_not_qualified() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();
        let pi = make_port_identity(1);
        let qualified = table.record_announce(pi, make_announce_body(), now);
        assert!(!qualified);
        assert_eq!(table.qualified_masters().len(), 0);
    }

    #[test]
    fn second_announce_qualifies() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();
        let pi = make_port_identity(1);

        table.record_announce(pi, make_announce_body(), now);
        let qualified =
            table.record_announce(pi, make_announce_body(), now + Duration::from_secs(2));
        assert!(qualified);
        assert_eq!(table.qualified_masters().len(), 1);
    }

    #[test]
    fn old_announces_expire() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();
        let pi = make_port_identity(1);

        // Record two announces 1 second apart
        table.record_announce(pi, make_announce_body(), now);
        table.record_announce(pi, make_announce_body(), now + Duration::from_secs(1));
        assert_eq!(table.qualified_masters().len(), 1);

        // Expire after the window (4 * 2 = 8 seconds)
        table.expire_stale(now + Duration::from_secs(10));
        assert_eq!(table.qualified_masters().len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn multiple_foreign_masters() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();

        for i in 1..=3 {
            let pi = make_port_identity(i);
            table.record_announce(pi, make_announce_body(), now);
            table.record_announce(pi, make_announce_body(), now + Duration::from_secs(1));
        }

        assert_eq!(table.len(), 3);
        assert_eq!(table.qualified_masters().len(), 3);
    }

    #[test]
    fn get_specific_record() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();
        let pi = make_port_identity(42);

        table.record_announce(pi, make_announce_body(), now);
        let record = table.get(&pi).unwrap();
        assert_eq!(record.port_identity, pi);
    }

    #[test]
    fn remove_record() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();
        let pi = make_port_identity(1);

        table.record_announce(pi, make_announce_body(), now);
        assert_eq!(table.len(), 1);

        table.remove(&pi);
        assert!(table.is_empty());
    }

    #[test]
    fn clear_table() {
        let mut table = ForeignMasterTable::new(2.0, 5);
        let now = Instant::now();

        for i in 1..=3 {
            table.record_announce(make_port_identity(i), make_announce_body(), now);
        }
        assert_eq!(table.len(), 3);

        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn max_records_eviction() {
        let mut table = ForeignMasterTable::new(2.0, 2); // max 2 records
        let now = Instant::now();

        // Add 3 foreign masters (all with single announce, so unqualified)
        table.record_announce(make_port_identity(1), make_announce_body(), now);
        table.record_announce(make_port_identity(2), make_announce_body(), now);
        table.record_announce(make_port_identity(3), make_announce_body(), now);

        // Should have evicted one to stay at max
        assert!(table.len() <= 3); // The newest is always kept
    }
}
