//! PTP port state machine (IEEE 1588-2019 Section 9.2).
//!
//! A PTP port transitions between states based on the BMCA result,
//! management commands, and protocol events.

use crate::bmca::BmcaResult;
use crate::message::PortIdentity;

/// PTP port states per IEEE 1588-2019 Section 9.2.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port has just been created, waiting for initialization.
    Initializing,
    /// Waiting for announce messages from other clocks.
    Listening,
    /// This port's clock is the grandmaster; sending Sync/Announce.
    Master,
    /// This port is synchronized to a remote master.
    Slave,
    /// Port is not master or slave (another port on this node is slave).
    Passive,
    /// Port is administratively disabled.
    Disabled,
}

/// Events that trigger port state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortEvent {
    /// Initialization complete.
    InitComplete,
    /// BMCA determined this clock is the best master.
    BmcaThisBetter,
    /// BMCA determined another clock is the best master.
    BmcaOtherBetter,
    /// Another port on this clock is already slave; this port should be passive.
    BmcaTopologyPassive,
    /// Announce receipt timeout expired (no announces received).
    AnnounceReceiptTimeout,
    /// Administrative disable command.
    Disable,
    /// Administrative enable command.
    Enable,
    /// Fault detected.
    Fault,
    /// Fault cleared.
    FaultCleared,
}

/// Configuration for a PTP port.
#[derive(Debug, Clone)]
pub struct PortConfig {
    /// The identity of this port.
    pub port_identity: PortIdentity,
    /// PTP domain number.
    pub domain_number: u8,
    /// Log2 of the announce interval in seconds (e.g., 1 => 2s).
    pub log_announce_interval: i8,
    /// Number of announce intervals before timeout.
    pub announce_receipt_timeout: u8,
    /// Log2 of the sync interval in seconds (e.g., 0 => 1s).
    pub log_sync_interval: i8,
    /// Log2 of the min delay request interval (e.g., 0 => 1s).
    pub log_min_delay_req_interval: i8,
    /// Whether to use two-step mode (FollowUp messages).
    pub two_step: bool,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            port_identity: PortIdentity::ZERO,
            domain_number: 0,
            log_announce_interval: 1,      // 2 seconds
            announce_receipt_timeout: 3,    // 3 intervals
            log_sync_interval: 0,          // 1 second
            log_min_delay_req_interval: 0, // 1 second
            two_step: true,
        }
    }
}

/// PTP port state machine.
#[derive(Debug)]
pub struct PtpPort {
    pub config: PortConfig,
    pub state: PortState,
    /// Sequence ID counter for Sync messages.
    pub sync_sequence_id: u16,
    /// Sequence ID counter for Delay_Req messages.
    pub delay_req_sequence_id: u16,
    /// Sequence ID counter for Announce messages.
    pub announce_sequence_id: u16,
    /// The best master port identity if in Slave state.
    pub master_identity: Option<PortIdentity>,
}

impl PtpPort {
    pub fn new(config: PortConfig) -> Self {
        Self {
            config,
            state: PortState::Initializing,
            sync_sequence_id: 0,
            delay_req_sequence_id: 0,
            announce_sequence_id: 0,
            master_identity: None,
        }
    }

    /// Process a port event and transition to the new state.
    /// Returns the new state after the transition.
    pub fn handle_event(&mut self, event: PortEvent) -> PortState {
        let new_state = self.next_state(event);
        if new_state != self.state {
            // Clear master identity when leaving Slave state
            if self.state == PortState::Slave && new_state != PortState::Slave {
                self.master_identity = None;
            }
            self.state = new_state;
        }
        self.state
    }

    /// Compute the next state given the current state and an event.
    fn next_state(&self, event: PortEvent) -> PortState {
        match (self.state, event) {
            // From Initializing
            (PortState::Initializing, PortEvent::InitComplete) => PortState::Listening,
            (PortState::Initializing, PortEvent::Disable) => PortState::Disabled,

            // From Listening
            (PortState::Listening, PortEvent::BmcaThisBetter) => PortState::Master,
            (PortState::Listening, PortEvent::BmcaOtherBetter) => PortState::Slave,
            (PortState::Listening, PortEvent::BmcaTopologyPassive) => PortState::Passive,
            (PortState::Listening, PortEvent::AnnounceReceiptTimeout) => PortState::Master,
            (PortState::Listening, PortEvent::Disable) => PortState::Disabled,

            // From Master
            (PortState::Master, PortEvent::BmcaOtherBetter) => PortState::Slave,
            (PortState::Master, PortEvent::BmcaTopologyPassive) => PortState::Passive,
            (PortState::Master, PortEvent::Disable) => PortState::Disabled,
            (PortState::Master, PortEvent::Fault) => PortState::Listening,

            // From Slave
            (PortState::Slave, PortEvent::BmcaThisBetter) => PortState::Master,
            (PortState::Slave, PortEvent::BmcaTopologyPassive) => PortState::Passive,
            (PortState::Slave, PortEvent::AnnounceReceiptTimeout) => PortState::Master,
            (PortState::Slave, PortEvent::Disable) => PortState::Disabled,
            (PortState::Slave, PortEvent::Fault) => PortState::Listening,

            // From Passive
            (PortState::Passive, PortEvent::BmcaThisBetter) => PortState::Master,
            (PortState::Passive, PortEvent::BmcaOtherBetter) => PortState::Slave,
            (PortState::Passive, PortEvent::AnnounceReceiptTimeout) => PortState::Master,
            (PortState::Passive, PortEvent::Disable) => PortState::Disabled,
            (PortState::Passive, PortEvent::Fault) => PortState::Listening,

            // From Disabled
            (PortState::Disabled, PortEvent::Enable) => PortState::Initializing,

            // All other transitions: stay in current state
            _ => self.state,
        }
    }

    /// Apply a BMCA result to determine the appropriate event and transition.
    pub fn apply_bmca(&mut self, result: BmcaResult, has_other_slave: bool) -> PortState {
        let event = match result {
            BmcaResult::ThisBetter => PortEvent::BmcaThisBetter,
            BmcaResult::OtherBetter => {
                if has_other_slave {
                    PortEvent::BmcaTopologyPassive
                } else {
                    PortEvent::BmcaOtherBetter
                }
            }
            BmcaResult::Equal => PortEvent::BmcaThisBetter,
        };
        self.handle_event(event)
    }

    /// Get the next Sync sequence ID and increment.
    pub fn next_sync_seq(&mut self) -> u16 {
        let seq = self.sync_sequence_id;
        self.sync_sequence_id = self.sync_sequence_id.wrapping_add(1);
        seq
    }

    /// Get the next Delay_Req sequence ID and increment.
    pub fn next_delay_req_seq(&mut self) -> u16 {
        let seq = self.delay_req_sequence_id;
        self.delay_req_sequence_id = self.delay_req_sequence_id.wrapping_add(1);
        seq
    }

    /// Get the next Announce sequence ID and increment.
    pub fn next_announce_seq(&mut self) -> u16 {
        let seq = self.announce_sequence_id;
        self.announce_sequence_id = self.announce_sequence_id.wrapping_add(1);
        seq
    }

    /// Compute the announce interval in seconds from the log value.
    pub fn announce_interval_secs(&self) -> f64 {
        2.0_f64.powi(self.config.log_announce_interval as i32)
    }

    /// Compute the sync interval in seconds from the log value.
    pub fn sync_interval_secs(&self) -> f64 {
        2.0_f64.powi(self.config.log_sync_interval as i32)
    }

    /// Compute the announce receipt timeout duration in seconds.
    pub fn announce_receipt_timeout_secs(&self) -> f64 {
        self.announce_interval_secs() * self.config.announce_receipt_timeout as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_port() -> PtpPort {
        PtpPort::new(PortConfig::default())
    }

    #[test]
    fn initial_state_is_initializing() {
        let port = default_port();
        assert_eq!(port.state, PortState::Initializing);
    }

    #[test]
    fn init_to_listening() {
        let mut port = default_port();
        let s = port.handle_event(PortEvent::InitComplete);
        assert_eq!(s, PortState::Listening);
    }

    #[test]
    fn listening_to_master_on_bmca_this_better() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        let s = port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(s, PortState::Master);
    }

    #[test]
    fn listening_to_slave_on_bmca_other_better() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        let s = port.handle_event(PortEvent::BmcaOtherBetter);
        assert_eq!(s, PortState::Slave);
    }

    #[test]
    fn listening_to_master_on_announce_timeout() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        let s = port.handle_event(PortEvent::AnnounceReceiptTimeout);
        assert_eq!(s, PortState::Master);
    }

    #[test]
    fn slave_to_master_on_bmca_this_better() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaOtherBetter);
        assert_eq!(port.state, PortState::Slave);
        let s = port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(s, PortState::Master);
    }

    #[test]
    fn master_to_slave_on_bmca_other_better() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(port.state, PortState::Master);
        let s = port.handle_event(PortEvent::BmcaOtherBetter);
        assert_eq!(s, PortState::Slave);
    }

    #[test]
    fn slave_to_master_on_announce_timeout() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaOtherBetter);
        assert_eq!(port.state, PortState::Slave);
        let s = port.handle_event(PortEvent::AnnounceReceiptTimeout);
        assert_eq!(s, PortState::Master);
    }

    #[test]
    fn disable_from_any_state() {
        for initial_event in [
            None,
            Some(PortEvent::InitComplete),
        ] {
            let mut port = default_port();
            if let Some(evt) = initial_event {
                port.handle_event(evt);
            }
            let s = port.handle_event(PortEvent::Disable);
            assert_eq!(s, PortState::Disabled);
        }
    }

    #[test]
    fn enable_from_disabled() {
        let mut port = default_port();
        port.handle_event(PortEvent::Disable);
        assert_eq!(port.state, PortState::Disabled);
        let s = port.handle_event(PortEvent::Enable);
        assert_eq!(s, PortState::Initializing);
    }

    #[test]
    fn passive_state_transitions() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaTopologyPassive);
        assert_eq!(port.state, PortState::Passive);

        // Passive -> Master on this-better
        let s = port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(s, PortState::Master);
    }

    #[test]
    fn apply_bmca_with_other_slave() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        // When another port is already slave, OtherBetter -> Passive
        let s = port.apply_bmca(BmcaResult::OtherBetter, true);
        assert_eq!(s, PortState::Passive);
    }

    #[test]
    fn apply_bmca_without_other_slave() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        // When no other port is slave, OtherBetter -> Slave
        let s = port.apply_bmca(BmcaResult::OtherBetter, false);
        assert_eq!(s, PortState::Slave);
    }

    #[test]
    fn sequence_id_wrapping() {
        let mut port = default_port();
        port.sync_sequence_id = u16::MAX;
        assert_eq!(port.next_sync_seq(), u16::MAX);
        assert_eq!(port.next_sync_seq(), 0);
    }

    #[test]
    fn interval_calculations() {
        let port = default_port();
        // log_announce_interval = 1 => 2^1 = 2 seconds
        assert!((port.announce_interval_secs() - 2.0).abs() < 1e-9);
        // log_sync_interval = 0 => 2^0 = 1 second
        assert!((port.sync_interval_secs() - 1.0).abs() < 1e-9);
        // timeout = 2 * 3 = 6 seconds
        assert!((port.announce_receipt_timeout_secs() - 6.0).abs() < 1e-9);
    }

    #[test]
    fn fault_returns_to_listening() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(port.state, PortState::Master);
        let s = port.handle_event(PortEvent::Fault);
        assert_eq!(s, PortState::Listening);
    }

    #[test]
    fn master_identity_cleared_on_leave_slave() {
        let mut port = default_port();
        port.handle_event(PortEvent::InitComplete);
        port.handle_event(PortEvent::BmcaOtherBetter);
        assert_eq!(port.state, PortState::Slave);
        port.master_identity = Some(PortIdentity {
            clock_identity: [1; 8],
            port_number: 1,
        });
        port.handle_event(PortEvent::BmcaThisBetter);
        assert_eq!(port.state, PortState::Master);
        assert!(port.master_identity.is_none());
    }
}
