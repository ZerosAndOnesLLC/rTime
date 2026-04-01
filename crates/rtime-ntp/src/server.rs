use rtime_core::clock::LeapIndicator;
use rtime_core::timestamp::NtpTimestamp;

use crate::packet::{NtpMode, NtpPacket, NTP_VERSION};

/// Server-side state used to populate response fields.
#[derive(Debug, Clone)]
pub struct ServerState {
    pub stratum: u8,
    pub reference_id: u32,
    pub reference_ts: NtpTimestamp,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub leap_indicator: LeapIndicator,
    pub precision: i8,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            stratum: 16, // unsynchronized
            reference_id: 0,
            reference_ts: NtpTimestamp::ZERO,
            root_delay: 0,
            root_dispersion: 0,
            leap_indicator: LeapIndicator::AlarmUnsynchronized,
            precision: -20,
        }
    }
}

/// Errors when validating an incoming client request.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("request mode is not Client (mode={0:?})")]
    NotClientRequest(NtpMode),

    #[error("unsupported NTP version: {0}")]
    UnsupportedVersion(u8),

    #[error("transmit timestamp is zero")]
    ZeroTransmit,
}

/// Validate an incoming NTP request packet.
///
/// Checks:
/// - Mode must be Client (3)
/// - Version must be 3 or 4
/// - Transmit timestamp must not be zero
pub fn validate_request(packet: &NtpPacket) -> Result<(), ServerError> {
    if packet.mode != NtpMode::Client {
        return Err(ServerError::NotClientRequest(packet.mode));
    }

    if !(3..=4).contains(&packet.version) {
        return Err(ServerError::UnsupportedVersion(packet.version));
    }

    if packet.transmit_ts == NtpTimestamp::ZERO {
        return Err(ServerError::ZeroTransmit);
    }

    Ok(())
}

/// Build an NTP server response from a validated client request.
///
/// The response:
/// - Sets mode to Server (4)
/// - Copies the request's transmit_ts into origin_ts (so client can match)
/// - Sets receive_ts and transmit_ts from the provided timestamps
/// - Fills in server state fields (stratum, reference_id, etc.)
/// - Sets version to 4
/// - Copies the client's poll interval
pub fn build_response(
    request: &NtpPacket,
    receive_ts: NtpTimestamp,
    transmit_ts: NtpTimestamp,
    server_state: &ServerState,
) -> NtpPacket {
    NtpPacket {
        leap_indicator: server_state.leap_indicator,
        version: NTP_VERSION,
        mode: NtpMode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_ts: server_state.reference_ts,
        origin_ts: request.transmit_ts,
        receive_ts,
        transmit_ts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client;

    fn test_server_state() -> ServerState {
        ServerState {
            stratum: 1,
            reference_id: u32::from_be_bytes(*b"GPS\0"),
            reference_ts: NtpTimestamp::new(3_900_000_000, 0),
            root_delay: 0,
            root_dispersion: 0x0001_0000, // ~15us in NTP short format
            leap_indicator: LeapIndicator::NoWarning,
            precision: -20,
        }
    }

    #[test]
    fn roundtrip_client_server() {
        let state = test_server_state();

        // T1: client transmit time (also used as cookie)
        let t1 = NtpTimestamp::new(3_900_000_100, 0);
        let cookie = t1;
        let request = client::build_request(cookie);

        // Validate the request
        validate_request(&request).expect("valid client request");

        // T2: server receive time (small network delay simulated)
        let t2 = NtpTimestamp::new(3_900_000_100, 100_000);
        // T3: server transmit time (tiny processing delay)
        let t3 = NtpTimestamp::new(3_900_000_100, 110_000);

        let response = build_response(&request, t2, t3, &state);

        // Verify response structure
        assert_eq!(response.mode, NtpMode::Server);
        assert_eq!(response.version, NTP_VERSION);
        assert_eq!(response.stratum, state.stratum);
        assert_eq!(response.origin_ts, cookie);
        assert_eq!(response.receive_ts, t2);
        assert_eq!(response.transmit_ts, t3);
        assert_eq!(response.reference_id, state.reference_id);
        assert_eq!(response.leap_indicator, LeapIndicator::NoWarning);

        // Serialize/deserialize roundtrip
        let wire = response.serialize();
        let parsed = NtpPacket::parse(&wire).expect("parse response");
        assert_eq!(parsed, response);

        // T4: client receive time
        let t4 = NtpTimestamp::new(3_900_000_100, 210_000);

        // Client processes the response
        let result = client::process_response(&parsed, t1, t4, cookie)
            .expect("process response");

        assert_eq!(result.stratum, 1);
        assert_eq!(result.leap_indicator, LeapIndicator::NoWarning);
        // Delay should be positive
        assert!(result.delay.to_nanos() >= 0, "delay should be non-negative");
    }

    #[test]
    fn validate_rejects_wrong_mode() {
        let mut pkt = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        pkt.mode = NtpMode::Server;

        let err = validate_request(&pkt).unwrap_err();
        assert!(
            matches!(err, ServerError::NotClientRequest(NtpMode::Server)),
            "expected NotClientRequest, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_zero_transmit() {
        let mut pkt = NtpPacket::new_client_request(NtpTimestamp::ZERO);
        // Force transmit_ts to zero (new_client_request already sets it, but be explicit)
        pkt.transmit_ts = NtpTimestamp::ZERO;

        let err = validate_request(&pkt).unwrap_err();
        assert!(
            matches!(err, ServerError::ZeroTransmit),
            "expected ZeroTransmit, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut pkt = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        pkt.version = 2;

        let err = validate_request(&pkt).unwrap_err();
        assert!(
            matches!(err, ServerError::UnsupportedVersion(2)),
            "expected UnsupportedVersion(2), got: {err:?}"
        );
    }

    #[test]
    fn validate_accepts_version_3() {
        let mut pkt = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        pkt.version = 3;
        validate_request(&pkt).expect("version 3 should be accepted");
    }

    #[test]
    fn validate_accepts_version_4() {
        let pkt = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        assert_eq!(pkt.version, 4);
        validate_request(&pkt).expect("version 4 should be accepted");
    }

    #[test]
    fn response_copies_client_poll() {
        let state = test_server_state();
        let mut request = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        request.poll = 10; // 1024 seconds

        let response = build_response(
            &request,
            NtpTimestamp::new(1000, 100),
            NtpTimestamp::new(1000, 200),
            &state,
        );

        assert_eq!(response.poll, 10);
    }
}
