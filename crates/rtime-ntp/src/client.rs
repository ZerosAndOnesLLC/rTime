use rtime_core::clock::LeapIndicator;
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

use crate::kiss_code::KissCode;
use crate::packet::{NtpMode, NtpPacket};

/// Result of processing an NTP server response.
#[derive(Debug, Clone)]
pub struct NtpResult {
    /// Estimated clock offset: positive means local clock is behind.
    pub offset: NtpDuration,
    /// Round-trip network delay.
    pub delay: NtpDuration,
    /// Server stratum.
    pub stratum: u8,
    /// Server leap indicator.
    pub leap_indicator: LeapIndicator,
    /// Server root delay.
    pub root_delay: NtpDuration,
    /// Server root dispersion.
    pub root_dispersion: NtpDuration,
    /// Server reference ID.
    pub reference_id: u32,
    /// Server precision (log2 seconds).
    pub precision: i8,
}

/// Errors when processing a server response.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("response is not server mode")]
    NotServerResponse,

    #[error("origin timestamp mismatch (possible spoofing)")]
    OriginMismatch,

    #[error("server sent zero transmit timestamp")]
    ZeroTransmit,

    #[error("Kiss-o'-Death received: {0:?}")]
    KissOfDeath(KissCode),
}

/// Build a client request packet.
///
/// The transmit timestamp is used as a cookie to match responses.
/// For security, use a random value rather than the actual time
/// (the real time is recorded separately for offset computation).
pub fn build_request(cookie: NtpTimestamp) -> NtpPacket {
    NtpPacket::new_client_request(cookie)
}

/// Process a server response and compute offset/delay.
///
/// Uses the standard NTP offset formula:
///   offset = ((T2 - T1) + (T3 - T4)) / 2
///   delay  = (T4 - T1) - (T3 - T2)
///
/// Where:
///   T1 = client transmit time (origin)
///   T2 = server receive time
///   T3 = server transmit time
///   T4 = client receive time
pub fn process_response(
    response: &NtpPacket,
    t1: NtpTimestamp,
    t4: NtpTimestamp,
    origin_cookie: NtpTimestamp,
) -> Result<NtpResult, ClientError> {
    // Validate response
    if response.mode != NtpMode::Server {
        return Err(ClientError::NotServerResponse);
    }

    // The server echoes our transmit timestamp in origin_ts
    if response.origin_ts != origin_cookie {
        return Err(ClientError::OriginMismatch);
    }

    if response.transmit_ts == NtpTimestamp::ZERO {
        return Err(ClientError::ZeroTransmit);
    }

    // Check for Kiss-o'-Death (stratum 0)
    if response.stratum == 0 {
        let kod = KissCode::from_reference_id(response.reference_id);
        return Err(ClientError::KissOfDeath(kod));
    }

    let t2 = response.receive_ts;
    let t3 = response.transmit_ts;

    // offset = ((T2 - T1) + (T3 - T4)) / 2
    let a = NtpDuration::between(t1, t2);
    let b = NtpDuration::between(t4, t3);
    let offset = (a + b) / 2;

    // delay = (T4 - T1) - (T3 - T2)
    let round_trip = NtpDuration::between(t1, t4);
    let server_processing = NtpDuration::between(t2, t3);
    let delay = round_trip - server_processing;

    Ok(NtpResult {
        offset,
        delay,
        stratum: response.stratum,
        leap_indicator: response.leap_indicator,
        root_delay: NtpDuration::from_ntp_short(response.root_delay),
        root_dispersion: NtpDuration::from_ntp_short(response.root_dispersion),
        reference_id: response.reference_id,
        precision: response.precision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_basic() {
        let cookie = NtpTimestamp::new(1000, 0);
        let pkt = build_request(cookie);
        assert_eq!(pkt.mode, NtpMode::Client);
        assert_eq!(pkt.transmit_ts, cookie);
    }

    #[test]
    fn process_response_computes_offset() {
        // Simulate: client is 100ms behind server
        let t1 = NtpTimestamp::new(1000, 0); // client transmit
        let t2 = NtpTimestamp::new(1000, 429496730); // server receive (~0.1s later)
        let t3 = NtpTimestamp::new(1000, 429496730); // server transmit (instant)
        let t4 = NtpTimestamp::new(1000, 0); // client receive (instant network for simplicity)

        let cookie = t1;
        let response = NtpPacket {
            leap_indicator: LeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Server,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: u32::from_be_bytes(*b"GPS\0"),
            reference_ts: NtpTimestamp::new(999, 0),
            origin_ts: cookie,
            receive_ts: t2,
            transmit_ts: t3,
        };

        let result = process_response(&response, t1, t4, cookie).unwrap();

        // offset should be ~100ms (positive = local clock behind)
        let offset_ms = result.offset.to_millis_f64();
        assert!(
            offset_ms.abs() > 50.0 && offset_ms.abs() < 200.0,
            "offset: {}ms",
            offset_ms
        );
    }

    #[test]
    fn process_response_rejects_wrong_origin() {
        let cookie = NtpTimestamp::new(1000, 0);
        let response = NtpPacket {
            leap_indicator: LeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Server,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_ts: NtpTimestamp::ZERO,
            origin_ts: NtpTimestamp::new(9999, 0), // wrong!
            receive_ts: NtpTimestamp::new(1000, 0),
            transmit_ts: NtpTimestamp::new(1000, 0),
        };

        let result = process_response(
            &response,
            NtpTimestamp::new(1000, 0),
            NtpTimestamp::new(1000, 0),
            cookie,
        );
        assert!(matches!(result, Err(ClientError::OriginMismatch)));
    }

    #[test]
    fn process_response_rejects_kod() {
        let cookie = NtpTimestamp::new(1000, 0);
        let response = NtpPacket {
            leap_indicator: LeapIndicator::AlarmUnsynchronized,
            version: 4,
            mode: NtpMode::Server,
            stratum: 0, // KoD
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: u32::from_be_bytes(*b"RATE"),
            reference_ts: NtpTimestamp::ZERO,
            origin_ts: cookie,
            receive_ts: NtpTimestamp::ZERO,
            transmit_ts: NtpTimestamp::new(1000, 0),
        };

        let result = process_response(
            &response,
            NtpTimestamp::new(1000, 0),
            NtpTimestamp::new(1000, 0),
            cookie,
        );
        assert!(matches!(result, Err(ClientError::KissOfDeath(KissCode::Rate))));
    }
}
