//! NTS-KE record types (RFC 8915 Section 4).
//!
//! Each record is encoded as:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|         Record Type         |        Body Length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                          Body Data                            .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::NtsError;

/// NTS-KE record header size (4 bytes: critical+type + body_length).
const RECORD_HEADER_SIZE: usize = 4;

/// NTS-KE record types per RFC 8915 Section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    EndOfMessage = 0,
    NextProtocol = 1,
    Error = 2,
    Warning = 3,
    AeadAlgorithm = 4,
    NewCookieForNtpv4 = 5,
    NtpV4ServerNegotiation = 6,
    NtpV4PortNegotiation = 7,
}

impl RecordType {
    pub fn from_u16(val: u16) -> Result<Self, NtsError> {
        match val {
            0 => Ok(Self::EndOfMessage),
            1 => Ok(Self::NextProtocol),
            2 => Ok(Self::Error),
            3 => Ok(Self::Warning),
            4 => Ok(Self::AeadAlgorithm),
            5 => Ok(Self::NewCookieForNtpv4),
            6 => Ok(Self::NtpV4ServerNegotiation),
            7 => Ok(Self::NtpV4PortNegotiation),
            other => Err(NtsError::UnknownRecordType(other)),
        }
    }
}

/// A single NTS-KE record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtsKeRecord {
    /// Whether the critical bit is set. If set, an unrecognized record type
    /// causes the connection to be aborted.
    pub critical: bool,
    /// The record type.
    pub record_type: RecordType,
    /// The record body (variable length).
    pub body: Vec<u8>,
}

impl NtsKeRecord {
    /// Create a new record.
    pub fn new(critical: bool, record_type: RecordType, body: Vec<u8>) -> Self {
        Self {
            critical,
            record_type,
            body,
        }
    }

    /// Create an End of Message record (always critical).
    pub fn end_of_message() -> Self {
        Self::new(true, RecordType::EndOfMessage, Vec::new())
    }

    /// Create a Next Protocol record (always critical). Body contains one or more
    /// 16-bit protocol IDs.
    pub fn next_protocol(protocol_ids: &[u16]) -> Self {
        let mut body = Vec::with_capacity(protocol_ids.len() * 2);
        for &id in protocol_ids {
            body.extend_from_slice(&id.to_be_bytes());
        }
        Self::new(true, RecordType::NextProtocol, body)
    }

    /// Create an AEAD Algorithm record (not critical). Body contains one or more
    /// 16-bit AEAD algorithm identifiers.
    pub fn aead_algorithm(algorithms: &[u16]) -> Self {
        let mut body = Vec::with_capacity(algorithms.len() * 2);
        for &alg in algorithms {
            body.extend_from_slice(&alg.to_be_bytes());
        }
        Self::new(false, RecordType::AeadAlgorithm, body)
    }

    /// Create a New Cookie for NTPv4 record.
    pub fn new_cookie(cookie: Vec<u8>) -> Self {
        Self::new(false, RecordType::NewCookieForNtpv4, cookie)
    }

    /// Create an Error record (always critical).
    pub fn error(error_code: u16) -> Self {
        Self::new(true, RecordType::Error, error_code.to_be_bytes().to_vec())
    }

    /// Create a Warning record.
    pub fn warning(warning_code: u16) -> Self {
        Self::new(false, RecordType::Warning, warning_code.to_be_bytes().to_vec())
    }

    /// Create a Server Negotiation record.
    pub fn server_negotiation(server: &str) -> Self {
        Self::new(false, RecordType::NtpV4ServerNegotiation, server.as_bytes().to_vec())
    }

    /// Create a Port Negotiation record.
    pub fn port_negotiation(port: u16) -> Self {
        Self::new(false, RecordType::NtpV4PortNegotiation, port.to_be_bytes().to_vec())
    }

    /// Serialize this record into wire format bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let body_len = self.body.len() as u16;
        let type_val = self.record_type as u16;
        let first_word = if self.critical {
            type_val | 0x8000 // Set the critical bit (bit 15)
        } else {
            type_val
        };

        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + self.body.len());
        buf.extend_from_slice(&first_word.to_be_bytes());
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Parse a single record from the given data. Returns the record and the
    /// number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), NtsError> {
        if data.len() < RECORD_HEADER_SIZE {
            return Err(NtsError::RecordTooShort {
                expected: RECORD_HEADER_SIZE,
                got: data.len(),
            });
        }

        let type_word = u16::from_be_bytes([data[0], data[1]]);
        let critical = (type_word & 0x8000) != 0;
        let record_type_val = type_word & 0x7FFF;
        let record_type = RecordType::from_u16(record_type_val)?;

        let body_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < RECORD_HEADER_SIZE + body_length {
            return Err(NtsError::InvalidBodyLength {
                declared: body_length,
                available: data.len() - RECORD_HEADER_SIZE,
            });
        }

        let body = data[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + body_length].to_vec();
        let total_consumed = RECORD_HEADER_SIZE + body_length;

        Ok((
            Self {
                critical,
                record_type,
                body,
            },
            total_consumed,
        ))
    }

    /// Parse all records from the given data.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, NtsError> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let (record, consumed) = Self::parse(&data[offset..])?;
            let is_end = record.record_type == RecordType::EndOfMessage;
            records.push(record);
            offset += consumed;

            if is_end {
                break;
            }
        }

        Ok(records)
    }

    /// Extract protocol IDs from a NextProtocol record body.
    pub fn protocol_ids(&self) -> Vec<u16> {
        self.body
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    /// Extract AEAD algorithm IDs from an AeadAlgorithm record body.
    pub fn algorithm_ids(&self) -> Vec<u16> {
        self.body
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_end_of_message() {
        let record = NtsKeRecord::end_of_message();
        let bytes = record.serialize();

        // Critical bit set, type=0, body_length=0
        assert_eq!(&bytes[0..2], &0x8000u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &0x0000u16.to_be_bytes());

        let (parsed, consumed) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(parsed, record);
    }

    #[test]
    fn roundtrip_next_protocol() {
        let record = NtsKeRecord::next_protocol(&[0]); // NTPv4
        let bytes = record.serialize();

        let (parsed, consumed) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 6); // 4 header + 2 body
        assert_eq!(parsed, record);
        assert!(parsed.critical);
        assert_eq!(parsed.record_type, RecordType::NextProtocol);
        assert_eq!(parsed.protocol_ids(), vec![0]);
    }

    #[test]
    fn roundtrip_aead_algorithm() {
        let record = NtsKeRecord::aead_algorithm(&[15]); // AEAD_AES_SIV_CMAC_256
        let bytes = record.serialize();

        let (parsed, consumed) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(parsed, record);
        assert!(!parsed.critical);
        assert_eq!(parsed.algorithm_ids(), vec![15]);
    }

    #[test]
    fn roundtrip_cookie() {
        let cookie_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let record = NtsKeRecord::new_cookie(cookie_data.clone());
        let bytes = record.serialize();

        let (parsed, consumed) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 4 + 8);
        assert_eq!(parsed.body, cookie_data);
    }

    #[test]
    fn roundtrip_error() {
        let record = NtsKeRecord::error(1); // Unrecognized critical record
        let bytes = record.serialize();

        let (parsed, _) = NtsKeRecord::parse(&bytes).unwrap();
        assert!(parsed.critical);
        assert_eq!(parsed.record_type, RecordType::Error);
        assert_eq!(
            u16::from_be_bytes([parsed.body[0], parsed.body[1]]),
            1
        );
    }

    #[test]
    fn roundtrip_server_negotiation() {
        let record = NtsKeRecord::server_negotiation("ntp.example.com");
        let bytes = record.serialize();

        let (parsed, _) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, RecordType::NtpV4ServerNegotiation);
        assert_eq!(
            std::str::from_utf8(&parsed.body).unwrap(),
            "ntp.example.com"
        );
    }

    #[test]
    fn roundtrip_port_negotiation() {
        let record = NtsKeRecord::port_negotiation(123);
        let bytes = record.serialize();

        let (parsed, _) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, RecordType::NtpV4PortNegotiation);
        assert_eq!(
            u16::from_be_bytes([parsed.body[0], parsed.body[1]]),
            123
        );
    }

    #[test]
    fn parse_all_records() {
        // Simulate a typical server response
        let mut data = Vec::new();
        data.extend_from_slice(&NtsKeRecord::next_protocol(&[0]).serialize());
        data.extend_from_slice(&NtsKeRecord::aead_algorithm(&[15]).serialize());
        data.extend_from_slice(&NtsKeRecord::new_cookie(vec![1, 2, 3, 4]).serialize());
        data.extend_from_slice(&NtsKeRecord::new_cookie(vec![5, 6, 7, 8]).serialize());
        data.extend_from_slice(&NtsKeRecord::end_of_message().serialize());

        let records = NtsKeRecord::parse_all(&data).unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].record_type, RecordType::NextProtocol);
        assert_eq!(records[1].record_type, RecordType::AeadAlgorithm);
        assert_eq!(records[2].record_type, RecordType::NewCookieForNtpv4);
        assert_eq!(records[3].record_type, RecordType::NewCookieForNtpv4);
        assert_eq!(records[4].record_type, RecordType::EndOfMessage);
    }

    #[test]
    fn parse_too_short() {
        let data = [0u8; 2];
        assert!(NtsKeRecord::parse(&data).is_err());
    }

    #[test]
    fn parse_body_length_exceeds_data() {
        // Header says body is 100 bytes but we only have 4 bytes of header
        let data = [0x00, 0x01, 0x00, 0x64]; // type=1, body_length=100
        assert!(NtsKeRecord::parse(&data).is_err());
    }

    #[test]
    fn parse_unknown_record_type() {
        let data = [0x00, 0xFF, 0x00, 0x00]; // type=255
        assert!(NtsKeRecord::parse(&data).is_err());
    }

    #[test]
    fn multiple_algorithms() {
        let record = NtsKeRecord::aead_algorithm(&[15, 16, 17]);
        let bytes = record.serialize();

        let (parsed, _) = NtsKeRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.algorithm_ids(), vec![15, 16, 17]);
    }

    #[test]
    fn critical_bit_encoding() {
        // Non-critical record
        let record = NtsKeRecord::new(false, RecordType::AeadAlgorithm, vec![0, 15]);
        let bytes = record.serialize();
        assert_eq!(bytes[0] & 0x80, 0x00); // Critical bit not set

        // Critical record
        let record = NtsKeRecord::new(true, RecordType::NextProtocol, vec![0, 0]);
        let bytes = record.serialize();
        assert_eq!(bytes[0] & 0x80, 0x80); // Critical bit set
    }

    #[test]
    fn parse_all_stops_at_end_of_message() {
        let mut data = Vec::new();
        data.extend_from_slice(&NtsKeRecord::next_protocol(&[0]).serialize());
        data.extend_from_slice(&NtsKeRecord::end_of_message().serialize());
        // Extra garbage after EndOfMessage
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let records = NtsKeRecord::parse_all(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].record_type, RecordType::EndOfMessage);
    }
}
