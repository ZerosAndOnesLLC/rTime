//! Type-Length-Value (TLV) parsing for PTP messages (IEEE 1588-2019 Section 14).
//!
//! TLVs appear at the end of PTP messages (after the message body) to carry
//! optional extensions like path trace, authentication, and organization-specific data.

/// Well-known TLV type values (IEEE 1588-2019 Table 52).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlvType {
    /// Management TLV.
    Management = 0x0001,
    /// Management error status.
    ManagementErrorStatus = 0x0002,
    /// Organization extension.
    OrganizationExtension = 0x0003,
    /// Request unicast transmission.
    RequestUnicastTransmission = 0x0004,
    /// Grant unicast transmission.
    GrantUnicastTransmission = 0x0005,
    /// Cancel unicast transmission.
    CancelUnicastTransmission = 0x0006,
    /// Acknowledge cancel unicast transmission.
    AcknowledgeCancelUnicastTransmission = 0x0007,
    /// Path trace (list of clock identities along the path).
    PathTrace = 0x0008,
    /// Alternate time offset indicator.
    AlternateTimeOffsetIndicator = 0x0009,
    /// Authentication TLV (IEEE 1588-2019 Section 14.4).
    Authentication = 0x8000,
    /// Padding TLV.
    Pad = 0x8008,
}

impl TlvType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Self::Management),
            0x0002 => Some(Self::ManagementErrorStatus),
            0x0003 => Some(Self::OrganizationExtension),
            0x0004 => Some(Self::RequestUnicastTransmission),
            0x0005 => Some(Self::GrantUnicastTransmission),
            0x0006 => Some(Self::CancelUnicastTransmission),
            0x0007 => Some(Self::AcknowledgeCancelUnicastTransmission),
            0x0008 => Some(Self::PathTrace),
            0x0009 => Some(Self::AlternateTimeOffsetIndicator),
            0x8000 => Some(Self::Authentication),
            0x8008 => Some(Self::Pad),
            _ => None,
        }
    }
}

/// TLV parsing error.
#[derive(Debug, thiserror::Error)]
pub enum TlvError {
    #[error("buffer too short: need {need} bytes, got {got}")]
    BufferTooShort { need: usize, got: usize },
    #[error("TLV length {length} exceeds remaining buffer {remaining}")]
    LengthExceedsBuffer { length: usize, remaining: usize },
}

/// A parsed TLV with its raw value data.
#[derive(Debug, Clone)]
pub struct Tlv {
    /// The TLV type code (may be unknown/vendor-specific).
    pub tlv_type: u16,
    /// The parsed known type, if recognized.
    pub known_type: Option<TlvType>,
    /// The TLV value bytes (not including type and length fields).
    pub value: Vec<u8>,
}

impl Tlv {
    /// Minimum TLV size: 2 bytes type + 2 bytes length.
    pub const HEADER_SIZE: usize = 4;

    /// Parse a single TLV from the beginning of `data`.
    /// Returns the parsed TLV and the total number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TlvError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(TlvError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: data.len(),
            });
        }

        let tlv_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let known_type = TlvType::from_u16(tlv_type);

        let total = Self::HEADER_SIZE + length;
        if data.len() < total {
            return Err(TlvError::LengthExceedsBuffer {
                length,
                remaining: data.len() - Self::HEADER_SIZE,
            });
        }

        let value = data[Self::HEADER_SIZE..total].to_vec();

        Ok((
            Self {
                tlv_type,
                known_type,
                value,
            },
            total,
        ))
    }

    /// Serialize this TLV into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.value.len());
        buf.extend_from_slice(&self.tlv_type.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }

    /// Create a new TLV with a known type.
    pub fn new(tlv_type: TlvType, value: Vec<u8>) -> Self {
        Self {
            tlv_type: tlv_type as u16,
            known_type: Some(tlv_type),
            value,
        }
    }

    /// Total size on wire (header + value).
    pub fn wire_size(&self) -> usize {
        Self::HEADER_SIZE + self.value.len()
    }
}

/// Parse all TLVs from a byte buffer (e.g., the suffix of a PTP message).
pub fn parse_tlvs(data: &[u8]) -> Result<Vec<Tlv>, TlvError> {
    let mut tlvs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // If remaining bytes can't form a TLV header, stop.
        if data.len() - offset < Tlv::HEADER_SIZE {
            break;
        }
        let (tlv, consumed) = Tlv::parse(&data[offset..])?;
        tlvs.push(tlv);
        offset += consumed;
    }

    Ok(tlvs)
}

/// Extract path trace clock identities from a PathTrace TLV value.
/// Each clock identity is 8 bytes.
pub fn parse_path_trace(value: &[u8]) -> Vec<[u8; 8]> {
    let mut identities = Vec::new();
    let mut offset = 0;
    while offset + 8 <= value.len() {
        let mut id = [0u8; 8];
        id.copy_from_slice(&value[offset..offset + 8]);
        identities.push(id);
        offset += 8;
    }
    identities
}

/// Build a PathTrace TLV from a list of clock identities.
pub fn build_path_trace(identities: &[[u8; 8]]) -> Tlv {
    let mut value = Vec::with_capacity(identities.len() * 8);
    for id in identities {
        value.extend_from_slice(id);
    }
    Tlv::new(TlvType::PathTrace, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let original = Tlv::new(TlvType::PathTrace, vec![0x01, 0x02, 0x03, 0x04]);
        let bytes = original.serialize();
        let (parsed, consumed) = Tlv::parse(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.tlv_type, TlvType::PathTrace as u16);
        assert_eq!(parsed.known_type, Some(TlvType::PathTrace));
        assert_eq!(parsed.value, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn tlv_unknown_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // unknown type
        buf.extend_from_slice(&2u16.to_be_bytes()); // length
        buf.extend_from_slice(&[0xAB, 0xCD]); // value

        let (parsed, consumed) = Tlv::parse(&buf).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(parsed.tlv_type, 0xFFFF);
        assert!(parsed.known_type.is_none());
        assert_eq!(parsed.value, vec![0xAB, 0xCD]);
    }

    #[test]
    fn tlv_buffer_too_short() {
        let result = Tlv::parse(&[0x00, 0x08]);
        assert!(result.is_err());
    }

    #[test]
    fn tlv_length_exceeds_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0008u16.to_be_bytes()); // PathTrace
        buf.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        buf.extend_from_slice(&[0x00; 4]); // only 4 bytes of value

        let result = Tlv::parse(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn parse_multiple_tlvs() {
        let tlv1 = Tlv::new(TlvType::PathTrace, vec![0x01; 8]);
        let tlv2 = Tlv::new(TlvType::OrganizationExtension, vec![0x02; 6]);

        let mut buf = tlv1.serialize();
        buf.extend_from_slice(&tlv2.serialize());

        let parsed = parse_tlvs(&buf).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].known_type, Some(TlvType::PathTrace));
        assert_eq!(parsed[1].known_type, Some(TlvType::OrganizationExtension));
    }

    #[test]
    fn parse_empty_tlvs() {
        let parsed = parse_tlvs(&[]).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn path_trace_roundtrip() {
        let identities = vec![
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
        ];
        let tlv = build_path_trace(&identities);
        let parsed = parse_path_trace(&tlv.value);
        assert_eq!(parsed, identities);
    }

    #[test]
    fn path_trace_empty() {
        let tlv = build_path_trace(&[]);
        assert!(tlv.value.is_empty());
        let parsed = parse_path_trace(&tlv.value);
        assert!(parsed.is_empty());
    }

    #[test]
    fn tlv_wire_size() {
        let tlv = Tlv::new(TlvType::PathTrace, vec![0; 16]);
        assert_eq!(tlv.wire_size(), 20); // 4 header + 16 value
    }

    #[test]
    fn tlv_zero_length_value() {
        let tlv = Tlv::new(TlvType::Pad, vec![]);
        let bytes = tlv.serialize();
        let (parsed, consumed) = Tlv::parse(&bytes).unwrap();
        assert_eq!(consumed, 4);
        assert!(parsed.value.is_empty());
        assert_eq!(parsed.known_type, Some(TlvType::Pad));
    }
}
