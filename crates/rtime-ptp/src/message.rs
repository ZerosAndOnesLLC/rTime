use rtime_core::timestamp::PtpTimestamp;

/// PTP header size in bytes (IEEE 1588-2019 Section 13.3).
pub const PTP_HEADER_SIZE: usize = 34;

/// PTP timestamp size on wire (6 bytes seconds + 4 bytes nanoseconds).
const PTP_TIMESTAMP_SIZE: usize = 10;

/// Port identity size on wire (8 bytes clock identity + 2 bytes port number).
const PORT_IDENTITY_SIZE: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum PtpParseError {
    #[error("buffer too short: need {need} bytes, got {got}")]
    BufferTooShort { need: usize, got: usize },
    #[error("unknown message type: 0x{0:x}")]
    UnknownMessageType(u8),
    #[error("unsupported PTP version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid slice length for array conversion: {0}")]
    InvalidSliceLength(#[from] std::array::TryFromSliceError),
}

/// PTP message type nibble values (IEEE 1588-2019 Table 36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PDelayReq = 0x2,
    PDelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PDelayRespFollowUp = 0xA,
    Announce = 0xB,
    Signaling = 0xC,
    Management = 0xD,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Result<Self, PtpParseError> {
        match val {
            0x0 => Ok(Self::Sync),
            0x1 => Ok(Self::DelayReq),
            0x2 => Ok(Self::PDelayReq),
            0x3 => Ok(Self::PDelayResp),
            0x8 => Ok(Self::FollowUp),
            0x9 => Ok(Self::DelayResp),
            0xA => Ok(Self::PDelayRespFollowUp),
            0xB => Ok(Self::Announce),
            0xC => Ok(Self::Signaling),
            0xD => Ok(Self::Management),
            other => Err(PtpParseError::UnknownMessageType(other)),
        }
    }

    /// Whether this is an event message (needs hardware timestamping).
    pub fn is_event(self) -> bool {
        (self as u8) < 0x8
    }
}

/// PTP port identity: clock identity (8 bytes) + port number (2 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortIdentity {
    pub clock_identity: [u8; 8],
    pub port_number: u16,
}

impl PortIdentity {
    pub const ZERO: Self = Self {
        clock_identity: [0; 8],
        port_number: 0,
    };

    pub fn parse(data: &[u8]) -> Result<Self, PtpParseError> {
        if data.len() < PORT_IDENTITY_SIZE {
            return Err(PtpParseError::BufferTooShort {
                need: PORT_IDENTITY_SIZE,
                got: data.len(),
            });
        }
        let mut clock_identity = [0u8; 8];
        clock_identity.copy_from_slice(&data[0..8]);
        let port_number = u16::from_be_bytes([data[8], data[9]]);
        Ok(Self {
            clock_identity,
            port_number,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.clock_identity);
        buf[8..10].copy_from_slice(&self.port_number.to_be_bytes());
    }
}

/// PTP flag field (IEEE 1588-2019 Table 37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpFlags(pub u16);

impl PtpFlags {
    pub const EMPTY: Self = Self(0);

    // Octet 0 flags
    pub const ALTERNATE_MASTER: u16 = 1 << 0;
    pub const TWO_STEP: u16 = 1 << 1;
    pub const UNICAST: u16 = 1 << 2;

    // Octet 1 flags
    pub const LEAP61: u16 = 1 << 8;
    pub const LEAP59: u16 = 1 << 9;
    pub const CURRENT_UTC_OFFSET_VALID: u16 = 1 << 10;
    pub const PTP_TIMESCALE: u16 = 1 << 11;
    pub const TIME_TRACEABLE: u16 = 1 << 12;
    pub const FREQUENCY_TRACEABLE: u16 = 1 << 13;

    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u16) {
        self.0 &= !flag;
    }
}

/// PTP common header (34 bytes, IEEE 1588-2019 Section 13.3).
#[derive(Debug, Clone)]
pub struct PtpHeader {
    pub transport_specific: u8,
    pub message_type: MessageType,
    pub version: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub minor_sdo_id: u8,
    pub flags: PtpFlags,
    /// Correction field: scaled nanoseconds (16.48 fixed-point).
    pub correction_field: i64,
    pub message_type_specific: u32,
    pub source_port_identity: PortIdentity,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: i8,
}

impl PtpHeader {
    /// Parse a PTP header from the beginning of `data`.
    /// Returns the parsed header and the number of bytes consumed (always 34).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), PtpParseError> {
        if data.len() < PTP_HEADER_SIZE {
            return Err(PtpParseError::BufferTooShort {
                need: PTP_HEADER_SIZE,
                got: data.len(),
            });
        }

        let transport_specific = (data[0] >> 4) & 0x0F;
        let msg_type_nibble = data[0] & 0x0F;
        let message_type = MessageType::from_u8(msg_type_nibble)?;

        let version = data[1] & 0x0F;
        if version != 2 {
            return Err(PtpParseError::UnsupportedVersion(version));
        }

        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let domain_number = data[4];
        let minor_sdo_id = data[5];
        let flags = PtpFlags(u16::from_be_bytes([data[6], data[7]]));

        let correction_field = i64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let message_type_specific = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

        let source_port_identity = PortIdentity::parse(&data[20..30])?;

        let sequence_id = u16::from_be_bytes([data[30], data[31]]);
        let control_field = data[32];
        let log_message_interval = data[33] as i8;

        Ok((
            Self {
                transport_specific,
                message_type,
                version,
                message_length,
                domain_number,
                minor_sdo_id,
                flags,
                correction_field,
                message_type_specific,
                source_port_identity,
                sequence_id,
                control_field,
                log_message_interval,
            },
            PTP_HEADER_SIZE,
        ))
    }

    /// Serialize the header into 34 bytes.
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0] = (self.transport_specific << 4) | (self.message_type as u8);
        buf[1] = self.version & 0x0F;
        buf[2..4].copy_from_slice(&self.message_length.to_be_bytes());
        buf[4] = self.domain_number;
        buf[5] = self.minor_sdo_id;
        buf[6..8].copy_from_slice(&self.flags.0.to_be_bytes());
        buf[8..16].copy_from_slice(&self.correction_field.to_be_bytes());
        buf[16..20].copy_from_slice(&self.message_type_specific.to_be_bytes());
        self.source_port_identity.serialize(&mut buf[20..30]);
        buf[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        buf[32] = self.control_field;
        buf[33] = self.log_message_interval as u8;
    }

    /// Create a default header for a given message type, filling in sane defaults.
    pub fn new(message_type: MessageType, domain: u8, source: PortIdentity, seq: u16) -> Self {
        let control_field = match message_type {
            MessageType::Sync => 0x00,
            MessageType::DelayReq => 0x01,
            MessageType::FollowUp => 0x02,
            MessageType::DelayResp => 0x03,
            MessageType::Management => 0x04,
            _ => 0x05, // other
        };
        Self {
            transport_specific: 0,
            message_type,
            version: 2,
            message_length: 0, // caller must set
            domain_number: domain,
            minor_sdo_id: 0,
            flags: PtpFlags::EMPTY,
            correction_field: 0,
            message_type_specific: 0,
            source_port_identity: source,
            sequence_id: seq,
            control_field,
            log_message_interval: 0,
        }
    }
}

/// Clock quality for announce messages (IEEE 1588-2019 Section 7.6.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
}

impl ClockQuality {
    pub const SIZE: usize = 4;

    pub fn parse(data: &[u8]) -> Result<Self, PtpParseError> {
        if data.len() < Self::SIZE {
            return Err(PtpParseError::BufferTooShort {
                need: Self::SIZE,
                got: data.len(),
            });
        }
        Ok(Self {
            clock_class: data[0],
            clock_accuracy: data[1],
            offset_scaled_log_variance: u16::from_be_bytes([data[2], data[3]]),
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0] = self.clock_class;
        buf[1] = self.clock_accuracy;
        buf[2..4].copy_from_slice(&self.offset_scaled_log_variance.to_be_bytes());
    }
}

/// Body of an Announce message (IEEE 1588-2019 Section 13.5.6).
#[derive(Debug, Clone)]
pub struct AnnounceBody {
    pub origin_timestamp: PtpTimestamp,
    pub current_utc_offset: i16,
    pub grandmaster_priority1: u8,
    pub grandmaster_clock_quality: ClockQuality,
    pub grandmaster_priority2: u8,
    pub grandmaster_identity: [u8; 8],
    pub steps_removed: u16,
    pub time_source: u8,
}

impl AnnounceBody {
    /// Size of the announce body on wire (after the header).
    /// 10 (timestamp) + 2 (utcOffset) + 1 (reserved) + 1 (priority1) + 4 (clockQuality)
    /// + 1 (priority2) + 8 (gmIdentity) + 2 (stepsRemoved) + 1 (timeSource) = 30
    pub const SIZE: usize = 30;

    pub fn parse(data: &[u8]) -> Result<Self, PtpParseError> {
        if data.len() < Self::SIZE {
            return Err(PtpParseError::BufferTooShort {
                need: Self::SIZE,
                got: data.len(),
            });
        }
        let origin_timestamp = PtpTimestamp::from_bytes(
            <[u8; 10]>::try_from(&data[0..10])?,
        );
        let current_utc_offset = i16::from_be_bytes([data[10], data[11]]);
        // data[12] is reserved
        let grandmaster_priority1 = data[13];
        let grandmaster_clock_quality = ClockQuality::parse(&data[14..18])?;
        let grandmaster_priority2 = data[18];
        let mut grandmaster_identity = [0u8; 8];
        grandmaster_identity.copy_from_slice(&data[19..27]);
        let steps_removed = u16::from_be_bytes([data[27], data[28]]);
        let time_source = data[29];

        Ok(Self {
            origin_timestamp,
            current_utc_offset,
            grandmaster_priority1,
            grandmaster_clock_quality,
            grandmaster_priority2,
            grandmaster_identity,
            steps_removed,
            time_source,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        let ts_bytes = self.origin_timestamp.to_bytes();
        buf[0..10].copy_from_slice(&ts_bytes);
        buf[10..12].copy_from_slice(&self.current_utc_offset.to_be_bytes());
        buf[12] = 0; // reserved
        buf[13] = self.grandmaster_priority1;
        self.grandmaster_clock_quality.serialize(&mut buf[14..18]);
        buf[18] = self.grandmaster_priority2;
        buf[19..27].copy_from_slice(&self.grandmaster_identity);
        buf[27..29].copy_from_slice(&self.steps_removed.to_be_bytes());
        buf[29] = self.time_source;
    }
}

/// A fully parsed PTP message.
#[derive(Debug, Clone)]
pub enum PtpMessage {
    Sync {
        header: PtpHeader,
        origin_timestamp: PtpTimestamp,
    },
    FollowUp {
        header: PtpHeader,
        precise_origin_timestamp: PtpTimestamp,
    },
    DelayReq {
        header: PtpHeader,
        origin_timestamp: PtpTimestamp,
    },
    DelayResp {
        header: PtpHeader,
        receive_timestamp: PtpTimestamp,
        requesting_port: PortIdentity,
    },
    Announce {
        header: PtpHeader,
        announce: AnnounceBody,
    },
}

/// Minimum body sizes for each message type we parse.
const SYNC_BODY_SIZE: usize = PTP_TIMESTAMP_SIZE; // 10
const FOLLOW_UP_BODY_SIZE: usize = PTP_TIMESTAMP_SIZE; // 10
const DELAY_REQ_BODY_SIZE: usize = PTP_TIMESTAMP_SIZE; // 10
const DELAY_RESP_BODY_SIZE: usize = PTP_TIMESTAMP_SIZE + PORT_IDENTITY_SIZE; // 20

impl PtpMessage {
    /// Parse a complete PTP message from wire bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PtpParseError> {
        let (header, hdr_len) = PtpHeader::parse(data)?;
        let body = &data[hdr_len..];

        match header.message_type {
            MessageType::Sync => {
                if body.len() < SYNC_BODY_SIZE {
                    return Err(PtpParseError::BufferTooShort {
                        need: PTP_HEADER_SIZE + SYNC_BODY_SIZE,
                        got: data.len(),
                    });
                }
                let origin_timestamp = PtpTimestamp::from_bytes(
                    <[u8; 10]>::try_from(&body[0..10])?,
                );
                Ok(Self::Sync {
                    header,
                    origin_timestamp,
                })
            }
            MessageType::FollowUp => {
                if body.len() < FOLLOW_UP_BODY_SIZE {
                    return Err(PtpParseError::BufferTooShort {
                        need: PTP_HEADER_SIZE + FOLLOW_UP_BODY_SIZE,
                        got: data.len(),
                    });
                }
                let precise_origin_timestamp = PtpTimestamp::from_bytes(
                    <[u8; 10]>::try_from(&body[0..10])?,
                );
                Ok(Self::FollowUp {
                    header,
                    precise_origin_timestamp,
                })
            }
            MessageType::DelayReq => {
                if body.len() < DELAY_REQ_BODY_SIZE {
                    return Err(PtpParseError::BufferTooShort {
                        need: PTP_HEADER_SIZE + DELAY_REQ_BODY_SIZE,
                        got: data.len(),
                    });
                }
                let origin_timestamp = PtpTimestamp::from_bytes(
                    <[u8; 10]>::try_from(&body[0..10])?,
                );
                Ok(Self::DelayReq {
                    header,
                    origin_timestamp,
                })
            }
            MessageType::DelayResp => {
                if body.len() < DELAY_RESP_BODY_SIZE {
                    return Err(PtpParseError::BufferTooShort {
                        need: PTP_HEADER_SIZE + DELAY_RESP_BODY_SIZE,
                        got: data.len(),
                    });
                }
                let receive_timestamp = PtpTimestamp::from_bytes(
                    <[u8; 10]>::try_from(&body[0..10])?,
                );
                let requesting_port = PortIdentity::parse(&body[10..20])?;
                Ok(Self::DelayResp {
                    header,
                    receive_timestamp,
                    requesting_port,
                })
            }
            MessageType::Announce => {
                if body.len() < AnnounceBody::SIZE {
                    return Err(PtpParseError::BufferTooShort {
                        need: PTP_HEADER_SIZE + AnnounceBody::SIZE,
                        got: data.len(),
                    });
                }
                let announce = AnnounceBody::parse(body)?;
                Ok(Self::Announce { header, announce })
            }
            other => Err(PtpParseError::UnknownMessageType(other as u8)),
        }
    }

    /// Serialize a PTP message into a Vec<u8>.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Sync {
                header,
                origin_timestamp,
            } => {
                let total = PTP_HEADER_SIZE + SYNC_BODY_SIZE;
                let mut buf = vec![0u8; total];
                let mut hdr = header.clone();
                hdr.message_length = total as u16;
                hdr.serialize(&mut buf[0..PTP_HEADER_SIZE]);
                let ts_bytes = origin_timestamp.to_bytes();
                buf[PTP_HEADER_SIZE..PTP_HEADER_SIZE + 10].copy_from_slice(&ts_bytes);
                buf
            }
            Self::FollowUp {
                header,
                precise_origin_timestamp,
            } => {
                let total = PTP_HEADER_SIZE + FOLLOW_UP_BODY_SIZE;
                let mut buf = vec![0u8; total];
                let mut hdr = header.clone();
                hdr.message_length = total as u16;
                hdr.serialize(&mut buf[0..PTP_HEADER_SIZE]);
                let ts_bytes = precise_origin_timestamp.to_bytes();
                buf[PTP_HEADER_SIZE..PTP_HEADER_SIZE + 10].copy_from_slice(&ts_bytes);
                buf
            }
            Self::DelayReq {
                header,
                origin_timestamp,
            } => {
                let total = PTP_HEADER_SIZE + DELAY_REQ_BODY_SIZE;
                let mut buf = vec![0u8; total];
                let mut hdr = header.clone();
                hdr.message_length = total as u16;
                hdr.serialize(&mut buf[0..PTP_HEADER_SIZE]);
                let ts_bytes = origin_timestamp.to_bytes();
                buf[PTP_HEADER_SIZE..PTP_HEADER_SIZE + 10].copy_from_slice(&ts_bytes);
                buf
            }
            Self::DelayResp {
                header,
                receive_timestamp,
                requesting_port,
            } => {
                let total = PTP_HEADER_SIZE + DELAY_RESP_BODY_SIZE;
                let mut buf = vec![0u8; total];
                let mut hdr = header.clone();
                hdr.message_length = total as u16;
                hdr.serialize(&mut buf[0..PTP_HEADER_SIZE]);
                let ts_bytes = receive_timestamp.to_bytes();
                buf[PTP_HEADER_SIZE..PTP_HEADER_SIZE + 10].copy_from_slice(&ts_bytes);
                requesting_port.serialize(&mut buf[PTP_HEADER_SIZE + 10..PTP_HEADER_SIZE + 20]);
                buf
            }
            Self::Announce { header, announce } => {
                let total = PTP_HEADER_SIZE + AnnounceBody::SIZE;
                let mut buf = vec![0u8; total];
                let mut hdr = header.clone();
                hdr.message_length = total as u16;
                hdr.serialize(&mut buf[0..PTP_HEADER_SIZE]);
                announce.serialize(&mut buf[PTP_HEADER_SIZE..]);
                buf
            }
        }
    }

    /// Get a reference to the header.
    pub fn header(&self) -> &PtpHeader {
        match self {
            Self::Sync { header, .. }
            | Self::FollowUp { header, .. }
            | Self::DelayReq { header, .. }
            | Self::DelayResp { header, .. }
            | Self::Announce { header, .. } => header,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_source() -> PortIdentity {
        PortIdentity {
            clock_identity: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            port_number: 1,
        }
    }

    fn test_header(msg_type: MessageType) -> PtpHeader {
        PtpHeader::new(msg_type, 0, test_source(), 42)
    }

    #[test]
    fn header_roundtrip() {
        let hdr = test_header(MessageType::Sync);
        let mut buf = [0u8; PTP_HEADER_SIZE];
        hdr.serialize(&mut buf);
        let (parsed, consumed) = PtpHeader::parse(&buf).unwrap();
        assert_eq!(consumed, PTP_HEADER_SIZE);
        assert_eq!(parsed.message_type, MessageType::Sync);
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.domain_number, 0);
        assert_eq!(parsed.source_port_identity, test_source());
        assert_eq!(parsed.sequence_id, 42);
    }

    #[test]
    fn sync_roundtrip() {
        let ts = PtpTimestamp::new(1_000_000, 500_000_000);
        let msg = PtpMessage::Sync {
            header: test_header(MessageType::Sync),
            origin_timestamp: ts,
        };
        let bytes = msg.serialize();
        let parsed = PtpMessage::parse(&bytes).unwrap();
        match parsed {
            PtpMessage::Sync {
                header,
                origin_timestamp,
            } => {
                assert_eq!(header.message_type, MessageType::Sync);
                assert_eq!(origin_timestamp, ts);
                assert_eq!(header.sequence_id, 42);
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn follow_up_roundtrip() {
        let ts = PtpTimestamp::new(2_000_000, 123_456_789);
        let msg = PtpMessage::FollowUp {
            header: test_header(MessageType::FollowUp),
            precise_origin_timestamp: ts,
        };
        let bytes = msg.serialize();
        let parsed = PtpMessage::parse(&bytes).unwrap();
        match parsed {
            PtpMessage::FollowUp {
                header,
                precise_origin_timestamp,
            } => {
                assert_eq!(header.message_type, MessageType::FollowUp);
                assert_eq!(precise_origin_timestamp, ts);
            }
            _ => panic!("expected FollowUp"),
        }
    }

    #[test]
    fn delay_req_roundtrip() {
        let ts = PtpTimestamp::new(3_000_000, 999_999_999);
        let msg = PtpMessage::DelayReq {
            header: test_header(MessageType::DelayReq),
            origin_timestamp: ts,
        };
        let bytes = msg.serialize();
        let parsed = PtpMessage::parse(&bytes).unwrap();
        match parsed {
            PtpMessage::DelayReq {
                header,
                origin_timestamp,
            } => {
                assert_eq!(header.message_type, MessageType::DelayReq);
                assert_eq!(origin_timestamp, ts);
            }
            _ => panic!("expected DelayReq"),
        }
    }

    #[test]
    fn delay_resp_roundtrip() {
        let ts = PtpTimestamp::new(4_000_000, 250_000_000);
        let req_port = PortIdentity {
            clock_identity: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            port_number: 5,
        };
        let msg = PtpMessage::DelayResp {
            header: test_header(MessageType::DelayResp),
            receive_timestamp: ts,
            requesting_port: req_port,
        };
        let bytes = msg.serialize();
        let parsed = PtpMessage::parse(&bytes).unwrap();
        match parsed {
            PtpMessage::DelayResp {
                header,
                receive_timestamp,
                requesting_port,
            } => {
                assert_eq!(header.message_type, MessageType::DelayResp);
                assert_eq!(receive_timestamp, ts);
                assert_eq!(requesting_port, req_port);
            }
            _ => panic!("expected DelayResp"),
        }
    }

    #[test]
    fn announce_roundtrip() {
        let body = AnnounceBody {
            origin_timestamp: PtpTimestamp::new(5_000_000, 0),
            current_utc_offset: 37,
            grandmaster_priority1: 128,
            grandmaster_clock_quality: ClockQuality {
                clock_class: 6,
                clock_accuracy: 0x21,
                offset_scaled_log_variance: 0x4E5D,
            },
            grandmaster_priority2: 128,
            grandmaster_identity: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            steps_removed: 0,
            time_source: 0x20, // GPS
        };
        let msg = PtpMessage::Announce {
            header: test_header(MessageType::Announce),
            announce: body,
        };
        let bytes = msg.serialize();
        let parsed = PtpMessage::parse(&bytes).unwrap();
        match parsed {
            PtpMessage::Announce { header, announce } => {
                assert_eq!(header.message_type, MessageType::Announce);
                assert_eq!(announce.current_utc_offset, 37);
                assert_eq!(announce.grandmaster_priority1, 128);
                assert_eq!(announce.grandmaster_clock_quality.clock_class, 6);
                assert_eq!(announce.grandmaster_clock_quality.clock_accuracy, 0x21);
                assert_eq!(
                    announce.grandmaster_clock_quality.offset_scaled_log_variance,
                    0x4E5D
                );
                assert_eq!(announce.grandmaster_priority2, 128);
                assert_eq!(
                    announce.grandmaster_identity,
                    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
                );
                assert_eq!(announce.steps_removed, 0);
                assert_eq!(announce.time_source, 0x20);
            }
            _ => panic!("expected Announce"),
        }
    }

    #[test]
    fn parse_buffer_too_short() {
        let result = PtpHeader::parse(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_message_type() {
        // Create a buffer with valid size but message type 0xF (unknown)
        let mut buf = [0u8; PTP_HEADER_SIZE];
        buf[0] = 0x0F; // transport_specific=0, messageType=0xF
        buf[1] = 0x02; // version 2
        let result = PtpHeader::parse(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unsupported_version() {
        let mut buf = [0u8; PTP_HEADER_SIZE];
        buf[0] = 0x00; // Sync
        buf[1] = 0x03; // version 3 (unsupported)
        let result = PtpHeader::parse(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn flags_operations() {
        let mut flags = PtpFlags::EMPTY;
        assert!(!flags.has(PtpFlags::TWO_STEP));
        flags.set(PtpFlags::TWO_STEP);
        assert!(flags.has(PtpFlags::TWO_STEP));
        flags.clear(PtpFlags::TWO_STEP);
        assert!(!flags.has(PtpFlags::TWO_STEP));
    }

    #[test]
    fn message_type_is_event() {
        assert!(MessageType::Sync.is_event());
        assert!(MessageType::DelayReq.is_event());
        assert!(MessageType::PDelayReq.is_event());
        assert!(MessageType::PDelayResp.is_event());
        assert!(!MessageType::FollowUp.is_event());
        assert!(!MessageType::DelayResp.is_event());
        assert!(!MessageType::Announce.is_event());
    }

    #[test]
    fn port_identity_roundtrip() {
        let pi = PortIdentity {
            clock_identity: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            port_number: 0x1234,
        };
        let mut buf = [0u8; 10];
        pi.serialize(&mut buf);
        let parsed = PortIdentity::parse(&buf).unwrap();
        assert_eq!(parsed, pi);
    }

    #[test]
    fn correction_field_roundtrip() {
        let mut hdr = test_header(MessageType::Sync);
        hdr.correction_field = -123_456_789_012;
        let mut buf = [0u8; PTP_HEADER_SIZE];
        hdr.serialize(&mut buf);
        let (parsed, _) = PtpHeader::parse(&buf).unwrap();
        assert_eq!(parsed.correction_field, -123_456_789_012);
    }
}
