use rtime_core::clock::LeapIndicator;
use rtime_core::timestamp::NtpTimestamp;

/// NTPv4 packet header size in bytes (without extensions or MAC).
pub const NTP_HEADER_SIZE: usize = 48;

/// NTP version number.
pub const NTP_VERSION: u8 = 4;

/// NTP association modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NtpMode {
    Reserved = 0,
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    Control = 6,
    Private = 7,
}

impl NtpMode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x07 {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            7 => Self::Private,
            _ => unreachable!(),
        }
    }
}

/// An NTPv4 packet (RFC 5905).
///
/// Wire format (48 bytes):
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |LI | VN  |Mode |   Stratum   |    Poll     |   Precision     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Root Delay                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Root Dispersion                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Reference ID                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Reference Timestamp (64)                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Origin Timestamp (64)                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Receive Timestamp (64)                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Transmit Timestamp (64)                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket {
    pub leap_indicator: LeapIndicator,
    pub version: u8,
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_ts: NtpTimestamp,
    pub origin_ts: NtpTimestamp,
    pub receive_ts: NtpTimestamp,
    pub transmit_ts: NtpTimestamp,
}

impl NtpPacket {
    /// Create a new client request packet.
    pub fn new_client_request(transmit_ts: NtpTimestamp) -> Self {
        Self {
            leap_indicator: LeapIndicator::AlarmUnsynchronized,
            version: NTP_VERSION,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 6, // 64 seconds default
            precision: -20, // ~1 microsecond
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_ts: NtpTimestamp::ZERO,
            origin_ts: NtpTimestamp::ZERO,
            receive_ts: NtpTimestamp::ZERO,
            transmit_ts,
        }
    }

    /// Parse from wire format bytes. Must be at least 48 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < NTP_HEADER_SIZE {
            return Err(PacketError::TooShort {
                got: data.len(),
                expected: NTP_HEADER_SIZE,
            });
        }

        let li_vn_mode = data[0];
        let leap_indicator = LeapIndicator::from_u8((li_vn_mode >> 6) & 0x03);
        let version = (li_vn_mode >> 3) & 0x07;
        let mode = NtpMode::from_u8(li_vn_mode & 0x07);

        if version < 1 || version > 4 {
            return Err(PacketError::UnsupportedVersion(version));
        }

        let stratum = data[1];
        let poll = data[2] as i8;
        let precision = data[3] as i8;
        let root_delay = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let root_dispersion = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let reference_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let reference_ts = read_timestamp(&data[16..24]);
        let origin_ts = read_timestamp(&data[24..32]);
        let receive_ts = read_timestamp(&data[32..40]);
        let transmit_ts = read_timestamp(&data[40..48]);

        Ok(Self {
            leap_indicator,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_ts,
            origin_ts,
            receive_ts,
            transmit_ts,
        })
    }

    /// Serialize to wire format bytes (48 bytes).
    pub fn serialize(&self) -> [u8; NTP_HEADER_SIZE] {
        let mut buf = [0u8; NTP_HEADER_SIZE];

        buf[0] = ((self.leap_indicator as u8) << 6)
            | ((self.version & 0x07) << 3)
            | (self.mode as u8 & 0x07);
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        buf[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id.to_be_bytes());
        buf[16..24].copy_from_slice(&self.reference_ts.to_bytes());
        buf[24..32].copy_from_slice(&self.origin_ts.to_bytes());
        buf[32..40].copy_from_slice(&self.receive_ts.to_bytes());
        buf[40..48].copy_from_slice(&self.transmit_ts.to_bytes());

        buf
    }

    /// Encode the first 4 bytes of reference ID as ASCII string (for stratum 1).
    pub fn reference_id_str(&self) -> String {
        let bytes = self.reference_id.to_be_bytes();
        bytes
            .iter()
            .filter(|&&b| b != 0 && b.is_ascii())
            .map(|&b| b as char)
            .collect()
    }
}

fn read_timestamp(data: &[u8]) -> NtpTimestamp {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    NtpTimestamp::from_bytes(buf)
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short: got {got} bytes, expected at least {expected}")]
    TooShort { got: usize, expected: usize },

    #[error("unsupported NTP version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid mode: {0}")]
    InvalidMode(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serialize_parse() {
        let pkt = NtpPacket {
            leap_indicator: LeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Server,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0x0100_0000, // 1 second in NTP short format
            root_dispersion: 0x0080_0000, // 0.5 seconds
            reference_id: u32::from_be_bytes(*b"GPS\0"),
            reference_ts: NtpTimestamp::new(3_900_000_000, 500),
            origin_ts: NtpTimestamp::new(3_900_000_001, 1000),
            receive_ts: NtpTimestamp::new(3_900_000_002, 2000),
            transmit_ts: NtpTimestamp::new(3_900_000_003, 3000),
        };

        let bytes = pkt.serialize();
        assert_eq!(bytes.len(), NTP_HEADER_SIZE);

        let parsed = NtpPacket::parse(&bytes).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn parse_too_short() {
        let data = [0u8; 10];
        assert!(NtpPacket::parse(&data).is_err());
    }

    #[test]
    fn client_request() {
        let ts = NtpTimestamp::now();
        let pkt = NtpPacket::new_client_request(ts);
        assert_eq!(pkt.mode, NtpMode::Client);
        assert_eq!(pkt.version, NTP_VERSION);
        assert_eq!(pkt.transmit_ts, ts);

        // Verify it round-trips
        let bytes = pkt.serialize();
        let parsed = NtpPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.mode, NtpMode::Client);
        assert_eq!(parsed.transmit_ts, ts);
    }

    #[test]
    fn reference_id_string() {
        let pkt = NtpPacket {
            reference_id: u32::from_be_bytes(*b"GPS\0"),
            ..NtpPacket::new_client_request(NtpTimestamp::ZERO)
        };
        assert_eq!(pkt.reference_id_str(), "GPS");
    }

    #[test]
    fn li_vn_mode_encoding() {
        // LI=0, VN=4, Mode=3 (client) -> 0b00_100_011 = 0x23
        let pkt = NtpPacket::new_client_request(NtpTimestamp::ZERO);
        let bytes = pkt.serialize();
        // LI=3 (alarm), VN=4, Mode=3 -> 0b11_100_011 = 0xE3
        assert_eq!(bytes[0], 0xE3);
    }

    #[test]
    fn parse_unsupported_version() {
        let mut bytes = NtpPacket::new_client_request(NtpTimestamp::ZERO).serialize();
        // Set version to 0: LI=3, VN=0, Mode=3 -> 0b11_000_011 = 0xC3
        bytes[0] = 0xC3;
        assert!(NtpPacket::parse(&bytes).is_err());
    }
}
