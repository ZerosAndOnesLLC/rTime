//! NTP extension fields (RFC 7822) with NTS-specific types (RFC 8915 Section 5.6).
//!
//! Extension field wire format:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Field Type            |        Field Length           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                         Field Value                           .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The length field includes the 4-byte header and must be a multiple of 4.

/// Extension field header size (type: 2 bytes + length: 2 bytes).
pub const EXT_HEADER_SIZE: usize = 4;

/// Minimum extension field size per RFC 7822 (must be at least 16 bytes
/// when used with NTPv4, but for parsing we accept the header minimum).
pub const EXT_MIN_SIZE: usize = 4;

// NTS extension field types (RFC 8915 Section 5.6).

/// Unique Identifier extension field. Contains a random nonce to prevent
/// replay attacks and link requests to responses.
pub const NTS_UNIQUE_IDENTIFIER: u16 = 0x0104;

/// NTS Cookie extension field. Contains an opaque cookie from the NTS-KE
/// server that the NTP server uses to recover session keys.
pub const NTS_COOKIE: u16 = 0x0204;

/// NTS Cookie Placeholder extension field. Sent by the client to reserve
/// space for the server to include replacement cookies in the response.
pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;

/// NTS Authenticator and Encrypted Extension Fields. Contains the AEAD
/// output (nonce + ciphertext + tag) that authenticates the NTP packet
/// and any preceding extension fields.
pub const NTS_AUTHENTICATOR: u16 = 0x0404;

/// An NTP extension field (RFC 7822).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    /// The 16-bit field type.
    pub field_type: u16,
    /// The field value (not including the 4-byte header, not including padding).
    pub value: Vec<u8>,
}

impl ExtensionField {
    /// Create a new extension field.
    pub fn new(field_type: u16, value: Vec<u8>) -> Self {
        Self { field_type, value }
    }

    /// Create an NTS Unique Identifier extension field.
    pub fn unique_identifier(nonce: Vec<u8>) -> Self {
        Self::new(NTS_UNIQUE_IDENTIFIER, nonce)
    }

    /// Create an NTS Cookie extension field.
    pub fn cookie(cookie: Vec<u8>) -> Self {
        Self::new(NTS_COOKIE, cookie)
    }

    /// Create an NTS Cookie Placeholder extension field.
    ///
    /// The placeholder must be the same length as a real cookie so the server
    /// can replace it in-place.
    pub fn cookie_placeholder(length: usize) -> Self {
        Self::new(NTS_COOKIE_PLACEHOLDER, vec![0u8; length])
    }

    /// Create an NTS Authenticator extension field.
    pub fn authenticator(nonce_and_ciphertext: Vec<u8>) -> Self {
        Self::new(NTS_AUTHENTICATOR, nonce_and_ciphertext)
    }

    /// Compute the padded length of the value (padded to 4-byte alignment).
    fn padded_value_len(&self) -> usize {
        let len = self.value.len();
        (len + 3) & !3
    }

    /// Total wire length including header and padding.
    pub fn wire_length(&self) -> usize {
        EXT_HEADER_SIZE + self.padded_value_len()
    }

    /// Serialize this extension field to wire format bytes.
    ///
    /// The length field includes the 4-byte header. The value is padded
    /// to a 4-byte boundary with zeros.
    pub fn serialize(&self) -> Vec<u8> {
        let total_len = self.wire_length();
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&self.field_type.to_be_bytes());
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);

        // Pad to 4-byte alignment
        let padding = self.padded_value_len() - self.value.len();
        buf.extend_from_slice(&vec![0u8; padding]);

        buf
    }

    /// Parse a single extension field from the given data.
    ///
    /// Returns the extension field and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ExtensionError> {
        if data.len() < EXT_HEADER_SIZE {
            return Err(ExtensionError::TooShort {
                got: data.len(),
                expected: EXT_HEADER_SIZE,
            });
        }

        let field_type = u16::from_be_bytes([data[0], data[1]]);
        let field_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Length must include the header
        if field_length < EXT_HEADER_SIZE {
            return Err(ExtensionError::InvalidLength(field_length as u16));
        }

        // Length must be a multiple of 4
        if field_length % 4 != 0 {
            return Err(ExtensionError::InvalidLength(field_length as u16));
        }

        if data.len() < field_length {
            return Err(ExtensionError::TooShort {
                got: data.len(),
                expected: field_length,
            });
        }

        let value_len = field_length - EXT_HEADER_SIZE;
        let value = data[EXT_HEADER_SIZE..EXT_HEADER_SIZE + value_len].to_vec();

        Ok((Self { field_type, value }, field_length))
    }

    /// Parse all extension fields from the given data.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, ExtensionError> {
        let mut fields = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            // Need at least the header to continue
            if data.len() - offset < EXT_HEADER_SIZE {
                break;
            }

            let (field, consumed) = Self::parse(&data[offset..])?;
            fields.push(field);
            offset += consumed;
        }

        Ok(fields)
    }
}

/// Errors from extension field parsing.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionError {
    #[error("extension field too short: got {got} bytes, expected at least {expected}")]
    TooShort { got: usize, expected: usize },

    #[error("invalid extension field length: {0}")]
    InvalidLength(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_unique_identifier() {
        let nonce = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ext = ExtensionField::unique_identifier(nonce.clone());
        let bytes = ext.serialize();

        // Type (2) + Length (2) + Value (8) = 12 bytes, already 4-byte aligned
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..2], &NTS_UNIQUE_IDENTIFIER.to_be_bytes());
        assert_eq!(&bytes[2..4], &12u16.to_be_bytes());

        let (parsed, consumed) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(parsed.field_type, NTS_UNIQUE_IDENTIFIER);
        assert_eq!(parsed.value, nonce);
    }

    #[test]
    fn roundtrip_with_padding() {
        // Value of 5 bytes should be padded to 8 bytes
        let ext = ExtensionField::new(0x1234, vec![1, 2, 3, 4, 5]);
        let bytes = ext.serialize();

        // 4 header + 8 padded value = 12 bytes
        assert_eq!(bytes.len(), 12);
        // Padding bytes should be zero
        assert_eq!(bytes[9], 0);
        assert_eq!(bytes[10], 0);
        assert_eq!(bytes[11], 0);

        let (parsed, consumed) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(consumed, 12);
        // Parsed value includes padding (since we can't distinguish value from padding
        // in the wire format without knowing the type semantics)
        assert_eq!(parsed.value.len(), 8); // padded length
        assert_eq!(&parsed.value[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn roundtrip_cookie() {
        let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let ext = ExtensionField::cookie(cookie.clone());
        let bytes = ext.serialize();

        let (parsed, _) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(parsed.field_type, NTS_COOKIE);
        assert_eq!(parsed.value, cookie);
    }

    #[test]
    fn roundtrip_cookie_placeholder() {
        let ext = ExtensionField::cookie_placeholder(64);
        let bytes = ext.serialize();

        let (parsed, _) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(parsed.field_type, NTS_COOKIE_PLACEHOLDER);
        assert_eq!(parsed.value.len(), 64);
        assert!(parsed.value.iter().all(|&b| b == 0));
    }

    #[test]
    fn roundtrip_authenticator() {
        let auth_data = vec![0xAA; 48]; // nonce (16) + ciphertext (16) + tag (16) example
        let ext = ExtensionField::authenticator(auth_data.clone());
        let bytes = ext.serialize();

        let (parsed, _) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(parsed.field_type, NTS_AUTHENTICATOR);
        assert_eq!(parsed.value, auth_data);
    }

    #[test]
    fn parse_too_short() {
        let data = [0u8; 2];
        assert!(ExtensionField::parse(&data).is_err());
    }

    #[test]
    fn parse_invalid_length_too_small() {
        // Length field says 2 (less than header size of 4)
        let data = [0x01, 0x04, 0x00, 0x02];
        assert!(ExtensionField::parse(&data).is_err());
    }

    #[test]
    fn parse_invalid_length_not_aligned() {
        // Length field says 5 (not multiple of 4)
        let data = [0x01, 0x04, 0x00, 0x05, 0x00];
        assert!(ExtensionField::parse(&data).is_err());
    }

    #[test]
    fn parse_length_exceeds_data() {
        // Length says 8 but only 4 bytes available
        let data = [0x01, 0x04, 0x00, 0x08];
        assert!(ExtensionField::parse(&data).is_err());
    }

    #[test]
    fn parse_all_multiple_fields() {
        let uid = ExtensionField::unique_identifier(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let cookie = ExtensionField::cookie(vec![0xAA; 16]);
        let auth = ExtensionField::authenticator(vec![0xBB; 32]);

        let mut data = Vec::new();
        data.extend_from_slice(&uid.serialize());
        data.extend_from_slice(&cookie.serialize());
        data.extend_from_slice(&auth.serialize());

        let fields = ExtensionField::parse_all(&data).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].field_type, NTS_UNIQUE_IDENTIFIER);
        assert_eq!(fields[1].field_type, NTS_COOKIE);
        assert_eq!(fields[2].field_type, NTS_AUTHENTICATOR);
    }

    #[test]
    fn wire_length_calculation() {
        // Exactly aligned
        let ext = ExtensionField::new(0, vec![0; 8]);
        assert_eq!(ext.wire_length(), 12);

        // Needs padding: 5 bytes -> padded to 8
        let ext = ExtensionField::new(0, vec![0; 5]);
        assert_eq!(ext.wire_length(), 12);

        // Needs padding: 1 byte -> padded to 4
        let ext = ExtensionField::new(0, vec![0; 1]);
        assert_eq!(ext.wire_length(), 8);

        // Empty value
        let ext = ExtensionField::new(0, vec![]);
        assert_eq!(ext.wire_length(), 4);
    }

    #[test]
    fn empty_extension_field() {
        let ext = ExtensionField::new(0x1234, vec![]);
        let bytes = ext.serialize();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes[2..4], &4u16.to_be_bytes());

        let (parsed, consumed) = ExtensionField::parse(&bytes).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(parsed.field_type, 0x1234);
        assert!(parsed.value.is_empty());
    }

    #[test]
    fn extension_type_constants() {
        assert_eq!(NTS_UNIQUE_IDENTIFIER, 0x0104);
        assert_eq!(NTS_COOKIE, 0x0204);
        assert_eq!(NTS_COOKIE_PLACEHOLDER, 0x0304);
        assert_eq!(NTS_AUTHENTICATOR, 0x0404);
    }
}
