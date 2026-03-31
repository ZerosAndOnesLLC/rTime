pub mod aead;
pub mod cookie;
pub mod ke;
pub mod records;

/// AEAD_AES_SIV_CMAC_256 algorithm identifier (RFC 5116 Section 5.4).
/// This is the mandatory-to-implement AEAD algorithm for NTS (RFC 8915 Section 5.1).
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;

/// NTPv4 next protocol identifier for NTS-KE (RFC 8915 Section 4.1.2).
pub const NTS_NEXT_PROTOCOL_NTPV4: u16 = 0;

/// Key length in bytes for AEAD_AES_SIV_CMAC_256.
/// The "256" refers to the output tag size; internally it uses two 128-bit subkeys (32 bytes total).
pub const AEAD_AES_SIV_CMAC_256_KEYLEN: usize = 32;

/// Default number of cookies provided during NTS-KE.
pub const DEFAULT_COOKIE_COUNT: usize = 8;

/// NTS-KE TCP port (RFC 8915 Section 4).
pub const NTS_KE_PORT: u16 = 4460;

/// TLS exporter label for NTS key derivation (RFC 8915 Section 5.1).
pub const NTS_TLS_EXPORTER_LABEL: &str = "EXPORTER-network-time-security";

#[derive(Debug, thiserror::Error)]
pub enum NtsError {
    #[error("record too short: need at least {expected} bytes, got {got}")]
    RecordTooShort { expected: usize, got: usize },

    #[error("unknown record type: {0}")]
    UnknownRecordType(u16),

    #[error("invalid record body length: declared {declared}, available {available}")]
    InvalidBodyLength { declared: usize, available: usize },

    #[error("NTS-KE error code: {0}")]
    KeError(u16),

    #[error("NTS-KE warning code: {0}")]
    KeWarning(u16),

    #[error("missing required record: {0}")]
    MissingRecord(&'static str),

    #[error("unsupported next protocol: {0}")]
    UnsupportedProtocol(u16),

    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAlgorithm(u16),

    #[error("no cookies received from server")]
    NoCookies,

    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption failed (authentication tag mismatch)")]
    DecryptionFailed,

    #[error("invalid cookie: {0}")]
    InvalidCookie(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("extension field too short: need at least {expected} bytes, got {got}")]
    ExtensionTooShort { expected: usize, got: usize },

    #[error("invalid extension field length: {0}")]
    InvalidExtensionLength(u16),
}
