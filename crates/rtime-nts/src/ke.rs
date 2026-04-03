//! NTS Key Exchange (NTS-KE) protocol (RFC 8915 Section 4).
//!
//! The NTS-KE protocol runs over TLS 1.3 on TCP port 4460. After the TLS
//! handshake completes, the client and server exchange NTS-KE records to
//! negotiate the AEAD algorithm and exchange cookies.
//!
//! Key derivation uses the TLS 1.3 exporter interface with the label
//! "EXPORTER-network-time-security" and a two-byte context of 0x0000
//! (for NTPv4 protocol negotiation).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::records::{NtsKeRecord, RecordType};
use crate::{
    AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_256_KEYLEN, NTS_NEXT_PROTOCOL_NTPV4,
    NTS_TLS_EXPORTER_LABEL, NtsError,
};

/// Result of a successful NTS-KE handshake.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NtsKeResult {
    /// Client-to-server AEAD key derived from TLS exporter.
    pub c2s_key: Vec<u8>,
    /// Server-to-client AEAD key derived from TLS exporter.
    pub s2c_key: Vec<u8>,
    /// Cookies received from the server (typically 8).
    pub cookies: Vec<Vec<u8>>,
    /// Negotiated AEAD algorithm identifier.
    pub aead_algorithm: u16,
    /// Optional NTP server hostname from server negotiation record.
    pub server: Option<String>,
    /// Optional NTP port from port negotiation record.
    pub port: Option<u16>,
}

impl std::fmt::Debug for NtsKeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsKeResult")
            .field("c2s_key", &"[REDACTED]")
            .field("s2c_key", &"[REDACTED]")
            .field("cookies", &format!("[{} cookies]", self.cookies.len()))
            .field("aead_algorithm", &self.aead_algorithm)
            .field("server", &self.server)
            .field("port", &self.port)
            .finish()
    }
}

/// Derive AEAD keys from a TLS 1.3 connection using the exporter interface.
///
/// Per RFC 8915 Section 5.1:
/// - Label: "EXPORTER-network-time-security"
/// - Context: two bytes encoding the numeric protocol ID (0x0000 for NTPv4)
///   followed by two bytes encoding the AEAD algorithm ID
/// - Length: 2 * key_length (C2S key + S2C key concatenated)
///
/// The first `key_length` bytes are the C2S key, and the next `key_length`
/// bytes are the S2C key.
pub fn derive_keys(
    tls_connection: &impl ExporterInterface,
    algorithm: u16,
) -> Result<(Vec<u8>, Vec<u8>), NtsError> {
    let key_length = key_length_for_algorithm(algorithm)?;

    // Context: protocol_id (2 bytes) + aead_algorithm (2 bytes)
    let mut context = Vec::with_capacity(4);
    context.extend_from_slice(&NTS_NEXT_PROTOCOL_NTPV4.to_be_bytes());
    context.extend_from_slice(&algorithm.to_be_bytes());

    let export_length = key_length * 2;
    let mut output = vec![0u8; export_length];

    tls_connection
        .export_keying_material(&mut output, NTS_TLS_EXPORTER_LABEL, Some(&context))
        .map_err(|e| NtsError::Tls(format!("TLS exporter failed: {}", e)))?;

    let c2s_key = output[..key_length].to_vec();
    let s2c_key = output[key_length..].to_vec();

    // Zeroize the raw exporter output buffer
    output.zeroize();

    Ok((c2s_key, s2c_key))
}

/// Trait abstracting the TLS exporter interface.
///
/// This is implemented by rustls `ConnectionCommon<T>` types but we define
/// our own trait for testability.
pub trait ExporterInterface {
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &str,
        context: Option<&[u8]>,
    ) -> Result<(), ExporterError>;
}

/// Error from TLS key export.
#[derive(Debug, thiserror::Error)]
pub enum ExporterError {
    #[error("TLS exporter not available (handshake not complete?)")]
    NotAvailable,
    #[error("export failed: {0}")]
    Failed(String),
}

/// Get the key length in bytes for a given AEAD algorithm identifier.
pub fn key_length_for_algorithm(algorithm: u16) -> Result<usize, NtsError> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => Ok(AEAD_AES_SIV_CMAC_256_KEYLEN),
        other => Err(NtsError::UnsupportedAlgorithm(other)),
    }
}

/// Build the NTS-KE client request records.
///
/// The client sends:
/// 1. NextProtocol(NTPv4 = 0) - critical
/// 2. AeadAlgorithm(AEAD_AES_SIV_CMAC_256 = 15) - not critical
/// 3. EndOfMessage - critical
pub fn build_client_request() -> Vec<u8> {
    let records = [
        NtsKeRecord::next_protocol(&[NTS_NEXT_PROTOCOL_NTPV4]),
        NtsKeRecord::aead_algorithm(&[AEAD_AES_SIV_CMAC_256]),
        NtsKeRecord::end_of_message(),
    ];

    let mut data = Vec::new();
    for record in &records {
        data.extend_from_slice(&record.serialize());
    }
    data
}

/// Build the NTS-KE server response records.
///
/// The server sends:
/// 1. NextProtocol(NTPv4 = 0) - critical
/// 2. AeadAlgorithm(negotiated algorithm) - not critical
/// 3. NewCookieForNtpv4(cookie) x `cookie_count`
/// 4. Optionally: NtpV4ServerNegotiation(hostname)
/// 5. Optionally: NtpV4PortNegotiation(port)
/// 6. EndOfMessage - critical
pub fn build_server_response(
    algorithm: u16,
    cookies: &[Vec<u8>],
    server: Option<&str>,
    port: Option<u16>,
) -> Vec<u8> {
    let mut records = Vec::new();

    records.push(NtsKeRecord::next_protocol(&[NTS_NEXT_PROTOCOL_NTPV4]));
    records.push(NtsKeRecord::aead_algorithm(&[algorithm]));

    for cookie in cookies {
        records.push(NtsKeRecord::new_cookie(cookie.clone()));
    }

    if let Some(srv) = server {
        records.push(NtsKeRecord::server_negotiation(srv));
    }

    if let Some(p) = port {
        records.push(NtsKeRecord::port_negotiation(p));
    }

    records.push(NtsKeRecord::end_of_message());

    let mut data = Vec::new();
    for record in &records {
        data.extend_from_slice(&record.serialize());
    }
    data
}

/// Parse an NTS-KE server response and extract the negotiation result.
///
/// This does not derive keys (that requires a TLS connection); it only
/// parses the record-layer response.
pub fn parse_server_response(data: &[u8]) -> Result<ParsedKeResponse, NtsError> {
    let records = NtsKeRecord::parse_all(data)?;

    let mut protocol = None;
    let mut algorithm = None;
    let mut cookies = Vec::new();
    let mut server = None;
    let mut port = None;

    for record in &records {
        match record.record_type {
            RecordType::NextProtocol => {
                let ids = record.protocol_ids();
                if ids.contains(&NTS_NEXT_PROTOCOL_NTPV4) {
                    protocol = Some(NTS_NEXT_PROTOCOL_NTPV4);
                } else if let Some(&first) = ids.first() {
                    return Err(NtsError::UnsupportedProtocol(first));
                }
            }
            RecordType::AeadAlgorithm => {
                let algos = record.algorithm_ids();
                // Take the first algorithm the server offers
                if let Some(&alg) = algos.first() {
                    algorithm = Some(alg);
                }
            }
            RecordType::NewCookieForNtpv4 => {
                cookies.push(record.body.clone());
            }
            RecordType::NtpV4ServerNegotiation => {
                server = Some(
                    String::from_utf8(record.body.clone())
                        .map_err(|_| NtsError::InvalidCookie("invalid server name UTF-8".to_string()))?,
                );
            }
            RecordType::NtpV4PortNegotiation => {
                if record.body.len() >= 2 {
                    port = Some(u16::from_be_bytes([record.body[0], record.body[1]]));
                }
            }
            RecordType::Error => {
                if record.body.len() >= 2 {
                    let code = u16::from_be_bytes([record.body[0], record.body[1]]);
                    return Err(NtsError::KeError(code));
                }
            }
            RecordType::Warning => {
                if record.body.len() >= 2 {
                    let code = u16::from_be_bytes([record.body[0], record.body[1]]);
                    tracing::warn!(code, "NTS-KE warning received");
                }
            }
            RecordType::EndOfMessage => break,
        }
    }

    if protocol.is_none() {
        return Err(NtsError::MissingRecord("NextProtocol"));
    }

    let aead_algorithm = algorithm.ok_or(NtsError::MissingRecord("AeadAlgorithm"))?;

    if cookies.is_empty() {
        return Err(NtsError::NoCookies);
    }

    Ok(ParsedKeResponse {
        aead_algorithm,
        cookies,
        server,
        port,
    })
}

/// Parse an NTS-KE client request and extract negotiation parameters.
pub fn parse_client_request(data: &[u8]) -> Result<ParsedKeRequest, NtsError> {
    let records = NtsKeRecord::parse_all(data)?;

    let mut protocol = None;
    let mut algorithms = Vec::new();

    for record in &records {
        match record.record_type {
            RecordType::NextProtocol => {
                let ids = record.protocol_ids();
                if ids.contains(&NTS_NEXT_PROTOCOL_NTPV4) {
                    protocol = Some(NTS_NEXT_PROTOCOL_NTPV4);
                } else if let Some(&first) = ids.first() {
                    return Err(NtsError::UnsupportedProtocol(first));
                }
            }
            RecordType::AeadAlgorithm => {
                algorithms.extend(record.algorithm_ids());
            }
            RecordType::EndOfMessage => break,
            _ => {
                if record.critical {
                    // Unknown critical record: respond with error
                    return Err(NtsError::UnknownRecordType(record.record_type as u16));
                }
                // Non-critical unknown records are ignored
            }
        }
    }

    if protocol.is_none() {
        return Err(NtsError::MissingRecord("NextProtocol"));
    }

    if algorithms.is_empty() {
        return Err(NtsError::MissingRecord("AeadAlgorithm"));
    }

    Ok(ParsedKeRequest { algorithms })
}

/// Parsed client NTS-KE request.
#[derive(Debug, Clone)]
pub struct ParsedKeRequest {
    /// AEAD algorithms offered by the client (in preference order).
    pub algorithms: Vec<u16>,
}

/// Parsed server NTS-KE response (before key derivation).
#[derive(Debug, Clone)]
pub struct ParsedKeResponse {
    /// Negotiated AEAD algorithm.
    pub aead_algorithm: u16,
    /// Cookies received from the server.
    pub cookies: Vec<Vec<u8>>,
    /// Optional NTP server to use.
    pub server: Option<String>,
    /// Optional NTP port to use.
    pub port: Option<u16>,
}

/// Select the best AEAD algorithm from the client's offered list.
///
/// Currently only supports AEAD_AES_SIV_CMAC_256 (mandatory-to-implement).
pub fn select_algorithm(offered: &[u16]) -> Option<u16> {
    if offered.contains(&AEAD_AES_SIV_CMAC_256) {
        Some(AEAD_AES_SIV_CMAC_256)
    } else {
        None
    }
}

/// Generate cookies for a new NTS-KE session.
///
/// Produces `count` cookies, each encrypting the same session keys.
pub fn generate_cookies(
    cookie_jar: &crate::cookie::CookieJar,
    c2s_key: &[u8],
    s2c_key: &[u8],
    algorithm: u16,
    count: usize,
) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| cookie_jar.make_cookie(c2s_key, s2c_key, algorithm))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_COOKIE_COUNT;
    use rand::RngCore;

    fn random_key() -> [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
        let mut key = [0u8; AEAD_AES_SIV_CMAC_256_KEYLEN];
        rand::rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn build_and_parse_client_request() {
        let data = build_client_request();
        let parsed = parse_client_request(&data).unwrap();
        assert_eq!(parsed.algorithms, vec![AEAD_AES_SIV_CMAC_256]);
    }

    #[test]
    fn build_and_parse_server_response() {
        let cookies = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        ];
        let data = build_server_response(
            AEAD_AES_SIV_CMAC_256,
            &cookies,
            Some("ntp.example.com"),
            Some(123),
        );

        let parsed = parse_server_response(&data).unwrap();
        assert_eq!(parsed.aead_algorithm, AEAD_AES_SIV_CMAC_256);
        assert_eq!(parsed.cookies, cookies);
        assert_eq!(parsed.server.as_deref(), Some("ntp.example.com"));
        assert_eq!(parsed.port, Some(123));
    }

    #[test]
    fn server_response_without_optional_fields() {
        let cookies = vec![vec![1, 2, 3]];
        let data = build_server_response(AEAD_AES_SIV_CMAC_256, &cookies, None, None);

        let parsed = parse_server_response(&data).unwrap();
        assert!(parsed.server.is_none());
        assert!(parsed.port.is_none());
    }

    #[test]
    fn server_response_no_cookies_fails() {
        let data = build_server_response(AEAD_AES_SIV_CMAC_256, &[], None, None);
        assert!(matches!(
            parse_server_response(&data),
            Err(NtsError::NoCookies)
        ));
    }

    #[test]
    fn select_algorithm_supported() {
        assert_eq!(
            select_algorithm(&[AEAD_AES_SIV_CMAC_256]),
            Some(AEAD_AES_SIV_CMAC_256)
        );
        assert_eq!(
            select_algorithm(&[99, AEAD_AES_SIV_CMAC_256, 100]),
            Some(AEAD_AES_SIV_CMAC_256)
        );
    }

    #[test]
    fn select_algorithm_unsupported() {
        assert_eq!(select_algorithm(&[99, 100]), None);
        assert_eq!(select_algorithm(&[]), None);
    }

    #[test]
    fn generate_cookies_count() {
        let mut jar = crate::cookie::CookieJar::new(random_key());
        let c2s = random_key();
        let s2c = random_key();

        let cookies = generate_cookies(&jar, &c2s, &s2c, AEAD_AES_SIV_CMAC_256, DEFAULT_COOKIE_COUNT);
        assert_eq!(cookies.len(), DEFAULT_COOKIE_COUNT);

        // Each cookie should decrypt to the same keys
        for cookie in &cookies {
            let contents = jar.open_cookie(cookie).unwrap();
            assert_eq!(contents.c2s_key, c2s);
            assert_eq!(contents.s2c_key, s2c);
            assert_eq!(contents.algorithm, AEAD_AES_SIV_CMAC_256);
        }
    }

    #[test]
    fn key_length_for_known_algorithm() {
        assert_eq!(
            key_length_for_algorithm(AEAD_AES_SIV_CMAC_256).unwrap(),
            AEAD_AES_SIV_CMAC_256_KEYLEN
        );
    }

    #[test]
    fn key_length_for_unknown_algorithm() {
        assert!(key_length_for_algorithm(999).is_err());
    }

    /// Mock TLS exporter for testing key derivation.
    struct MockExporter {
        material: Vec<u8>,
    }

    impl MockExporter {
        fn new(len: usize) -> Self {
            let mut material = vec![0u8; len];
            rand::rng().fill_bytes(&mut material);
            Self { material }
        }
    }

    impl ExporterInterface for MockExporter {
        fn export_keying_material(
            &self,
            output: &mut [u8],
            _label: &str,
            _context: Option<&[u8]>,
        ) -> Result<(), ExporterError> {
            if output.len() > self.material.len() {
                return Err(ExporterError::Failed("output too large".to_string()));
            }
            output.copy_from_slice(&self.material[..output.len()]);
            Ok(())
        }
    }

    #[test]
    fn derive_keys_splits_correctly() {
        let key_len = AEAD_AES_SIV_CMAC_256_KEYLEN;
        let exporter = MockExporter::new(key_len * 2);

        let (c2s, s2c) = derive_keys(&exporter, AEAD_AES_SIV_CMAC_256).unwrap();

        assert_eq!(c2s.len(), key_len);
        assert_eq!(s2c.len(), key_len);
        assert_eq!(&c2s, &exporter.material[..key_len]);
        assert_eq!(&s2c, &exporter.material[key_len..]);
        // C2S and S2C should (almost certainly) be different
        assert_ne!(c2s, s2c);
    }

    #[test]
    fn derive_keys_unsupported_algorithm() {
        let exporter = MockExporter::new(64);
        assert!(derive_keys(&exporter, 999).is_err());
    }

    #[test]
    fn full_ke_exchange_simulation() {
        // Simulate a complete NTS-KE exchange

        // 1. Client builds request
        let client_request = build_client_request();

        // 2. Server parses request
        let parsed_req = parse_client_request(&client_request).unwrap();

        // 3. Server selects algorithm
        let algorithm = select_algorithm(&parsed_req.algorithms)
            .expect("should find supported algorithm");
        assert_eq!(algorithm, AEAD_AES_SIV_CMAC_256);

        // 4. Both sides derive keys from TLS exporter
        let exporter = MockExporter::new(AEAD_AES_SIV_CMAC_256_KEYLEN * 2);
        let (c2s_key, s2c_key) = derive_keys(&exporter, algorithm).unwrap();

        // 5. Server generates cookies and builds response
        let mut jar = crate::cookie::CookieJar::new(random_key());
        let cookies = generate_cookies(&jar, &c2s_key, &s2c_key, algorithm, DEFAULT_COOKIE_COUNT);
        let server_response = build_server_response(algorithm, &cookies, None, None);

        // 6. Client parses response
        let parsed_resp = parse_server_response(&server_response).unwrap();
        assert_eq!(parsed_resp.aead_algorithm, algorithm);
        assert_eq!(parsed_resp.cookies.len(), DEFAULT_COOKIE_COUNT);

        // 7. Verify cookies are valid (server can open them)
        for cookie in &parsed_resp.cookies {
            let contents = jar.open_cookie(cookie).unwrap();
            assert_eq!(contents.c2s_key, c2s_key);
            assert_eq!(contents.s2c_key, s2c_key);
            assert_eq!(contents.algorithm, algorithm);
        }
    }

    #[test]
    fn error_record_in_response() {
        let mut data = Vec::new();
        data.extend_from_slice(&NtsKeRecord::next_protocol(&[NTS_NEXT_PROTOCOL_NTPV4]).serialize());
        data.extend_from_slice(&NtsKeRecord::error(1).serialize());
        data.extend_from_slice(&NtsKeRecord::end_of_message().serialize());

        assert!(matches!(
            parse_server_response(&data),
            Err(NtsError::KeError(1))
        ));
    }
}
