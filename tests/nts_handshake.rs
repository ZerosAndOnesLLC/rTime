//! NTS authentication roundtrip integration tests.
//!
//! Tests the complete NTS-KE handshake flow: record creation, parsing,
//! key derivation, cookie management, and AEAD authentication.

use rand::RngCore;
use rtime_nts::aead::{NtsAead, SIV_TAG_SIZE};
use rtime_nts::cookie::CookieJar;
use rtime_nts::ke::{
    build_client_request, build_server_response, derive_keys, generate_cookies,
    parse_client_request, parse_server_response, select_algorithm, ExporterError,
    ExporterInterface,
};
use rtime_nts::records::{NtsKeRecord, RecordType};
use rtime_nts::{AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_256_KEYLEN, DEFAULT_COOKIE_COUNT};

fn random_key() -> [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
    let mut key = [0u8; AEAD_AES_SIV_CMAC_256_KEYLEN];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Mock TLS exporter for testing key derivation without a real TLS connection.
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
fn full_nts_ke_handshake() {
    // 1. Client builds request.
    let client_request = build_client_request();

    // 2. Server parses client request.
    let parsed_req = parse_client_request(&client_request).unwrap();
    assert!(
        parsed_req.algorithms.contains(&AEAD_AES_SIV_CMAC_256),
        "client should offer AEAD_AES_SIV_CMAC_256"
    );

    // 3. Server selects algorithm.
    let algorithm =
        select_algorithm(&parsed_req.algorithms).expect("should find supported algorithm");
    assert_eq!(algorithm, AEAD_AES_SIV_CMAC_256);

    // 4. Both sides derive keys from TLS exporter (mocked).
    let exporter = MockExporter::new(AEAD_AES_SIV_CMAC_256_KEYLEN * 2);
    let (c2s_key, s2c_key) = derive_keys(&exporter, algorithm).unwrap();
    assert_eq!(c2s_key.len(), AEAD_AES_SIV_CMAC_256_KEYLEN);
    assert_eq!(s2c_key.len(), AEAD_AES_SIV_CMAC_256_KEYLEN);
    assert_ne!(c2s_key, s2c_key, "C2S and S2C keys should differ");

    // 5. Server generates cookies and builds response.
    let master_key = random_key();
    let mut jar = CookieJar::new(master_key);
    let cookies = generate_cookies(&jar, &c2s_key, &s2c_key, algorithm, DEFAULT_COOKIE_COUNT);
    assert_eq!(cookies.len(), DEFAULT_COOKIE_COUNT);

    let server_response =
        build_server_response(algorithm, &cookies, Some("ntp.example.com"), Some(123));

    // 6. Client parses response.
    let parsed_resp = parse_server_response(&server_response).unwrap();
    assert_eq!(parsed_resp.aead_algorithm, AEAD_AES_SIV_CMAC_256);
    assert_eq!(parsed_resp.cookies.len(), DEFAULT_COOKIE_COUNT);
    assert_eq!(parsed_resp.server.as_deref(), Some("ntp.example.com"));
    assert_eq!(parsed_resp.port, Some(123));

    // 7. Server can open all cookies and recover the session keys.
    for cookie in &parsed_resp.cookies {
        let contents = jar.open_cookie(cookie).unwrap();
        assert_eq!(contents.algorithm, AEAD_AES_SIV_CMAC_256);
        assert_eq!(contents.c2s_key, c2s_key);
        assert_eq!(contents.s2c_key, s2c_key);
    }

    // 8. AEAD operations work with the derived keys.
    let c2s_arr: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] = c2s_key.clone().try_into().unwrap();
    let s2c_arr: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] = s2c_key.clone().try_into().unwrap();
    let aead = NtsAead::new(c2s_arr, s2c_arr);

    let nonce = b"unique-nonce-val";
    let plaintext = b"NTP extension field payload";
    let aad = b"NTP packet header bytes";

    let ciphertext = aead.encrypt_c2s(nonce, plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + SIV_TAG_SIZE);

    let decrypted = aead.decrypt_c2s(nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn cookie_survives_key_rotation() {
    let key1 = random_key();
    let key2 = random_key();
    let mut jar = CookieJar::new(key1);

    let c2s_key = random_key();
    let s2c_key = random_key();

    // Make cookies with old key.
    let cookies_old = generate_cookies(&jar, &c2s_key, &s2c_key, AEAD_AES_SIV_CMAC_256, 4);

    // Rotate key.
    jar.rotate_key(key2);

    // Old cookies should still be decryptable.
    for cookie in &cookies_old {
        let contents = jar.open_cookie(cookie).unwrap();
        assert_eq!(contents.c2s_key, c2s_key);
        assert_eq!(contents.s2c_key, s2c_key);
    }

    // New cookies with new key should also work.
    let cookies_new = generate_cookies(&jar, &c2s_key, &s2c_key, AEAD_AES_SIV_CMAC_256, 4);
    for cookie in &cookies_new {
        let contents = jar.open_cookie(cookie).unwrap();
        assert_eq!(contents.c2s_key, c2s_key);
    }
}

#[test]
fn aead_directional_isolation() {
    // Verify that C2S-encrypted data cannot be decrypted with the S2C key and vice versa.
    let aead = NtsAead::new(random_key(), random_key());
    let nonce = b"test-nonce";
    let plaintext = b"directional test data";
    let aad = b"aad";

    // Encrypt with C2S key.
    let ct = aead.encrypt_c2s(nonce, plaintext, aad).unwrap();

    // Should decrypt with C2S key.
    let pt = aead.decrypt_c2s(nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);

    // Should NOT decrypt with S2C key.
    let bad_result = aead.decrypt_s2c(nonce, &ct, aad);
    assert!(
        bad_result.is_err(),
        "S2C key should not decrypt C2S-encrypted data"
    );

    // And the reverse.
    let ct_s2c = aead.encrypt_s2c(nonce, plaintext, aad).unwrap();
    let pt_s2c = aead.decrypt_s2c(nonce, &ct_s2c, aad).unwrap();
    assert_eq!(pt_s2c, plaintext);

    let bad_c2s = aead.decrypt_c2s(nonce, &ct_s2c, aad);
    assert!(
        bad_c2s.is_err(),
        "C2S key should not decrypt S2C-encrypted data"
    );
}

#[test]
fn nts_ke_records_roundtrip() {
    // Build a full set of NTS-KE records and verify they roundtrip through
    // serialization and parsing.
    let mut wire_data = Vec::new();
    wire_data.extend_from_slice(&NtsKeRecord::next_protocol(&[0]).serialize());
    wire_data.extend_from_slice(&NtsKeRecord::aead_algorithm(&[AEAD_AES_SIV_CMAC_256]).serialize());
    wire_data.extend_from_slice(&NtsKeRecord::new_cookie(vec![0xAA; 64]).serialize());
    wire_data.extend_from_slice(&NtsKeRecord::new_cookie(vec![0xBB; 64]).serialize());
    wire_data
        .extend_from_slice(&NtsKeRecord::server_negotiation("time.example.org").serialize());
    wire_data.extend_from_slice(&NtsKeRecord::port_negotiation(4460).serialize());
    wire_data.extend_from_slice(&NtsKeRecord::end_of_message().serialize());

    let records = NtsKeRecord::parse_all(&wire_data).unwrap();
    assert_eq!(records.len(), 7);

    assert_eq!(records[0].record_type, RecordType::NextProtocol);
    assert!(records[0].critical);
    assert_eq!(records[0].protocol_ids(), vec![0]);

    assert_eq!(records[1].record_type, RecordType::AeadAlgorithm);
    assert!(!records[1].critical);
    assert_eq!(records[1].algorithm_ids(), vec![AEAD_AES_SIV_CMAC_256]);

    assert_eq!(records[2].record_type, RecordType::NewCookieForNtpv4);
    assert_eq!(records[2].body, vec![0xAA; 64]);

    assert_eq!(records[3].record_type, RecordType::NewCookieForNtpv4);
    assert_eq!(records[3].body, vec![0xBB; 64]);

    assert_eq!(records[4].record_type, RecordType::NtpV4ServerNegotiation);
    assert_eq!(
        std::str::from_utf8(&records[4].body).unwrap(),
        "time.example.org"
    );

    assert_eq!(records[5].record_type, RecordType::NtpV4PortNegotiation);
    assert_eq!(
        u16::from_be_bytes([records[5].body[0], records[5].body[1]]),
        4460
    );

    assert_eq!(records[6].record_type, RecordType::EndOfMessage);
    assert!(records[6].critical);
}

#[test]
fn tampered_cookie_is_rejected() {
    let mut jar = CookieJar::new(random_key());
    let c2s = random_key();
    let s2c = random_key();

    let mut cookie = jar.make_cookie(&c2s, &s2c, AEAD_AES_SIV_CMAC_256);

    // Flip a byte in the ciphertext.
    let last = cookie.len() - 1;
    cookie[last] ^= 0xFF;

    let result = jar.open_cookie(&cookie);
    assert!(result.is_err(), "tampered cookie should be rejected");
}

#[test]
fn wrong_master_key_rejects_cookie() {
    let jar1 = CookieJar::new(random_key());
    let mut jar2 = CookieJar::new(random_key());

    let cookie = jar1.make_cookie(&random_key(), &random_key(), AEAD_AES_SIV_CMAC_256);

    let result = jar2.open_cookie(&cookie);
    assert!(
        result.is_err(),
        "cookie from a different server should be rejected"
    );
}
