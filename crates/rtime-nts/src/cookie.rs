//! NTS cookie generation and validation (RFC 8915 Section 6).
//!
//! Cookies contain the encrypted session keys (c2s_key, s2c_key) and the
//! AEAD algorithm identifier. The server encrypts them using a master key
//! so that clients cannot forge or inspect cookie contents.
//!
//! Cookie format (our implementation):
//! ```text
//! +--------+--------+------------------+
//! | key_id | nonce  | encrypted_data   |
//! | 4 bytes| 16 byte| variable         |
//! +--------+--------+------------------+
//! ```
//!
//! The encrypted data contains:
//! ```text
//! +----------+----------+-----------+
//! | algo(2B) | c2s_key  | s2c_key   |
//! +----------+----------+-----------+
//! ```

use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes128SivAead;
use rand::RngCore;

use crate::{AEAD_AES_SIV_CMAC_256_KEYLEN, NtsError};

/// Size of the key identifier in cookies.
const KEY_ID_SIZE: usize = 4;

/// Current key identifier value.
const CURRENT_KEY_ID: u32 = 1;

/// Previous key identifier value (after rotation).
const _PREVIOUS_KEY_ID: u32 = 0;

/// Nonce size for cookie encryption.
const COOKIE_NONCE_SIZE: usize = 16;

/// Result of decrypting a cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieContents {
    /// The AEAD algorithm identifier.
    pub algorithm: u16,
    /// The client-to-server key.
    pub c2s_key: Vec<u8>,
    /// The server-to-client key.
    pub s2c_key: Vec<u8>,
}

/// Server-side cookie management.
///
/// Cookies contain encrypted (c2s_key, s2c_key, aead_algorithm) using a server
/// master key. The `CookieJar` supports key rotation by keeping track of
/// both the current and previous master key.
pub struct CookieJar {
    current_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    previous_key: Option<[u8; AEAD_AES_SIV_CMAC_256_KEYLEN]>,
}

impl CookieJar {
    /// Create a new cookie jar with the given master key.
    pub fn new(master_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN]) -> Self {
        Self {
            current_key: master_key,
            previous_key: None,
        }
    }

    /// Generate a cookie encrypting the given session keys and algorithm.
    ///
    /// Returns an opaque cookie byte vector that can be sent to the client.
    pub fn make_cookie(&self, c2s_key: &[u8], s2c_key: &[u8], algorithm: u16) -> Vec<u8> {
        // Build plaintext: algorithm (2 bytes) + c2s_key + s2c_key
        let mut plaintext = Vec::with_capacity(2 + c2s_key.len() + s2c_key.len());
        plaintext.extend_from_slice(&algorithm.to_be_bytes());
        plaintext.extend_from_slice(c2s_key);
        plaintext.extend_from_slice(s2c_key);

        // Generate random nonce for AAD
        let mut nonce = [0u8; COOKIE_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);

        // Encrypt with current key
        let cipher = Aes128SivAead::new((&self.current_key).into());
        let zero_nonce = GenericArray::default();
        let payload = Payload {
            msg: &plaintext,
            aad: &nonce,
        };
        let ciphertext = cipher
            .encrypt(&zero_nonce, payload)
            .expect("cookie encryption should not fail with valid key");

        // Build cookie: key_id (4 bytes) + nonce (16 bytes) + ciphertext
        let mut cookie = Vec::with_capacity(KEY_ID_SIZE + COOKIE_NONCE_SIZE + ciphertext.len());
        cookie.extend_from_slice(&CURRENT_KEY_ID.to_be_bytes());
        cookie.extend_from_slice(&nonce);
        cookie.extend_from_slice(&ciphertext);

        cookie
    }

    /// Validate and decrypt a cookie, returning the session keys and algorithm.
    pub fn open_cookie(&self, cookie: &[u8]) -> Result<CookieContents, NtsError> {
        let min_size = KEY_ID_SIZE + COOKIE_NONCE_SIZE;
        if cookie.len() < min_size {
            return Err(NtsError::InvalidCookie(format!(
                "cookie too short: {} bytes, need at least {}",
                cookie.len(),
                min_size
            )));
        }

        let key_id = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
        let nonce = &cookie[KEY_ID_SIZE..KEY_ID_SIZE + COOKIE_NONCE_SIZE];
        let ciphertext = &cookie[KEY_ID_SIZE + COOKIE_NONCE_SIZE..];

        // Try to decrypt with the current key first, then fall back to the
        // previous key. After key rotation, existing cookies still carry the
        // old key_id but need to be decrypted with what is now the previous key.
        let plaintext = match decrypt_cookie_data(&self.current_key, nonce, ciphertext) {
            Ok(pt) => pt,
            Err(_) => {
                if let Some(ref prev_key) = self.previous_key {
                    decrypt_cookie_data(prev_key, nonce, ciphertext)?
                } else {
                    return Err(NtsError::InvalidCookie(format!(
                        "decryption failed with current key and no previous key (key_id={})",
                        key_id
                    )));
                }
            }
        };

        // Parse plaintext: algorithm (2 bytes) + c2s_key + s2c_key
        if plaintext.len() < 2 {
            return Err(NtsError::InvalidCookie(
                "decrypted cookie too short for algorithm".to_string(),
            ));
        }

        let algorithm = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let key_data = &plaintext[2..];

        // Keys should be equal length (both are AEAD key length)
        if key_data.len() % 2 != 0 {
            return Err(NtsError::InvalidCookie(
                "key data has odd length".to_string(),
            ));
        }
        let key_len = key_data.len() / 2;
        let c2s_key = key_data[..key_len].to_vec();
        let s2c_key = key_data[key_len..].to_vec();

        Ok(CookieContents {
            algorithm,
            c2s_key,
            s2c_key,
        })
    }

    /// Rotate the master key. The current key becomes the previous key.
    pub fn rotate_key(&mut self, new_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN]) {
        self.previous_key = Some(self.current_key);
        self.current_key = new_key;
    }

    /// Get a reference to the current master key.
    pub fn current_key(&self) -> &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
        &self.current_key
    }
}

/// Decrypt cookie data with a specific key.
fn decrypt_cookie_data(
    key: &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NtsError> {
    let cipher = Aes128SivAead::new(key.into());
    let zero_nonce = GenericArray::default();
    let payload = Payload {
        msg: ciphertext,
        aad: nonce,
    };
    cipher
        .decrypt(&zero_nonce, payload)
        .map_err(|_| NtsError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
        let mut key = [0u8; AEAD_AES_SIV_CMAC_256_KEYLEN];
        rand::rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn make_open_roundtrip() {
        let master_key = random_key();
        let jar = CookieJar::new(master_key);

        let c2s_key = random_key();
        let s2c_key = random_key();
        let algorithm = 15u16; // AEAD_AES_SIV_CMAC_256

        let cookie = jar.make_cookie(&c2s_key, &s2c_key, algorithm);
        let contents = jar.open_cookie(&cookie).unwrap();

        assert_eq!(contents.algorithm, algorithm);
        assert_eq!(contents.c2s_key, c2s_key);
        assert_eq!(contents.s2c_key, s2c_key);
    }

    #[test]
    fn different_cookies_are_unique() {
        let master_key = random_key();
        let jar = CookieJar::new(master_key);

        let c2s_key = random_key();
        let s2c_key = random_key();

        let cookie1 = jar.make_cookie(&c2s_key, &s2c_key, 15);
        let cookie2 = jar.make_cookie(&c2s_key, &s2c_key, 15);

        // Same keys but different nonces, so cookies should differ
        assert_ne!(cookie1, cookie2);

        // Both should decrypt successfully
        let c1 = jar.open_cookie(&cookie1).unwrap();
        let c2 = jar.open_cookie(&cookie2).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn wrong_master_key_fails() {
        let jar1 = CookieJar::new(random_key());
        let jar2 = CookieJar::new(random_key());

        let cookie = jar1.make_cookie(&random_key(), &random_key(), 15);
        assert!(jar2.open_cookie(&cookie).is_err());
    }

    #[test]
    fn key_rotation_current_key_works() {
        let key1 = random_key();
        let key2 = random_key();
        let mut jar = CookieJar::new(key1);

        // Make a cookie with key1
        let c2s = random_key();
        let s2c = random_key();
        let cookie_old = jar.make_cookie(&c2s, &s2c, 15);

        // Rotate to key2
        jar.rotate_key(key2);

        // Old cookie (made with key1, now the previous key) should still work
        let contents = jar.open_cookie(&cookie_old).unwrap();
        assert_eq!(contents.c2s_key, c2s);
        assert_eq!(contents.s2c_key, s2c);
    }

    #[test]
    fn key_rotation_new_key_works() {
        let key1 = random_key();
        let key2 = random_key();
        let mut jar = CookieJar::new(key1);

        jar.rotate_key(key2);

        // Make a cookie with key2 (new current key)
        let c2s = random_key();
        let s2c = random_key();
        let cookie_new = jar.make_cookie(&c2s, &s2c, 15);

        let contents = jar.open_cookie(&cookie_new).unwrap();
        assert_eq!(contents.c2s_key, c2s);
        assert_eq!(contents.s2c_key, s2c);
    }

    #[test]
    fn double_rotation_drops_oldest_key() {
        let key1 = random_key();
        let key2 = random_key();
        let key3 = random_key();
        let mut jar = CookieJar::new(key1);

        let cookie_k1 = jar.make_cookie(&random_key(), &random_key(), 15);

        jar.rotate_key(key2);
        // key1 is now previous, cookie_k1 should still work
        assert!(jar.open_cookie(&cookie_k1).is_ok());

        jar.rotate_key(key3);
        // key2 is now previous, key1 is gone. cookie_k1 should fail.
        assert!(jar.open_cookie(&cookie_k1).is_err());
    }

    #[test]
    fn tampered_cookie_fails() {
        let jar = CookieJar::new(random_key());
        let mut cookie = jar.make_cookie(&random_key(), &random_key(), 15);

        // Tamper with a byte in the ciphertext portion
        let last = cookie.len() - 1;
        cookie[last] ^= 0xFF;

        assert!(jar.open_cookie(&cookie).is_err());
    }

    #[test]
    fn too_short_cookie_fails() {
        let jar = CookieJar::new(random_key());
        assert!(jar.open_cookie(&[0u8; 10]).is_err());
    }

    #[test]
    fn cookie_preserves_algorithm() {
        let jar = CookieJar::new(random_key());
        let c2s = random_key();
        let s2c = random_key();

        for algo in [15u16, 16, 0, 0xFFFF] {
            let cookie = jar.make_cookie(&c2s, &s2c, algo);
            let contents = jar.open_cookie(&cookie).unwrap();
            assert_eq!(contents.algorithm, algo);
        }
    }
}
