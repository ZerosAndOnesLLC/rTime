//! AEAD operations for NTS using AES-SIV-CMAC-256 (RFC 8915 Section 5.1).
//!
//! AEAD_AES_SIV_CMAC_256 is the mandatory-to-implement algorithm for NTS.
//! It corresponds to `Aes128SivAead` in the `aes-siv` crate because
//! "256" refers to the output tag size (256 bits = 32 bytes), while
//! internally it uses two 128-bit subkeys, totaling a 32-byte key.

use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes128SivAead;

use crate::{AEAD_AES_SIV_CMAC_256_KEYLEN, NtsError};

/// SIV tag size for AES-SIV (16 bytes).
pub const SIV_TAG_SIZE: usize = 16;

/// Handles AEAD encryption and decryption for NTS.
///
/// Maintains separate keys for client-to-server (C2S) and server-to-client (S2C)
/// directions as specified by RFC 8915.
pub struct NtsAead {
    c2s_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    s2c_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
}

impl NtsAead {
    /// Create a new AEAD context with the given directional keys.
    ///
    /// Each key must be exactly 32 bytes (for AEAD_AES_SIV_CMAC_256).
    pub fn new(
        c2s_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
        s2c_key: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    ) -> Self {
        Self { c2s_key, s2c_key }
    }

    /// Create from variable-length slices (validates length).
    pub fn from_slices(c2s_key: &[u8], s2c_key: &[u8]) -> Result<Self, NtsError> {
        let c2s: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] = c2s_key.try_into().map_err(|_| {
            NtsError::InvalidCookie(format!(
                "C2S key length {} != {}",
                c2s_key.len(),
                AEAD_AES_SIV_CMAC_256_KEYLEN
            ))
        })?;
        let s2c: [u8; AEAD_AES_SIV_CMAC_256_KEYLEN] = s2c_key.try_into().map_err(|_| {
            NtsError::InvalidCookie(format!(
                "S2C key length {} != {}",
                s2c_key.len(),
                AEAD_AES_SIV_CMAC_256_KEYLEN
            ))
        })?;
        Ok(Self::new(c2s, s2c))
    }

    /// Get the C2S key.
    pub fn c2s_key(&self) -> &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
        &self.c2s_key
    }

    /// Get the S2C key.
    pub fn s2c_key(&self) -> &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN] {
        &self.s2c_key
    }

    /// Encrypt plaintext with associated data in the client-to-server direction.
    ///
    /// The nonce is combined with the AAD for the SIV construction.
    /// The returned ciphertext includes the SIV tag prepended (16 bytes + plaintext length).
    pub fn encrypt_c2s(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NtsError> {
        encrypt_aes_siv(&self.c2s_key, nonce, plaintext, aad)
    }

    /// Decrypt ciphertext with associated data in the server-to-client direction.
    ///
    /// The ciphertext must include the SIV tag prepended.
    pub fn decrypt_s2c(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NtsError> {
        decrypt_aes_siv(&self.s2c_key, nonce, ciphertext, aad)
    }

    /// Encrypt plaintext with associated data in the server-to-client direction.
    pub fn encrypt_s2c(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NtsError> {
        encrypt_aes_siv(&self.s2c_key, nonce, plaintext, aad)
    }

    /// Decrypt ciphertext with associated data in the client-to-server direction.
    pub fn decrypt_c2s(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NtsError> {
        decrypt_aes_siv(&self.c2s_key, nonce, ciphertext, aad)
    }
}

/// Encrypt using AES-SIV-CMAC-256.
///
/// AES-SIV is a nonce-misuse-resistant AEAD. In this implementation, the caller's
/// nonce and AAD are combined into the associated data for the SIV construction.
/// The AEAD nonce parameter is set to all zeros (the SIV itself provides
/// the initialization vector for the underlying CTR mode encryption).
fn encrypt_aes_siv(
    key: &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, NtsError> {
    let cipher = Aes128SivAead::new(key.into());

    // Combine the caller's nonce and AAD into the SIV associated data.
    let mut combined_aad = Vec::with_capacity(nonce.len() + aad.len());
    combined_aad.extend_from_slice(nonce);
    combined_aad.extend_from_slice(aad);

    let payload = Payload {
        msg: plaintext,
        aad: &combined_aad,
    };

    // Use a zero nonce for the Aead trait call. The SIV construction
    // derives its own IV from the authentication tag.
    let zero_nonce = GenericArray::default();
    cipher
        .encrypt(&zero_nonce, payload)
        .map_err(|_| NtsError::EncryptionFailed)
}

/// Decrypt using AES-SIV-CMAC-256.
fn decrypt_aes_siv(
    key: &[u8; AEAD_AES_SIV_CMAC_256_KEYLEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, NtsError> {
    let cipher = Aes128SivAead::new(key.into());

    let mut combined_aad = Vec::with_capacity(nonce.len() + aad.len());
    combined_aad.extend_from_slice(nonce);
    combined_aad.extend_from_slice(aad);

    let payload = Payload {
        msg: ciphertext,
        aad: &combined_aad,
    };

    let zero_nonce = GenericArray::default();
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
    fn encrypt_decrypt_c2s_roundtrip() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"Hello, NTS!";
        let nonce = b"unique-nonce-123";
        let aad = b"NTP packet header";

        let ciphertext = aead.encrypt_c2s(nonce, plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..], plaintext);
        // Ciphertext should be plaintext + SIV tag (16 bytes)
        assert_eq!(ciphertext.len(), plaintext.len() + SIV_TAG_SIZE);

        let decrypted = aead.decrypt_c2s(nonce, &ciphertext, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_s2c_roundtrip() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"Server response data";
        let nonce = b"server-nonce-456";
        let aad = b"response header";

        let ciphertext = aead.encrypt_s2c(nonce, plaintext, aad).unwrap();
        let decrypted = aead.decrypt_s2c(nonce, &ciphertext, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"secret data";
        let nonce = b"nonce";
        let aad = b"aad";

        let ciphertext = aead.encrypt_c2s(nonce, plaintext, aad).unwrap();

        // Try to decrypt with S2C key (wrong direction)
        let result = aead.decrypt_s2c(nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"integrity test";
        let nonce = b"nonce";
        let aad = b"aad";

        let mut ciphertext = aead.encrypt_c2s(nonce, plaintext, aad).unwrap();
        // Flip a bit
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0x01;
        }

        let result = aead.decrypt_c2s(nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"aad test";
        let nonce = b"nonce";

        let ciphertext = aead.encrypt_c2s(nonce, plaintext, b"correct aad").unwrap();
        let result = aead.decrypt_c2s(nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let plaintext = b"nonce test";
        let aad = b"aad";

        let ciphertext = aead.encrypt_c2s(b"nonce-1", plaintext, aad).unwrap();
        let result = aead.decrypt_c2s(b"nonce-2", &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext() {
        let c2s_key = random_key();
        let s2c_key = random_key();
        let aead = NtsAead::new(c2s_key, s2c_key);

        let ciphertext = aead.encrypt_c2s(b"nonce", b"", b"aad").unwrap();
        assert_eq!(ciphertext.len(), SIV_TAG_SIZE); // Just the tag

        let decrypted = aead.decrypt_c2s(b"nonce", &ciphertext, b"aad").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn from_slices_valid() {
        let c2s = random_key();
        let s2c = random_key();
        let aead = NtsAead::from_slices(&c2s, &s2c).unwrap();

        let ct = aead.encrypt_c2s(b"n", b"test", b"a").unwrap();
        let pt = aead.decrypt_c2s(b"n", &ct, b"a").unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn from_slices_wrong_length() {
        let short = [0u8; 16];
        let correct = random_key();
        assert!(NtsAead::from_slices(&short, &correct).is_err());
        assert!(NtsAead::from_slices(&correct, &short).is_err());
    }
}
