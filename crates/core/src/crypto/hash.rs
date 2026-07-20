//! Hash utilities for the X Chat SDK.
//!
//! Provides SHA-256, HKDF-SHA256, and HMAC-SHA256 operations.
//! Uses pure-Rust implementations that are WASM-compatible.
//!

use crate::error::CryptoError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 hash of the input bytes.
///
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256.
///
pub fn hmac_sha256(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Compute HKDF-SHA256 key derivation.
///
/// Compatible with the X Chat key derivation scheme.
///
/// # Arguments
/// * `secret` - The input keying material
/// * `salt` - Salt value (empty string uses 32 zero bytes)
/// * `length` - Desired output length (max 32 * 255 = 8160 bytes)
///
pub fn hkdf(secret: &[u8], salt: &str, length: usize) -> Result<Vec<u8>, CryptoError> {
    // Maximum output length per HKDF spec
    const MAX_LENGTH: usize = 32 * 255;

    if length > MAX_LENGTH {
        return Err(CryptoError::HkdfFailed(format!(
            "Requested length {} exceeds maximum {}",
            length, MAX_LENGTH
        )));
    }

    // An empty salt expands to 32 zero bytes.
    let salt_bytes: Vec<u8> = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.as_bytes().to_vec()
    };

    // HKDF-Extract: PRK = HMAC-SHA256(key=salt, msg=IKM). Note hmac_sha256
    // takes (msg, key), so the salt is passed as the second argument.
    let prk = hmac_sha256(secret, &salt_bytes);

    // HKDF-Expand
    let mut output = vec![0u8; length];
    let mut offset = 0;
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while offset < length {
        // Each round hashes T || counter. The HKDF "info" parameter is omitted,
        // so there is no domain separation between derived keys.
        let mut input = t.clone();
        input.push(counter);

        t = hmac_sha256(&input, &prk);

        let to_copy = std::cmp::min(32, length - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);

        offset += to_copy;
        counter = counter.wrapping_add(1);
    }

    Ok(output)
}

/// X9.63 Key Derivation Function (KDF2).
///
/// Used by the ECIES implementation for deriving AES keys. Each round
/// computes Hash(Z || counter || SharedInfo), concatenated and truncated
/// to the requested length.
///
/// # Arguments
/// * `shared_secret` - The shared secret from ECDH (Z)
/// * `shared_info` - Shared info bytes (typically the ephemeral public key)
/// * `length` - Desired output length in bytes
///
pub fn kdf2_sha256(shared_secret: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32; // SHA-256 output size
    let iterations = length.div_ceil(hash_len);

    let mut result = Vec::with_capacity(iterations * hash_len);

    for counter in 1..=iterations {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        // Counter is 4-byte big-endian
        hasher.update((counter as u32).to_be_bytes());
        hasher.update(shared_info);
        result.extend_from_slice(&hasher.finalize());
    }

    result.truncate(length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Test vector: SHA256("hello")
        let result = sha256(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_empty() {
        // Test vector: SHA256("")
        let result = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha256() {
        // Test vector from RFC 4231
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let result = hmac_sha256(data, &key);
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hkdf_basic() {
        // Generate 32 bytes from a simple secret
        let secret = b"secret key material";
        let result = hkdf(secret, "conversation key", 32).unwrap();
        assert_eq!(result.len(), 32);

        // Same inputs should produce same output (deterministic)
        let result2 = hkdf(secret, "conversation key", 32).unwrap();
        assert_eq!(result, result2);

        // Different salt should produce different output
        let result3 = hkdf(secret, "different salt", 32).unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hkdf_empty_salt() {
        // Empty salt should use 32 zero bytes
        let secret = b"secret";
        let result = hkdf(secret, "", 32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_various_lengths() {
        let secret = b"secret";

        // Small output
        let result = hkdf(secret, "salt", 16).unwrap();
        assert_eq!(result.len(), 16);

        // Larger output (multiple blocks)
        let result = hkdf(secret, "salt", 64).unwrap();
        assert_eq!(result.len(), 64);

        // Maximum allowed
        let result = hkdf(secret, "salt", 32 * 255).unwrap();
        assert_eq!(result.len(), 32 * 255);
    }

    #[test]
    fn test_hkdf_max_length_exceeded() {
        let secret = b"secret";
        let result = hkdf(secret, "salt", 32 * 255 + 1);
        assert!(result.is_err());
    }
}
