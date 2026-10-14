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
    hkdf_with_info(secret, salt, b"", length)
}

/// HKDF-SHA256 with an explicit `info` parameter.
///
/// `hkdf` is this with an empty `info`.
pub fn hkdf_with_info(
    secret: &[u8],
    salt: &str,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
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
        // Each round hashes T || info || counter.
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);

        t = hmac_sha256(&input, &prk);

        let to_copy = std::cmp::min(32, length - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);

        offset += to_copy;
        counter = counter.wrapping_add(1);
    }

    Ok(output)
}

/// Salt for a per-message key derived from a conversation key.
pub const MESSAGE_KEY_SALT: &str = "xchat-message-key";

/// Salt for an attachment key derived from a message key.
pub const ATTACHMENT_KEY_SALT: &str = "xchat-attachment-key";

/// Contents encryption version that selects a per-message key.
pub const MESSAGE_KEY_VERSION: i16 = 1;

/// Whether `contents_encryption_version` selects a per-message key.
pub fn uses_message_key(version: Option<i16>) -> bool {
    matches!(version, Some(v) if v >= MESSAGE_KEY_VERSION)
}

/// 32-byte message key: HKDF-SHA256(conversation key, salt `xchat-message-key`,
/// info `<sender_id>:<message_id>`).
pub fn derive_message_key(
    conversation_key: &[u8],
    sender_id: &str,
    message_id: &str,
) -> Result<Vec<u8>, CryptoError> {
    let info = format!("{sender_id}:{message_id}");
    hkdf_with_info(conversation_key, MESSAGE_KEY_SALT, info.as_bytes(), 32)
}

/// 32-byte attachment key: HKDF-SHA256(message key, salt `xchat-attachment-key`,
/// info the attachment id as UTF-8).
pub fn derive_attachment_key(
    message_key: &[u8],
    attachment_id: &str,
) -> Result<Vec<u8>, CryptoError> {
    hkdf_with_info(
        message_key,
        ATTACHMENT_KEY_SALT,
        attachment_id.as_bytes(),
        32,
    )
}

/// Attachment id used for key derivation.
///
/// A stored id is kept as given, including the empty string. A missing id is
/// the message id for the first attachment and `<message_id>#<index>` after.
pub fn resolve_attachment_id(stored: Option<&str>, message_id: &str, index: usize) -> String {
    match stored {
        Some(id) => id.to_string(),
        None if index == 0 => message_id.to_string(),
        None => format!("{message_id}#{index}"),
    }
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
    fn message_and_attachment_keys_match_known_answers() {
        let conv = hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let message = derive_message_key(
            &conv,
            "1876543210987654321",
            "9d8c7b6a-5f4e-4d3c-8b2a-190807060504",
        )
        .unwrap();
        assert_eq!(
            hex_encode(&message),
            "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084"
        );
        let first =
            derive_attachment_key(&message, "9d8c7b6a-5f4e-4d3c-8b2a-190807060504").unwrap();
        assert_eq!(
            hex_encode(&first),
            "1ef86545f91f8a3078e276949f7555df2ca584e9c6509b261a558a2e618a1b4b"
        );
        let second =
            derive_attachment_key(&message, "9d8c7b6a-5f4e-4d3c-8b2a-190807060504#1").unwrap();
        assert_eq!(
            hex_encode(&second),
            "8a7bc01f2ff35c661140da68606b2370cecc13810f245d791aeb8ba6b40d4ea8"
        );

        let short_conv =
            hex_decode("c3a1f0e2d4b6987a5c3e1f0d2b4a6987c3a1f0e2d4b6987a5c3e1f0d2b4a6987");
        let short =
            derive_message_key(&short_conv, "12", "00000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!(
            hex_encode(&short),
            "685bd4a20c7efb64c99147ab5854560c72eac9a826b04880b64e1951d4ef4cc7"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

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
