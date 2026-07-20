//! Key type definitions for the X Chat SDK.
//!
//! This module defines the core key types used throughout the SDK:
//! - `XChatKeyPair` - Public/private keypair container
//! - `XChatPublicKey` - EC P-256 public key
//! - `XChatPrivateKey` - EC P-256 private key
//! - `XChatConversationKey` - Symmetric key for message encryption
//!

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Purpose of a keypair - determines how the key is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeypairPurpose {
    /// Identity key - used for ECDH key agreement to encrypt conversation keys.
    Identity,
    /// Signing key - used for ECDSA signatures on messages.
    Signing,
}

/// A public/private keypair.
///
#[derive(Clone, ZeroizeOnDrop)]
pub struct XChatKeyPair {
    /// The public key component.
    pub public: XChatPublicKey,
    /// The private key component (zeroized on drop).
    pub private: XChatPrivateKey,
}

impl XChatKeyPair {
    /// Create a new keypair from public and private keys.
    pub fn new(public: XChatPublicKey, private: XChatPrivateKey) -> Self {
        Self { public, private }
    }
}

impl std::fmt::Debug for XChatKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChatKeyPair")
            .field("public", &self.public)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// An EC P-256 public key.
///
/// Used for:
/// - Encrypting conversation keys (ECDH with identity key)
/// - Verifying signatures (with signing key)
///
/// # Wire Format
/// - Uncompressed: 65 bytes (0x04 || x || y)
/// - Compressed: 33 bytes (0x02/0x03 || x)
///
#[derive(Clone)]
pub struct XChatPublicKey {
    /// Raw bytes of the public key (uncompressed SEC1 format, 65 bytes).
    #[allow(dead_code)]
    bytes: Vec<u8>,
    /// Purpose of this key.
    purpose: KeypairPurpose,
}

impl Zeroize for XChatPublicKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for XChatPublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl XChatPublicKey {
    /// Create a public key from raw SEC1-encoded bytes.
    ///
    /// Accepts both uncompressed (65 bytes, `0x04 || x || y`) and
    /// compressed (33 bytes, `0x02`/`0x03 || x`) SEC1 format.
    ///
    /// The bytes are validated against the P-256 curve — inputs that
    /// are structurally correct but do not encode a valid curve point
    /// are rejected.
    pub fn from_bytes(bytes: Vec<u8>, purpose: KeypairPurpose) -> Option<Self> {
        // Validate that the bytes encode a valid P-256 point.
        // This catches off-curve points like 0x04 || [0x00; 64].
        p256::PublicKey::from_sec1_bytes(&bytes).ok()?;
        Some(Self { bytes, purpose })
    }

    /// Get the raw bytes of this public key.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the raw bytes as a Vec.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get the purpose of this key.
    pub fn purpose(&self) -> KeypairPurpose {
        self.purpose
    }

    /// Returns true if this is an identity key.
    pub fn is_identity(&self) -> bool {
        self.purpose == KeypairPurpose::Identity
    }

    /// Returns true if this is a signing key.
    pub fn is_signing(&self) -> bool {
        self.purpose == KeypairPurpose::Signing
    }
}

impl std::fmt::Debug for XChatPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::{engine::general_purpose::STANDARD, Engine};
        f.debug_struct("XChatPublicKey")
            .field("purpose", &self.purpose)
            .field("bytes", &STANDARD.encode(&self.bytes))
            .finish()
    }
}

impl PartialEq for XChatPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.purpose == other.purpose
    }
}

impl Eq for XChatPublicKey {}

/// An EC P-256 private key.
///
/// Used for:
/// - Decrypting conversation keys (ECDH with identity key)
/// - Signing messages (with signing key)
///
/// # Security
/// - Zeroized on drop to prevent key material from lingering in memory.
/// - Debug output is redacted.
///
#[derive(Clone)]
pub struct XChatPrivateKey {
    /// Raw bytes of the private key (32-byte scalar).
    bytes: Vec<u8>,
    /// Purpose of this key.
    purpose: KeypairPurpose,
}

impl Zeroize for XChatPrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for XChatPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl XChatPrivateKey {
    /// Create a private key from raw bytes.
    ///
    /// Expects a 32-byte P-256 scalar in `[1, n-1]` (the "d" value).
    /// The zero scalar and values ≥ the curve order are rejected.
    pub fn from_bytes(bytes: Vec<u8>, purpose: KeypairPurpose) -> Option<Self> {
        // P-256 private key must be exactly 32 bytes.
        if bytes.len() != 32 {
            return None;
        }
        // Validate that the bytes represent a valid P-256 scalar.
        // SecretKey::from_bytes rejects the zero scalar and values >= n.
        p256::SecretKey::from_bytes(bytes.as_slice().into()).ok()?;
        Some(Self { bytes, purpose })
    }

    /// Get the raw bytes of this private key.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the raw bytes as a Vec.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get the purpose of this key.
    pub fn purpose(&self) -> KeypairPurpose {
        self.purpose
    }
}

impl std::fmt::Debug for XChatPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChatPrivateKey")
            .field("purpose", &self.purpose)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A symmetric conversation key for message encryption.
///
/// This is a 32-byte key used with XSalsa20-Poly1305 (SecretBox) for
/// encrypting message payloads and with `crypto_secretstream_xchacha20poly1305`
/// for streaming media encryption.
///
/// # Lifecycle
/// - Generated when starting a new conversation or rotating keys.
/// - Encrypted with each participant's public key for distribution.
/// - Used to encrypt/decrypt all messages in a conversation.
///
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XChatConversationKey {
    /// Raw bytes of the conversation key (32 bytes).
    bytes: Vec<u8>,
}

impl XChatConversationKey {
    /// Key size in bytes (256 bits).
    pub const KEY_SIZE: usize = 32;

    /// Create a conversation key from raw bytes.
    ///
    /// Expects exactly 32 bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() == Self::KEY_SIZE {
            Some(Self { bytes })
        } else {
            None
        }
    }

    /// Get the raw bytes of this conversation key.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the raw bytes as a Vec.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl std::fmt::Debug for XChatConversationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChatConversationKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Container for a user's private keys (identity + signing).
///
#[derive(Clone, ZeroizeOnDrop)]
pub struct XChatPrivateKeys {
    /// Identity private key (for ECDH).
    pub identity: XChatPrivateKey,
    /// Signing private key (for ECDSA). Absent when only the 32-byte
    /// identity key is stored.
    pub signing: Option<XChatPrivateKey>,
}

impl XChatPrivateKeys {
    /// Create a new private keys container.
    pub fn new(identity: XChatPrivateKey, signing: Option<XChatPrivateKey>) -> Self {
        Self { identity, signing }
    }

    /// Serialize the private keys to bytes for storage.
    ///
    /// Format: identity_bytes (32) || signing_bytes (32) if present
    ///
    /// The returned buffer is a caller-owned copy of raw private key
    /// material; callers should zeroize it when done. Pre-allocating avoids
    /// a reallocation that would leave a stale, un-wiped copy behind.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.identity.encoded());
        if let Some(ref signing) = self.signing {
            bytes.extend_from_slice(signing.encoded());
        }
        bytes
    }

    /// Deserialize private keys from bytes.
    ///
    /// Expects 32 bytes (identity only) or 64 bytes (identity + signing).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let identity = XChatPrivateKey::from_bytes(bytes.to_vec(), KeypairPurpose::Identity)?;
            Some(Self {
                identity,
                signing: None,
            })
        } else if bytes.len() == 64 {
            let identity =
                XChatPrivateKey::from_bytes(bytes[0..32].to_vec(), KeypairPurpose::Identity)?;
            let signing =
                XChatPrivateKey::from_bytes(bytes[32..64].to_vec(), KeypairPurpose::Signing)?;
            Some(Self {
                identity,
                signing: Some(signing),
            })
        } else {
            None
        }
    }
}

impl std::fmt::Debug for XChatPrivateKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChatPrivateKeys")
            .field("identity", &"[REDACTED]")
            .field("signing", &self.signing.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// Generate a valid P-256 keypair and return (uncompressed_public, private) bytes.
    fn valid_p256_keypair() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let pk = sk.public_key();
        let pub_bytes = pk.to_encoded_point(false).as_bytes().to_vec();
        let priv_bytes = sk.to_bytes().to_vec();
        (pub_bytes, priv_bytes)
    }

    #[test]
    fn test_conversation_key_size() {
        assert_eq!(XChatConversationKey::KEY_SIZE, 32);
    }

    #[test]
    fn test_conversation_key_from_bytes() {
        let valid_bytes = vec![0u8; 32];
        let key = XChatConversationKey::from_bytes(valid_bytes.clone());
        assert!(key.is_some());
        assert_eq!(key.unwrap().encoded(), &valid_bytes[..]);

        let invalid_bytes = vec![0u8; 16];
        assert!(XChatConversationKey::from_bytes(invalid_bytes).is_none());
    }

    #[test]
    fn test_public_key_from_valid_bytes() {
        let (pub_bytes, _) = valid_p256_keypair();
        let key = XChatPublicKey::from_bytes(pub_bytes, KeypairPurpose::Identity);
        assert!(key.is_some());
    }

    #[test]
    fn test_public_key_from_compressed() {
        // Compressed SEC1 format via p256
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let compressed = sk.public_key().to_encoded_point(true).as_bytes().to_vec();
        assert_eq!(compressed.len(), 33);
        let key = XChatPublicKey::from_bytes(compressed, KeypairPurpose::Identity);
        assert!(key.is_some());
    }

    #[test]
    fn test_public_key_rejects_off_curve_point() {
        // 0x04 || [0x00; 64] is structurally valid but not on the curve
        let mut off_curve = vec![0x04];
        off_curve.extend(vec![0u8; 64]);
        assert!(XChatPublicKey::from_bytes(off_curve, KeypairPurpose::Identity).is_none());
    }

    #[test]
    fn test_public_key_rejects_wrong_length() {
        let invalid = vec![0u8; 32];
        assert!(XChatPublicKey::from_bytes(invalid, KeypairPurpose::Identity).is_none());
    }

    #[test]
    fn test_private_key_from_valid_bytes() {
        let (_, priv_bytes) = valid_p256_keypair();
        let key = XChatPrivateKey::from_bytes(priv_bytes, KeypairPurpose::Signing);
        assert!(key.is_some());
    }

    #[test]
    fn test_private_key_rejects_zero_scalar() {
        assert!(XChatPrivateKey::from_bytes(vec![0u8; 32], KeypairPurpose::Signing).is_none());
    }

    #[test]
    fn test_private_key_rejects_wrong_length() {
        let invalid_bytes = vec![0u8; 16];
        assert!(XChatPrivateKey::from_bytes(invalid_bytes, KeypairPurpose::Signing).is_none());
    }

    #[test]
    fn test_private_key_rejects_scalar_gte_order() {
        // P-256 order n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        // Use all-0xFF which is > n
        assert!(XChatPrivateKey::from_bytes(vec![0xFFu8; 32], KeypairPurpose::Signing).is_none());
    }

    #[test]
    fn test_private_keys_serialization() {
        let (_, id_bytes) = valid_p256_keypair();
        let (_, sig_bytes) = valid_p256_keypair();

        let identity =
            XChatPrivateKey::from_bytes(id_bytes.clone(), KeypairPurpose::Identity).unwrap();
        let signing =
            XChatPrivateKey::from_bytes(sig_bytes.clone(), KeypairPurpose::Signing).unwrap();

        let keys = XChatPrivateKeys::new(identity, Some(signing));
        let serialized = keys.to_bytes();
        assert_eq!(serialized.len(), 64);

        let deserialized = XChatPrivateKeys::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.identity.encoded(), &id_bytes[..]);
        assert_eq!(
            deserialized.signing.as_ref().unwrap().encoded(),
            &sig_bytes[..]
        );
    }

    #[test]
    fn test_keypair_debug_redaction() {
        let (_, priv_bytes) = valid_p256_keypair();
        let private = XChatPrivateKey::from_bytes(priv_bytes, KeypairPurpose::Signing).unwrap();
        let debug = format!("{:?}", private);
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_public_key_purpose() {
        let (pub_bytes, _) = valid_p256_keypair();
        let pk = XChatPublicKey::from_bytes(pub_bytes, KeypairPurpose::Identity).unwrap();
        assert!(pk.is_identity());
        assert!(!pk.is_signing());
        assert_eq!(pk.purpose(), KeypairPurpose::Identity);
    }

    #[test]
    fn test_public_key_equality() {
        let (bytes, _) = valid_p256_keypair();
        let pk1 = XChatPublicKey::from_bytes(bytes.clone(), KeypairPurpose::Identity).unwrap();
        let pk2 = XChatPublicKey::from_bytes(bytes.clone(), KeypairPurpose::Identity).unwrap();
        let pk3 = XChatPublicKey::from_bytes(bytes.clone(), KeypairPurpose::Signing).unwrap();
        assert_eq!(pk1, pk2);
        assert_ne!(pk1, pk3); // same bytes, different purpose
    }

    #[test]
    fn test_public_key_debug_shows_base64() {
        let (bytes, _) = valid_p256_keypair();
        let pk = XChatPublicKey::from_bytes(bytes, KeypairPurpose::Identity).unwrap();
        let debug = format!("{:?}", pk);
        assert!(debug.contains("Identity"));
    }

    #[test]
    fn test_private_keys_identity_only() {
        let (_, priv_bytes) = valid_p256_keypair();
        let identity = XChatPrivateKey::from_bytes(priv_bytes, KeypairPurpose::Identity).unwrap();
        let keys = XChatPrivateKeys::new(identity, None);
        let bytes = keys.to_bytes();
        assert_eq!(bytes.len(), 32);

        let restored = XChatPrivateKeys::from_bytes(&bytes).unwrap();
        assert!(restored.signing.is_none());
    }

    #[test]
    fn test_private_keys_invalid_size() {
        assert!(XChatPrivateKeys::from_bytes(&[0u8; 0]).is_none());
        assert!(XChatPrivateKeys::from_bytes(&[0u8; 16]).is_none());
        assert!(XChatPrivateKeys::from_bytes(&[0u8; 48]).is_none());
        assert!(XChatPrivateKeys::from_bytes(&[0u8; 96]).is_none());
    }

    #[test]
    fn test_private_keys_debug_redaction() {
        let (_, id_bytes) = valid_p256_keypair();
        let (_, sig_bytes) = valid_p256_keypair();
        let identity = XChatPrivateKey::from_bytes(id_bytes, KeypairPurpose::Identity).unwrap();
        let signing = XChatPrivateKey::from_bytes(sig_bytes, KeypairPurpose::Signing).unwrap();
        let keys = XChatPrivateKeys::new(identity, Some(signing));
        let debug = format!("{:?}", keys);
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_conversation_key_to_bytes() {
        let key = XChatConversationKey::from_bytes(vec![42u8; 32]).unwrap();
        let bytes = key.to_bytes();
        assert_eq!(bytes, vec![42u8; 32]);
    }

    #[test]
    fn test_debug_redaction() {
        let key = XChatConversationKey::from_bytes(vec![0u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("0, 0, 0")); // Should not contain actual bytes
    }
}
