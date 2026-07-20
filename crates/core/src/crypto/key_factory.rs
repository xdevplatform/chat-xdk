//! Key factory for cryptographic operations.
//!
//! Provides key generation, ECDH key agreement, and digital signatures using P-256.
//!

use crate::crypto::hash::kdf2_sha256;
use crate::crypto::keys::{
    KeypairPurpose, XChatConversationKey, XChatKeyPair, XChatPrivateKey, XChatPublicKey,
};
use crate::error::CryptoError;

use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;

/// Key factory providing all cryptographic key operations.
///
/// This is a stateless utility struct - all methods are associated functions.
pub struct KeyFactory;

impl KeyFactory {
    /// Generate a new EC P-256 keypair.
    ///
    /// # Arguments
    /// * `purpose` - Whether this is an Identity key (for ECDH) or Signing key (for ECDSA)
    ///
    pub fn generate_keypair(purpose: KeypairPurpose) -> Result<XChatKeyPair, CryptoError> {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        let private_bytes = secret_key.to_bytes().to_vec();
        let public_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();

        let private = XChatPrivateKey::from_bytes(private_bytes, purpose)
            .ok_or_else(|| CryptoError::KeyGenerationFailed("Invalid private key".into()))?;
        let public = XChatPublicKey::from_bytes(public_bytes, purpose)
            .ok_or_else(|| CryptoError::KeyGenerationFailed("Invalid public key".into()))?;

        Ok(XChatKeyPair::new(public, private))
    }

    /// Generate a new random 32-byte conversation key.
    pub fn generate_conversation_key() -> Result<XChatConversationKey, CryptoError> {
        use rand::RngCore;
        let mut bytes = vec![0u8; XChatConversationKey::KEY_SIZE];
        OsRng.fill_bytes(&mut bytes);
        XChatConversationKey::from_bytes(bytes)
            .ok_or_else(|| CryptoError::KeyGenerationFailed("Invalid conversation key".into()))
    }

    /// Encrypt data using ECIES (Ephemeral ECDH + AES-GCM).
    ///
    /// This creates an ephemeral keypair, performs ECDH with the recipient's public key,
    /// derives an AES key using X9.63 KDF, and encrypts the data with AES-128-GCM.
    ///
    /// # Wire Format
    /// Output: ephemeral_public_key (65 bytes) || ciphertext || tag (16 bytes)
    ///
    pub fn encrypt_with_public_key(
        public_key: &XChatPublicKey,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{
            aead::{consts::U16, Aead, KeyInit},
            aes::Aes128,
            AesGcm,
        };

        // AES-128-GCM with a 16-byte nonce (not the usual 12-byte length).
        // The IV is derived from a fresh ephemeral ECDH secret on every call,
        // so a nonce is never reused under the same key.
        type Aes128Gcm16 = AesGcm<Aes128, U16>;

        // Parse recipient's public key
        let recipient_point = EncodedPoint::from_bytes(public_key.encoded())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;
        let recipient_pk = PublicKey::from_encoded_point(&recipient_point)
            .into_option()
            .ok_or_else(|| CryptoError::InvalidKey("Invalid public key point".into()))?;

        // Generate ephemeral keypair for ECDH
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral_secret.public_key();
        let ephemeral_public_bytes = ephemeral_public.to_encoded_point(false).as_bytes().to_vec();

        // Perform ECDH
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        // Derive key material using X9.63 KDF (KDF2) with ephemeral public key as shared info
        // Output: 16 bytes for AES-128 key + 16 bytes for IV = 32 bytes.
        // Wrapped so the derived AES key + IV are wiped on drop.
        let kdf_output = zeroize::Zeroizing::new(kdf2_sha256(
            &shared_secret.raw_secret_bytes()[..],
            &ephemeral_public_bytes,
            32,
        ));
        let aes_key = &kdf_output[0..16];
        let iv = &kdf_output[16..32];

        // Encrypt with AES-128-GCM using 16-byte nonce
        let cipher = Aes128Gcm16::new_from_slice(aes_key)
            .map_err(|_| CryptoError::EncryptionFailed("Failed to create AES key".into()))?;

        let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| CryptoError::EncryptionFailed("AES-GCM encryption failed".into()))?;

        // Output: ephemeral_public || ciphertext || tag
        let mut output = ephemeral_public_bytes;
        output.extend(ciphertext);

        Ok(output)
    }

    /// Decrypt data using ECIES (ECDH + AES-GCM).
    ///
    /// # Wire Format
    /// Input: ephemeral_public_key (65 bytes) || ciphertext || tag (16 bytes)
    ///
    pub fn decrypt_with_private_key(
        private_key: &XChatPrivateKey,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{
            aead::{consts::U16, Aead, KeyInit},
            aes::Aes128,
            AesGcm,
        };

        // AES-128-GCM with a 16-byte (128-bit) nonce.
        type Aes128Gcm16 = AesGcm<Aes128, U16>;

        // Minimum size: 65 (pubkey) + 16 (tag) = 81 bytes
        if data.len() < 81 {
            return Err(CryptoError::DecryptionFailed("Data too short".into()));
        }

        // Parse ephemeral public key
        let ephemeral_public_bytes = &data[..65];
        let ephemeral_point = EncodedPoint::from_bytes(ephemeral_public_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid ephemeral public key: {}", e)))?;
        let ephemeral_pk = PublicKey::from_encoded_point(&ephemeral_point)
            .into_option()
            .ok_or_else(|| CryptoError::InvalidKey("Invalid ephemeral public key point".into()))?;

        // Parse our private key
        let secret_key = SecretKey::from_bytes(private_key.encoded().into())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid private key: {}", e)))?;

        // Perform ECDH
        let shared_secret =
            p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), ephemeral_pk.as_affine());

        // Derive key material using X9.63 KDF (KDF2) with ephemeral public key as shared info
        // Output: 16 bytes for AES-128 key + 16 bytes for IV = 32 bytes.
        // Wrapped so the derived AES key + IV are wiped on drop.
        let kdf_output = zeroize::Zeroizing::new(kdf2_sha256(
            &shared_secret.raw_secret_bytes()[..],
            ephemeral_public_bytes,
            32,
        ));
        let aes_key = &kdf_output[0..16];
        let iv = &kdf_output[16..32];

        // Extract ciphertext (everything after ephemeral public key)
        let ciphertext = &data[65..];

        // Decrypt with AES-128-GCM using 16-byte nonce
        let cipher = Aes128Gcm16::new_from_slice(aes_key)
            .map_err(|_| CryptoError::DecryptionFailed("Failed to create AES key".into()))?;

        let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            CryptoError::DecryptionFailed(
                "Decryption failed - invalid key or corrupted data".into(),
            )
        })?;

        Ok(plaintext)
    }

    /// Sign data using ECDSA P-256.
    ///
    pub fn sign(private_key: &XChatPrivateKey, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signing_key = SigningKey::from_bytes(private_key.encoded().into())
            .map_err(|e| CryptoError::SigningFailed(format!("Invalid signing key: {}", e)))?;

        let signature: Signature = signing_key.sign(payload);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify an ECDSA P-256 signature (raw 64-byte r‖s format).
    pub fn verify(
        public_key: &XChatPublicKey,
        signature: &[u8],
        payload: &[u8],
    ) -> Result<bool, CryptoError> {
        if signature.len() != 64 {
            return Err(CryptoError::VerificationFailed(
                "Invalid signature length".to_string(),
            ));
        }
        // Parse public key
        let point = EncodedPoint::from_bytes(public_key.encoded())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;
        let verifying_key = VerifyingKey::from_encoded_point(&point)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid verifying key: {}", e)))?;

        // Parse signature
        let sig = Signature::from_bytes(signature.into())
            .map_err(|e| CryptoError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        // Verify
        match verifying_key.verify(payload, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Reconstruct a public key from raw bytes.
    ///
    pub fn reconstruct_public_key(
        bytes: &[u8],
        purpose: KeypairPurpose,
    ) -> Result<XChatPublicKey, CryptoError> {
        // Validate that the bytes represent a valid P-256 point
        let point = EncodedPoint::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid key bytes: {}", e)))?;
        let _pk = PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or_else(|| CryptoError::InvalidKey("Invalid curve point".into()))?;

        XChatPublicKey::from_bytes(bytes.to_vec(), purpose)
            .ok_or_else(|| CryptoError::InvalidKey("Invalid public key format".into()))
    }

    /// Reconstruct a private key from raw bytes.
    ///
    /// Validates that `bytes` is a valid P-256 scalar in `[1, n-1]`.
    /// Use [`KeyFactory::get_keypair_from_private_key_bytes`] when you also need the
    /// corresponding public key — it derives and validates both.
    pub fn reconstruct_private_key(
        bytes: &[u8],
        purpose: KeypairPurpose,
    ) -> Result<XChatPrivateKey, CryptoError> {
        XChatPrivateKey::from_bytes(bytes.to_vec(), purpose)
            .ok_or_else(|| CryptoError::InvalidKey("Invalid private key".into()))
    }

    /// Reconstruct a conversation key from raw bytes.
    ///
    pub fn reconstruct_conversation_key(bytes: &[u8]) -> Result<XChatConversationKey, CryptoError> {
        XChatConversationKey::from_bytes(bytes.to_vec())
            .ok_or_else(|| CryptoError::InvalidKey("Invalid conversation key".into()))
    }

    /// Get a keypair from private key bytes.
    ///
    /// Derives the public key from the private key.
    ///
    pub fn get_keypair_from_private_key_bytes(
        private_key_bytes: &[u8],
        purpose: KeypairPurpose,
    ) -> Result<XChatKeyPair, CryptoError> {
        let secret_key = SecretKey::from_bytes(private_key_bytes.into())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid private key: {}", e)))?;
        let public_key = secret_key.public_key();

        let private = XChatPrivateKey::from_bytes(private_key_bytes.to_vec(), purpose)
            .ok_or_else(|| CryptoError::InvalidKey("Invalid private key format".into()))?;
        let public = XChatPublicKey::from_bytes(
            public_key.to_encoded_point(false).as_bytes().to_vec(),
            purpose,
        )
        .ok_or_else(|| CryptoError::InvalidKey("Invalid public key format".into()))?;

        Ok(XChatKeyPair::new(public, private))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        assert_eq!(keypair.public.encoded().len(), 65); // Uncompressed P-256
        assert_eq!(keypair.private.encoded().len(), 32); // P-256 scalar
        assert!(keypair.public.is_identity());
    }

    #[test]
    fn test_generate_signing_keypair() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        assert!(keypair.public.is_signing());
    }

    #[test]
    fn test_generate_conversation_key() {
        let ckey = KeyFactory::generate_conversation_key().unwrap();
        assert_eq!(ckey.encoded().len(), 32);
    }

    #[test]
    fn test_ecies_encrypt_decrypt() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair.public, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len());

        let decrypted =
            KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_different_data() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();

        // Empty data
        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair.public, b"").unwrap();
        let decrypted =
            KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext).unwrap();
        assert_eq!(decrypted, b"");

        // Larger data
        let large_data = vec![0x42u8; 1024];
        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair.public, &large_data).unwrap();
        let decrypted =
            KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext).unwrap();
        assert_eq!(decrypted, large_data);
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        let keypair1 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let keypair2 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"Secret message";

        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair1.public, plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = KeyFactory::decrypt_with_private_key(&keypair2.private, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let message = b"Message to sign";

        let signature = KeyFactory::sign(&keypair.private, message).unwrap();
        assert_eq!(signature.len(), 64); // P-256 signature is 64 bytes (r || s)

        let is_valid = KeyFactory::verify(&keypair.public, &signature, message).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let message = b"Original message";
        let wrong_message = b"Different message";

        let signature = KeyFactory::sign(&keypair.private, message).unwrap();

        let is_valid = KeyFactory::verify(&keypair.public, &signature, wrong_message).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let keypair1 = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let keypair2 = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let message = b"Message";

        let signature = KeyFactory::sign(&keypair1.private, message).unwrap();

        let is_valid = KeyFactory::verify(&keypair2.public, &signature, message).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_reconstruct_public_key() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let bytes = keypair.public.to_bytes();

        let reconstructed =
            KeyFactory::reconstruct_public_key(&bytes, KeypairPurpose::Identity).unwrap();
        assert_eq!(reconstructed.encoded(), keypair.public.encoded());
    }

    #[test]
    fn test_reconstruct_private_key() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let private_bytes = keypair.private.to_bytes();

        let reconstructed =
            KeyFactory::reconstruct_private_key(&private_bytes, KeypairPurpose::Signing).unwrap();
        assert_eq!(reconstructed.encoded(), keypair.private.encoded());
    }

    #[test]
    fn test_reconstruct_private_key_rejects_zero_scalar() {
        assert!(KeyFactory::reconstruct_private_key(&[0u8; 32], KeypairPurpose::Identity).is_err());
    }

    #[test]
    fn test_get_keypair_from_private_bytes() {
        let original = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let private_bytes = original.private.to_bytes();

        let reconstructed = KeyFactory::get_keypair_from_private_key_bytes(
            &private_bytes,
            KeypairPurpose::Identity,
        )
        .unwrap();

        assert_eq!(reconstructed.public.encoded(), original.public.encoded());
        assert_eq!(reconstructed.private.encoded(), original.private.encoded());
    }

    // decrypt_with_private_key — short-data error path

    #[test]
    fn test_decrypt_with_private_key_data_too_short() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        // 80 bytes < minimum 81 (65 pubkey + 16 tag)
        let result = KeyFactory::decrypt_with_private_key(&keypair.private, &[0u8; 80]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_private_key_empty() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let result = KeyFactory::decrypt_with_private_key(&keypair.private, &[]);
        assert!(result.is_err());
    }

    // ECIES corrupted-ciphertext tests

    #[test]
    fn test_ecies_corrupted_ciphertext_body() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"Secret data for corruption test";

        let mut ciphertext =
            KeyFactory::encrypt_with_public_key(&keypair.public, plaintext).unwrap();
        // Corrupt a byte in the AES-GCM ciphertext portion (after the 65-byte ephemeral key)
        let idx = 65 + 2;
        ciphertext[idx] ^= 0xFF;

        let result = KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_corrupted_ephemeral_key_coordinate() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"Secret data";

        let mut ciphertext =
            KeyFactory::encrypt_with_public_key(&keypair.public, plaintext).unwrap();
        // Corrupt the x-coordinate of the ephemeral public key (byte 1, after the 0x04 prefix).
        // This may produce an off-curve point or a different valid point → decryption fails.
        ciphertext[1] ^= 0xFF;

        let result = KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_corrupted_ephemeral_key_prefix() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"Secret data";

        let mut ciphertext =
            KeyFactory::encrypt_with_public_key(&keypair.public, plaintext).unwrap();
        // Corrupt byte 0 (the 0x04 uncompressed prefix) → EncodedPoint parse failure
        ciphertext[0] = 0x00;

        let result = KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext);
        assert!(result.is_err());
    }

    // reconstruct_public_key — compressed key and error cases

    #[test]
    fn test_reconstruct_public_key_compressed() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        // Re-encode the public key in compressed SEC1 form (33 bytes)
        let point = EncodedPoint::from_bytes(keypair.public.encoded()).unwrap();
        let pk = PublicKey::from_encoded_point(&point).into_option().unwrap();
        let compressed = pk.to_encoded_point(true).as_bytes().to_vec();
        assert_eq!(compressed.len(), 33);

        let reconstructed =
            KeyFactory::reconstruct_public_key(&compressed, KeypairPurpose::Identity).unwrap();
        assert_eq!(reconstructed.encoded().len(), 33);
    }

    #[test]
    fn test_reconstruct_public_key_invalid_bytes() {
        let result = KeyFactory::reconstruct_public_key(&[0xFFu8; 10], KeypairPurpose::Identity);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_public_key_off_curve() {
        let mut off_curve = vec![0x04];
        off_curve.extend(vec![0u8; 64]);
        let result = KeyFactory::reconstruct_public_key(&off_curve, KeypairPurpose::Identity);
        assert!(result.is_err());
    }

    // get_keypair_from_private_key_bytes — error cases

    #[test]
    #[should_panic]
    fn test_get_keypair_from_private_key_bytes_wrong_length() {
        // GenericArray panics when slice length ≠ 32
        let _ =
            KeyFactory::get_keypair_from_private_key_bytes(&[0x42u8; 16], KeypairPurpose::Identity);
    }

    #[test]
    fn test_get_keypair_from_private_key_bytes_zero_scalar() {
        let result =
            KeyFactory::get_keypair_from_private_key_bytes(&[0u8; 32], KeypairPurpose::Identity);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic]
    fn test_get_keypair_from_private_key_bytes_too_long() {
        // GenericArray panics when slice length ≠ 32
        let _ =
            KeyFactory::get_keypair_from_private_key_bytes(&[0x42u8; 64], KeypairPurpose::Identity);
    }

    // verify — invalid signature length / corrupted signature

    #[test]
    fn test_verify_signature_too_short() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let result = KeyFactory::verify(&keypair.public, &[0u8; 63], b"msg");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_too_long() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let result = KeyFactory::verify(&keypair.public, &[0u8; 65], b"msg");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_empty() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let result = KeyFactory::verify(&keypair.public, &[], b"msg");
        assert!(result.is_err());
    }

    // reconstruct_conversation_key

    #[test]
    fn test_reconstruct_conversation_key_valid() {
        let key = KeyFactory::reconstruct_conversation_key(&[0x42u8; 32]).unwrap();
        assert_eq!(key.encoded(), &[0x42u8; 32]);
    }

    #[test]
    fn test_reconstruct_conversation_key_wrong_size() {
        assert!(KeyFactory::reconstruct_conversation_key(&[0u8; 16]).is_err());
        assert!(KeyFactory::reconstruct_conversation_key(&[0u8; 64]).is_err());
        assert!(KeyFactory::reconstruct_conversation_key(&[]).is_err());
    }

    // sign / verify — empty payload

    #[test]
    fn test_sign_verify_empty_payload() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let signature = KeyFactory::sign(&keypair.private, b"").unwrap();
        assert_eq!(signature.len(), 64);
        let valid = KeyFactory::verify(&keypair.public, &signature, b"").unwrap();
        assert!(valid);
    }

    // reconstruct_private_key — wrong length

    #[test]
    fn test_reconstruct_private_key_wrong_length() {
        let result = KeyFactory::reconstruct_private_key(&[0x42u8; 16], KeypairPurpose::Signing);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_private_key_too_long() {
        let result = KeyFactory::reconstruct_private_key(&[0x42u8; 64], KeypairPurpose::Identity);
        assert!(result.is_err());
    }

    // generate_keypair — both purposes produce valid key sizes

    #[test]
    fn test_generate_keypair_identity_key_sizes() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        assert_eq!(keypair.public.encoded().len(), 65);
        assert_eq!(keypair.private.encoded().len(), 32);
        assert!(keypair.public.is_identity());
        assert_eq!(keypair.private.purpose(), KeypairPurpose::Identity);
    }

    #[test]
    fn test_generate_keypair_signing_key_sizes() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        assert_eq!(keypair.public.encoded().len(), 65);
        assert_eq!(keypair.private.encoded().len(), 32);
        assert!(keypair.public.is_signing());
        assert_eq!(keypair.private.purpose(), KeypairPurpose::Signing);
    }

    // ECIES — encrypt_with_public_key wire format validation

    #[test]
    fn test_ecies_ciphertext_wire_format() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let plaintext = b"wire format test";

        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair.public, plaintext).unwrap();

        // Wire format: ephemeral_pubkey (65) || ciphertext (len) || tag (16)
        assert!(ciphertext.len() >= 65 + 16);
        // First byte should be 0x04 (uncompressed point prefix)
        assert_eq!(ciphertext[0], 0x04);
    }

    #[test]
    fn test_ecies_encrypt_decrypt_large_payload() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let large_data = vec![0xEFu8; 8192];

        let ciphertext = KeyFactory::encrypt_with_public_key(&keypair.public, &large_data).unwrap();
        let decrypted =
            KeyFactory::decrypt_with_private_key(&keypair.private, &ciphertext).unwrap();
        assert_eq!(decrypted, large_data);
    }
}
