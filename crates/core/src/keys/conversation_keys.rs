//! Conversation key operations.
//!
//! Handles encrypting conversation keys for recipients and
//! decrypting received conversation keys.

use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{XChatConversationKey, XChatPrivateKey, XChatPublicKey};
use crate::error::CryptoError;

/// A conversation key encrypted for a specific recipient.
#[derive(Debug, Clone)]
pub struct EncryptedConversationKey {
    /// User ID of the recipient.
    pub user_id: String,
    /// Encrypted conversation key bytes.
    pub encrypted_key: Vec<u8>,
    /// Version of the recipient's public key used for encryption.
    pub public_key_version: String,
}

/// Encrypt a conversation key for a single recipient.
///
/// # Arguments
/// * `conversation_key` - The conversation key to encrypt
/// * `recipient_public_key` - The recipient's identity public key
///
/// # Returns
/// The encrypted conversation key bytes
pub fn encrypt_conversation_key(
    conversation_key: &XChatConversationKey,
    recipient_public_key: &XChatPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    KeyFactory::encrypt_with_public_key(recipient_public_key, conversation_key.encoded())
}

/// Encrypt a conversation key for multiple recipients.
///
/// # Arguments
/// * `conversation_key` - The conversation key to encrypt
/// * `recipients` - List of (user_id, public_key, public_key_version) tuples
///
/// # Returns
/// List of encrypted conversation keys, one per recipient
pub fn encrypt_conversation_key_for_recipients(
    conversation_key: &XChatConversationKey,
    recipients: &[(String, XChatPublicKey, String)],
) -> Result<Vec<EncryptedConversationKey>, CryptoError> {
    recipients
        .iter()
        .map(|(user_id, public_key, version)| {
            let encrypted_key = encrypt_conversation_key(conversation_key, public_key)?;
            Ok(EncryptedConversationKey {
                user_id: user_id.clone(),
                encrypted_key,
                public_key_version: version.clone(),
            })
        })
        .collect()
}

/// Decrypt a conversation key using our identity private key.
///
/// # Arguments
/// * `encrypted_key` - The encrypted conversation key bytes
/// * `private_key` - Our identity private key
///
/// # Returns
/// The decrypted conversation key
pub fn decrypt_conversation_key(
    encrypted_key: &[u8],
    private_key: &XChatPrivateKey,
) -> Result<XChatConversationKey, CryptoError> {
    // The decrypted buffer holds the raw conversation key; wipe it on drop
    // (reconstruction copies the bytes into its own zeroize-on-drop container).
    let decrypted_bytes = zeroize::Zeroizing::new(KeyFactory::decrypt_with_private_key(
        private_key,
        encrypted_key,
    )?);
    KeyFactory::reconstruct_conversation_key(&decrypted_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeypairPurpose;

    #[test]
    fn test_encrypt_decrypt_conversation_key() {
        let keypair = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let ckey = KeyFactory::generate_conversation_key().unwrap();

        let encrypted = encrypt_conversation_key(&ckey, &keypair.public).unwrap();
        let decrypted = decrypt_conversation_key(&encrypted, &keypair.private).unwrap();

        assert_eq!(decrypted.encoded(), ckey.encoded());
    }

    #[test]
    fn test_encrypt_for_multiple_recipients() {
        let keypair1 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let keypair2 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let ckey = KeyFactory::generate_conversation_key().unwrap();

        let recipients = vec![
            (
                "user1".to_string(),
                keypair1.public.clone(),
                "v1".to_string(),
            ),
            (
                "user2".to_string(),
                keypair2.public.clone(),
                "v1".to_string(),
            ),
        ];

        let encrypted = encrypt_conversation_key_for_recipients(&ckey, &recipients).unwrap();

        assert_eq!(encrypted.len(), 2);
        assert_eq!(encrypted[0].user_id, "user1");
        assert_eq!(encrypted[1].user_id, "user2");

        // Each recipient should be able to decrypt
        let decrypted1 =
            decrypt_conversation_key(&encrypted[0].encrypted_key, &keypair1.private).unwrap();
        assert_eq!(decrypted1.encoded(), ckey.encoded());

        let decrypted2 =
            decrypt_conversation_key(&encrypted[1].encrypted_key, &keypair2.private).unwrap();
        assert_eq!(decrypted2.encoded(), ckey.encoded());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let keypair2 = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let ckey = KeyFactory::generate_conversation_key().unwrap();

        let encrypted = encrypt_conversation_key(&ckey, &keypair1.public).unwrap();

        // Decrypting with wrong key should fail
        let result = decrypt_conversation_key(&encrypted, &keypair2.private);
        assert!(result.is_err());
    }
}
