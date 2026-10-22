//! Per-message keys.
//!
//! A message whose `contents_encryption_version` is 1 or more is encrypted
//! under a key derived for that message from the conversation key. Messages
//! without a version use the conversation key.

use crate::crypto::hash::hkdf_with_info;
use crate::crypto::keys::XChatConversationKey;
use crate::error::CryptoError;

const MESSAGE_KEY_SALT: &str = "xchat-message-key";
const KEY_LENGTH: usize = 32;

/// Whether a message with this `contents_encryption_version` uses a message
/// key. Unset, zero, and negative versions use the conversation key.
pub(crate) fn uses_message_key(contents_encryption_version: Option<i16>) -> bool {
    contents_encryption_version.is_some_and(|v| v >= 1)
}

/// Derive a message's key from its conversation key, sender, and message id.
///
/// The HKDF info is `<sender id>:<message id>` with the sender id in
/// canonical decimal form, so a sender id that is not an integer has no
/// message key.
pub(crate) fn derive_message_key(
    conversation_key: &XChatConversationKey,
    sender_id: &str,
    message_id: &str,
) -> Result<XChatConversationKey, CryptoError> {
    let sender = sender_id.parse::<i64>().map_err(|_| {
        CryptoError::DecryptionFailed(format!(
            "message key needs a numeric sender id, got '{}'",
            sender_id
        ))
    })?;
    let info = format!("{}:{}", sender, message_id);
    derive(conversation_key, MESSAGE_KEY_SALT, info.as_bytes())
}

fn derive(
    secret: &XChatConversationKey,
    salt: &str,
    info: &[u8],
) -> Result<XChatConversationKey, CryptoError> {
    let bytes = zeroize::Zeroizing::new(hkdf_with_info(secret.encoded(), salt, info, KEY_LENGTH)?);
    XChatConversationKey::from_bytes(bytes.to_vec())
        .ok_or_else(|| CryptoError::InvalidKey("derived key must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(hex_str: &str) -> XChatConversationKey {
        XChatConversationKey::from_bytes(hex::decode(hex_str).unwrap()).unwrap()
    }

    #[test]
    fn message_keys_match_known_answers() {
        let ckey = key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let message_id = "9d8c7b6a-5f4e-4d3c-8b2a-190807060504";
        let message_key = derive_message_key(&ckey, "1876543210987654321", message_id).unwrap();
        assert_eq!(
            hex::encode(message_key.encoded()),
            "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084"
        );
    }

    #[test]
    fn short_sender_id_is_its_digits() {
        let ckey = key("c3a1f0e2d4b6987a5c3e1f0d2b4a6987c3a1f0e2d4b6987a5c3e1f0d2b4a6987");
        let message_id = "00000000-0000-4000-8000-000000000001";
        let message_key = derive_message_key(&ckey, "12", message_id).unwrap();
        assert_eq!(
            hex::encode(message_key.encoded()),
            "685bd4a20c7efb64c99147ab5854560c72eac9a826b04880b64e1951d4ef4cc7"
        );
    }

    #[test]
    fn non_numeric_sender_has_no_message_key() {
        let ckey = XChatConversationKey::from_bytes(vec![1u8; 32]).unwrap();
        assert!(derive_message_key(&ckey, "sender-1", "m").is_err());
    }

    #[test]
    fn sender_id_is_canonicalized() {
        let ckey = XChatConversationKey::from_bytes(vec![1u8; 32]).unwrap();
        let canonical = derive_message_key(&ckey, "12", "m").unwrap();
        let padded = derive_message_key(&ckey, "+012", "m").unwrap();
        assert_eq!(canonical.encoded(), padded.encoded());
    }

    #[test]
    fn version_one_or_more_uses_a_message_key() {
        assert!(!uses_message_key(None));
        assert!(!uses_message_key(Some(0)));
        assert!(!uses_message_key(Some(-1)));
        assert!(uses_message_key(Some(1)));
        assert!(uses_message_key(Some(2)));
    }
}
