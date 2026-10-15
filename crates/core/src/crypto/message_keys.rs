//! Per-message and per-attachment keys.
//!
//! A message whose `contents_encryption_version` is 1 or more is encrypted
//! under a key derived for that message from the conversation key, and each
//! of its attachments under a key derived from the message key. Messages
//! without a version use the conversation key for both.

use crate::crypto::hash::hkdf_with_info;
use crate::crypto::keys::XChatConversationKey;
use crate::error::CryptoError;

const MESSAGE_KEY_SALT: &str = "xchat-message-key";
const ATTACHMENT_KEY_SALT: &str = "xchat-attachment-key";
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

/// Derive an attachment's key from its message key and attachment id.
pub(crate) fn derive_attachment_key(
    message_key: &XChatConversationKey,
    attachment_id: &str,
) -> Result<XChatConversationKey, CryptoError> {
    derive(message_key, ATTACHMENT_KEY_SALT, attachment_id.as_bytes())
}

/// The id an attachment's key is derived from: the attachment's own id when
/// set (an empty id counts), otherwise the message id for the first
/// attachment and `<message id>#<index>` for later ones.
pub(crate) fn resolve_attachment_id(
    stored_id: Option<&str>,
    message_id: &str,
    index: usize,
) -> String {
    match stored_id {
        Some(id) => id.to_string(),
        None if index == 0 => message_id.to_string(),
        None => format!("{}#{}", message_id, index),
    }
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
    fn message_and_attachment_keys_match_known_answers() {
        let ckey = key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let message_id = "9d8c7b6a-5f4e-4d3c-8b2a-190807060504";
        let message_key = derive_message_key(&ckey, "1876543210987654321", message_id).unwrap();
        assert_eq!(
            hex::encode(message_key.encoded()),
            "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084"
        );
        let first = derive_attachment_key(&message_key, message_id).unwrap();
        assert_eq!(
            hex::encode(first.encoded()),
            "1ef86545f91f8a3078e276949f7555df2ca584e9c6509b261a558a2e618a1b4b"
        );
        let second = derive_attachment_key(&message_key, &format!("{}#1", message_id)).unwrap();
        assert_eq!(
            hex::encode(second.encoded()),
            "8a7bc01f2ff35c661140da68606b2370cecc13810f245d791aeb8ba6b40d4ea8"
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
        let attachment_key = derive_attachment_key(&message_key, message_id).unwrap();
        assert_eq!(
            hex::encode(attachment_key.encoded()),
            "4f7d8ca1ef7cb1319743204496358333126086d0a23bdae26bbe5186ba8de093"
        );
    }

    #[test]
    fn attachment_key_for_message_id_matches_known_answer() {
        let ckey = XChatConversationKey::from_bytes(vec![7u8; 32]).unwrap();
        let message_id = "1975816253410000000";
        let message_key = derive_message_key(&ckey, "42", message_id).unwrap();
        let attachment_key = derive_attachment_key(&message_key, message_id).unwrap();
        assert_eq!(
            hex::encode(attachment_key.encoded()),
            "d3f7222df89d36796148c1e5a7520b7e71baacde799acf247eeea2c80d0933bf"
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

    #[test]
    fn missing_attachment_ids_fall_back_to_the_message_id_by_position() {
        assert_eq!(resolve_attachment_id(None, "m", 0), "m");
        assert_eq!(resolve_attachment_id(None, "m", 1), "m#1");
        assert_eq!(resolve_attachment_id(None, "m", 2), "m#2");
    }

    #[test]
    fn a_set_attachment_id_wins_even_when_empty() {
        assert_eq!(resolve_attachment_id(Some("att-9"), "m", 0), "att-9");
        assert_eq!(resolve_attachment_id(Some("att-9"), "m", 3), "att-9");
        assert_eq!(resolve_attachment_id(Some(""), "m", 1), "");
    }
}
