//! Encrypting a file for the message that sends it, and decrypting it
//! with that message.

use super::*;

/// A core with keys and the session identity of user 1000.
fn sending_core() -> ChatCore {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("1000", "1"))
        .unwrap();
    core
}

/// The outgoing event of a message `core` sends under key version "1"
/// whose only attachment is the file `media_hash_key`, and the key map
/// that opens it.
fn sent_file_message(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    media_hash_key: &str,
) -> (String, HashMap<String, XChatConversationKey>) {
    let mut params = crate::EncryptMessageParams::new("1000:2000", "a file")
        .with_conversation_key(ckey.to_bytes(), "1");
    params.attachments = Some(vec![crate::AttachmentDescriptor::Media {
        media_hash_key: media_hash_key.to_string(),
        width: 4,
        height: 3,
        filesize_bytes: 64,
        filename: "photo.png".to_string(),
        media_type: None,
        duration_millis: None,
    }]);
    let payload = core.encrypt_message(&params).unwrap();
    (
        payload.event_b64,
        [("1".to_string(), ckey.clone())].into_iter().collect(),
    )
}

#[test]
fn encrypt_decrypt_file_roundtrip() {
    let core = sending_core();
    let ckey = core.generate_conversation_key().unwrap();
    let (event, keys) = sent_file_message(&core, &ckey, "hash-1");

    let plaintext = b"file data for media encryption test";
    let encrypted = core
        .encrypt_file(
            &EncryptFileParams::new(plaintext.to_vec(), event.clone(), "hash-1")
                .with_conversation_key(ckey.to_bytes(), "1"),
        )
        .unwrap();
    assert_ne!(&encrypted[..], plaintext);

    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(encrypted, event, keys, "hash-1"))
        .unwrap();
    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn encrypt_decrypt_file_empty() {
    let core = sending_core();
    let ckey = core.generate_conversation_key().unwrap();
    let (event, keys) = sent_file_message(&core, &ckey, "hash-1");

    let encrypted = core
        .encrypt_file(
            &EncryptFileParams::new(Vec::new(), event.clone(), "hash-1")
                .with_conversation_key(ckey.to_bytes(), "1"),
        )
        .unwrap();
    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(encrypted, event, keys, "hash-1"))
        .unwrap();
    assert!(decrypted.is_empty());
}
