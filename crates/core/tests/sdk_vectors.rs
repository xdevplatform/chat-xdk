use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::{
    encryption::{decrypt_message, encrypt_message},
    key_factory::KeyFactory,
    keys::{KeypairPurpose, XChatConversationKey},
};
use chat_xdk_core::keys::conversation_keys::{decrypt_conversation_key, encrypt_conversation_key};

#[derive(serde::Deserialize)]
struct Vectors {
    identity_private_b64: String,
    signing_private_b64: String,
    private_keys_concat_b64: String,
    message_utf8: String,
    conversation_key_b64: String,
    plaintext_b64: String,
    identity_public_b64: String,
    signing_public_b64: String,
    signature_b64: String,
    identity_public_key_signature_b64: String,
    event_key_change_b64: String,
    event_message_b64: String,
    event_reply_valid_b64: String,
    event_reply_forged_b64: String,
    event_reply_text: String,
    event_garbage_b64: String,
    event_sender_id: String,
    event_conversation_key_version: String,
    event_signing_key_version: String,
    event_recipient_key_version: String,
    event_message_text: String,
}

fn load_vectors() -> Vectors {
    serde_json::from_str(include_str!("../../../tests/fixtures/sdk_vectors.json"))
        .expect("valid sdk_vectors.json")
}

#[test]
fn vectors_public_keys_and_signature_match_rust_reference() {
    let v = load_vectors();

    let identity_private = B64
        .decode(&v.identity_private_b64)
        .expect("identity_private_b64 base64");
    let signing_private = B64
        .decode(&v.signing_private_b64)
        .expect("signing_private_b64 base64");
    let private_concat = B64
        .decode(&v.private_keys_concat_b64)
        .expect("private_keys_concat_b64 base64");

    assert_eq!(identity_private.len(), 32);
    assert_eq!(signing_private.len(), 32);
    assert_eq!(private_concat.len(), 64);
    assert_eq!(&private_concat[0..32], &identity_private);
    assert_eq!(&private_concat[32..64], &signing_private);

    let identity_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&identity_private, KeypairPurpose::Identity)
            .expect("identity keypair from bytes");
    let signing_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&signing_private, KeypairPurpose::Signing)
            .expect("signing keypair from bytes");

    assert_eq!(
        v.identity_public_b64,
        B64.encode(identity_kp.public.encoded())
    );
    assert_eq!(
        v.signing_public_b64,
        B64.encode(signing_kp.public.encoded())
    );

    let sig = KeyFactory::sign(&signing_kp.private, v.message_utf8.as_bytes()).unwrap();
    assert_eq!(v.signature_b64, B64.encode(sig));
}

#[test]
fn vectors_signature_verifies_and_fails_on_tamper() {
    let v = load_vectors();
    let signing_private = B64.decode(&v.signing_private_b64).unwrap();
    let signing_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&signing_private, KeypairPurpose::Signing)
            .unwrap();

    let sig = B64.decode(&v.signature_b64).unwrap();

    let ok = KeyFactory::verify(&signing_kp.public, &sig, v.message_utf8.as_bytes()).unwrap();
    assert!(ok);

    let bad = KeyFactory::verify(
        &signing_kp.public,
        &sig,
        format!("{}!", v.message_utf8).as_bytes(),
    )
    .unwrap();
    assert!(!bad);
}

#[test]
fn vectors_conversation_key_ecies_roundtrip_and_wrong_key_fails() {
    let v = load_vectors();
    let identity_private = B64.decode(&v.identity_private_b64).unwrap();
    let identity_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&identity_private, KeypairPurpose::Identity)
            .unwrap();

    let conversation_key_bytes = B64.decode(&v.conversation_key_b64).unwrap();
    let ckey = XChatConversationKey::from_bytes(conversation_key_bytes).unwrap();

    let encrypted = encrypt_conversation_key(&ckey, &identity_kp.public).unwrap();
    let decrypted = decrypt_conversation_key(&encrypted, &identity_kp.private).unwrap();
    assert_eq!(decrypted.encoded(), ckey.encoded());

    let other_identity =
        KeyFactory::generate_keypair(KeypairPurpose::Identity).expect("fresh identity keypair");
    let wrong = decrypt_conversation_key(&encrypted, &other_identity.private);
    assert!(wrong.is_err());
}

#[test]
fn vectors_decrypt_events_batch_and_single_event_contracts() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new(); // default reject_unverified = true
    core.import_keys_with_version(
        &B64.decode(&v.private_keys_concat_b64).unwrap(),
        &v.event_recipient_key_version,
    )
    .unwrap();

    let signing_keys = [chat_xdk_core::SigningKeyEntry {
        user_id: v.event_sender_id.clone(),
        public_key_version: v.event_signing_key_version.clone(),
        public_key: v.signing_public_b64.clone(),
        identity_public_key: v.identity_public_b64.clone(),
        identity_public_key_signature: v.identity_public_key_signature_b64.clone(),
    }];

    // Batch path: [KeyChange, message, garbage] never throws; the garbage
    // event is collected as an indexed error.
    let events: Vec<&str> = vec![
        &v.event_key_change_b64,
        &v.event_message_b64,
        &v.event_garbage_b64,
    ];
    let result = core.decrypt_events(&events, &signing_keys);

    assert_eq!(result.errors.len(), 1, "errors: {:?}", result.errors);
    assert!(
        result.errors.contains_key(&2),
        "errors: {:?}",
        result.errors
    );

    // The signed KeyChange is adopted: key bytes and latest version match.
    let adopted = result
        .conversation_keys
        .keys
        .get(&v.event_conversation_key_version)
        .expect("conversation key adopted from KeyChange");
    assert_eq!(B64.encode(adopted.encoded()), v.conversation_key_b64);
    assert_eq!(
        result.conversation_keys.latest_version,
        Some(v.event_conversation_key_version.clone())
    );

    let key_changes: Vec<_> = result
        .messages
        .iter()
        .filter_map(|m| match &m.event {
            chat_xdk_core::Event::KeyChange(kc) => Some(kc),
            _ => None,
        })
        .collect();
    assert_eq!(key_changes.len(), 1);
    assert!(key_changes[0].verified);
    assert_eq!(key_changes[0].key_version, v.event_conversation_key_version);

    // Exactly one verified message with the fixture text.
    let messages: Vec<_> = result
        .messages
        .iter()
        .filter_map(|m| match &m.event {
            chat_xdk_core::Event::Message(msg) => Some(msg),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text(), Some(v.event_message_text.as_str()));
    assert!(messages[0].verified);

    // Single-event path with pre-cached keys verifies the same message …
    let cached = result.conversation_keys.keys.clone();
    let event = core
        .decrypt_event(&v.event_message_b64, &cached, &signing_keys)
        .unwrap();
    match event {
        chat_xdk_core::Event::Message(msg) => {
            assert_eq!(msg.text(), Some(v.event_message_text.as_str()));
            assert!(msg.verified);
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }

    // … and throws on the garbage event.
    assert!(core
        .decrypt_event(&v.event_garbage_b64, &Default::default(), &signing_keys)
        .is_err());
}

#[test]
fn vectors_reply_preview_validation_accepts_genuine_and_rejects_forged() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new();
    core.import_keys_with_version(
        &B64.decode(&v.private_keys_concat_b64).unwrap(),
        &v.event_recipient_key_version,
    )
    .unwrap();

    let signing_keys = [chat_xdk_core::SigningKeyEntry {
        user_id: v.event_sender_id.clone(),
        public_key_version: v.event_signing_key_version.clone(),
        public_key: v.signing_public_b64.clone(),
        identity_public_key: v.identity_public_b64.clone(),
        identity_public_key_signature: v.identity_public_key_signature_b64.clone(),
    }];

    let events: Vec<&str> = vec![
        &v.event_key_change_b64,
        &v.event_reply_valid_b64,
        &v.event_reply_forged_b64,
    ];
    let result = core.decrypt_events(&events, &signing_keys);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);

    let messages: Vec<_> = result
        .messages
        .iter()
        .filter_map(|m| match &m.event {
            chat_xdk_core::Event::Message(msg) => Some(msg),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), 2);

    // Both replies decrypt; the derived preview validates, the forged one
    // is marked invalid.
    assert_eq!(messages[0].text(), Some(v.event_reply_text.as_str()));
    assert_eq!(
        messages[0].reply_preview_validation,
        Some(chat_xdk_core::ReplyPreviewValidation::Valid)
    );
    assert_eq!(
        messages[1].reply_preview_validation,
        Some(chat_xdk_core::ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn vectors_message_xchacha_roundtrip_and_ciphertext_is_randomized() {
    let v = load_vectors();
    let ckey_bytes = B64.decode(&v.conversation_key_b64).unwrap();
    let ckey = XChatConversationKey::from_bytes(ckey_bytes).unwrap();
    let plaintext = B64.decode(&v.plaintext_b64).unwrap();

    let ct1 = encrypt_message(&ckey, &plaintext).unwrap();
    let ct2 = encrypt_message(&ckey, &plaintext).unwrap();
    assert_ne!(ct1, ct2, "nonce should randomize ciphertext");

    let pt1 = decrypt_message(&ckey, &ct1).unwrap();
    assert_eq!(pt1, plaintext);
}
