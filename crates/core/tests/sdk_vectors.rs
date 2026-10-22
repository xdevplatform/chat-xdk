use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::{
    encryption::{decrypt_message, encrypt_message},
    key_factory::KeyFactory,
    keys::{KeypairPurpose, XChatConversationKey},
};
use chat_xdk_core::keys::conversation_keys::{decrypt_conversation_key, encrypt_conversation_key};
use chat_xdk_core::ImportKeysParams;
use chat_xdk_core::{
    DecryptEventParams, DecryptEventsParams, DecryptFileParams, FileDecryptorParams,
};

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
    event_failure_b64: String,
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
    event_conversation_id: String,
    message_key_conversation_key_hex: String,
    message_key_conversation_key_version: String,
    message_key_sender_id: String,
    message_key_short_conversation_key_hex: String,
    message_key_short_conversation_key_version: String,
    message_key_short_sender_id: String,
    event_message_key_b64: String,
    event_message_key_text: String,
    event_message_key_short_b64: String,
    event_message_key_short_text: String,
    event_key_change_message_key_b64: String,
    event_reply_message_key_b64: String,
    event_reply_message_key_text: String,
    media_first_hash_key: String,
    media_first_encrypted_b64: String,
    media_first_plaintext_b64: String,
    media_second_hash_key: String,
    media_second_encrypted_b64: String,
    media_second_plaintext_b64: String,
    media_short_hash_key: String,
    media_short_encrypted_b64: String,
    media_short_plaintext_b64: String,
    event_link_card_b64: String,
    media_banner_hash_key: String,
    media_banner_encrypted_b64: String,
    media_banner_plaintext_b64: String,
    media_favicon_hash_key: String,
    media_favicon_encrypted_b64: String,
    media_favicon_plaintext_b64: String,
    event_conversation_key_media_b64: String,
    media_conversation_key_hash_key: String,
    media_conversation_key_encrypted_b64: String,
    media_conversation_key_plaintext_b64: String,
    event_unencrypted_b64: String,
    media_unencrypted_hash_key: String,
    payload_message_v10_cev1: String,
    payload_message_v10: String,
    signature_v10_cev1_public_key_b64: String,
    signature_v10_cev1_b64: String,
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
    core.import_keys(
        &ImportKeysParams::new(B64.decode(&v.private_keys_concat_b64).unwrap().to_vec())
            .with_signing_key_version(&v.event_recipient_key_version),
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
    let events = vec![
        v.event_key_change_b64.clone(),
        v.event_message_b64.clone(),
        v.event_garbage_b64.clone(),
    ];
    let result = core
        .decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys.to_vec()));

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
    assert_eq!(
        key_changes[0].conversation_key_version,
        v.event_conversation_key_version
    );
    let key_change_json = serde_json::to_value(key_changes[0]).unwrap();
    let participant_keys = key_change_json["conversation_participant_keys"]
        .as_array()
        .expect("conversation_participant_keys");
    assert!(!participant_keys.is_empty());
    for key in participant_keys {
        let mut names: Vec<&String> = key.as_object().unwrap().keys().collect();
        names.sort();
        assert_eq!(
            names,
            [
                "encrypted_conversation_key",
                "public_key_version",
                "user_id"
            ]
        );
    }

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
        .decrypt_event(
            DecryptEventParams::new(v.event_message_b64.clone(), cached)
                .with_signing_keys(signing_keys.to_vec()),
        )
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
        .decrypt_event(
            DecryptEventParams::new(v.event_garbage_b64.clone(), Default::default())
                .with_signing_keys(signing_keys.to_vec()),
        )
        .is_err());
}

#[test]
fn vectors_failure_event_decodes_type_and_rate_limit_tier() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new(); // default reject_unverified = true

    // Failure events are unsigned by protocol, so they decode with no
    // conversation or signing keys even under the default reject policy.
    let event = core
        .decrypt_event(DecryptEventParams::new(
            v.event_failure_b64.clone(),
            Default::default(),
        ))
        .unwrap();
    match event {
        chat_xdk_core::Event::Failure(f) => {
            assert_eq!(f.failure, chat_xdk_core::FailureType::RateLimitUpsell);
            assert_eq!(
                f.rate_limit_tier,
                Some(chat_xdk_core::RateLimitTier::Premium)
            );
            assert_eq!(
                f.meta.sender_id.as_deref(),
                Some(v.event_sender_id.as_str())
            );
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn vectors_reply_preview_validation_accepts_genuine_and_rejects_forged() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new();
    core.import_keys(
        &ImportKeysParams::new(B64.decode(&v.private_keys_concat_b64).unwrap().to_vec())
            .with_signing_key_version(&v.event_recipient_key_version),
    )
    .unwrap();

    let signing_keys = [chat_xdk_core::SigningKeyEntry {
        user_id: v.event_sender_id.clone(),
        public_key_version: v.event_signing_key_version.clone(),
        public_key: v.signing_public_b64.clone(),
        identity_public_key: v.identity_public_b64.clone(),
        identity_public_key_signature: v.identity_public_key_signature_b64.clone(),
    }];

    let events = vec![
        v.event_key_change_b64.clone(),
        v.event_reply_valid_b64.clone(),
        v.event_reply_forged_b64.clone(),
    ];
    let result = core
        .decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys.to_vec()));
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

/// The fixture signing key, registered to `user_id`.
fn signing_key_for(v: &Vectors, user_id: &str) -> chat_xdk_core::SigningKeyEntry {
    chat_xdk_core::SigningKeyEntry {
        user_id: user_id.to_string(),
        public_key_version: v.event_signing_key_version.clone(),
        public_key: v.signing_public_b64.clone(),
        identity_public_key: v.identity_public_b64.clone(),
        identity_public_key_signature: v.identity_public_key_signature_b64.clone(),
    }
}

fn key_map(
    version: &str,
    key_hex: &str,
) -> std::collections::HashMap<String, XChatConversationKey> {
    [(
        version.to_string(),
        XChatConversationKey::from_bytes(hex::decode(key_hex).unwrap()).unwrap(),
    )]
    .into_iter()
    .collect()
}

fn expect_message(event: chat_xdk_core::Event) -> Box<chat_xdk_core::Message> {
    match event {
        chat_xdk_core::Event::Message(message) => message,
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

fn fixture_key_map(v: &Vectors) -> std::collections::HashMap<String, XChatConversationKey> {
    let ckey =
        XChatConversationKey::from_bytes(B64.decode(&v.conversation_key_b64).unwrap()).unwrap();
    [(v.event_conversation_key_version.clone(), ckey)]
        .into_iter()
        .collect()
}

fn message_key_map(v: &Vectors) -> std::collections::HashMap<String, XChatConversationKey> {
    key_map(
        &v.message_key_conversation_key_version,
        &v.message_key_conversation_key_hex,
    )
}

/// Decrypt `encrypted_b64` as the media `media_hash_key` names in
/// `event_b64`, whole and in 700-byte chunks, checking both agree.
fn open_media(
    event_b64: &str,
    keys: &std::collections::HashMap<String, XChatConversationKey>,
    media_hash_key: &str,
    encrypted_b64: &str,
) -> Result<Vec<u8>, chat_xdk_core::error::SdkError> {
    let core = chat_xdk_core::ChatCore::new();
    let encrypted = B64.decode(encrypted_b64).unwrap();
    let whole = core.decrypt_file(DecryptFileParams::new(
        encrypted.clone(),
        event_b64,
        keys.clone(),
        media_hash_key,
    ))?;
    let mut decryptor = core.file_decryptor(FileDecryptorParams::new(
        event_b64,
        keys.clone(),
        media_hash_key,
    ))?;
    let mut incremental = Vec::new();
    for chunk in encrypted.chunks(700) {
        incremental.extend(decryptor.push(chunk)?);
    }
    incremental.extend(decryptor.finish()?);
    assert_eq!(whole, incremental);
    Ok(whole)
}

fn media_error(
    event_b64: &str,
    keys: &std::collections::HashMap<String, XChatConversationKey>,
    media_hash_key: &str,
    encrypted: &[u8],
) -> String {
    chat_xdk_core::ChatCore::new()
        .decrypt_file(DecryptFileParams::new(
            encrypted.to_vec(),
            event_b64,
            keys.clone(),
            media_hash_key,
        ))
        .unwrap_err()
        .to_string()
}

#[test]
fn vectors_message_key_event_decrypts_with_the_conversation_key() {
    let v = load_vectors();
    let message = expect_message(
        chat_xdk_core::ChatCore::new()
            .decrypt_event(
                DecryptEventParams::new(v.event_message_key_b64.clone(), message_key_map(&v))
                    .with_signing_keys(vec![signing_key_for(&v, &v.message_key_sender_id)]),
            )
            .unwrap(),
    );
    assert!(message.verified);
    assert_eq!(message.text(), Some(v.event_message_key_text.as_str()));
    let hashes: Vec<_> = message
        .media_hashes
        .iter()
        .map(|h| h.media_hash_key.as_str())
        .collect();
    assert_eq!(
        hashes,
        vec![
            v.media_first_hash_key.as_str(),
            v.media_second_hash_key.as_str()
        ]
    );
}

#[test]
fn vectors_one_media_file_opens_from_its_message() {
    let v = load_vectors();
    let keys = key_map(
        &v.message_key_short_conversation_key_version,
        &v.message_key_short_conversation_key_hex,
    );
    assert_eq!(
        open_media(
            &v.event_message_key_short_b64,
            &keys,
            &v.media_short_hash_key,
            &v.media_short_encrypted_b64
        )
        .unwrap(),
        B64.decode(&v.media_short_plaintext_b64).unwrap()
    );
}

#[test]
fn vectors_several_media_files_open_from_their_message() {
    let v = load_vectors();
    let keys = message_key_map(&v);
    for (hash, encrypted, plaintext) in [
        (
            &v.media_first_hash_key,
            &v.media_first_encrypted_b64,
            &v.media_first_plaintext_b64,
        ),
        (
            &v.media_second_hash_key,
            &v.media_second_encrypted_b64,
            &v.media_second_plaintext_b64,
        ),
    ] {
        assert_eq!(
            open_media(&v.event_message_key_b64, &keys, hash, encrypted).unwrap(),
            B64.decode(plaintext).unwrap(),
            "{hash}"
        );
    }
}

#[test]
fn vectors_link_card_images_open_from_their_message() {
    let v = load_vectors();
    let keys = message_key_map(&v);
    for (hash, encrypted, plaintext) in [
        (
            &v.media_banner_hash_key,
            &v.media_banner_encrypted_b64,
            &v.media_banner_plaintext_b64,
        ),
        (
            &v.media_favicon_hash_key,
            &v.media_favicon_encrypted_b64,
            &v.media_favicon_plaintext_b64,
        ),
    ] {
        assert_eq!(
            open_media(&v.event_link_card_b64, &keys, hash, encrypted).unwrap(),
            B64.decode(plaintext).unwrap(),
            "{hash}"
        );
    }
}

#[test]
fn vectors_conversation_key_media_opens_from_its_message() {
    let v = load_vectors();
    assert_eq!(
        open_media(
            &v.event_conversation_key_media_b64,
            &fixture_key_map(&v),
            &v.media_conversation_key_hash_key,
            &v.media_conversation_key_encrypted_b64
        )
        .unwrap(),
        B64.decode(&v.media_conversation_key_plaintext_b64).unwrap()
    );
}

#[test]
fn vectors_media_errors_say_what_to_pass() {
    let v = load_vectors();
    let keys = message_key_map(&v);
    let first = B64.decode(&v.media_first_encrypted_b64).unwrap();
    let second = B64.decode(&v.media_second_encrypted_b64).unwrap();
    let cases = [
        (
            media_error(
                &v.event_message_key_b64,
                &fixture_key_map(&v),
                &v.media_first_hash_key,
                &first,
            ),
            format!(
                "no key for version '{}'",
                v.message_key_conversation_key_version
            ),
        ),
        (
            media_error(&v.event_message_key_b64, &keys, "not-a-hash-key", &first),
            "is not in the message".to_string(),
        ),
        (
            media_error(
                &v.event_key_change_b64,
                &keys,
                &v.media_first_hash_key,
                &first,
            ),
            "the event is not a message".to_string(),
        ),
        (
            media_error(
                &v.event_message_b64,
                &fixture_key_map(&v),
                &v.media_first_hash_key,
                &first,
            ),
            "the message has no media".to_string(),
        ),
        (
            media_error(
                &v.event_message_key_b64,
                &keys,
                &v.media_first_hash_key,
                &second,
            ),
            format!(
                "encrypted file of media_hash_key '{}'",
                v.media_first_hash_key
            ),
        ),
        (
            media_error(
                &v.event_message_key_b64,
                &keys,
                &v.media_first_hash_key,
                &first[..first.len() / 2],
            ),
            "truncated".to_string(),
        ),
        (
            media_error(
                &v.event_unencrypted_b64,
                &keys,
                &v.media_unencrypted_hash_key,
                &first,
            ),
            "the message is not encrypted".to_string(),
        ),
    ];
    for (error, expected) in cases {
        assert!(error.contains(&expected), "{error:?} lacks {expected:?}");
    }
}

#[test]
fn vectors_message_key_event_decrypts_in_a_batch_with_its_key_change() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new();
    core.import_keys(
        &ImportKeysParams::new(B64.decode(&v.private_keys_concat_b64).unwrap().to_vec())
            .with_signing_key_version(&v.event_recipient_key_version),
    )
    .unwrap();
    let signing_keys = [
        signing_key_for(&v, &v.event_sender_id),
        signing_key_for(&v, &v.message_key_sender_id),
    ];
    let result = core.decrypt_events(
        DecryptEventsParams::new(vec![
            v.event_key_change_message_key_b64.clone(),
            v.event_message_key_b64.clone(),
        ])
        .with_signing_keys(signing_keys.to_vec()),
    );
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    let ckey = result
        .conversation_keys
        .get(&v.message_key_conversation_key_version)
        .expect("conversation key adopted from the key change");
    assert_eq!(
        hex::encode(ckey.encoded()),
        v.message_key_conversation_key_hex
    );
    let texts: Vec<_> = result
        .messages
        .iter()
        .filter_map(|m| match &m.event {
            chat_xdk_core::Event::Message(msg) => msg.text().map(str::to_string),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec![v.event_message_key_text.clone()]);
    assert_eq!(
        open_media(
            &v.event_message_key_b64,
            &result.conversation_keys.keys,
            &v.media_second_hash_key,
            &v.media_second_encrypted_b64
        )
        .unwrap(),
        B64.decode(&v.media_second_plaintext_b64).unwrap()
    );
}

#[test]
fn vectors_short_sender_message_key_event_verifies_at_v11() {
    let v = load_vectors();
    let message = expect_message(
        chat_xdk_core::ChatCore::new()
            .decrypt_event(
                DecryptEventParams::new(
                    v.event_message_key_short_b64.clone(),
                    key_map(
                        &v.message_key_short_conversation_key_version,
                        &v.message_key_short_conversation_key_hex,
                    ),
                )
                .with_signing_keys(vec![signing_key_for(&v, &v.message_key_short_sender_id)]),
            )
            .unwrap(),
    );
    assert!(message.verified);
    assert_eq!(
        message.text(),
        Some(v.event_message_key_short_text.as_str())
    );
}

#[test]
fn vectors_reply_carrying_a_message_key_validates_and_opens_the_quoted_media() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new();
    let keys = fixture_key_map(&v);
    let message = expect_message(
        core.decrypt_event(
            DecryptEventParams::new(v.event_reply_message_key_b64.clone(), keys.clone())
                .with_signing_keys(vec![
                    signing_key_for(&v, &v.event_sender_id),
                    signing_key_for(&v, &v.message_key_sender_id),
                ]),
        )
        .unwrap(),
    );
    assert!(message.verified);
    assert_eq!(
        message.text(),
        Some(v.event_reply_message_key_text.as_str())
    );
    assert_eq!(
        message.meta.conversation_id.as_deref(),
        Some(v.event_conversation_id.as_str())
    );
    assert_eq!(
        message.reply_preview_validation,
        Some(chat_xdk_core::ReplyPreviewValidation::Valid)
    );
    assert_eq!(
        open_media(
            &v.event_reply_message_key_b64,
            &keys,
            &v.media_first_hash_key,
            &v.media_first_encrypted_b64
        )
        .unwrap(),
        B64.decode(&v.media_first_plaintext_b64).unwrap()
    );
}

#[test]
fn vectors_known_signature_covers_the_contents_encryption_version() {
    let v = load_vectors();
    let core = chat_xdk_core::ChatCore::new();
    let signature = B64.decode(&v.signature_v10_cev1_b64).unwrap();
    assert!(core
        .verify(
            &v.signature_v10_cev1_public_key_b64,
            &signature,
            v.payload_message_v10_cev1.as_bytes()
        )
        .unwrap());
    assert!(!core
        .verify(
            &v.signature_v10_cev1_public_key_b64,
            &signature,
            v.payload_message_v10.as_bytes()
        )
        .unwrap());
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
