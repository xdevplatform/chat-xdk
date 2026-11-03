//! Conversation keys: key-change events, extracting keys from them,
//! decrypting a key, and `ConversationKeyResult`.

use super::*;

#[test]
fn decrypt_event_key_change() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let kce = ThriftCKCE::new(
        Some("v42".to_string()),
        Some(vec![
            ConversationParticipantKey::new(
                Some("910004".to_string()),
                Some("encrypted-key-1".to_string()),
                Some("pkv-1".to_string()),
            ),
            ConversationParticipantKey::new(
                Some("910007".to_string()),
                Some("encrypted-key-2".to_string()),
                Some("63".to_string()),
            ),
        ]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::KeyChange(kc) => {
            assert_eq!(kc.conversation_key_version, "v42");
            assert_eq!(kc.conversation_participant_keys.len(), 2);
            assert_eq!(kc.conversation_participant_keys[0].user_id, "910004");
            assert_eq!(
                kc.conversation_participant_keys[0].encrypted_conversation_key,
                "encrypted-key-1"
            );
            assert_eq!(kc.conversation_participant_keys[1].user_id, "910007");
            assert!(!kc.verified);
        }
        other => panic!("Expected Event::KeyChange, got {:?}", other),
    }
}

/// A KeyChange whose signature was produced by `sign_key_change` must
/// verify on `decrypt_event` — even with an empty conversation-key map,
/// because the SDK self-decrypts the plaintext key from the event's own
/// participant entry (encrypted to our identity key). Guards the v7
/// plaintext-ckey verification path end to end (default reject_unverified).
#[test]
fn decrypt_event_key_change_verifies_signature() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let pubkeys = core.get_public_keys().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1733889755256";

    // Encrypt the conversation key for ourselves so the SDK can
    // self-decrypt it from the event to rebuild the signed payload.
    let recipients = [RecipientInput {
        user_id: "910003".to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap();

    // Sign the key change (v7 signs the plaintext conversation key).
    let sig = crate::core::test_support::key_change_signature(
        &core,
        "pkv-self",
        "msg-1",
        "910003",
        "conv-1",
        ckey_version,
        ckey.encoded(),
    )
    .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            Some("pkv-self".to_string()),
        )]),
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(sig.message_event_signature.signature.clone()),
        Some(sig.message_event_signature.public_key_version.clone()),
        Some(sig.message_event_signature.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let signing_keys = [SigningKeyEntry::new(
        "910003",
        "pkv-self",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    // Empty key map forces the self-decrypt path.
    let decrypted = core
        .decrypt_event_with(&event_b64, &Default::default(), &signing_keys)
        .unwrap();
    match decrypted {
        Event::KeyChange(kc) => {
            assert!(kc.verified, "CKCE signature must verify via self-decrypt");
            assert_eq!(kc.conversation_key_version, ckey_version);
        }
        other => panic!("Expected Event::KeyChange, got {:?}", other),
    }
}

// extract_conversation_keys tests

#[test]
fn extract_conversation_keys_empty_events() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core.extract_conversation_keys(&[]);
    assert!(result.is_empty());
    assert!(result.latest_version.is_none());
    assert_eq!(result.len(), 0);
}

#[test]
fn extract_conversation_keys_no_keys_loaded() {
    let core = ChatCore::new();
    // Don't generate keys — no identity key loaded

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));
    let result = core.extract_conversation_keys(&[&typing_b64]);
    assert!(result.is_empty());
}

#[test]
fn extract_conversation_keys_skips_non_key_events() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INTERNAL_ERROR),
        None::<ThriftRateLimitTier>,
    );
    let failure_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let result = core.extract_conversation_keys(&[&typing_b64, &failure_b64]);
    assert!(result.is_empty());
}

#[test]
fn extract_conversation_keys_skips_malformed_b64() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core.extract_conversation_keys(&["not-valid-base64!!!"]);
    assert!(result.is_empty());
}

#[test]
fn registered_key_version_selects_matching_participant_entry_and_skips_others() {
    // With a registered key version, participant-key entries targeting a
    // different version are skipped instead of trial-decrypted: an entry
    // matching the version is used even when an earlier decryptable entry
    // exists, and an event with only mismatched entries yields no key.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "64"))
        .unwrap();

    let pubkeys = core.get_public_keys().unwrap();
    let encrypt_for_self = |ckey: &XChatConversationKey| {
        let recipients = [RecipientInput {
            user_id: "910003".to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "unused".to_string(),
        }];
        core.encrypt_conversation_key_for_recipients(ckey, &recipients)
            .unwrap()[0]
            .encrypted_conversation_key
            .clone()
    };

    // Both entries decrypt with our identity key but carry different
    // conversation keys, so the extracted key reveals which entry was used.
    let ckey_mismatch = core.generate_conversation_key().unwrap();
    let ckey_match = core.generate_conversation_key().unwrap();

    let entry = |ckey_b64: String, version: &str| {
        ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(ckey_b64),
            Some(version.to_string()),
        )
    };

    let kce = ThriftCKCE::new(
        Some("42".to_string()),
        Some(vec![
            entry(encrypt_for_self(&ckey_mismatch), "not-V"),
            entry(encrypt_for_self(&ckey_match), "64"),
        ]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

    let result = core.extract_conversation_keys(&[&event_b64]);
    let extracted = result.get("42").expect("matching-version entry adopted");
    assert_eq!(extracted.encoded(), ckey_match.encoded());

    // Mismatched-only event: the key must not be adopted.
    let kce_mismatch_only = ThriftCKCE::new(
        Some("43".to_string()),
        Some(vec![entry(encrypt_for_self(&ckey_mismatch), "not-V")]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce_mismatch_only));
    let result = core.extract_conversation_keys(&[&event_b64]);
    assert!(result.is_empty());
}

// Conversation key encryption/decryption roundtrip

#[test]
fn generate_and_decrypt_conversation_key() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let public_keys = core.get_public_keys().unwrap();

    let recipients = vec![RecipientInput {
        user_id: "self".to_string(),
        public_key: public_keys.identity.clone(),
        key_version: "v1".to_string(),
    }];

    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].user_id, "self");

    let decrypted = core
        .decrypt_conversation_key(&encrypted[0].encrypted_conversation_key)
        .unwrap();
    assert_eq!(decrypted.encoded(), ckey.encoded());
}

// ConversationKeyResult accessors

#[test]
fn conversation_key_result_accessors() {
    let ckey = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), ckey.clone());

    let result = ConversationKeyResult {
        keys,
        latest_version: Some("v1".to_string()),
    };

    assert!(!result.is_empty());
    assert_eq!(result.len(), 1);
    assert!(result.get("v1").is_some());
    assert!(result.get("v2").is_none());
    assert!(result.latest_key().is_some());
}

#[test]
fn conversation_key_result_latest_key_none() {
    let result = ConversationKeyResult {
        keys: HashMap::new(),
        latest_version: None,
    };

    assert!(result.is_empty());
    assert!(result.latest_key().is_none());
}

// decrypt_conversation_key without keys errors

#[test]
fn decrypt_conversation_key_without_identity_errors() {
    let core = ChatCore::new();
    let result = core.decrypt_conversation_key("AAAA");
    assert!(result.is_err());
}
