//! The conversation-key cache and the signing-key store.

use super::*;

#[test]
fn cache_resolves_verified_latest_key_for_encrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);

    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "4001",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    // No key passed: it resolves from the cache at the verified version.
    let payload = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "cached"))
        .unwrap();
    assert_eq!(payload.conversation_key_version, "1001");

    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");
    let conv_keys = [("1001".to_string(), ckey)].into_iter().collect();
    match core
        .decrypt_event_with(&msg_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => assert_eq!(msg.text(), Some("cached")),
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn files_take_the_messages_key_from_the_cache_too() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);
    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "4001",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    let mut params = crate::EncryptMessageParams::new("conv-1", "a photo");
    params.attachments = Some(vec![AttachmentDescriptor::Media {
        media_hash_key: "photo".into(),
        width: 1,
        height: 1,
        filesize_bytes: 10,
        filename: "photo.jpg".into(),
        media_type: Some(1),
        duration_millis: None,
    }]);
    let payload = core.encrypt_message(&params).unwrap();

    // No key passed: the file takes the cached key, as its message did.
    let encrypted = core
        .encrypt_file(&EncryptFileParams::new(
            b"photo bytes".to_vec(),
            payload.event_b64.clone(),
            "photo",
        ))
        .unwrap();
    let keys = [("1001".to_string(), ckey.clone())].into_iter().collect();
    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(
            encrypted,
            payload.event_b64.clone(),
            keys,
            "photo",
        ))
        .unwrap();
    assert_eq!(decrypted, b"photo bytes");

    let err = core
        .encrypt_file(
            &EncryptFileParams::new(b"photo".to_vec(), payload.event_b64, "photo")
                .with_conversation_key(ckey.to_bytes(), "1002"),
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("conversation_key_version '1002' is not the message's key version '1001'"),
        "{err}"
    );
}

#[test]
fn cache_is_off_by_default() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "61"))
        .unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "910003",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "910003")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    let err = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "no cache"))
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
}

#[test]
fn unverified_key_change_never_becomes_an_encryption_key() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "61"))
        .unwrap();
    core.set_cache_keys(true);

    // Adopted-for-decryption key change with an unverifiable signature.
    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_self_keychange_event(&core, &ckey, "2002", "910003", Some("61".to_string()));
    let signing_keys = [signing_key_entry_for(&reg, "910003")];
    let result = core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);
    assert!(result.conversation_keys.keys.contains_key("2002"));

    let err = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "must fail"))
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
}

#[test]
fn cache_never_moves_below_the_verified_high_water() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);
    let signing_keys = [signing_key_entry_for(&reg, "4001")];

    let newer = core.generate_conversation_key().unwrap();
    let kc_newer = build_signed_self_keychange_event(
        &core,
        &newer,
        "2000",
        "4001",
        "61",
        Some("61".to_string()),
    );
    core.decrypt_events_with(&[kc_newer.as_str()], &signing_keys);

    // A validly signed but older key change replayed later must not
    // displace the newer cached key.
    let older = core.generate_conversation_key().unwrap();
    let kc_older = build_signed_self_keychange_event(
        &core,
        &older,
        "1000",
        "4001",
        "61",
        Some("61".to_string()),
    );
    core.decrypt_events_with(&[kc_older.as_str()], &signing_keys);

    let payload = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "fresh"))
        .unwrap();
    assert_eq!(payload.conversation_key_version, "2000");
}

#[test]
fn signing_key_store_is_used_when_the_argument_is_omitted() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");
    let conv_keys: HashMap<String, XChatConversationKey> =
        [("9001".to_string(), ckey)].into_iter().collect();

    // Without stored keys an empty slice still fails verification.
    assert!(core.decrypt_event_with(&msg_b64, &conv_keys, &[]).is_err());

    core.set_signing_keys(&[signing_key_entry_for(&reg, "4001")]);
    match core.decrypt_event_with(&msg_b64, &conv_keys, &[]).unwrap() {
        Event::Message(msg) => {
            assert!(msg.verified);
            assert_eq!(msg.text(), Some("hello"));
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn cached_key_debug_output_is_redacted() {
    let key = KeyFactory::generate_conversation_key().unwrap();
    let cached = CachedConversationKey { version: 1, key };
    let debug = format!("{:?}", cached);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("bytes"));
}
