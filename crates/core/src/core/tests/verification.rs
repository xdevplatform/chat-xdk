//! Verifying received events: `reject_unverified` and the signature-version
//! floor.

use super::*;

#[test]
fn reject_unverified_rejects_group_title_change_without_signing_keys() {
    // GroupTitleChange with no signing keys — reject_unverified=true
    // must reject it (not silently pass it through).
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupTitleChange(
            GroupTitleChange::new(
                Some(encrypted_metadata(&key, "New Title")),
                Some("7".to_string()),
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));
    let keys = HashMap::from([("7".to_string(), key)]);

    let result = core.decrypt_event_with(&event_b64, &keys, &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");

    // With reject_unverified=false it passes through with verified=false.
    core.set_reject_unverified(false);
    let event = core.decrypt_event_with(&event_b64, &keys, &[]).unwrap();
    match event {
        Event::GroupChange(gc) => {
            assert!(!gc.verified);
            assert!(
                matches!(gc.change, GroupChange::TitleChanged { ref new_title } if *new_title == text("New Title"))
            );
        }
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn reject_unverified_rejects_group_member_add_without_signing_keys() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberAdd(
            GroupMemberAddChange::new(
                Some(vec!["new-member".to_string()]),
                Some(vec!["member-1".to_string()]),
                Some(vec!["admin-1".to_string()]),
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                None::<Vec<String>>,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");
}

#[test]
fn reject_unverified_rejects_message_delete_without_signing_keys() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let del = ThriftMDE::new(
        Some(vec!["seq-99".to_string()]),
        None::<DeleteMessageAction>,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned MessageDelete");
}

#[test]
fn reject_unverified_rejects_group_change_with_no_inner_change() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let gc = ThriftGCE::new(None::<crate::thrift::event::GroupChange>, None);
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");
}

// Signature versions below the floor are rejected

/// Build a signed message event but overwrite the embedded
/// signature_version with `version`.
fn build_message_event_with_sig_version(core: &ChatCore, version: &str) -> (String, String) {
    let ckey = core.generate_conversation_key().unwrap();
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "downgrade probe")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    let mut event_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    // Re-parse and rewrite the signature_version field.
    let bytes = base64_decode(&event_b64).unwrap();
    let mut event = parse_message_event(&bytes).unwrap();
    if let Some(sig) = event.message_event_signature.as_mut() {
        sig.signature_version = Some(version.to_string());
    }
    event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let ckey_b64 = STANDARD_NO_PAD.encode(ckey.encoded());
    (event_b64, ckey_b64)
}

#[test]
fn signature_version_below_floor_is_rejected() {
    let core = ChatCore::new(); // default reject_unverified = true
    let reg = core.generate_keypairs().unwrap();
    let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "1");

    let ckey =
        XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    let result = core.decrypt_event_with(&event_b64, &conv_keys, &signing_keys);
    let err = result.expect_err("v1 signature must be rejected");
    assert!(
        err.to_string().contains("no longer accepted"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn signature_version_below_floor_never_verifies_in_permissive_mode() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    let reg = core.generate_keypairs().unwrap();
    let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "0");

    let ckey =
        XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    match core.decrypt_event_with(&event_b64, &conv_keys, &signing_keys) {
        Ok(Event::Message(msg)) => {
            assert!(!msg.verified, "below-floor version must never verify")
        }
        Ok(other) => panic!("expected Message, got {:?}", other),
        Err(e) => panic!("permissive mode should pass through unverified: {}", e),
    }
}

#[test]
fn signature_version_at_floor_is_processed() {
    let author = super::test_support::Party::new("4001");
    let ckey = author.core.generate_conversation_key().unwrap();
    let event = super::test_support::message_event(
        &author,
        "m-1",
        "100",
        "9001",
        None,
        crate::signatures::MIN_SIGNATURE_VERSION,
        &ckey,
        &crate::pipeline::build_message_content("at the floor", None, None, None).unwrap(),
    );
    let message = super::test_support::decrypt_message(
        &ChatCore::new(),
        &event,
        &[("9001".to_string(), ckey)].into_iter().collect(),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
}

// Default reject_unverified=true rejects unverifiable events

#[test]
fn reject_unverified_rejects_keychange_without_matching_signing_key() {
    // Default reject_unverified=true. A signed KeyChange with no
    // matching signing key cannot be verified and must be rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let kce = ThriftCKCE::new(
        Some("ckv-1".to_string()),
        None::<Vec<ConversationParticipantKey>>,
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some("AAAA".to_string()),
        Some("61".to_string()),
        Some("7".to_string()),
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

    // No matching signing key supplied → rejected.
    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "KeyChange with no matching signing key must be rejected"
    );
}

#[test]
fn reject_unverified_rejects_unencrypted_message_by_default() {
    // An unencrypted message (no conversation_key_version) carries no
    // signature, so under the default reject_unverified it is rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("plaintext");
    let event_b64 = build_test_message_event(&content, None);

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "unencrypted message must be rejected under default reject_unverified"
    );
}
