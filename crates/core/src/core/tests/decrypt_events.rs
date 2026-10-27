//! `decrypt_events`: batches, and the conversation keys it adopts from
//! verified key changes (signing-key bindings, signatures, freshness).

use super::*;

#[test]
fn decrypt_events_mixed_event_types() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INTERNAL_ERROR),
        None::<ThriftRateLimitTier>,
    );
    let failure_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let member_del = ThriftMADE::new(Some("user-99".to_string()), None);
    let member_del_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

    let events: Vec<&str> = vec![&typing_b64, &failure_b64, &member_del_b64];
    let result = core.decrypt_events_with(&events, &[]);

    assert_eq!(result.events.len(), 3);
    assert!(result.errors.is_empty());

    assert!(matches!(result.events[0].event, Event::Typing(_)));
    assert!(matches!(result.events[1].event, Event::Failure(_)));
    assert!(matches!(result.events[2].event, Event::MemberDeleted(_)));
}

#[test]
fn decrypt_events_with_errors_for_invalid_b64() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let events: Vec<&str> = vec![&typing_b64, "!!!invalid-base64!!!"];
    let result = core.decrypt_events_with(&events, &[]);

    assert_eq!(result.events.len(), 1);
    assert!(result.errors.contains_key(&1));
}

#[test]
fn decrypt_events_preserves_original_b64() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let events: Vec<&str> = vec![&typing_b64];
    let result = core.decrypt_events_with(&events, &[]);

    assert_eq!(result.events.len(), 1);
    assert_eq!(
        result.events[0].original_b64.as_deref(),
        Some(typing_b64.as_str()),
    );
}

// decrypt_events drops signing keys whose identity binding is invalid

#[test]
fn decrypt_events_drops_key_with_invalid_binding() {
    let core = ChatCore::new();
    // We supply unsigned KeyChange events; allow unverified through so
    // the conversation key is still extracted and the message decodes.
    core.set_reject_unverified(false);
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1";

    // KeyChange event seeds the conversation key for the batch.
    let kc_b64 =
        build_self_keychange_event(&core, &ckey, ckey_version, "4001", Some("61".to_string()));

    // A signed message encrypted with that conversation key.
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "binding check")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), ckey_version),
        )
        .unwrap();
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let good_key = SigningKeyEntry::new(
        "4001",
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    );

    // A bad-binding variant: corrupt the identity binding signature.
    let mut bad_sig_bytes = base64_decode(&reg.public_key.identity_public_key_signature).unwrap();
    bad_sig_bytes[0] ^= 0xFF;
    let mut bad_key = good_key.clone();
    bad_key.identity_public_key_signature = base64_encode(&bad_sig_bytes);

    let events: Vec<&str> = vec![&kc_b64, &msg_b64];

    // With only the bad-binding key, it is dropped → message unverified.
    let result_bad = core.decrypt_events_with(&events, std::slice::from_ref(&bad_key));
    let msg_bad = result_bad
        .events
        .iter()
        .find_map(|m| match &m.event {
            Event::Message(b) => Some(b),
            _ => None,
        })
        .expect("expected a decrypted Message");
    assert_eq!(msg_bad.text(), Some("binding check"));
    assert!(
        !msg_bad.verified,
        "key with invalid binding must be dropped → unverified"
    );

    // With the correct key, the same message verifies.
    let result_good = core.decrypt_events_with(&events, std::slice::from_ref(&good_key));
    let msg_good = result_good
        .events
        .iter()
        .find_map(|m| match &m.event {
            Event::Message(b) => Some(b),
            _ => None,
        })
        .expect("expected a decrypted Message");
    assert!(msg_good.verified, "valid binding → verified");
}

// decrypt_events only adopts keys from verified KeyChange events

#[test]
fn decrypt_events_adopts_key_from_keychange_the_sdk_cannot_verify() {
    // Some KeyChange events are signed with a payload the SDK does not
    // reproduce, so the signature does not verify here. The key is still
    // adopted so messages decrypt (the KeyChange event is reported as an
    // error under the default reject_unverified policy).
    let core = ChatCore::new(); // default reject_unverified = true
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1001";

    let kc_b64 =
        build_self_keychange_event(&core, &ckey, ckey_version, "4001", Some("61".to_string()));

    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), ckey_version),
        )
        .unwrap();
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    let events: Vec<&str> = vec![&kc_b64, &msg_b64];
    let result = core.decrypt_events_with(&events, &signing_keys);

    // Key adopted despite the unverifiable KeyChange signature, but an
    // unverified key change never becomes the latest version.
    assert!(result.conversation_keys.keys.contains_key(ckey_version));
    assert_eq!(result.conversation_keys.latest_version, None);
    // The message under it decrypts (its own signature verifies).
    let msg = result
        .events
        .iter()
        .find_map(|m| match &m.event {
            Event::Message(b) => Some(b),
            _ => None,
        })
        .expect("message under adopted key must decrypt");
    assert_eq!(msg.text(), Some("hello"));
    // The KeyChange event itself is still reported unverified.
    assert!(result.errors.contains_key(&0));
}

#[test]
fn decrypt_events_adopts_key_from_signed_keychange() {
    // The legitimate path: a v7-signed KeyChange is adopted and the
    // message encrypted under it decrypts and verifies.
    let core = ChatCore::new(); // default reject_unverified = true
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1001";

    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        ckey_version,
        "4001",
        "61",
        Some("61".to_string()),
    );

    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello verified")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), ckey_version),
        )
        .unwrap();
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    let events: Vec<&str> = vec![&kc_b64, &msg_b64];
    let result = core.decrypt_events_with(&events, &signing_keys);

    assert!(
        result.conversation_keys.keys.contains_key(ckey_version),
        "key from signed KeyChange must be adopted; errors: {:?}",
        result.errors
    );
    assert_eq!(
        result.conversation_keys.latest_version,
        Some(ckey_version.to_string())
    );
    let msg = result
        .events
        .iter()
        .find_map(|m| match &m.event {
            Event::Message(b) => Some(b),
            _ => None,
        })
        .expect("message under adopted key must decrypt");
    assert_eq!(msg.text(), Some("hello verified"));
    assert!(msg.verified);
}

#[test]
fn ckey_sig_v6_enforcement_gates_adoption_by_sequence_number() {
    // Build a v7-signed CKCE at a numeric sequence number, optionally
    // corrupting its signature, and confirm the sequence-number threshold
    // gates key adoption.
    let build = |core: &ChatCore, seq: &str, corrupt: bool| -> String {
        let ckey = core.generate_conversation_key().unwrap();
        let pubkeys = core.get_public_keys().unwrap();
        let recipients = [RecipientInput {
            user_id: "910003".to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "pkv-self".to_string(),
        }];
        let encrypted = core
            .encrypt_conversation_key_for_recipients(&ckey, &recipients)
            .unwrap();
        let action_sig = core
            .sign_key_change("61", "msg-kc", "910003", "conv-1", "1001", ckey.encoded())
            .unwrap();
        let signature = if corrupt {
            let mut raw = base64_decode(&action_sig.message_event_signature.signature).unwrap();
            raw[5] ^= 0xff;
            STANDARD_NO_PAD.encode(raw)
        } else {
            action_sig.message_event_signature.signature.clone()
        };
        let kce = ThriftCKCE::new(
            Some("1001".to_string()),
            Some(vec![ConversationParticipantKey::new(
                Some("910003".to_string()),
                Some(encrypted[0].encrypted_conversation_key.clone()),
                None,
            )]),
            None,
            None,
        );
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(signature),
            Some(
                action_sig
                    .message_event_signature
                    .public_key_version
                    .clone(),
            ),
            Some(action_sig.message_event_signature.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some(seq.to_string()),
            Some("msg-kc".to_string()),
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
        base64_encode(&serialize_thrift(&event).unwrap())
    };

    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    // The shipped decrypt path holds enforcement off, so a bad signature
    // is still adopted (and surfaced as an error), but it is not reported
    // as the latest version.
    let bad = build(&core, "100", true);
    let result = core.decrypt_events_with(&[&bad], &signing_keys);
    assert!(result.conversation_keys.keys.contains_key("1001"));
    assert!(result.errors.contains_key(&0));
    assert_eq!(result.conversation_keys.latest_version, None);

    // Enforce from sequence 0: a valid signature is kept.
    let good = build(&core, "100", false);
    let mut kr = core.extract_conversation_keys(&[&good]);
    core.enforce_ckey_signatures(&[&good], &signing_keys, &mut kr, 0);
    assert!(kr.keys.contains_key("1001"));

    // Enforce from sequence 0: a bad signature is dropped, not adopted.
    let bad = build(&core, "100", true);
    let mut kr = core.extract_conversation_keys(&[&bad]);
    core.enforce_ckey_signatures(&[&bad], &signing_keys, &mut kr, 0);
    assert!(!kr.keys.contains_key("1001"));

    // Threshold above the event sequence: the bad signature is kept.
    let bad = build(&core, "100", true);
    let mut kr = core.extract_conversation_keys(&[&bad]);
    core.enforce_ckey_signatures(&[&bad], &signing_keys, &mut kr, 200);
    assert!(kr.keys.contains_key("1001"));
}

#[test]
fn decrypt_events_opt_out_preserves_unsigned_keychange_adoption() {
    // With reject_unverified disabled, any decryptable key is adopted.
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1001";

    let kc_b64 =
        build_self_keychange_event(&core, &ckey, ckey_version, "910003", Some("61".to_string()));

    let signing_keys = [signing_key_entry_for(&reg, "910003")];
    let result = core.decrypt_events_with(&[&kc_b64], &signing_keys);

    assert!(
        result.conversation_keys.keys.contains_key(ckey_version),
        "opt-out mode must still adopt any decryptable key"
    );
}

// Conversation-key freshness (monotonic latest version)

/// Build a v7-signed CKCE for `conv_id` at `version`, optionally corrupting
/// the signature so it fails verification.
fn build_freshness_keychange(
    core: &ChatCore,
    conv_id: &str,
    version: &str,
    corrupt: bool,
) -> String {
    let ckey = core.generate_conversation_key().unwrap();
    let pubkeys = core.get_public_keys().unwrap();
    let recipients = [RecipientInput {
        user_id: "910003".to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap();
    let action_sig = core
        .sign_key_change("61", "msg-kc", "910003", conv_id, version, ckey.encoded())
        .unwrap();
    let signature = if corrupt {
        let mut raw = base64_decode(&action_sig.message_event_signature.signature).unwrap();
        raw[5] ^= 0xff;
        STANDARD_NO_PAD.encode(raw)
    } else {
        action_sig.message_event_signature.signature.clone()
    };
    let kce = ThriftCKCE::new(
        Some(version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            None,
        )]),
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(signature),
        Some(
            action_sig
                .message_event_signature
                .public_key_version
                .clone(),
        ),
        Some(action_sig.message_event_signature.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-kc".to_string()),
        Some("msg-kc".to_string()),
        Some("910003".to_string()),
        Some(conv_id.to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

#[test]
fn latest_version_holds_at_newest_verified_keychange() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    // A verified key change at version 200 is reported as latest.
    let kc200 = build_freshness_keychange(&core, "conv-1", "200", false);
    let result = core.decrypt_events_with(&[&kc200], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("200")
    );

    // A later replay of an OLDER verified key change does not downgrade the
    // reported latest, but its key is still adopted for decryption.
    let kc100 = build_freshness_keychange(&core, "conv-1", "100", false);
    let result = core.decrypt_events_with(&[&kc100], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("200")
    );
    assert!(result.conversation_keys.keys.contains_key("100"));
}

#[test]
fn latest_version_is_none_until_a_keychange_verifies() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    // A key change whose signature is rejected sets no latest version,
    // though its key still decrypts.
    let kc200_bad = build_freshness_keychange(&core, "conv-1", "200", true);
    let result = core.decrypt_events_with(&[&kc200_bad], &signing_keys);
    assert!(result.errors.contains_key(&0));
    assert!(result.conversation_keys.keys.contains_key("200"));
    assert_eq!(result.conversation_keys.latest_version, None);

    // Without the sender's signing key nothing verifies either.
    let kc300 = build_freshness_keychange(&core, "conv-1", "300", false);
    let result = core.decrypt_events_with(&[&kc300], &[]);
    assert_eq!(result.conversation_keys.latest_version, None);

    // Once a key change verifies, it is the latest version, and the
    // rejected higher one still is not.
    let kc100 = build_freshness_keychange(&core, "conv-1", "100", false);
    let result = core.decrypt_events_with(&[&kc200_bad, &kc100], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("100")
    );
}

#[test]
fn latest_version_ignores_unverified_higher_keychange() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    // Establish a verified high-water at 100.
    let kc100 = build_freshness_keychange(&core, "conv-1", "100", false);
    let result = core.decrypt_events_with(&[&kc100], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("100")
    );

    // A higher version 200 with a bad signature must not become latest.
    let kc200_bad = build_freshness_keychange(&core, "conv-1", "200", true);
    let result = core.decrypt_events_with(&[&kc200_bad], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("100")
    );
}

#[test]
fn freshness_high_water_is_per_conversation() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    // High-water for conv-1 at 500.
    let kc_a = build_freshness_keychange(&core, "conv-1", "500", false);
    let _ = core.decrypt_events_with(&[&kc_a], &signing_keys);

    // conv-2 is independent: its own verified version 100 is latest.
    let kc_b = build_freshness_keychange(&core, "conv-2", "100", false);
    let result = core.decrypt_events_with(&[&kc_b], &signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("100")
    );
}
