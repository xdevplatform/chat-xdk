//! The prepare calls: conversation-key changes, group actions, message
//! deletes and read receipts, and the action signatures they return.

use super::*;

/// An explicit conversation id passed to prepare_conversation_key_change
/// canonicalizes the same way: the returned id is the colon form and the
/// signature round-trips against it.
#[test]
fn prepare_conversation_key_change_canonicalizes_explicit_id() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("111", &pk.identity, "1")];

    for form in ["222", "222-111", "111:222"] {
        let mut params =
            crate::ConversationKeyChangeParams::new(input.clone()).with_identity("111", "1");
        params.conversation_id = Some(form.to_string());
        let prepared = core.prepare_conversation_key_change(&params).unwrap();
        assert_eq!(prepared.conversation_id, "111:222", "form {form:?}");
        let ckey_b64 =
            STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
        assert_action_signature_round_trips(
            &core,
            &prepared.action_signatures[0],
            "111",
            "111:222",
            Some(&ckey_b64),
        );
    }
}

#[test]
fn prepare_conversation_key_change_empty_input_errors() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let mut params = crate::ConversationKeyChangeParams::new(vec![]).with_identity("910002", "1");
    params.conversation_id = Some("conv-1".into());
    let result = core.prepare_conversation_key_change(&params);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("must not be empty"));
}

#[test]
fn prepare_conversation_key_change_picks_latest_version() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let public_keys = core.get_public_keys().unwrap();
    let input = vec![
        PublicKeyInput::new("910004", &public_keys.identity, "100"),
        PublicKeyInput::new("910004", &public_keys.identity, "200"),
    ];

    let mut params = crate::ConversationKeyChangeParams::new(input).with_identity("910004", "1");
    params.conversation_id = Some("conv-1".into());
    let result = core.prepare_conversation_key_change(&params).unwrap();
    assert_eq!(result.conversation_participant_keys.len(), 1);
    assert_eq!(
        result.conversation_participant_keys[0].public_key_version,
        "200"
    );
    assert!(result.conversation_key.is_some());
    assert!(!result.conversation_key_version.is_empty());
    assert_eq!(result.action_signatures.len(), 1);
}

#[test]
fn derive_one_to_one_conversation_id_sorts_numerically() {
    // Numeric ordering: the shorter id is numerically smaller and sorts
    // first, even though it would sort last lexically.
    let input = vec![
        PublicKeyInput::new("1491585161162473473", "x", "1"),
        PublicKeyInput::new("17380288", "y", "1"),
    ];
    let id = ChatCore::derive_one_to_one_conversation_id(&input).unwrap();
    assert_eq!(id, "17380288:1491585161162473473");
}

#[test]
fn derive_one_to_one_conversation_id_requires_two_users() {
    let one = vec![PublicKeyInput::new("solo", "x", "1")];
    assert!(ChatCore::derive_one_to_one_conversation_id(&one).is_err());
}

#[test]
fn prepare_conversation_key_change_encodes_event_detail() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];
    let mut params = crate::ConversationKeyChangeParams::new(input).with_identity("910004", "1");
    params.conversation_id = Some("conv-1".into());
    let result = core.prepare_conversation_key_change(&params).unwrap();
    let sig = &result.action_signatures[0];
    assert!(!sig.encoded_message_event_detail.is_empty());

    // The encoded detail must decode as a ConversationKeyChangeEvent carrying
    // the same key version and one participant key.
    let bytes = base64_decode(&sig.encoded_message_event_detail).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
    let mut proto = BoundedProtocol::new(&mut raw);
    let detail = MessageEventDetail::read_from_in_protocol(&mut proto).unwrap();
    match detail {
        MessageEventDetail::ConversationKeyChangeEvent(kce) => {
            assert_eq!(
                kce.conversation_key_version.as_deref(),
                Some(result.conversation_key_version.as_str())
            );
            assert_eq!(kce.conversation_participant_keys.unwrap().len(), 1);
        }
        _ => panic!("expected ConversationKeyChangeEvent"),
    }
}

fn decode_detail(b64: &str) -> MessageEventDetail {
    let bytes = base64_decode(b64).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
    let mut proto = BoundedProtocol::new(&mut raw);
    MessageEventDetail::read_from_in_protocol(&mut proto).unwrap()
}

#[test]
fn prepare_group_create_emits_two_signatures_with_details() {
    use crate::thrift::event::GroupChange as GenGC;
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];

    let params = crate::GroupCreateParams::new(
        input,
        "g999",
        vec!["910004".to_string(), "910007".to_string()],
        vec!["910004".to_string()],
    )
    .with_identity("910004", "1")
    .with_title("Squad")
    .with_ttl_msec(86400000);
    let result = core.prepare_group_create(&params).unwrap();

    assert_eq!(result.conversation_id, "g999");
    assert_eq!(result.action_signatures.len(), 2);

    let ckce = &result.action_signatures[0];
    // Withheld: the key-change payload embeds the plaintext conversation key.
    assert!(ckce.signature_payload.is_empty());
    assert!(matches!(
        decode_detail(&ckce.encoded_message_event_detail),
        MessageEventDetail::ConversationKeyChangeEvent(_)
    ));

    let create = &result.action_signatures[1];
    assert!(create
        .signature_payload
        .starts_with("GroupChangeEvent.GroupCreate,"));
    // conversation id is not part of the signed create payload.
    assert!(!create.signature_payload.contains("g999"));
    match decode_detail(&create.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
            GenGC::GroupCreate(gc) => {
                assert_eq!(
                    gc.member_ids.as_deref(),
                    Some(["910004".to_string(), "910007".to_string()].as_slice())
                );
                assert_eq!(
                    gc.admin_ids.as_deref(),
                    Some(["910004".to_string()].as_slice())
                );
                // The title goes out encrypted under the new key, as the
                // result returns it for the request; a create sets no avatar.
                let key = result.conversation_key.as_ref().unwrap();
                assert_eq!(gc.title, result.encrypted_title);
                assert_eq!(result.encrypted_description, None);
                assert_eq!(gc.avatar_url, None);
                assert_eq!(
                    core.decrypt(gc.title.as_deref().unwrap(), key).unwrap(),
                    "Squad"
                );
                assert!(create
                    .signature_payload
                    .contains(gc.title.as_deref().unwrap()));
                assert!(!create.signature_payload.contains("Squad"));
                assert_eq!(
                    gc.conversation_key_version.as_deref(),
                    Some(result.conversation_key_version.as_str())
                );
                assert_eq!(gc.ttl_msec, Some(86400000));
            }
            other => panic!("expected GroupCreate, got {:?}", other),
        },
        _ => panic!("expected GroupChangeEvent"),
    }
}

#[test]
fn prepare_group_members_change_emits_two_signatures_with_details() {
    use crate::thrift::event::GroupChange as GenGC;
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];

    let params = crate::GroupMembersChangeParams::new(
        input,
        "g555",
        vec!["910006".to_string()],
        vec!["910004".to_string()],
        vec!["910004".to_string()],
        vec![],
    )
    .with_identity("910004", "1")
    .with_current_title("Team")
    .with_current_description("Ships the app")
    .with_current_avatar_url("https://ton.x.com/xchat_media/g555/avatar");
    let result = core.prepare_group_members_change(&params).unwrap();

    assert_eq!(result.action_signatures.len(), 2);

    let ckce = &result.action_signatures[0];
    // Withheld: the key-change payload embeds the plaintext conversation key.
    assert!(ckce.signature_payload.is_empty());
    assert!(matches!(
        decode_detail(&ckce.encoded_message_event_detail),
        MessageEventDetail::ConversationKeyChangeEvent(_)
    ));

    let add = &result.action_signatures[1];
    assert!(add
        .signature_payload
        .starts_with("GroupChangeEvent.GroupMemberAddChange,"));
    assert!(!add.signature_payload.contains("Team"));
    assert!(!add.signature_payload.contains("Ships the app"));
    assert_eq!(add.message_event_signature.signature_version, "8");
    match decode_detail(&add.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
            GenGC::GroupMemberAdd(c) => {
                assert_eq!(
                    c.member_ids.as_deref(),
                    Some(["910006".to_string()].as_slice())
                );
                assert_eq!(
                    c.current_member_ids.as_deref(),
                    Some(["910004".to_string()].as_slice())
                );
                // The title and description go out encrypted under the
                // key the add generates, as the result returns them for
                // the request; the avatar URL goes out as passed.
                let key = result.conversation_key.as_ref().unwrap();
                assert_eq!(c.current_title, result.encrypted_title);
                assert_eq!(c.current_description, result.encrypted_description);
                assert_eq!(
                    core.decrypt(c.current_title.as_deref().unwrap(), key)
                        .unwrap(),
                    "Team"
                );
                assert_eq!(
                    core.decrypt(c.current_description.as_deref().unwrap(), key)
                        .unwrap(),
                    "Ships the app"
                );
                assert!(add
                    .signature_payload
                    .contains(c.current_description.as_deref().unwrap()));
                assert_eq!(
                    c.current_avatar_url.as_deref(),
                    Some("https://ton.x.com/xchat_media/g555/avatar")
                );
                assert_eq!(c.screen_capture_blocking_enabled, None);
                assert_eq!(
                    c.conversation_key_version.as_deref(),
                    Some(result.conversation_key_version.as_str())
                );
            }
            other => panic!("expected GroupMemberAdd, got {:?}", other),
        },
        _ => panic!("expected GroupChangeEvent"),
    }
}

/// Reconstruct the canonical signed payload for an emitted action signature
/// through the exact code `decrypt_events` uses to verify, assert it equals
/// the bytes the signer signed, and verify the signature with the signer's
/// public key. This pins sign↔verify self-consistency for group actions.
fn assert_action_signature_round_trips(
    core: &ChatCore,
    sig: &crate::signatures::ActionSignature,
    sender_id: &str,
    conversation_id: &str,
    plaintext_ckey_b64: Option<&str>,
) {
    let detail = decode_detail(&sig.encoded_message_event_detail);
    let signed = &sig.message_event_signature;
    let event_sig = crate::thrift::event::MessageEventSignature::new(
        Some(signed.signature.clone()),
        Some(signed.public_key_version.clone()),
        Some(signed.signature_version.clone()),
        None::<String>,
        None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
    );
    let event = crate::thrift::event::MessageEvent::new(
        Some("seq-1".to_string()),
        Some(sig.message_id.clone()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(detail.clone()),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(event_sig),
        None::<String>,
        None::<bool>,
        None,
    );

    let reconstructed = build_event_signature_payload(&event, &detail, plaintext_ckey_b64)
        .expect("verifier could not reconstruct the signed payload");
    // Key-change signatures withhold their payload (it embeds the
    // plaintext conversation key); for those the ECDSA check below is
    // the sign↔verify pin. Group actions keep the payload — compare it.
    if !sig.signature_payload.is_empty() {
        assert_eq!(
            reconstructed.as_slice(),
            sig.signature_payload.as_bytes(),
            "signer payload and verifier reconstruction diverge"
        );
    }

    let signing_pubkey = core.get_public_keys().unwrap().signing;
    assert_eq!(signed.signing_public_key, signing_pubkey);
    let sig_bytes = base64_decode(&signed.signature).unwrap();
    assert!(
        core.verify(&signing_pubkey, &sig_bytes, &reconstructed)
            .unwrap(),
        "signature did not verify against the reconstructed payload"
    );
}

#[test]
fn group_signatures_verify_against_own_reconstruction() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];

    // GroupCreate: CKCE + GroupCreate signatures both round-trip.
    let create_params = crate::GroupCreateParams::new(
        input.clone(),
        "g999",
        vec!["910004".to_string(), "910007".to_string()],
        vec!["910004".to_string()],
    )
    .with_identity("910004", "1")
    .with_title("Squad")
    .with_ttl_msec(86400000);
    let created = core.prepare_group_create(&create_params).unwrap();
    let created_ckey_b64 =
        STANDARD_NO_PAD.encode(created.conversation_key.as_ref().unwrap().encoded());
    assert_action_signature_round_trips(
        &core,
        &created.action_signatures[0],
        "910004",
        "g999",
        Some(&created_ckey_b64),
    );
    assert_action_signature_round_trips(
        &core,
        &created.action_signatures[1],
        "910004",
        "g999",
        None,
    );

    // GroupMemberAdd: CKCE + GroupMemberAdd signatures both round-trip,
    // with the description the add signs at version 8.
    let add_params = crate::GroupMembersChangeParams::new(
        input.clone(),
        "g555",
        vec!["910006".to_string()],
        vec!["910004".to_string()],
        vec!["910004".to_string()],
        vec!["910008".to_string()],
    )
    .with_identity("910004", "1")
    .with_current_title("Team")
    .with_current_description("Ships the app")
    .with_current_avatar_url("https://img/b.png")
    .with_current_ttl_msec(3600000);
    let added = core.prepare_group_members_change(&add_params).unwrap();
    let added_ckey_b64 = STANDARD_NO_PAD.encode(added.conversation_key.as_ref().unwrap().encoded());
    assert_action_signature_round_trips(
        &core,
        &added.action_signatures[0],
        "910004",
        "g555",
        Some(&added_ckey_b64),
    );
    assert_action_signature_round_trips(&core, &added.action_signatures[1], "910004", "g555", None);

    // GroupMemberAdd with screen-capture blocking enabled: the flag lands
    // in the encoded detail, is signed, and the signature round-trips.
    let blocked_params = crate::GroupMembersChangeParams::new(
        input,
        "g555",
        vec!["910006".to_string()],
        vec!["910004".to_string()],
        vec!["910004".to_string()],
        vec![],
    )
    .with_identity("910004", "1")
    .with_current_screen_capture_blocking_enabled(true);
    let blocked = core.prepare_group_members_change(&blocked_params).unwrap();
    let blocked_add = &blocked.action_signatures[1];
    assert!(blocked_add.signature_payload.ends_with(",true"));
    // An add without a description signs at the current version, which
    // every reader verifies.
    assert_eq!(
        blocked_add.message_event_signature.signature_version,
        crate::signatures::SIGNATURE_VERSION
    );
    match decode_detail(&blocked_add.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
            crate::thrift::event::GroupChange::GroupMemberAdd(c) => {
                assert_eq!(c.screen_capture_blocking_enabled, Some(true));
            }
            other => panic!("expected GroupMemberAdd, got {:?}", other),
        },
        _ => panic!("expected GroupChangeEvent"),
    }
    assert_action_signature_round_trips(&core, blocked_add, "910004", "g555", None);
}

#[test]
fn message_delete_signature_verifies_against_own_reconstruction() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let params = crate::MessageDeleteParams::new(
        "222-111",
        vec!["seq-10".to_string(), "seq-11".to_string()],
        true,
    )
    .with_identity("111", "1");
    let sig = only_action(core.prepare_message_delete(&params).unwrap());

    // The 1:1 conversation id is signed in canonical colon form even when
    // the params carry the hyphen form.
    assert_eq!(
        sig.signature_payload,
        format!(
            "MessageDeleteEvent,{},111,111:222,2,seq-10,seq-11",
            sig.message_id
        )
    );

    match decode_detail(&sig.encoded_message_event_detail) {
        MessageEventDetail::MessageDeleteEvent(del) => {
            assert_eq!(
                del.sequence_ids,
                Some(vec!["seq-10".to_string(), "seq-11".to_string()])
            );
            assert_eq!(
                del.delete_message_action,
                Some(crate::thrift::event::DeleteMessageAction::DELETE_FOR_ALL)
            );
        }
        other => panic!("expected MessageDeleteEvent, got {:?}", other),
    }

    assert_action_signature_round_trips(&core, &sig, "111", "111:222", None);
}

#[test]
fn message_delete_for_self_signs_action_one() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let params = crate::MessageDeleteParams::new("g999", vec!["seq-1".to_string()], false)
        .with_identity("111", "1");
    let sig = only_action(core.prepare_message_delete(&params).unwrap());

    assert_eq!(
        sig.signature_payload,
        format!("MessageDeleteEvent,{},111,g999,1,seq-1", sig.message_id)
    );
    assert_action_signature_round_trips(&core, &sig, "111", "g999", None);
}

#[test]
fn prepare_message_delete_rejects_empty_sequence_ids() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let params = crate::MessageDeleteParams::new("g999", vec![], true).with_identity("111", "1");
    assert!(core.prepare_message_delete(&params).is_err());
}

/// Empty id components would sign a degenerate payload with empty
/// comma-separated slots (e.g. `...,111,,2,,seq-2`) that only fails
/// server-side; reject them up front instead.
#[test]
fn prepare_message_delete_rejects_empty_id_components() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let empty_conversation = crate::MessageDeleteParams::new("", vec!["seq-1".to_string()], true)
        .with_identity("111", "1");
    let err = core
        .prepare_message_delete(&empty_conversation)
        .unwrap_err();
    assert!(
        err.to_string().contains("conversation_id is empty"),
        "unexpected error: {err}"
    );

    let empty_member =
        crate::MessageDeleteParams::new("g999", vec!["".to_string(), "seq-2".to_string()], true)
            .with_identity("111", "1");
    let err = core.prepare_message_delete(&empty_member).unwrap_err();
    assert!(
        err.to_string().contains("empty id"),
        "unexpected error: {err}"
    );
}

#[test]
fn mark_conversation_read_decrypts_as_a_verified_read_receipt() {
    let core = ChatCore::new(); // default reject_unverified = true
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("111", "61"))
        .unwrap();

    let params = crate::MarkConversationReadParams::new("222-111", "2011626338877079553")
        .with_seen_at_msec(1_700_000_000_123);
    let sig = only_action(core.prepare_mark_conversation_read(&params).unwrap());

    // The session identity's signing key version signs the receipt, and
    // the 1:1 conversation id is signed in canonical colon form.
    assert_eq!(sig.message_event_signature.public_key_version, "61");
    assert_eq!(
        sig.signature_payload,
        format!(
            "MarkConversationReadEvent,{},111,111:222,2011626338877079553,1700000000123",
            sig.message_id
        )
    );
    assert_action_signature_round_trips(&core, &sig, "111", "111:222", None);

    let event = MessageEvent::new(
        Some("2011626338877079560".to_string()),
        Some(sig.message_id.clone()),
        Some("111".to_string()),
        Some("111:222".to_string()),
        None::<String>,
        Some("1700000000123".to_string()),
        Some(decode_detail(&sig.encoded_message_event_detail)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(crate::thrift::event::MessageEventSignature::new(
            Some(sig.message_event_signature.signature.clone()),
            Some(sig.message_event_signature.public_key_version.clone()),
            Some(sig.message_event_signature.signature_version.clone()),
            None::<String>,
            None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
        )),
        None::<String>,
        None::<bool>,
        None::<String>,
    );
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());
    let signing_keys = vec![signing_key_entry_for(&reg, "111")];

    match core
        .decrypt_event(
            &DecryptEventParams::new(event_b64, Default::default()).with_signing_keys(signing_keys),
        )
        .unwrap()
    {
        Event::ReadReceipt(read) => {
            assert!(read.verified);
            assert_eq!(
                read.seen_until_sequence_id.as_deref(),
                Some("2011626338877079553")
            );
            assert_eq!(read.seen_at_msec, Some(1_700_000_000_123));
        }
        other => panic!("expected Event::ReadReceipt, got {:?}", other),
    }
}

#[test]
fn mark_conversation_read_defaults_seen_at_to_now() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let params = crate::MarkConversationReadParams::new("g999", "seq-1").with_identity("111", "1");
    let before = now_msec();
    let sig = only_action(core.prepare_mark_conversation_read(&params).unwrap());
    let after = now_msec();

    let seen_at = match decode_detail(&sig.encoded_message_event_detail) {
        MessageEventDetail::MarkConversationReadEvent(read) => {
            assert_eq!(read.seen_until_sequence_id.as_deref(), Some("seq-1"));
            read.seen_at_millis.expect("seen_at_millis is set")
        }
        other => panic!("expected MarkConversationReadEvent, got {:?}", other),
    };
    assert!((before..=after).contains(&seen_at));
    assert_eq!(
        sig.signature_payload,
        format!(
            "MarkConversationReadEvent,{},111,g999,seq-1,{seen_at}",
            sig.message_id
        )
    );
    assert_action_signature_round_trips(&core, &sig, "111", "g999", None);
}

#[test]
fn prepare_mark_conversation_read_rejects_empty_ids() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let empty_conversation =
        crate::MarkConversationReadParams::new("", "seq-1").with_identity("111", "1");
    let err = core
        .prepare_mark_conversation_read(&empty_conversation)
        .unwrap_err();
    assert!(
        err.to_string().contains("conversation_id is empty"),
        "unexpected error: {err}"
    );

    let empty_seen_until =
        crate::MarkConversationReadParams::new("g999", "").with_identity("111", "1");
    let err = core
        .prepare_mark_conversation_read(&empty_seen_until)
        .unwrap_err();
    assert!(
        err.to_string().contains("seen_until_sequence_id is empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn deletes_and_read_receipts_return_the_requests_action_signatures() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("111", "61"))
        .unwrap();
    let signing_public_key = core.get_public_keys().unwrap().signing;

    let delete = core
        .prepare_message_delete(&crate::MessageDeleteParams::new(
            "g999",
            vec!["5".to_string()],
            true,
        ))
        .unwrap();
    let read = core
        .prepare_mark_conversation_read(&crate::MarkConversationReadParams::new("g999", "5"))
        .unwrap();
    for prepared in [delete, read] {
        let json = serde_json::to_value(&prepared).unwrap();
        let entries = json["action_signatures"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(
            entry["message_id"],
            prepared.action_signatures[0].message_id
        );
        assert!(entry["encoded_message_event_detail"].as_str().is_some());
        let signed = &entry["message_event_signature"];
        assert_eq!(signed["public_key_version"], "61");
        assert_eq!(signed["signature_version"], "7");
        assert_eq!(signed["signing_public_key"], signing_public_key.as_str());
        assert!(signed["signature"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(entry.get("signature").is_none());
    }
}

#[test]
fn prepare_group_create_normalizes_absent_value_encodings() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];
    let members = vec!["910004".to_string()];
    let admins = vec!["910004".to_string()];

    // Empty strings and a negative TTL are the FFI encodings of "not
    // set"; they must produce the same signed bytes as None.
    let mut ffi_params =
        crate::GroupCreateParams::new(input.clone(), "g999", members.clone(), admins.clone())
            .with_identity("910004", "1");
    ffi_params.title = Some("".into());
    ffi_params.ttl_msec = Some(-1);
    let ffi_form = core
        .prepare_group_create_with_version(&ffi_params, "42")
        .unwrap();
    let none_form = core
        .prepare_group_create_with_version(
            &crate::GroupCreateParams::new(input, "g999", members, admins)
                .with_identity("910004", "1"),
            "42",
        )
        .unwrap();
    assert_eq!(
        ffi_form.action_signatures[1].encoded_message_event_detail,
        none_form.action_signatures[1].encoded_message_event_detail,
        "empty-string/negative inputs must encode identically to None"
    );
    assert!(
        ffi_form.action_signatures[1]
            .signature_payload
            .ends_with(",null,null,null"),
        "a normalized title and the unset avatar must sign as the null sentinel"
    );
}

#[test]
fn prepare_group_members_change_signs_a_comma_title_but_not_a_comma_avatar_url() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];
    let params = crate::GroupMembersChangeParams::new(
        input,
        "g999",
        vec!["910006".to_string()],
        vec!["910004".to_string()],
        vec!["910004".to_string()],
        vec![],
    )
    .with_identity("910004", "1");

    // The add signs the title's ciphertext, so a comma in the plaintext
    // never reaches the comma-joined payload.
    let added = core
        .prepare_group_members_change(&params.clone().with_current_title("Team, the sequel"))
        .unwrap();
    assert_eq!(
        core.decrypt(
            added.encrypted_title.as_deref().unwrap(),
            added.conversation_key.as_ref().unwrap()
        )
        .unwrap(),
        "Team, the sequel"
    );

    // The avatar URL is signed as passed.
    let result =
        core.prepare_group_members_change(&params.with_current_avatar_url("https://ton.x.com/a,b"));
    assert!(matches!(result, Err(SdkError::InvalidInput(_))));
}

#[test]
fn prepare_group_members_change_normalizes_absent_value_encodings() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pk = core.get_public_keys().unwrap();
    let input = vec![PublicKeyInput::new("910004", &pk.identity, "1")];
    let new_members = vec!["910006".to_string()];
    let members = vec!["910004".to_string()];
    let admins = vec!["910004".to_string()];

    // Empty strings and a negative TTL are the FFI encodings of "not
    // set"; unlike group create, title/avatar/TTL all enter the signed
    // member-add payload, so both the detail and the signed bytes must
    // match the None form, and an empty description must not move the
    // add to the version that signs one.
    let mut ffi_params = crate::GroupMembersChangeParams::new(
        input.clone(),
        "g999",
        new_members.clone(),
        members.clone(),
        admins.clone(),
        vec![],
    )
    .with_identity("910004", "1");
    ffi_params.current_title = Some("".into());
    ffi_params.current_avatar_url = Some("".into());
    ffi_params.current_description = Some("".into());
    ffi_params.current_ttl_msec = Some(-1);
    let ffi_form = core
        .prepare_group_members_change_with_version(&ffi_params, "42")
        .unwrap();
    let none_form = core
        .prepare_group_members_change_with_version(
            &crate::GroupMembersChangeParams::new(
                input,
                "g999",
                new_members,
                members,
                admins,
                vec![],
            )
            .with_identity("910004", "1"),
            "42",
        )
        .unwrap();
    let ffi_add = &ffi_form.action_signatures[1];
    let none_add = &none_form.action_signatures[1];
    // The message id (second component) is random per call; every other
    // signed component must match.
    let strip_msg_id = |payload: &str| {
        let mut parts: Vec<&str> = payload.split(',').collect();
        parts.remove(1);
        parts.join(",")
    };
    assert_eq!(
        strip_msg_id(&ffi_add.signature_payload),
        strip_msg_id(&none_add.signature_payload),
        "empty-string/negative inputs must sign identically to None"
    );
    assert_eq!(
        ffi_add.encoded_message_event_detail, none_add.encoded_message_event_detail,
        "empty-string/negative inputs must encode identically to None"
    );
    assert!(
        ffi_add
            .signature_payload
            .ends_with(",null,null,null,42,null"),
        "normalized title/avatar/ttl must sign as the null sentinel"
    );
}
