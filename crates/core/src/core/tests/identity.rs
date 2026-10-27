//! The session identity: `set_identity`, and the sender id and signing-key
//! version calls sign with when their params leave them out.

use super::*;

#[test]
fn session_identity_signs_the_same_values_as_explicit_params() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hi")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    assert_eq!(payload.signature_info.public_key_version, "61");

    // Verifying against the session sender_id and signing_key_version
    // proves the signature covers exactly the values an explicit call
    // would have signed.
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    match core
        .decrypt_event_with(&msg_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => {
            assert!(msg.verified);
            assert_eq!(msg.text(), Some("hi"));
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn encrypt_message_without_sender_id_errors() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let err = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hi")
                .with_conversation_key(ckey.to_bytes(), "1"),
        )
        .unwrap_err();
    assert!(err.to_string().contains("sender_id"), "got: {err}");
}

#[test]
fn encrypt_message_without_signing_key_version_errors() {
    let source = ChatCore::new();
    source.generate_keypairs().unwrap();
    let exported = source.export_keys().unwrap();

    // A raw import carries no key version, so nothing can resolve it.
    let core = ChatCore::new();
    core.import_keys(&ImportKeysParams::new(exported.to_vec()))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let mut params = crate::EncryptMessageParams::new("conv-1", "hi")
        .with_conversation_key(ckey.to_bytes(), "1");
    params.sender_id = Some("910003".into());
    let err = core.encrypt_message(&params).unwrap_err();
    assert!(
        err.to_string().contains("signing_key_version"),
        "got: {err}"
    );
}

#[test]
fn generate_keypairs_leaves_the_signing_key_version_unset() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let mut message = crate::EncryptMessageParams::new("conv-1", "hi")
        .with_conversation_key(ckey.to_bytes(), "1");
    message.sender_id = Some("4001".into());
    let err = core.encrypt_message(&message.clone()).unwrap_err();
    assert!(
        err.to_string().contains("signing_key_version"),
        "got: {err}"
    );

    let mut delete = crate::MessageDeleteParams::new("conv-1", vec!["seq-1".into()], true);
    delete.sender_id = Some("4001".into());
    let err = core.prepare_message_delete(&delete).unwrap_err();
    assert!(
        err.to_string().contains("signing_key_version"),
        "got: {err}"
    );

    core.set_identity(&SetIdentityParams::new("4001", "1700000000123"))
        .unwrap();
    let payload = core.encrypt_message(&message).unwrap();
    assert_eq!(payload.signature_info.public_key_version, "1700000000123");
    let signature = only_action(core.prepare_message_delete(&delete).unwrap());
    assert_eq!(
        signature.message_event_signature.public_key_version,
        "1700000000123"
    );
}

#[test]
fn generated_keys_decrypt_their_participant_entry_before_the_version_is_known() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let pubkeys = core.get_public_keys().unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let recipients = [RecipientInput {
        user_id: "910003".to_string(),
        public_key: pubkeys.identity,
        key_version: "1700000000123".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap()[0]
        .encrypted_conversation_key
        .clone();

    let kce = ThriftCKCE::new(
        Some("42".to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(encrypted),
            Some("1700000000123".to_string()),
        )]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));
    let result = core.extract_conversation_keys(&[&event_b64]);
    let extracted = result.get("42").expect("own participant entry decrypts");
    assert_eq!(extracted.encoded(), ckey.encoded());
}

#[test]
fn import_keys_with_a_signing_key_version_completes_the_identity() {
    let source = ChatCore::new();
    source.generate_keypairs().unwrap();
    let exported = source.export_keys().unwrap();

    let core = ChatCore::new();
    core.import_keys(&ImportKeysParams::new(exported.to_vec()).with_signing_key_version("63"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let mut params = crate::EncryptMessageParams::new("conv-1", "hi")
        .with_conversation_key(ckey.to_bytes(), "1");
    params.sender_id = Some("4001".into());
    let payload = core.encrypt_message(&params).unwrap();
    assert_eq!(payload.signature_info.public_key_version, "63");
}

#[test]
fn prepare_conversation_key_change_uses_session_identity() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910002", "1"))
        .unwrap();
    let pubkeys = core.get_public_keys().unwrap();
    let mut params = crate::ConversationKeyChangeParams::new(vec![PublicKeyInput::new(
        "910002",
        pubkeys.identity,
        "1",
    )]);
    params.conversation_id = Some("conv-1".into());
    let prepared = core.prepare_conversation_key_change(&params).unwrap();
    assert_eq!(
        prepared.action_signatures[0]
            .message_event_signature
            .public_key_version,
        "1"
    );
}
