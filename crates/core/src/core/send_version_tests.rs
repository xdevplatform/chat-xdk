//! The send format switch: v0 (the 0.5.x format) until the `v1_send` feature
//! switch is on, v1 (per-message keys) while it is.

use super::test_support::{
    decrypt_message, enable_v1_send, frame, key, keys, sent_event, Party, CONVERSATION,
    SIGNING_KEY_VERSION,
};
use super::*;
use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::features::FeatureApply;
use crate::thrift::event::{MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail};

const AUTHOR: &str = "1001";
const KEY_VERSION: &str = "7";

fn author() -> Party {
    let party = Party::new(AUTHOR);
    party.core.set_identity(AUTHOR, SIGNING_KEY_VERSION);
    party
}

fn message_params(text: &str, ckey: &XChatConversationKey) -> EncryptMessageParams {
    EncryptMessageParams::new(CONVERSATION, text)
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION)
}

fn delivered(payload: &SendPayload, sequence_id: &str) -> ThriftEvent {
    ThriftEvent {
        sequence_id: Some(sequence_id.to_string()),
        ..sent_event(payload, AUTHOR, CONVERSATION)
    }
}

fn create_event(event: &ThriftEvent) -> &MessageCreateEvent {
    match &event.detail {
        Some(MessageEventDetail::MessageCreateEvent(create)) => create,
        other => panic!("expected a MessageCreateEvent, got {:?}", other),
    }
}

/// Every kind of send `party` makes in a conversation keyed by `ckey`.
fn every_send(party: &Party, ckey: &XChatConversationKey) -> Vec<(&'static str, SendPayload)> {
    let original = party
        .core
        .encrypt_message(message_params("original", ckey))
        .unwrap();
    let original_event = frame(&delivered(&original, "100"));
    let reply = EncryptReplyParams::new(CONVERSATION, "reply", original_event.clone())
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let reaction = EncryptReactionParams::new(original_event.clone(), "👍")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let edit = EncryptEditParams::new(original_event, "edited")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    vec![
        ("message", original),
        ("reply", party.core.encrypt_reply(reply).unwrap()),
        (
            "reaction add",
            party.core.encrypt_add_reaction(&reaction).unwrap(),
        ),
        (
            "reaction remove",
            party.core.encrypt_remove_reaction(&reaction).unwrap(),
        ),
        ("edit", party.core.encrypt_edit(&edit).unwrap()),
    ]
}

fn assert_v0(party: &Party, ckey: &XChatConversationKey, what: &str, payload: &SendPayload) {
    assert_eq!(payload.signature_info.signature_version, "7", "{what}");
    let event = delivered(payload, "200");
    let create = create_event(&event);
    assert_eq!(create.contents_encryption_version, None, "{what}");
    let contents = create.contents.as_ref().unwrap();
    assert!(
        decrypt_message_bytes(ckey, contents).is_ok(),
        "{what} opens with the conversation key"
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys(KEY_VERSION, ckey),
        std::slice::from_ref(&party.entry),
    )
    .unwrap();
    assert!(message.verified, "{what}");
}

fn assert_v1(party: &Party, ckey: &XChatConversationKey, what: &str, payload: &SendPayload) {
    assert_eq!(payload.signature_info.signature_version, "10", "{what}");
    let event = delivered(payload, "200");
    let create = create_event(&event);
    assert_eq!(create.contents_encryption_version, Some(1), "{what}");
    assert!(
        decrypt_message_bytes(ckey, create.contents.as_ref().unwrap()).is_err(),
        "{what} opens with the conversation key"
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys(KEY_VERSION, ckey),
        std::slice::from_ref(&party.entry),
    )
    .unwrap();
    assert!(message.verified, "{what}");
}

#[test]
fn every_kind_of_send_is_v0_until_v1_send_is_on() {
    let party = author();
    let ckey = key(3);
    for (what, payload) in every_send(&party, &ckey) {
        assert_v0(&party, &ckey, what, &payload);
    }
}

#[test]
fn every_kind_of_send_is_v1_while_v1_send_is_on() {
    let party = author();
    enable_v1_send(&party.core);
    let ckey = key(3);
    for (what, payload) in every_send(&party, &ckey) {
        assert_v1(&party, &ckey, what, &payload);
    }
}

#[test]
fn the_v0_signature_covers_the_0_5_payload() {
    let party = author();
    let ckey = key(3);
    let payload = party
        .core
        .encrypt_message(message_params("signed like 0.5", &ckey))
        .unwrap();
    let event = delivered(&payload, "100");
    let contents = create_event(&event).contents.clone().unwrap();
    let expected = format!(
        "MessageCreateEvent,{},{},{},{},{}",
        payload.message_id,
        AUTHOR,
        CONVERSATION,
        KEY_VERSION,
        STANDARD_NO_PAD.encode(&contents)
    );
    let signature = STANDARD_NO_PAD.decode(&payload.signature).unwrap();
    assert!(ChatCore::new()
        .verify(&party.entry.public_key, &signature, expected.as_bytes())
        .unwrap());
}

#[test]
fn a_flag_that_is_missing_false_or_not_boolean_sends_v0() {
    let party = author();
    let ckey = key(3);
    for body in [
        r#"{"features":{}}"#,
        r#"{"features":{"v1_send":false}}"#,
        r#"{"features":{"v1_send":"true"}}"#,
        r#"{"features":{"v1_send":1}}"#,
        r#"{"features":{"other":true}}"#,
    ] {
        party
            .core
            .apply_feature_config(body, FeatureApply::Full, Some(1))
            .unwrap();
        assert!(!party.core.is_enabled(crate::features::V1_SEND), "{body}");
        let payload = party
            .core
            .encrypt_message(message_params("hi", &ckey))
            .unwrap();
        assert_v0(&party, &ckey, body, &payload);
    }
}

#[test]
fn an_unparsable_response_changes_nothing() {
    let party = author();
    enable_v1_send(&party.core);
    for body in [
        "",
        "<html>",
        r#"{"v1_send":false}"#,
        r#"{"features":false}"#,
    ] {
        assert!(party
            .core
            .apply_feature_config(body, FeatureApply::DowngradeOnly, Some(1))
            .is_err());
        assert!(party.core.is_enabled(crate::features::V1_SEND), "{body}");
    }
}

#[test]
fn a_recheck_turns_v1_send_off_and_never_back_on() {
    let party = author();
    let ckey = key(3);
    enable_v1_send(&party.core);
    party
        .core
        .apply_feature_config(
            r#"{"features":{"v1_send":false}}"#,
            FeatureApply::DowngradeOnly,
            Some(1),
        )
        .unwrap();
    let payload = party
        .core
        .encrypt_message(message_params("after the kill switch", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "after downgrade", &payload);

    party
        .core
        .apply_feature_config(
            r#"{"features":{"v1_send":true}}"#,
            FeatureApply::DowngradeOnly,
            Some(1),
        )
        .unwrap();
    assert!(!party.core.is_enabled(crate::features::V1_SEND));
}

#[test]
fn an_ip_bucketed_answer_reads_off_once_keys_load_until_refetched() {
    let core = ChatCore::new();
    assert_eq!(core.feature_bucket(), None);
    core.apply_feature_config(r#"{"features":{"v1_send":true}}"#, FeatureApply::Full, None)
        .unwrap();
    assert!(core.is_enabled(crate::features::V1_SEND));
    assert!(!core.feature_refetch_due());

    core.generate_keypairs().unwrap();
    core.set_identity(AUTHOR, SIGNING_KEY_VERSION);
    assert!(core.feature_refetch_due());
    assert!(!core.is_enabled(crate::features::V1_SEND));
    let ckey = key(3);
    let payload = core
        .encrypt_message(message_params("pending", &ckey))
        .unwrap();
    assert_eq!(payload.signature_info.signature_version, "7");

    let bucket = core.feature_bucket();
    assert!(bucket.is_some());
    core.apply_feature_config(
        r#"{"features":{"v1_send":true}}"#,
        FeatureApply::Full,
        bucket,
    )
    .unwrap();
    assert!(!core.feature_refetch_due());
    assert!(core.is_enabled(crate::features::V1_SEND));
    let payload = core
        .encrypt_message(message_params("refetched", &ckey))
        .unwrap();
    assert_eq!(payload.signature_info.signature_version, "10");
}

#[test]
fn the_feature_bucket_follows_the_identity_key() {
    let core = ChatCore::new();
    assert_eq!(core.feature_bucket(), None);
    let registration = core.generate_keypairs().unwrap();
    let bucket = core.feature_bucket().unwrap();
    assert!(bucket < 10_000);

    let spki = base64_decode(&registration.public_key.public_key).unwrap();
    assert_eq!(bucket, crate::features::bucket_for_public_key(&spki));

    let restored = ChatCore::new();
    restored.import_keys(&core.export_keys().unwrap()).unwrap();
    assert_eq!(restored.feature_bucket(), Some(bucket));

    core.lock();
    assert_eq!(core.feature_bucket(), None);
}

#[test]
fn files_of_a_v0_message_use_the_conversation_key() {
    let party = author();
    let ckey = key(3);
    let mut params = message_params("with a file", &ckey);
    params.attachments = Some(vec![AttachmentDescriptor::Media {
        media_hash_key: "file-1".to_string(),
        width: 1,
        height: 1,
        filesize_bytes: 5,
        filename: "f.bin".to_string(),
        media_type: Some(5),
        duration_millis: None,
    }]);
    let payload = party.core.encrypt_message(params).unwrap();
    assert_v0(&party, &ckey, "message with a file", &payload);

    let encrypted = ChatCore::new()
        .encrypt_file(EncryptFileParams::new(
            b"hello".to_vec(),
            payload.event_b64.clone(),
            keys(KEY_VERSION, &ckey),
            "file-1",
        ))
        .unwrap();
    let mut opened = Vec::new();
    crate::crypto::encryption::decrypt_file(&ckey, encrypted.as_slice(), &mut opened).unwrap();
    assert_eq!(opened, b"hello");
}

#[test]
fn every_payload_carries_the_sdk_version() {
    let party = author();
    let ckey = key(3);
    for (what, payload) in every_send(&party, &ckey) {
        assert_eq!(payload.xdk_version, crate::XDK_VERSION, "{what}");
        assert!(!payload.xdk_version.is_empty(), "{what}");
    }
}
