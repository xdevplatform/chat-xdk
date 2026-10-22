//! The send format switch: v0 (the 0.5.x format) until the `v1_send` feature
//! switch is on, v1 (per-message keys) while it is.

use super::test_support::{
    decrypt_message, enable_v1_send, frame, key, keys, sent_event, Party, CONVERSATION,
    SIGNING_KEY_VERSION,
};
use super::*;
use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::thrift::event::{MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail};
use crate::thrift::product::{
    MessageAttachment as ThriftAttachment, MessageEntryContents as Contents,
};

const AUTHOR: &str = "1001";
const KEY_VERSION: &str = "7";

fn author() -> Party {
    let party = Party::new(AUTHOR);
    party
        .core
        .set_identity(&SetIdentityParams::new(AUTHOR, SIGNING_KEY_VERSION))
        .unwrap();
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
        .encrypt_message(&message_params("original", ckey))
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
        ("reply", party.core.encrypt_reply(&reply).unwrap()),
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
        .encrypt_message(&message_params("signed like 0.5", &ckey))
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

/// A fresh endpoint, so tests running at once never share a schedule.
#[cfg(feature = "bindings")]
fn own_endpoint(core: &ChatCore) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let endpoint = format!(
        "https://features.test/{}/2/chat/features",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    core.configure_features(&endpoint, crate::features::Timings::default());
    endpoint
}

#[cfg(feature = "bindings")]
#[test]
fn the_first_send_asks_for_its_key_bucket_and_v1_starts_with_the_answer() {
    use crate::features::shared;
    let party = author();
    let endpoint = own_endpoint(&party.core);
    let bucket = party.core.feature_bucket().unwrap();
    let ckey = key(3);
    assert_eq!(
        shared::subscribers(&endpoint, bucket),
        0,
        "keys alone ask for nothing"
    );

    let first = party
        .core
        .encrypt_message(&message_params("first", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "before the answer", &first);
    assert_eq!(shared::subscribers(&endpoint, bucket), 1);

    assert!(shared::answer(
        &endpoint,
        bucket,
        200,
        r#"{"features":{"v1_send":true}}"#
    ));
    let second = party
        .core
        .encrypt_message(&message_params("second", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "after the answer", &second);
    assert_eq!(shared::subscribers(&endpoint, bucket), 1, "one per chat");
}

#[cfg(feature = "bindings")]
#[test]
fn chats_with_one_key_share_one_answer_and_leave_when_dropped() {
    use crate::features::shared;
    let party = author();
    let endpoint = own_endpoint(&party.core);
    let twin = ChatCore::new();
    twin.import_keys(&ImportKeysParams::new(
        party.core.export_keys().unwrap().to_vec(),
    ))
    .unwrap();
    twin.set_identity(&SetIdentityParams::new(AUTHOR, SIGNING_KEY_VERSION))
        .unwrap();
    twin.configure_features(&endpoint, crate::features::Timings::default());
    let bucket = party.core.feature_bucket().unwrap();
    assert_eq!(twin.feature_bucket(), Some(bucket));

    let ckey = key(3);
    party
        .core
        .encrypt_message(&message_params("ask", &ckey))
        .unwrap();
    twin.encrypt_message(&message_params("ask", &ckey)).unwrap();
    assert_eq!(shared::subscribers(&endpoint, bucket), 2);

    assert!(shared::answer(
        &endpoint,
        bucket,
        200,
        r#"{"features":{"v1_send":true}}"#
    ));
    for core in [&party.core, &twin] {
        let payload = core
            .encrypt_message(&message_params("shared", &ckey))
            .unwrap();
        assert_eq!(payload.signature_info.signature_version, "10");
    }
    drop(twin);
    assert_eq!(shared::subscribers(&endpoint, bucket), 1);
}

#[cfg(feature = "bindings")]
#[test]
fn a_flag_that_is_missing_false_or_not_boolean_sends_v0() {
    use crate::features::shared;
    let ckey = key(3);
    for body in [
        r#"{"features":{}}"#,
        r#"{"features":{"v1_send":false}}"#,
        r#"{"features":{"v1_send":"true"}}"#,
        r#"{"features":{"v1_send":1}}"#,
        r#"{"features":{"other":true}}"#,
    ] {
        let party = author();
        let endpoint = own_endpoint(&party.core);
        party
            .core
            .encrypt_message(&message_params("ask", &ckey))
            .unwrap();
        let bucket = party.core.feature_bucket().unwrap();
        assert!(shared::answer(&endpoint, bucket, 200, body));
        let payload = party
            .core
            .encrypt_message(&message_params("hi", &ckey))
            .unwrap();
        assert_v0(&party, &ckey, body, &payload);
    }
}

#[cfg(feature = "bindings")]
#[test]
fn a_failed_request_sends_v0() {
    use crate::features::shared;
    let party = author();
    let endpoint = own_endpoint(&party.core);
    let ckey = key(3);
    party
        .core
        .encrypt_message(&message_params("ask", &ckey))
        .unwrap();
    let bucket = party.core.feature_bucket().unwrap();
    assert!(shared::answer(
        &endpoint,
        bucket,
        503,
        r#"{"features":{"v1_send":true}}"#
    ));
    let payload = party
        .core
        .encrypt_message(&message_params("hi", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "after a 503", &payload);
}

#[cfg(feature = "bindings")]
#[test]
fn a_released_chat_keeps_its_switches_and_never_asks_again() {
    use crate::features::shared;
    let party = author();
    let endpoint = own_endpoint(&party.core);
    let ckey = key(3);
    party
        .core
        .encrypt_message(&message_params("ask", &ckey))
        .unwrap();
    let bucket = party.core.feature_bucket().unwrap();
    assert!(shared::answer(
        &endpoint,
        bucket,
        200,
        r#"{"features":{"v1_send":true}}"#
    ));

    party.core.release_features();
    assert_eq!(shared::subscribers(&endpoint, bucket), 0);
    let payload = party
        .core
        .encrypt_message(&message_params("released", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "released", &payload);
    assert_eq!(shared::subscribers(&endpoint, bucket), 0);
}

#[cfg(feature = "bindings")]
#[test]
fn a_chat_whose_key_changes_asks_for_the_new_bucket() {
    use crate::features::shared;
    let party = author();
    let endpoint = own_endpoint(&party.core);
    let ckey = key(3);
    party
        .core
        .encrypt_message(&message_params("ask", &ckey))
        .unwrap();
    let old_bucket = party.core.feature_bucket().unwrap();

    let other = ChatCore::new();
    other.generate_keypairs().unwrap();
    party
        .core
        .import_keys(&ImportKeysParams::new(
            other.export_keys().unwrap().to_vec(),
        ))
        .unwrap();
    party
        .core
        .set_identity(&SetIdentityParams::new(AUTHOR, SIGNING_KEY_VERSION))
        .unwrap();
    let new_bucket = party.core.feature_bucket().unwrap();
    party
        .core
        .encrypt_message(&message_params("ask again", &ckey))
        .unwrap();
    if new_bucket != old_bucket {
        assert_eq!(shared::subscribers(&endpoint, old_bucket), 0);
    }
    assert_eq!(shared::subscribers(&endpoint, new_bucket), 1);
}

#[cfg(not(feature = "bindings"))]
#[test]
fn without_the_bindings_every_send_is_v0() {
    let party = author();
    let ckey = key(3);
    for text in ["first", "second"] {
        let payload = party
            .core
            .encrypt_message(&message_params(text, &ckey))
            .unwrap();
        assert_v0(&party, &ckey, text, &payload);
    }
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
    restored
        .import_keys(&ImportKeysParams::new(core.export_keys().unwrap().to_vec()))
        .unwrap();
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
    let payload = party.core.encrypt_message(&params).unwrap();
    assert_v0(&party, &ckey, "message with a file", &payload);

    let encrypted = ChatCore::new()
        .encrypt_file(
            &EncryptFileParams::new(b"hello".to_vec(), payload.event_b64.clone(), "file-1")
                .with_conversation_key(ckey.to_bytes(), KEY_VERSION),
        )
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

/// The contents of a send, opened with `key`: the conversation key for v0,
/// the message key for v1.
fn opened_contents(payload: &SendPayload, key: &XChatConversationKey) -> Contents {
    let event = delivered(payload, "300");
    let plaintext =
        decrypt_message_bytes(key, create_event(&event).contents.as_ref().unwrap()).unwrap();
    ChatCore::parse_thrift_entry_contents(&plaintext).unwrap()
}

fn message_key(payload: &SendPayload, ckey: &XChatConversationKey) -> XChatConversationKey {
    message_keys::derive_message_key(ckey, AUTHOR, &payload.message_id).unwrap()
}

fn with_photos(text: &str, ckey: &XChatConversationKey) -> EncryptMessageParams {
    let photo = |media_hash_key: &str| AttachmentDescriptor::Media {
        media_hash_key: media_hash_key.to_string(),
        width: 640,
        height: 480,
        filesize_bytes: 4096,
        filename: format!("{media_hash_key}.jpg"),
        media_type: Some(1),
        duration_millis: None,
    };
    let mut params = message_params(text, ckey);
    params.attachments = Some(vec![photo("photo-a"), photo("photo-b")]);
    params
}

#[allow(clippy::vec_box)]
fn attachment_ids(contents: Contents) -> Vec<Option<String>> {
    let Contents::Message(message) = contents else {
        panic!("expected message contents, got {:?}", contents);
    };
    message
        .attachments
        .unwrap_or_default()
        .iter()
        .map(|attachment| match attachment.as_ref() {
            ThriftAttachment::Media(media) => media.attachment_id.clone(),
            other => panic!("unexpected attachment {:?}", other),
        })
        .collect()
}

#[test]
fn a_v0_message_with_files_takes_a_random_id_and_unnamed_attachments() {
    let party = author();
    let ckey = key(3);
    let first = party
        .core
        .encrypt_message(&with_photos("photos", &ckey))
        .unwrap();
    let again = party
        .core
        .encrypt_message(&with_photos("photos", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "message with files", &first);
    assert_ne!(first.message_id, again.message_id);
    assert_eq!(attachment_ids(opened_contents(&first, &ckey)), [None, None]);
}

#[test]
fn a_v1_message_with_files_derives_its_id_and_names_its_attachments() {
    let party = author();
    enable_v1_send(&party.core);
    let ckey = key(3);
    let first = party
        .core
        .encrypt_message(&with_photos("photos", &ckey))
        .unwrap();
    let again = party
        .core
        .encrypt_message(&with_photos("photos", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "message with files", &first);
    assert_eq!(first.message_id, again.message_id);
    let second = format!("{}#1", first.message_id);
    assert_eq!(
        attachment_ids(opened_contents(&first, &message_key(&first, &ckey))),
        [Some(first.message_id.clone()), Some(second)]
    );
}

#[test]
fn only_a_v1_edit_names_the_message_it_edits() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let target = frame(&delivered(&original, "100"));
    let edit = |party: &Party| {
        let params = EncryptEditParams::new(target.clone(), "edited")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        party.core.encrypt_edit(&params).unwrap()
    };

    let v0 = edit(&party);
    let Contents::MessageEdit(v0_edit) = opened_contents(&v0, &ckey) else {
        panic!("expected an edit");
    };
    assert_eq!(v0_edit.message_sequence_id.as_deref(), Some("100"));
    assert_eq!(v0_edit.message_id, None);

    enable_v1_send(&party.core);
    let v1 = edit(&party);
    let Contents::MessageEdit(v1_edit) = opened_contents(&v1, &message_key(&v1, &ckey)) else {
        panic!("expected an edit");
    };
    assert_eq!(
        v1_edit.message_id.as_deref(),
        Some(original.message_id.as_str())
    );
}
