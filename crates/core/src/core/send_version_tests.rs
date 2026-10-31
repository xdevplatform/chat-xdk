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

/// An endpoint of its own, so tests running at once never share a GET.
#[cfg(feature = "bindings")]
fn own_endpoint() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "https://features.test/{}/2/chat/features",
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Point `core`'s reads of the feature switches at `endpoint`, again
/// `REFRESH_MS` after each answer, and start them.
#[cfg(feature = "bindings")]
fn start_read(core: &ChatCore, endpoint: &str) -> Option<crate::features::Fetch> {
    core.configure_features(endpoint, 2_000, REFRESH_MS);
    core.start_features()
}

#[cfg(feature = "bindings")]
const REFRESH_MS: u64 = 60_000;

#[cfg(feature = "bindings")]
fn complete(
    fetch: &crate::features::Fetch,
    status: u16,
    body: &str,
) -> Option<crate::features::Fetch> {
    crate::bindings::complete_fetch(fetch.id, status, body.as_bytes())
}

#[cfg(feature = "bindings")]
const V1_ON: &str = r#"{"features":{"v1_send":true}}"#;

#[cfg(feature = "bindings")]
const V1_OFF: &str = r#"{"features":{"v1_send":false}}"#;

#[cfg(feature = "bindings")]
#[test]
fn sends_are_v0_until_the_answer_turns_v1_on() {
    let party = author();
    let endpoint = own_endpoint();
    let fetch = start_read(&party.core, &endpoint).expect("a GET");
    assert_eq!(
        fetch.url,
        format!("{endpoint}?bucket={AUTHOR}"),
        "its sender's bucket"
    );
    let ckey = key(3);
    let first = party
        .core
        .encrypt_message(&message_params("first", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "before the answer", &first);

    complete(&fetch, 200, V1_ON);
    let second = party
        .core
        .encrypt_message(&message_params("second", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "after the answer", &second);
    assert_eq!(party.core.start_features(), None, "one read per sender");
}

#[cfg(feature = "bindings")]
#[test]
fn a_chat_created_while_a_read_is_in_flight_takes_its_answer() {
    let party = author();
    let endpoint = own_endpoint();
    let fetch = start_read(&party.core, &endpoint).expect("a GET");
    let twin = author();
    assert_eq!(start_read(&twin.core, &endpoint), None, "no second GET");
    let dropped = ChatCore::new();
    dropped
        .set_identity(&SetIdentityParams::new(AUTHOR, SIGNING_KEY_VERSION))
        .unwrap();
    assert_eq!(start_read(&dropped, &endpoint), None);
    drop(dropped);

    complete(&fetch, 200, V1_ON);
    let ckey = key(3);
    for chat in [&party, &twin] {
        let payload = chat
            .core
            .encrypt_message(&message_params("shared", &ckey))
            .unwrap();
        assert_v1(chat, &ckey, "shared answer", &payload);
    }
}

#[cfg(feature = "bindings")]
#[test]
fn a_flag_that_is_missing_false_or_not_boolean_sends_v0() {
    let ckey = key(3);
    for body in [
        r#"{"features":{}}"#,
        V1_OFF,
        r#"{"features":{"v1_send":"true"}}"#,
        r#"{"features":{"v1_send":1}}"#,
        r#"{"features":{"other":true}}"#,
    ] {
        let party = author();
        let fetch = start_read(&party.core, &own_endpoint()).expect("a GET");
        complete(&fetch, 200, body);
        let payload = party
            .core
            .encrypt_message(&message_params("hi", &ckey))
            .unwrap();
        assert_v0(&party, &ckey, body, &payload);
    }
}

#[cfg(feature = "bindings")]
#[test]
fn a_failed_read_is_retried_and_the_retrys_answer_turns_v1_on() {
    let party = author();
    let fetch = start_read(&party.core, &own_endpoint()).expect("a GET");
    let retry = complete(&fetch, 503, V1_ON).expect("the failed read is retried");
    assert_eq!(retry.url, fetch.url);
    assert_eq!(retry.delay_ms, crate::features::RETRY_FIRST_DELAY_MS);
    assert_eq!(party.core.start_features(), None, "the read goes on");
    let ckey = key(3);
    let payload = party
        .core
        .encrypt_message(&message_params("hi", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "after a 503", &payload);

    complete(&retry, 200, V1_ON);
    let payload = party
        .core
        .encrypt_message(&message_params("hi", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "after the retry's answer", &payload);
}

#[cfg(feature = "bindings")]
#[test]
fn a_refresh_reaches_a_running_chat() {
    let party = author();
    let endpoint = own_endpoint();
    let fetch = start_read(&party.core, &endpoint).expect("a GET");
    let refresh = complete(&fetch, 200, V1_ON).expect("a refresh");
    assert_eq!(refresh.delay_ms, REFRESH_MS);

    let later = author();
    assert_eq!(
        start_read(&later.core, &endpoint),
        None,
        "a later chat takes the latest answer"
    );
    let ckey = key(3);
    for chat in [&party, &later] {
        let payload = chat
            .core
            .encrypt_message(&message_params("v1", &ckey))
            .unwrap();
        assert_v1(chat, &ckey, "the first answer", &payload);
    }

    complete(&refresh, 200, V1_OFF);
    for chat in [&party, &later] {
        let payload = chat
            .core
            .encrypt_message(&message_params("v0", &ckey))
            .unwrap();
        assert_v0(chat, &ckey, "the refresh's answer", &payload);
    }
}

#[cfg(feature = "bindings")]
#[test]
fn setting_the_identity_moves_the_reads_to_the_senders_bucket() {
    let party = Party::new(AUTHOR);
    let endpoint = own_endpoint();
    let anonymous = start_read(&party.core, &endpoint).expect("a GET");
    assert_eq!(anonymous.url, endpoint, "no identity, no bucket");
    complete(&anonymous, 200, V1_ON);
    assert!(party.core.send_version() == crate::pipeline::SendVersion::V1);

    party
        .core
        .set_identity(&SetIdentityParams::new(AUTHOR, SIGNING_KEY_VERSION))
        .unwrap();
    let bucketed = party.core.start_features().expect("its bucket's GET");
    assert_eq!(bucketed.url, format!("{endpoint}?bucket={AUTHOR}"));
    let ckey = key(3);
    let payload = party
        .core
        .encrypt_message(&message_params("waiting", &ckey))
        .unwrap();
    assert_v0(&party, &ckey, "until its bucket answers", &payload);
    complete(&bucketed, 200, V1_ON);
    let payload = party
        .core
        .encrypt_message(&message_params("bucketed", &ckey))
        .unwrap();
    assert_v1(&party, &ckey, "its bucket's answer", &payload);
}

#[cfg(not(feature = "bindings"))]
#[test]
fn without_the_bindings_every_send_is_v0() {
    let party = author();
    assert_eq!(party.core.start_features(), None, "nothing to fetch");
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
        plaintext_sha256: None,
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
        plaintext_sha256: None,
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

#[test]
fn a_decrypted_v1_edit_names_the_message_it_edits() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let target = frame(&delivered(&original, "100"));
    let decrypted_edit = |party: &Party| {
        let params = EncryptEditParams::new(target.clone(), "edited")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        let edit = party.core.encrypt_edit(&params).unwrap();
        let message = decrypt_message(
            &ChatCore::new(),
            &delivered(&edit, "200"),
            &keys(KEY_VERSION, &ckey),
            std::slice::from_ref(&party.entry),
        )
        .unwrap();
        assert!(message.verified);
        match message.content {
            MessageContent::Edit {
                target_message_sequence_id,
                target_message_id,
                updated_text,
                ..
            } => (target_message_sequence_id, target_message_id, updated_text),
            other => panic!("expected an edit, got {:?}", other),
        }
    };

    assert_eq!(
        decrypted_edit(&party),
        ("100".to_string(), None, "edited".to_string())
    );
    enable_v1_send(&party.core);
    assert_eq!(
        decrypted_edit(&party),
        (
            "100".to_string(),
            Some(original.message_id.clone()),
            "edited".to_string()
        )
    );
}

/// The message id a v1 edit built by `params` names, read from its opened
/// contents.
fn edited_message_id(
    party: &Party,
    ckey: &XChatConversationKey,
    params: &EncryptEditParams,
) -> Option<String> {
    let edit = party.core.encrypt_edit(params).unwrap();
    let key = match create_event(&delivered(&edit, "200")).contents_encryption_version {
        Some(_) => message_key(&edit, ckey),
        None => ckey.clone(),
    };
    let Contents::MessageEdit(contents) = opened_contents(&edit, &key) else {
        panic!("expected an edit");
    };
    contents.message_id
}

#[test]
fn a_v1_edit_built_without_its_target_event_names_the_message_its_params_name() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let explicit = EncryptEditParams::new("", "edited")
        .with_conversation_id(CONVERSATION)
        .with_target_message_sequence_id("100")
        .with_target_message_id(original.message_id.clone())
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);

    assert_eq!(edited_message_id(&party, &ckey, &explicit), None);
    enable_v1_send(&party.core);
    assert_eq!(
        edited_message_id(&party, &ckey, &explicit),
        Some(original.message_id.clone())
    );
    let unnamed = EncryptEditParams::new("", "edited")
        .with_conversation_id(CONVERSATION)
        .with_target_message_sequence_id("100")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    assert_eq!(edited_message_id(&party, &ckey, &unnamed), None);
}

#[test]
fn a_target_message_id_must_be_the_one_the_target_event_carries() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let target = frame(&delivered(&original, "100"));
    let edit = |message_id: &str| {
        EncryptEditParams::new(target.clone(), "edited")
            .with_target_message_id(message_id)
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION)
    };
    let other = "6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f";
    let expected = format!(
        "target_message_id '{other}' is not the message_id '{}' that \
         target_event carries: pass that id or leave target_message_id unset",
        original.message_id
    );
    for v1 in [false, true] {
        if v1 {
            enable_v1_send(&party.core);
        }
        let error = party.core.encrypt_edit(&edit(other)).unwrap_err();
        assert!(matches!(error, SdkError::InvalidInput(_)), "v1 {v1}");
        assert_eq!(error.to_string(), expected, "v1 {v1}");
    }
    assert_eq!(
        edited_message_id(&party, &ckey, &edit(&original.message_id)),
        Some(original.message_id.clone()),
        "the id the event carries is accepted"
    );
}

/// The `replying_to_message_id` of the preview a reply built by `params`
/// carries, read from its opened contents.
fn quoted_message_id(
    party: &Party,
    ckey: &XChatConversationKey,
    params: &EncryptReplyParams,
) -> Option<String> {
    let reply = party.core.encrypt_reply(params).unwrap();
    let key = match create_event(&delivered(&reply, "200")).contents_encryption_version {
        Some(_) => message_key(&reply, ckey),
        None => ckey.clone(),
    };
    let Contents::Message(contents) = opened_contents(&reply, &key) else {
        panic!("expected a message");
    };
    contents
        .replying_to_preview
        .and_then(|preview| preview.replying_to_message_id)
}

#[test]
fn a_reply_built_from_explicit_fields_names_the_message_its_params_name() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let explicit = |message_id: Option<&str>| {
        let params = EncryptReplyParams::new(CONVERSATION, "reply", "")
            .with_reply_to_sequence_id("100")
            .with_reply_to_sender_id(AUTHOR)
            .with_reply_to_text("original")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        match message_id {
            Some(id) => params.with_reply_to_message_id(id),
            None => params,
        }
    };

    for v1 in [false, true] {
        if v1 {
            enable_v1_send(&party.core);
        }
        assert_eq!(
            quoted_message_id(&party, &ckey, &explicit(Some(&original.message_id))),
            Some(original.message_id.clone()),
            "v1 {v1}"
        );
        assert_eq!(
            quoted_message_id(&party, &ckey, &explicit(None)),
            None,
            "v1 {v1}"
        );
    }
}

#[test]
fn a_reply_to_message_id_must_be_the_one_the_reply_to_event_carries() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let event = frame(&delivered(&original, "100"));
    let reply = |message_id: Option<&str>| {
        let params = EncryptReplyParams::new(CONVERSATION, "reply", event.clone())
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        match message_id {
            Some(id) => params.with_reply_to_message_id(id),
            None => params,
        }
    };
    let other = "6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f";
    let error = party.core.encrypt_reply(&reply(Some(other))).unwrap_err();
    assert!(matches!(error, SdkError::InvalidInput(_)));
    assert_eq!(
        error.to_string(),
        format!(
            "reply_to_message_id '{other}' is not the message_id '{}' that \
             reply_to_event carries: pass that id or leave reply_to_message_id unset",
            original.message_id
        )
    );
    for message_id in [None, Some(original.message_id.as_str())] {
        assert_eq!(
            quoted_message_id(&party, &ckey, &reply(message_id)),
            Some(original.message_id.clone()),
            "{message_id:?}"
        );
    }
}

fn photo_with_hash(media_hash_key: &str, plaintext_sha256: Option<&str>) -> AttachmentDescriptor {
    AttachmentDescriptor::Media {
        media_hash_key: media_hash_key.to_string(),
        width: 640,
        height: 480,
        filesize_bytes: 4096,
        filename: format!("{media_hash_key}.jpg"),
        media_type: Some(1),
        duration_millis: None,
        plaintext_sha256: plaintext_sha256.map(str::to_string),
    }
}

#[test]
fn a_media_attachment_carries_and_decrypts_its_plaintext_sha256() {
    use sha2::{Digest, Sha256};
    let party = author();
    let ckey = key(3);
    let digest = Sha256::digest(b"the photo's plaintext bytes").to_vec();
    let hash = base64_encode(&digest);
    for v1 in [false, true] {
        if v1 {
            enable_v1_send(&party.core);
        }
        let mut params = message_params("photo", &ckey);
        params.attachments = Some(vec![
            photo_with_hash("photo-a", Some(&hash)),
            photo_with_hash("photo-b", None),
        ]);
        let payload = party.core.encrypt_message(&params).unwrap();
        let key = if v1 {
            message_key(&payload, &ckey)
        } else {
            ckey.clone()
        };
        let Contents::Message(contents) = opened_contents(&payload, &key) else {
            panic!("expected a message");
        };
        let sent: Vec<Option<Vec<u8>>> = contents
            .attachments
            .unwrap_or_default()
            .iter()
            .map(|attachment| match attachment.as_ref() {
                ThriftAttachment::Media(media) => media.plaintext_sha256.clone(),
                other => panic!("unexpected attachment {:?}", other),
            })
            .collect();
        assert_eq!(sent, [Some(digest.clone()), None], "v1 {v1}");

        let message = decrypt_message(
            &ChatCore::new(),
            &delivered(&payload, "100"),
            &keys(KEY_VERSION, &ckey),
            std::slice::from_ref(&party.entry),
        )
        .unwrap();
        assert!(message.verified, "v1 {v1}");
        let infos: Vec<Option<String>> = message
            .attachments
            .iter()
            .map(|attachment| match attachment {
                AttachmentInfo::Media(media) => media.plaintext_sha256.clone(),
                other => panic!("unexpected attachment {:?}", other),
            })
            .collect();
        assert_eq!(infos, [Some(hash.clone()), None], "v1 {v1}");
        let MessageContent::Text { attachments, .. } = message.content else {
            panic!("expected text content");
        };
        let content: Vec<Option<String>> = attachments
            .unwrap_or_default()
            .into_iter()
            .map(|attachment| match attachment {
                MessageAttachment::Media { media } => media.plaintext_sha256,
                other => panic!("unexpected attachment {:?}", other),
            })
            .collect();
        assert_eq!(content, [Some(hash.clone()), None], "v1 {v1}");
    }
}

#[test]
fn a_plaintext_sha256_that_is_not_a_base64_sha256_fails_the_send() {
    let party = author();
    let ckey = key(3);
    let original = party
        .core
        .encrypt_message(&message_params("original", &ckey))
        .unwrap();
    let event = frame(&delivered(&original, "100"));
    for bad in ["not base64!", "c2hvcnQ=", &base64_encode(&[7u8; 33])] {
        let expected = format!("media_hash_key 'photo-a' has plaintext_sha256 '{bad}'");
        let mut message = message_params("photo", &ckey);
        message.attachments = Some(vec![photo_with_hash("photo-a", Some(bad))]);
        let reply = EncryptReplyParams::new(CONVERSATION, "reply", event.clone())
            .with_attachments(vec![photo_with_hash("photo-a", Some(bad))])
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        let quoting = EncryptReplyParams::new(CONVERSATION, "reply", event.clone())
            .with_reply_to_attachments(vec![photo_with_hash("photo-a", Some(bad))])
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        let errors = [
            party.core.encrypt_message(&message).unwrap_err(),
            party.core.encrypt_reply(&reply).unwrap_err(),
            party.core.encrypt_reply(&quoting).unwrap_err(),
        ];
        for error in errors {
            assert!(
                matches!(&error, SdkError::InvalidInput(m) if m.starts_with(&expected)),
                "{bad}: {error:?}"
            );
        }
    }
    let mut empty = message_params("photo", &ckey);
    empty.attachments = Some(vec![photo_with_hash("photo-a", Some(""))]);
    assert!(party.core.encrypt_message(&empty).is_ok());
}

#[test]
fn each_answer_a_caller_hands_over_sets_the_send_format() {
    let ckey = key(1);
    let send = |party: &Party| {
        party
            .core
            .encrypt_message(&message_params("hi", &ckey))
            .unwrap()
            .signature_info
            .signature_version
    };
    let on = br#"{"features":{"v1_send":true}}"#;
    let off = br#"{"features":{"v1_send":false}}"#;

    let party = author();
    assert_eq!(send(&party), "7", "no answer: v0");
    party.core.set_feature_switches(200, on);
    assert_eq!(send(&party), "10");
    party.core.set_feature_switches(200, off);
    assert_eq!(send(&party), "7", "a later answer replaces it");
    party.core.set_feature_switches(503, on);
    assert_eq!(send(&party), "7", "a failed read changes nothing");
    party.core.set_feature_switches(200, on);
    assert_eq!(send(&party), "10");

    let mut oversized = on.to_vec();
    oversized.resize(crate::FEATURES_MAX_BODY + 1, b' ');
    for (status, body) in [
        (404, on.as_slice()),
        (200, b"not json".as_slice()),
        (200, oversized.as_slice()),
    ] {
        let party = author();
        party.core.set_feature_switches(status, body);
        assert_eq!(send(&party), "7", "{status} {}", body.len());
        party.core.set_feature_switches(200, on);
        assert_eq!(
            send(&party),
            "10",
            "the retried GET's answer after {status}"
        );
    }

    let party = author();
    party
        .core
        .set_feature_switches(200, br#"{"features":{"v1_send":"true"}}"#);
    assert_eq!(send(&party), "7", "a flag that is not a boolean reads off");
}

#[test]
fn the_feature_switch_url_carries_the_senders_bucket() {
    assert_eq!(
        ChatCore::new().feature_switches_url(),
        crate::FEATURES_ENDPOINT
    );
    let party = Party::new("1234567890");
    party
        .core
        .set_identity(&SetIdentityParams::new("1234567890", SIGNING_KEY_VERSION))
        .unwrap();
    assert_eq!(
        party.core.feature_switches_url(),
        format!("{}?bucket=7890", crate::FEATURES_ENDPOINT)
    );
}

/// Whether each of a reaction add, a reaction removal and an edit `party`
/// sends in `conversation_id` asks for a notification, read from the
/// payload and from the `MessageCreateEvent` it carries.
fn notifies(party: &Party, conversation_id: &str) -> [bool; 3] {
    let ckey = key(3);
    let target = |params: EncryptReactionParams| {
        let mut params = params.with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        params.conversation_id = Some(conversation_id.to_string());
        params.target_message_sequence_id = Some("100".to_string());
        params
    };
    let mut edit =
        EncryptEditParams::new("", "edited").with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    edit.conversation_id = Some(conversation_id.to_string());
    edit.target_message_sequence_id = Some("100".to_string());
    [
        party
            .core
            .encrypt_add_reaction(&target(EncryptReactionParams::new("", "👍")))
            .unwrap(),
        party
            .core
            .encrypt_remove_reaction(&target(EncryptReactionParams::new("", "👍")))
            .unwrap(),
        party.core.encrypt_edit(&edit).unwrap(),
    ]
    .map(|payload| {
        let event = sent_event(&payload, AUTHOR, conversation_id);
        assert_eq!(
            create_event(&event).should_notify,
            Some(payload.should_notify)
        );
        payload.should_notify
    })
}

#[test]
fn a_v1_reaction_notifies_only_in_a_one_to_one_conversation_and_never_on_removal() {
    let party = author();
    enable_v1_send(&party.core);
    for one_to_one in [CONVERSATION, "1491585161162473473-2", "2"] {
        assert_eq!(
            notifies(&party, one_to_one),
            [true, false, false],
            "{one_to_one}"
        );
    }
    assert_eq!(
        notifies(&party, "g2031597666757378493"),
        [false, false, false]
    );
}

#[test]
fn v0_reactions_and_edits_notify_as_0_5_did() {
    let party = author();
    for conversation_id in [CONVERSATION, "g2031597666757378493"] {
        assert_eq!(notifies(&party, conversation_id), [true, true, true]);
    }
}
