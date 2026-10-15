//! Sending: contents under the message's own key, signed at the message
//! signature version, and media encrypted for its message and position.

use super::test_support::{
    decrypt_message, frame, key, keys, sent_event, Party, CONVERSATION, SIGNING_KEY_VERSION,
};
use super::*;
use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::thrift::event::{
    MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail as Detail,
};
use crate::thrift::product::{
    MessageAttachment as ThriftAttachment, MessageEntryContents as Contents,
};

const AUTHOR: &str = "1001";
const KEY_VERSION: &str = "7";

/// A party whose session identity is its own user id.
fn author() -> Party {
    let party = Party::new(AUTHOR);
    party.core.set_identity(AUTHOR, SIGNING_KEY_VERSION);
    party
}

fn message_params(text: &str, ckey: &XChatConversationKey) -> EncryptMessageParams {
    EncryptMessageParams::new(CONVERSATION, text)
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION)
}

fn image(media_hash_key: &str) -> AttachmentDescriptor {
    AttachmentDescriptor::Media {
        media_hash_key: media_hash_key.to_string(),
        width: 640,
        height: 480,
        filesize_bytes: 4096,
        filename: format!("{media_hash_key}.jpg"),
        media_type: Some(1),
        duration_millis: None,
    }
}

fn card_image(media_hash_key: &str) -> UrlAttachmentImageDescriptor {
    UrlAttachmentImageDescriptor {
        media_hash_key: media_hash_key.to_string(),
        filesize_bytes: 512,
        filename: format!("{media_hash_key}.png"),
        width: None,
        height: None,
    }
}

/// The delivered event of `payload` from the author, at `sequence_id`.
fn delivered(payload: &SendPayload, sequence_id: &str) -> ThriftEvent {
    ThriftEvent {
        sequence_id: Some(sequence_id.to_string()),
        ..sent_event(payload, AUTHOR, CONVERSATION)
    }
}

fn create_event(event: &ThriftEvent) -> &MessageCreateEvent {
    match &event.detail {
        Some(Detail::MessageCreateEvent(create)) => create,
        other => panic!("expected a MessageCreateEvent, got {:?}", other),
    }
}

/// The sent contents, opened with the message key recipients derive.
fn sent_contents(payload: &SendPayload, ckey: &XChatConversationKey) -> Contents {
    let event = sent_event(payload, AUTHOR, CONVERSATION);
    let message_key = message_keys::derive_message_key(ckey, AUTHOR, &payload.message_id).unwrap();
    let plaintext = decrypt_message_bytes(
        &message_key,
        create_event(&event).contents.as_ref().unwrap(),
    )
    .unwrap();
    ChatCore::parse_thrift_entry_contents(&plaintext).unwrap()
}

#[allow(clippy::vec_box)]
fn attachment_ids(attachments: &[Box<ThriftAttachment>]) -> Vec<Option<String>> {
    attachments
        .iter()
        .map(|attachment| match attachment.as_ref() {
            ThriftAttachment::Media(media) => media.attachment_id.clone(),
            ThriftAttachment::Url(card) => card.attachment_id.clone(),
            ThriftAttachment::Post(post) => post.attachment_id.clone(),
            other => panic!("unexpected attachment {:?}", other),
        })
        .collect()
}

fn open_media(
    event: &ThriftEvent,
    ckey: &XChatConversationKey,
    media_hash_key: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, SdkError> {
    ChatCore::new().decrypt_stream(
        encrypted,
        &frame(event),
        &keys(KEY_VERSION, ckey),
        media_hash_key,
    )
}

fn error_text<T>(result: Result<T, SdkError>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err.to_string(),
    }
}

// Messages, replies, reactions, and edits.

#[test]
fn every_kind_of_send_uses_its_message_key_and_signs_at_v10() {
    let author = author();
    let ckey = key(3);
    let original = author
        .core
        .encrypt_message(message_params("original", &ckey))
        .unwrap();
    let original_event = frame(&delivered(&original, "100"));
    let reply = EncryptReplyParams::new(CONVERSATION, "reply", original_event.clone())
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let reaction = EncryptReactionParams::new(original_event.clone(), "👍")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let edit = EncryptEditParams::new(original_event, "edited")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);

    let sends = [
        ("message", original),
        ("reply", author.core.encrypt_reply(reply).unwrap()),
        (
            "reaction add",
            author.core.encrypt_add_reaction(&reaction).unwrap(),
        ),
        (
            "reaction remove",
            author.core.encrypt_remove_reaction(&reaction).unwrap(),
        ),
        ("edit", author.core.encrypt_edit(&edit).unwrap()),
    ];
    for (what, payload) in sends {
        assert_eq!(payload.signature_info.signature_version, "10", "{what}");
        let event = delivered(&payload, "200");
        let create = create_event(&event);
        assert_eq!(create.contents_encryption_version, Some(1), "{what}");
        let contents = create.contents.as_ref().unwrap();
        assert!(
            decrypt_message_bytes(&ckey, contents).is_err(),
            "{what} opens with the conversation key"
        );
        let message_key =
            message_keys::derive_message_key(&ckey, AUTHOR, &payload.message_id).unwrap();
        assert!(
            decrypt_message_bytes(&message_key, contents).is_ok(),
            "{what}"
        );

        let message = decrypt_message(
            &ChatCore::new(),
            &event,
            &keys(KEY_VERSION, &ckey),
            std::slice::from_ref(&author.entry),
        )
        .unwrap();
        assert!(message.verified, "{what}");
    }
}

#[test]
fn the_signature_covers_the_contents_encryption_version() {
    let author = author();
    let ckey = key(3);
    let payload = author
        .core
        .encrypt_message(message_params("bound", &ckey))
        .unwrap();
    let event = delivered(&payload, "100");
    let contents = create_event(&event).contents.clone().unwrap();
    let expected = format!(
        "MessageCreateEvent,{},{},{},{},{},1,signature_version=10",
        payload.message_id,
        AUTHOR,
        CONVERSATION,
        KEY_VERSION,
        STANDARD_NO_PAD.encode(&contents)
    );
    let signature = STANDARD_NO_PAD.decode(&payload.signature).unwrap();
    assert!(ChatCore::new()
        .verify(&author.entry.public_key, &signature, expected.as_bytes())
        .unwrap());

    let receive = |event: &ThriftEvent| {
        ChatCore::new().decrypt_event(
            &frame(event),
            &keys(KEY_VERSION, &ckey),
            std::slice::from_ref(&author.entry),
        )
    };
    for version in [None, Some(0), Some(2)] {
        let mut tampered = event.clone();
        if let Some(Detail::MessageCreateEvent(create)) = tampered.detail.as_mut() {
            create.contents_encryption_version = version;
        }
        let err = error_text(receive(&tampered));
        assert!(
            err.contains("Signature verification failed"),
            "{version:?}: {err}"
        );
    }
    let mut relabeled = event.clone();
    if let Some(signature) = relabeled.message_event_signature.as_mut() {
        signature.signature_version = Some("9".to_string());
    }
    let err = error_text(receive(&relabeled));
    assert!(err.contains("Signature verification failed"), "{err}");
}

#[test]
fn a_message_id_from_the_caller_is_the_one_sent() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    let payload = author
        .core
        .encrypt_message(message_params("chosen id", &ckey).with_message_id(message_id.clone()))
        .unwrap();
    assert_eq!(payload.message_id, message_id);
    let message = decrypt_message(
        &ChatCore::new(),
        &delivered(&payload, "100"),
        &keys(KEY_VERSION, &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
    assert_eq!(message.meta.id.as_deref(), Some(message_id.as_str()));
}

#[test]
fn new_message_id_returns_a_fresh_lowercase_uuid() {
    let core = ChatCore::new();
    let first = core.new_message_id();
    let second = core.new_message_id();
    assert_ne!(first, second);
    for id in [&first, &second] {
        assert_eq!(id.len(), 36);
        assert_eq!(id.to_lowercase(), *id);
        crate::pipeline::validate_message_id(id).unwrap();
    }
}

// Media.

#[test]
fn media_encrypted_for_its_position_opens_from_the_sent_message() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    let files: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 3000 + usize::from(i)]).collect();
    let encrypted: Vec<Vec<u8>> = files
        .iter()
        .zip(0..)
        .map(|(file, index)| {
            author
                .core
                .encrypt_stream(file, &ckey, &message_id, index)
                .unwrap()
        })
        .collect();

    let mut params = message_params("three photos", &ckey).with_message_id(message_id.clone());
    params.attachments = Some(vec![image("photo-0"), image("photo-1"), image("photo-2")]);
    let payload = author.core.encrypt_message(params).unwrap();
    let event = delivered(&payload, "100");
    for (index, (file, encrypted)) in files.iter().zip(&encrypted).enumerate() {
        let opened = open_media(&event, &ckey, &format!("photo-{index}"), encrypted).unwrap();
        assert_eq!(&opened, file, "photo {index}");
    }

    let Contents::Message(message) = sent_contents(&payload, &ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        attachment_ids(message.attachments.as_deref().unwrap()),
        vec![
            Some(message_id.clone()),
            Some(format!("{message_id}#1")),
            Some(format!("{message_id}#2")),
        ]
    );
}

#[test]
fn the_incremental_encryptor_takes_the_same_message_and_position() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    let file: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let mut encryptor = author.core.stream_encryptor(&ckey, &message_id, 1).unwrap();
    let mut encrypted = Vec::new();
    for chunk in file.chunks(4096) {
        encrypted.extend(encryptor.push(chunk).unwrap());
    }
    encrypted.extend(encryptor.finish().unwrap());

    let mut params = message_params("two photos", &ckey).with_message_id(message_id);
    params.attachments = Some(vec![image("first"), image("second")]);
    let payload = author.core.encrypt_message(params).unwrap();
    let event = delivered(&payload, "100");
    assert_eq!(
        open_media(&event, &ckey, "second", &encrypted).unwrap(),
        file
    );
    assert!(open_media(&event, &ckey, "first", &encrypted).is_err());
}

#[test]
fn a_link_cards_banner_and_favicon_take_the_cards_position() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    let banner = author
        .core
        .encrypt_stream(b"banner bytes", &ckey, &message_id, 0)
        .unwrap();
    let favicon = author
        .core
        .encrypt_stream(b"favicon bytes", &ckey, &message_id, 0)
        .unwrap();

    let mut params = message_params("a link", &ckey).with_message_id(message_id.clone());
    params.attachments = Some(vec![AttachmentDescriptor::Url {
        url: "https://example.com".to_string(),
        display_title: Some("Example".to_string()),
        banner_image: Some(card_image("banner")),
        favicon_image: Some(card_image("favicon")),
    }]);
    let payload = author.core.encrypt_message(params).unwrap();
    let event = delivered(&payload, "100");
    assert_eq!(
        open_media(&event, &ckey, "banner", &banner).unwrap(),
        b"banner bytes"
    );
    assert_eq!(
        open_media(&event, &ckey, "favicon", &favicon).unwrap(),
        b"favicon bytes"
    );

    let Contents::Message(message) = sent_contents(&payload, &ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        attachment_ids(message.attachments.as_deref().unwrap()),
        vec![Some(message_id)]
    );
}

#[test]
fn a_reply_sends_its_own_media_and_quotes_the_originals_with_their_ids() {
    let author = author();
    let ckey = key(3);
    let original_id = author.core.new_message_id();
    let original_photo = author
        .core
        .encrypt_stream(b"original photo", &ckey, &original_id, 0)
        .unwrap();
    let mut params = message_params("a photo", &ckey).with_message_id(original_id.clone());
    params.attachments = Some(vec![image("original-photo")]);
    let original = author.core.encrypt_message(params).unwrap();

    let reply_id = author.core.new_message_id();
    let reply_photo = author
        .core
        .encrypt_stream(b"reply photo", &ckey, &reply_id, 0)
        .unwrap();
    let mut params = EncryptReplyParams::new(
        CONVERSATION,
        "and mine",
        frame(&delivered(&original, "100")),
    )
    .with_conversation_key(ckey.to_bytes(), KEY_VERSION)
    .with_message_id(reply_id.clone());
    params.attachments = Some(vec![image("reply-photo")]);
    let reply = author.core.encrypt_reply(params).unwrap();
    assert_eq!(reply.message_id, reply_id);

    let event = delivered(&reply, "200");
    assert_eq!(
        open_media(&event, &ckey, "reply-photo", &reply_photo).unwrap(),
        b"reply photo"
    );
    assert_eq!(
        open_media(&event, &ckey, "original-photo", &original_photo).unwrap(),
        b"original photo"
    );

    let Contents::Message(message) = sent_contents(&reply, &ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        attachment_ids(message.attachments.as_deref().unwrap()),
        vec![Some(reply_id)]
    );
    let preview = message.replying_to_preview.unwrap();
    assert_eq!(
        attachment_ids(preview.attachments.as_deref().unwrap()),
        vec![Some(original_id)]
    );
    let validated = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys(KEY_VERSION, &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert_eq!(
        validated.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn media_encrypted_for_another_position_or_message_does_not_open() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    let other_id = author.core.new_message_id();
    let at_one = author
        .core
        .encrypt_stream(b"photo", &ckey, &message_id, 1)
        .unwrap();
    let for_other = author
        .core
        .encrypt_stream(b"photo", &ckey, &other_id, 0)
        .unwrap();

    let mut params = message_params("a photo", &ckey).with_message_id(message_id);
    params.attachments = Some(vec![image("photo")]);
    let event = delivered(&author.core.encrypt_message(params).unwrap(), "100");
    assert!(open_media(&event, &ckey, "photo", &at_one).is_err());
    assert!(open_media(&event, &ckey, "photo", &for_other).is_err());
}

// Invalid input.

#[test]
fn a_message_with_media_must_carry_its_message_id() {
    let author = author();
    let ckey = key(3);
    let media_attachments = [
        image("photo"),
        AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: None,
            banner_image: Some(card_image("banner")),
            favicon_image: None,
        },
        AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: None,
            banner_image: None,
            favicon_image: Some(card_image("favicon")),
        },
    ];
    for attachment in media_attachments {
        let mut params = message_params("media", &ckey);
        params.attachments = Some(vec![attachment.clone()]);
        let err = author.core.encrypt_message(params).unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "{err}");
        assert!(err.to_string().contains("message_id is not set"), "{err}");

        let mut params = EncryptReplyParams::new(CONVERSATION, "media", "")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        params.reply_to_sequence_id = Some("100".to_string());
        params.attachments = Some(vec![attachment]);
        let err = error_text(author.core.encrypt_reply(params));
        assert!(err.contains("message_id is not set"), "{err}");
    }

    let no_media = [
        AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: Some("Example".to_string()),
            banner_image: None,
            favicon_image: None,
        },
        AttachmentDescriptor::Post {
            rest_id: Some("1234".to_string()),
            post_url: None,
        },
    ];
    for attachment in no_media {
        let mut params = message_params("no media", &ckey);
        params.attachments = Some(vec![attachment]);
        author.core.encrypt_message(params).unwrap();
    }
}

#[test]
fn a_message_id_must_be_a_lowercase_hyphenated_uuid() {
    let author = author();
    let ckey = key(3);
    let valid = author.core.new_message_id();
    let invalid = [
        valid.to_uppercase(),
        format!("{{{valid}}}"),
        format!("urn:uuid:{valid}"),
        valid.replace('-', ""),
        format!("{valid} "),
        valid[..35].to_string(),
        format!("{},{}", &valid[..8], &valid[9..]),
        "msg-1".to_string(),
    ];
    for message_id in invalid {
        let expected = format!("Invalid message_id '{message_id}'");
        let err =
            error_text(author.core.encrypt_message(
                message_params("text", &ckey).with_message_id(message_id.clone()),
            ));
        assert!(err.contains(&expected), "{err}");

        let mut params = EncryptReplyParams::new(CONVERSATION, "reply", "")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION)
            .with_message_id(message_id.clone());
        params.reply_to_sequence_id = Some("100".to_string());
        let err = error_text(author.core.encrypt_reply(params));
        assert!(err.contains(&expected), "{err}");

        let err = error_text(author.core.encrypt_stream(b"photo", &ckey, &message_id, 0));
        assert!(err.contains(&expected), "{err}");
        let err = error_text(author.core.stream_encryptor(&ckey, &message_id, 0));
        assert!(err.contains(&expected), "{err}");
    }
}

#[test]
fn media_encryption_rejects_a_position_no_message_has() {
    let author = author();
    let ckey = key(3);
    let message_id = author.core.new_message_id();
    for index in [-1, 10, i64::MIN, i64::MAX] {
        let err = error_text(
            author
                .core
                .encrypt_stream(b"photo", &ckey, &message_id, index),
        );
        assert!(
            err.contains(&format!("Invalid attachment_index {index}")),
            "{err}"
        );
        let err = error_text(author.core.stream_encryptor(&ckey, &message_id, index));
        assert!(
            err.contains(&format!("Invalid attachment_index {index}")),
            "{err}"
        );
    }
    author
        .core
        .encrypt_stream(b"photo", &ckey, &message_id, 9)
        .unwrap();
}

#[test]
fn media_encryption_needs_a_numeric_session_identity() {
    let ckey = key(3);
    let core = ChatCore::new();
    let message_id = core.new_message_id();
    let err = error_text(core.encrypt_stream(b"photo", &ckey, &message_id, 0));
    assert!(err.contains("call set_identity() first"), "{err}");

    core.set_identity("me", SIGNING_KEY_VERSION);
    let err = error_text(core.encrypt_stream(b"photo", &ckey, &message_id, 0));
    assert!(err.contains("Invalid sender_id 'me'"), "{err}");
}

#[test]
fn a_send_needs_a_numeric_sender_and_an_integer_key_version() {
    let author = author();
    let ckey = key(3);
    let err = error_text(
        author
            .core
            .encrypt_message(message_params("text", &ckey).with_identity("me", "1")),
    );
    assert!(err.contains("Invalid sender_id 'me'"), "{err}");

    let err = error_text(
        author.core.encrypt_message(
            EncryptMessageParams::new(CONVERSATION, "text")
                .with_conversation_key(ckey.to_bytes(), "v7"),
        ),
    );
    assert!(
        err.contains("Invalid conversation_key_version 'v7'"),
        "{err}"
    );
}
