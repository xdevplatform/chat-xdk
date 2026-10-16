//! Sending: contents under the message's own key, signed at the message
//! signature version, and files encrypted from the sent message.

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
use crate::utils::encrypted_file_size;

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

/// `params` with `attachments`, or with none when the list is empty.
fn with_attachments(
    mut params: EncryptMessageParams,
    attachments: Vec<AttachmentDescriptor>,
) -> EncryptMessageParams {
    params.attachments = (!attachments.is_empty()).then_some(attachments);
    params
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

fn link_card(banner: Option<&str>, favicon: Option<&str>) -> AttachmentDescriptor {
    AttachmentDescriptor::Url {
        url: "https://example.com".to_string(),
        display_title: Some("Example".to_string()),
        banner_image: banner.map(card_image),
        favicon_image: favicon.map(card_image),
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

/// `file` encrypted for the attachment `media_hash_key` names in the sent
/// message `payload`, by a session with no identity.
fn encrypt_file(
    payload: &SendPayload,
    ckey: &XChatConversationKey,
    media_hash_key: &str,
    file: &[u8],
) -> Result<Vec<u8>, SdkError> {
    ChatCore::new().encrypt_file(EncryptFileParams::new(
        file.to_vec(),
        payload.event_b64.clone(),
        keys(KEY_VERSION, ckey),
        media_hash_key,
    ))
}

fn open_file(
    event: &ThriftEvent,
    ckey: &XChatConversationKey,
    media_hash_key: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, SdkError> {
    ChatCore::new().decrypt_file(DecryptFileParams::new(
        encrypted.to_vec(),
        frame(event),
        keys(KEY_VERSION, ckey),
        media_hash_key,
    ))
}

fn error_text<T>(result: Result<T, SdkError>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err.to_string(),
    }
}

fn assert_lowercase_v4_uuid(id: &str) {
    let uuid = uuid::Uuid::parse_str(id).unwrap();
    assert_eq!(uuid.get_version_num(), 4, "{id}");
    assert_eq!(uuid.to_string(), id);
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
            DecryptEventParams::new(frame(event), keys(KEY_VERSION, &ckey))
                .with_signing_keys(vec![author.entry.clone()]),
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
fn event_b64_is_the_sent_message_as_recipients_receive_it() {
    let author = author();
    let ckey = key(3);
    let original = author
        .core
        .encrypt_message(with_attachments(
            message_params("original", &ckey),
            vec![image("photo")],
        ))
        .unwrap();
    let original_event = frame(&delivered(&original, "100"));
    let reply = EncryptReplyParams::new(CONVERSATION, "reply", original_event.clone())
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let reaction = EncryptReactionParams::new(original_event.clone(), "👍")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let edit = EncryptEditParams::new(original_event, "edited")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    let hyphenated = EncryptMessageParams::new("1491585161162473473-2", "hyphenated")
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
        (
            "hyphenated conversation id",
            author.core.encrypt_message(hyphenated).unwrap(),
        ),
    ];
    for (what, payload) in sends {
        let event = ChatCore::parse_event_b64(&payload.event_b64).unwrap();
        assert_eq!(event, sent_event(&payload, AUTHOR, CONVERSATION), "{what}");

        let Event::Message(message) = ChatCore::new()
            .decrypt_event(
                DecryptEventParams::new(payload.event_b64.clone(), keys(KEY_VERSION, &ckey))
                    .with_signing_keys(vec![author.entry.clone()]),
            )
            .unwrap()
        else {
            panic!("{what} is not a message");
        };
        assert!(message.verified, "{what}");
        assert_eq!(
            message.meta.id.as_deref(),
            Some(payload.message_id.as_str()),
            "{what}"
        );
        assert_eq!(message.meta.sequence_id, None, "{what}");
    }
}

// Message ids.

#[test]
fn a_message_without_files_takes_a_random_id() {
    let author = author();
    let ckey = key(3);
    let without_files = [
        Vec::new(),
        vec![link_card(None, None)],
        vec![AttachmentDescriptor::Post {
            rest_id: Some("1234".to_string()),
            post_url: None,
        }],
    ];
    for attachments in without_files {
        let send = || {
            author
                .core
                .encrypt_message(with_attachments(
                    message_params("same text", &ckey),
                    attachments.clone(),
                ))
                .unwrap()
                .message_id
        };
        let (first, second) = (send(), send());
        assert_ne!(first, second, "{attachments:?}");
        assert_lowercase_v4_uuid(&first);
        assert_lowercase_v4_uuid(&second);
    }
}

#[test]
fn a_message_with_files_takes_the_id_its_files_derive() {
    let author = author();
    let ckey = key(3);
    let send = |params: EncryptMessageParams, files: &[&str]| {
        let attachments = files.iter().map(|hash| image(hash)).collect();
        author
            .core
            .encrypt_message(with_attachments(params, attachments))
            .unwrap()
            .message_id
    };
    let id = send(message_params("two photos", &ckey), &["photo-a", "photo-b"]);
    assert_lowercase_v4_uuid(&id);
    assert_eq!(
        id,
        message_keys::derive_media_message_id(
            &ckey,
            KEY_VERSION,
            AUTHOR,
            CONVERSATION,
            &["photo-a", "photo-b"]
        )
        .unwrap()
    );

    let same = [
        (
            "the same message",
            send(message_params("two photos", &ckey), &["photo-a", "photo-b"]),
        ),
        (
            "other text",
            send(message_params("other text", &ckey), &["photo-a", "photo-b"]),
        ),
        (
            "the hyphenated conversation id",
            send(
                EncryptMessageParams::new("1491585161162473473-2", "two photos")
                    .with_conversation_key(ckey.to_bytes(), KEY_VERSION),
                &["photo-a", "photo-b"],
            ),
        ),
    ];
    for (what, other) in same {
        assert_eq!(other, id, "{what}");
    }

    let different = [
        (
            "files in another order",
            send(message_params("two photos", &ckey), &["photo-b", "photo-a"]),
        ),
        (
            "fewer files",
            send(message_params("two photos", &ckey), &["photo-a"]),
        ),
        (
            "another sender",
            send(
                message_params("two photos", &ckey).with_identity("1002", SIGNING_KEY_VERSION),
                &["photo-a", "photo-b"],
            ),
        ),
        (
            "another conversation",
            send(
                EncryptMessageParams::new("g1234", "two photos")
                    .with_conversation_key(ckey.to_bytes(), KEY_VERSION),
                &["photo-a", "photo-b"],
            ),
        ),
        (
            "another conversation key",
            send(
                message_params("two photos", &key(4)),
                &["photo-a", "photo-b"],
            ),
        ),
        (
            "another conversation key version",
            send(
                EncryptMessageParams::new(CONVERSATION, "two photos")
                    .with_conversation_key(ckey.to_bytes(), "8"),
                &["photo-a", "photo-b"],
            ),
        ),
    ];
    for (what, other) in different {
        assert_ne!(other, id, "{what}");
    }
}

#[test]
fn a_reply_with_files_takes_the_id_its_files_derive() {
    let author = author();
    let ckey = key(3);
    let original = author
        .core
        .encrypt_message(message_params("original", &ckey))
        .unwrap();
    let original_event = frame(&delivered(&original, "100"));
    let send = |text: &str| {
        let mut params = EncryptReplyParams::new(CONVERSATION, text, original_event.clone())
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        params.attachments = Some(vec![image("reply-photo")]);
        author.core.encrypt_reply(params).unwrap().message_id
    };
    let id = send("a photo");
    assert_eq!(id, send("another caption"));
    assert_eq!(
        id,
        message_keys::derive_media_message_id(
            &ckey,
            KEY_VERSION,
            AUTHOR,
            CONVERSATION,
            &["reply-photo"]
        )
        .unwrap()
    );
}

// Files.

#[test]
fn files_encrypted_from_the_payload_open_from_the_sent_message() {
    let author = author();
    let ckey = key(3);
    let files: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 3000 + usize::from(i)]).collect();
    let payload = author
        .core
        .encrypt_message(with_attachments(
            message_params("three photos", &ckey),
            vec![image("photo-0"), image("photo-1"), image("photo-2")],
        ))
        .unwrap();
    let event = delivered(&payload, "100");
    for (index, file) in files.iter().enumerate() {
        let media_hash_key = format!("photo-{index}");
        let encrypted = encrypt_file(&payload, &ckey, &media_hash_key, file).unwrap();
        assert_eq!(
            Some(encrypted.len() as u64),
            encrypted_file_size(file.len() as u64)
        );
        assert_eq!(
            &open_file(&event, &ckey, &media_hash_key, &encrypted).unwrap(),
            file,
            "photo {index}"
        );
    }

    let Contents::Message(message) = sent_contents(&payload, &ckey) else {
        panic!("expected a message");
    };
    let message_id = &payload.message_id;
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
fn the_file_encryptor_and_decryptor_match_the_one_shot_calls() {
    let author = author();
    let ckey = key(3);
    let file: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let payload = author
        .core
        .encrypt_message(with_attachments(
            message_params("two photos", &ckey),
            vec![image("first"), image("second")],
        ))
        .unwrap();
    let mut encryptor = ChatCore::new()
        .file_encryptor(FileEncryptorParams::new(
            payload.event_b64.clone(),
            keys(KEY_VERSION, &ckey),
            "second",
        ))
        .unwrap();
    let mut encrypted = Vec::new();
    for chunk in file.chunks(4093) {
        encrypted.extend(encryptor.push(chunk).unwrap());
    }
    encrypted.extend(encryptor.finish().unwrap());
    assert_eq!(
        Some(encrypted.len() as u64),
        encrypted_file_size(file.len() as u64)
    );

    let event = delivered(&payload, "100");
    assert_eq!(
        open_file(&event, &ckey, "second", &encrypted).unwrap(),
        file
    );
    assert!(open_file(&event, &ckey, "first", &encrypted).is_err());
    let one_shot = encrypt_file(&payload, &ckey, "second", &file).unwrap();
    assert_eq!(open_file(&event, &ckey, "second", &one_shot).unwrap(), file);

    let mut decryptor = ChatCore::new()
        .file_decryptor(FileDecryptorParams::new(
            frame(&event),
            keys(KEY_VERSION, &ckey),
            "second",
        ))
        .unwrap();
    let mut opened = Vec::new();
    for chunk in encrypted.chunks(1000) {
        opened.extend(decryptor.push(chunk).unwrap());
    }
    opened.extend(decryptor.finish().unwrap());
    assert_eq!(opened, file);
}

#[test]
fn an_empty_file_encrypts_and_opens() {
    let author = author();
    let ckey = key(3);
    let payload = author
        .core
        .encrypt_message(with_attachments(
            message_params("empty", &ckey),
            vec![image("empty")],
        ))
        .unwrap();
    let encrypted = encrypt_file(&payload, &ckey, "empty", b"").unwrap();
    assert_eq!(Some(encrypted.len() as u64), encrypted_file_size(0));
    assert!(
        open_file(&delivered(&payload, "100"), &ckey, "empty", &encrypted)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_link_cards_banner_and_favicon_take_the_cards_key() {
    let author = author();
    let ckey = key(3);
    let payload = author
        .core
        .encrypt_message(with_attachments(
            message_params("a link", &ckey),
            vec![link_card(Some("banner"), Some("favicon"))],
        ))
        .unwrap();
    let banner = encrypt_file(&payload, &ckey, "banner", b"banner bytes").unwrap();
    let favicon = encrypt_file(&payload, &ckey, "favicon", b"favicon bytes").unwrap();
    let event = delivered(&payload, "100");
    assert_eq!(
        open_file(&event, &ckey, "banner", &banner).unwrap(),
        b"banner bytes"
    );
    assert_eq!(
        open_file(&event, &ckey, "favicon", &favicon).unwrap(),
        b"favicon bytes"
    );

    let Contents::Message(message) = sent_contents(&payload, &ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        attachment_ids(message.attachments.as_deref().unwrap()),
        vec![Some(payload.message_id.clone())]
    );
}

#[test]
fn a_reply_encrypts_its_own_files_and_quotes_the_originals() {
    let author = author();
    let ckey = key(3);
    let original = author
        .core
        .encrypt_message(with_attachments(
            message_params("a photo", &ckey),
            vec![image("original-photo")],
        ))
        .unwrap();
    let original_photo =
        encrypt_file(&original, &ckey, "original-photo", b"original photo").unwrap();

    let mut params = EncryptReplyParams::new(
        CONVERSATION,
        "and mine",
        frame(&delivered(&original, "100")),
    )
    .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    params.attachments = Some(vec![image("reply-photo")]);
    let reply = author.core.encrypt_reply(params).unwrap();
    let reply_photo = encrypt_file(&reply, &ckey, "reply-photo", b"reply photo").unwrap();
    let err = error_text(encrypt_file(
        &reply,
        &ckey,
        "original-photo",
        b"original photo",
    ));
    assert!(
        err.contains("media_hash_key 'original-photo' is media the reply quotes"),
        "{err}"
    );

    let event = delivered(&reply, "200");
    assert_eq!(
        open_file(&event, &ckey, "reply-photo", &reply_photo).unwrap(),
        b"reply photo"
    );
    assert_eq!(
        open_file(&event, &ckey, "original-photo", &original_photo).unwrap(),
        b"original photo"
    );

    let Contents::Message(message) = sent_contents(&reply, &ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        attachment_ids(message.attachments.as_deref().unwrap()),
        vec![Some(reply.message_id.clone())]
    );
    let preview = message.replying_to_preview.unwrap();
    assert_eq!(
        attachment_ids(preview.attachments.as_deref().unwrap()),
        vec![Some(original.message_id.clone())]
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
fn a_rebuilt_message_keeps_its_encrypted_files_valid() {
    let author = author();
    let ckey = key(3);
    let build = |party: &Party, text: &str| {
        party
            .core
            .encrypt_message(with_attachments(
                message_params(text, &ckey),
                vec![image("photo-a"), image("photo-b")],
            ))
            .unwrap()
    };
    let draft = build(&author, "draft");
    let photo_b = encrypt_file(&draft, &ckey, "photo-b", b"photo b").unwrap();

    // Another session of the same sender, with other signing keys.
    let restarted = Party::new(AUTHOR);
    restarted.core.set_identity(AUTHOR, "2");
    for (what, rebuilt) in [
        ("rebuilt", build(&author, "final text")),
        (
            "rebuilt in another session",
            build(&restarted, "final text"),
        ),
    ] {
        assert_eq!(rebuilt.message_id, draft.message_id, "{what}");
        assert_eq!(
            open_file(&delivered(&rebuilt, "100"), &ckey, "photo-b", &photo_b).unwrap(),
            b"photo b",
            "{what}"
        );
    }
}

#[test]
fn a_file_encrypted_for_another_attachment_or_message_does_not_open() {
    let author = author();
    let ckey = key(3);
    let payload = author
        .core
        .encrypt_message(with_attachments(
            message_params("two photos", &ckey),
            vec![image("photo-a"), image("photo-b")],
        ))
        .unwrap();
    let other = author
        .core
        .encrypt_message(with_attachments(
            message_params("another photo", &ckey),
            vec![image("photo-c")],
        ))
        .unwrap();
    let event = delivered(&payload, "100");
    let for_a = encrypt_file(&payload, &ckey, "photo-a", b"photo").unwrap();
    let for_other = encrypt_file(&other, &ckey, "photo-c", b"photo").unwrap();
    assert!(open_file(&event, &ckey, "photo-b", &for_a).is_err());
    assert!(open_file(&event, &ckey, "photo-a", &for_other).is_err());
    assert!(open_file(&delivered(&other, "101"), &ckey, "photo-c", &for_a).is_err());
}

#[test]
fn file_encryption_errors_say_what_to_pass() {
    let author = author();
    let ckey = key(3);
    let with_photo = author
        .core
        .encrypt_message(with_attachments(
            message_params("a photo", &ckey),
            vec![image("photo")],
        ))
        .unwrap();
    let without_files = author
        .core
        .encrypt_message(message_params("text", &ckey))
        .unwrap();
    let photo_event = frame(&delivered(&with_photo, "100"));
    let reaction = author
        .core
        .encrypt_add_reaction(
            &EncryptReactionParams::new(photo_event.clone(), "👍")
                .with_conversation_key(ckey.to_bytes(), KEY_VERSION),
        )
        .unwrap();
    let edit = author
        .core
        .encrypt_edit(
            &EncryptEditParams::new(photo_event, "edited")
                .with_conversation_key(ckey.to_bytes(), KEY_VERSION),
        )
        .unwrap();
    let not_a_message = frame(&ThriftEvent {
        message_id: Some(with_photo.message_id.clone()),
        sender_id: Some(AUTHOR.to_string()),
        ..Default::default()
    });

    let ok_keys = keys(KEY_VERSION, &ckey);
    let cases = [
        (
            with_photo.event_b64.clone(),
            ok_keys.clone(),
            "",
            "media_hash_key is empty".to_string(),
        ),
        (
            with_photo.event_b64.clone(),
            ok_keys.clone(),
            "other",
            "media_hash_key 'other' is not one of the message's files, whose media hash keys are \
             photo"
                .to_string(),
        ),
        (
            without_files.event_b64.clone(),
            ok_keys.clone(),
            "photo",
            "the message has no files".to_string(),
        ),
        (
            reaction.event_b64.clone(),
            ok_keys.clone(),
            "photo",
            "is a reaction".to_string(),
        ),
        (
            edit.event_b64.clone(),
            ok_keys.clone(),
            "photo",
            "is an edit".to_string(),
        ),
        (
            not_a_message,
            ok_keys.clone(),
            "photo",
            "the event is not a message".to_string(),
        ),
        (
            with_photo.event_b64.clone(),
            keys(KEY_VERSION, &key(4)),
            "photo",
            format!("the key for version '{KEY_VERSION}' in conversation_keys does not decrypt"),
        ),
        (
            with_photo.event_b64.clone(),
            keys("8", &ckey),
            "photo",
            format!("conversation_keys has no key for version '{KEY_VERSION}'"),
        ),
        (
            "not base64!".to_string(),
            ok_keys.clone(),
            "photo",
            "Base64 error".to_string(),
        ),
    ];
    let core = ChatCore::new();
    for (event_b64, conversation_keys, media_hash_key, expected) in cases {
        let err = error_text(core.encrypt_file(EncryptFileParams::new(
            b"photo".to_vec(),
            event_b64.clone(),
            conversation_keys.clone(),
            media_hash_key,
        )));
        assert!(err.contains(&expected), "{err:?} lacks {expected:?}");
        let err = error_text(core.file_encryptor(FileEncryptorParams::new(
            event_b64,
            conversation_keys,
            media_hash_key,
        )));
        assert!(err.contains(&expected), "{err:?} lacks {expected:?}");
    }
}

#[test]
fn each_file_needs_its_own_media_hash_key() {
    let author = author();
    let ckey = key(3);
    let cases = [
        (vec![image("")], "an attachment's media_hash_key is empty"),
        (
            vec![link_card(Some(""), None)],
            "an attachment's media_hash_key is empty",
        ),
        (
            vec![image("photo"), image("photo")],
            "media_hash_key 'photo' is in more than one attachment",
        ),
    ];
    for (attachments, expected) in cases {
        let err = error_text(author.core.encrypt_message(with_attachments(
            message_params("files", &ckey),
            attachments.clone(),
        )));
        assert!(err.contains(expected), "{err}");

        let mut params = EncryptReplyParams::new(CONVERSATION, "files", "")
            .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
        params.reply_to_sequence_id = Some("100".to_string());
        params.attachments = Some(attachments);
        let err = error_text(author.core.encrypt_reply(params));
        assert!(err.contains(expected), "{err}");
    }

    let shared = author
        .core
        .encrypt_message(with_attachments(
            message_params("a link", &ckey),
            vec![link_card(Some("image"), Some("image"))],
        ))
        .unwrap();
    let encrypted = encrypt_file(&shared, &ckey, "image", b"image").unwrap();
    assert_eq!(
        open_file(&delivered(&shared, "100"), &ckey, "image", &encrypted).unwrap(),
        b"image"
    );
}

// Identity.

#[test]
fn a_send_takes_its_identity_from_the_params_then_the_session() {
    let ckey = key(3);
    let sends = |text: &str| {
        [
            message_params(text, &ckey),
            with_attachments(message_params(text, &ckey), vec![image("photo")]),
        ]
    };

    let anonymous = Party::new(AUTHOR);
    for params in sends("no identity") {
        let err = error_text(anonymous.core.encrypt_message(params));
        assert!(
            err.contains("sender_id is not set: pass it explicitly or call set_identity() first"),
            "{err}"
        );
    }
    let mut reply = EncryptReplyParams::new(CONVERSATION, "no identity", "")
        .with_conversation_key(ckey.to_bytes(), KEY_VERSION);
    reply.reply_to_sequence_id = Some("100".to_string());
    reply.attachments = Some(vec![image("photo")]);
    let err = error_text(anonymous.core.encrypt_reply(reply));
    assert!(err.contains("call set_identity() first"), "{err}");

    let author = author();
    let as_other = SigningKeyEntry {
        user_id: "1002".to_string(),
        public_key_version: "2".to_string(),
        ..author.entry.clone()
    };
    let cases = [
        (
            &anonymous,
            Some((AUTHOR, SIGNING_KEY_VERSION)),
            &anonymous.entry,
        ),
        (&author, None, &author.entry),
        (&author, Some(("1002", "2")), &as_other),
    ];
    for (party, identity, signing_key) in cases {
        for params in sends("identity") {
            let params = match identity {
                Some((sender_id, version)) => params.with_identity(sender_id, version),
                None => params,
            };
            let has_file = params.attachments.is_some();
            let payload = party.core.encrypt_message(params).unwrap();
            let event = ChatCore::parse_event_b64(&payload.event_b64).unwrap();
            assert_eq!(event.sender_id, Some(signing_key.user_id.clone()));
            assert_eq!(
                payload.signature_info.public_key_version,
                signing_key.public_key_version
            );
            let message = decrypt_message(
                &ChatCore::new(),
                &event,
                &keys(KEY_VERSION, &ckey),
                std::slice::from_ref(signing_key),
            )
            .unwrap();
            assert!(message.verified, "{identity:?}");
            if has_file {
                let encrypted = encrypt_file(&payload, &ckey, "photo", b"photo").unwrap();
                let opened = ChatCore::new()
                    .decrypt_file(DecryptFileParams::new(
                        encrypted,
                        frame(&event),
                        keys(KEY_VERSION, &ckey),
                        "photo",
                    ))
                    .unwrap();
                assert_eq!(opened, b"photo", "{identity:?}");
            }
        }
    }
}

#[test]
fn a_send_needs_a_numeric_sender_and_an_integer_key_version() {
    let author = author();
    let ckey = key(3);
    for attachments in [Vec::new(), vec![image("photo")]] {
        let err = error_text(author.core.encrypt_message(with_attachments(
            message_params("text", &ckey).with_identity("me", "1"),
            attachments.clone(),
        )));
        assert!(err.contains("Invalid sender_id 'me'"), "{err}");

        let err = error_text(
            author.core.encrypt_message(with_attachments(
                EncryptMessageParams::new(CONVERSATION, "text")
                    .with_conversation_key(ckey.to_bytes(), "v7"),
                attachments,
            )),
        );
        assert!(
            err.contains("Invalid conversation_key_version 'v7'"),
            "{err}"
        );
    }
}
