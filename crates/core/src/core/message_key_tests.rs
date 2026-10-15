//! Per-message keys, and reply previews that carry message keys.

use super::test_support::{
    decrypt_message, frame, hex_key, holder, key, keys, known_answer_media_message, media,
    message_event, message_key, sent_event, Party, CONVERSATION, KAT_CONVERSATION_KEY,
    KAT_KEY_SENDER, SIGNING_KEY_VERSION,
};
use super::*;
use crate::pipeline::{build_message_content, serialize_thrift};
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{
    ConversationKeyChangeEvent, ConversationParticipantKey, MessageEvent as ThriftEvent,
    MessageEventDetail as Detail,
};
use crate::thrift::product::{
    MediaAttachment as ThriftMedia, MessageAttachment as ThriftAttachment, MessageContents,
    MessageEdit, MessageEntryContents as Contents, PaymentReceiptAttachment,
    ReplyingToPreview as ThriftPreview,
};

fn edit_holder(message_sequence_id: &str, text: &str, message_id: Option<&str>) -> Vec<u8> {
    serialize_thrift(&MessageEntryHolder::new(Some(Box::new(
        Contents::MessageEdit(Box::new(MessageEdit::new(
            Some(message_sequence_id.to_string()),
            Some(text.to_string()),
            None,
            message_id.map(str::to_string),
        ))),
    ))))
    .unwrap()
}

// Signatures of message-key messages.

#[test]
fn a_message_key_message_verifies_at_v11_and_at_v9() {
    let author = Party::new("1001");
    let ckey = key(5);
    for version in [11, 9] {
        let message_id = format!("m-{}", version);
        let event = message_event(
            &author,
            &message_id,
            "100",
            "7",
            Some(1),
            version,
            &message_key(&ckey, "1001", &message_id),
            &build_message_content("with key", None, None).unwrap(),
        );
        let message = decrypt_message(
            &ChatCore::new(),
            &event,
            &keys("7", &ckey),
            std::slice::from_ref(&author.entry),
        )
        .unwrap();
        assert!(message.verified, "v{}", version);
        assert_eq!(message.text(), Some("with key"));
    }
}

#[test]
fn changing_the_contents_encryption_version_of_a_v10_message_fails_verification() {
    let author = Party::new("1001");
    let ckey = key(5);
    let mut event = message_event(
        &author,
        "m-1",
        "100",
        "7",
        Some(1),
        10,
        &message_key(&ckey, "1001", "m-1"),
        &build_message_content("signed", None, None).unwrap(),
    );
    if let Some(Detail::MessageCreateEvent(mce)) = event.detail.as_mut() {
        mce.contents_encryption_version = Some(2);
    }
    let err = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{}", err);
}

// Per-message keys.

#[test]
fn a_message_key_message_decrypts_with_the_known_message_key() {
    let author = Party::new(KAT_KEY_SENDER);
    let message = decrypt_message(
        &ChatCore::new(),
        &known_answer_media_message(&author),
        &keys("7", &hex_key(KAT_CONVERSATION_KEY)),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
    assert_eq!(message.text(), Some("two photos"));
    assert_eq!(message.attachments.len(), 2);
}

#[test]
fn a_message_key_needs_a_numeric_sender() {
    let author = Party::new("sender-1");
    let ckey = key(6);
    let event = message_event(
        &author,
        "m-1",
        "100",
        "7",
        Some(1),
        10,
        &ckey,
        &build_message_content("x", None, None).unwrap(),
    );
    let err = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap_err();
    assert!(err.to_string().contains("numeric sender id"), "{}", err);
}

#[test]
fn a_zero_contents_encryption_version_uses_the_conversation_key() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_event(
        &author,
        "m-1",
        "100",
        "7",
        Some(0),
        10,
        &ckey,
        &build_message_content("zero", None, None).unwrap(),
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert_eq!(message.text(), Some("zero"));
}

#[test]
fn payment_receipt_attachments_are_not_surfaced() {
    let author = Party::new("1001");
    let ckey = key(6);
    let receipt = Box::new(ThriftAttachment::PaymentReceipt(Box::new(
        PaymentReceiptAttachment {
            receipt_token: Some("jwt".to_string()),
        },
    )));
    let contents = holder(MessageContents {
        attachments: Some(vec![receipt, media("photo", None)]),
        ..Default::default()
    });
    let event = message_event(&author, "m-1", "100", "7", None, 7, &ckey, &contents);
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert_eq!(message.attachments.len(), 1);
    match &message.content {
        MessageContent::Text { attachments, .. } => {
            assert_eq!(attachments.as_ref().map(Vec::len), Some(1))
        }
        other => panic!("expected text, got {:?}", other),
    }
}

// Reply previews.

const AUTHOR: &str = "1001";
const REPLIER: &str = "1002";

struct ReplyFixture {
    author: Party,
    replier: Party,
    ckey: XChatConversationKey,
    original: ThriftEvent,
    original_key: XChatConversationKey,
}

impl ReplyFixture {
    /// An original v10 message-key message from the author with one photo.
    fn new() -> Self {
        let author = Party::new(AUTHOR);
        let replier = Party::new(REPLIER);
        let ckey = key(7);
        let original_key = message_key(&ckey, AUTHOR, "orig-1");
        let contents = holder(MessageContents {
            message_text: Some("Hello there".to_string()),
            attachments: Some(vec![media("photo", None)]),
            ..Default::default()
        });
        let original = message_event(
            &author,
            "orig-1",
            "200",
            "7",
            Some(1),
            10,
            &original_key,
            &contents,
        );
        Self {
            author,
            replier,
            ckey,
            original,
            original_key,
        }
    }

    fn preview(&self, text: &str) -> ThriftPreview {
        ThriftPreview {
            sender_id: Some(AUTHOR.parse().unwrap()),
            message_text: Some(text.to_string()),
            replying_to_message_sequence_id: Some("200".to_string()),
            replying_to_message_id: Some("orig-1".to_string()),
            raw_event_message_create: Some(self.original.clone()),
            raw_event_message_key: Some(self.original_key.to_bytes()),
            ..Default::default()
        }
    }

    /// The replier's v7 reply carrying `preview`, under the conversation key.
    fn reply(&self, preview: ThriftPreview) -> ThriftEvent {
        let contents = holder(MessageContents {
            message_text: Some("a reply".to_string()),
            replying_to_preview: Some(Box::new(preview)),
            ..Default::default()
        });
        message_event(
            &self.replier,
            "reply-1",
            "300",
            "7",
            None,
            7,
            &self.ckey,
            &contents,
        )
    }

    fn signing_keys(&self) -> Vec<SigningKeyEntry> {
        vec![self.author.entry.clone(), self.replier.entry.clone()]
    }

    /// Validate `reply` on a receiver holding the conversation key that both
    /// the reply and the original are under.
    fn validate(&self, reply: &ThriftEvent) -> Option<ReplyPreviewValidation> {
        decrypt_message(
            &ChatCore::new(),
            reply,
            &keys("7", &self.ckey),
            &self.signing_keys(),
        )
        .unwrap()
        .reply_preview_validation
    }
}

/// A reply carrying `preview` under a newer conversation key than the
/// original's, with the key map a receiver holding only that key has. Only a
/// carried key can open the original there.
fn rotated_reply(
    fixture: &ReplyFixture,
    preview: ThriftPreview,
) -> (ThriftEvent, HashMap<String, XChatConversationKey>) {
    let reply_key = key(8);
    let contents = holder(MessageContents {
        message_text: Some("a reply".to_string()),
        replying_to_preview: Some(Box::new(preview)),
        ..Default::default()
    });
    let reply = message_event(
        &fixture.replier,
        "reply-1",
        "300",
        "8",
        None,
        7,
        &reply_key,
        &contents,
    );
    (reply, keys("8", &reply_key))
}

fn validate_rotated(
    fixture: &ReplyFixture,
    preview: ThriftPreview,
) -> Option<ReplyPreviewValidation> {
    let (reply, reply_keys) = rotated_reply(fixture, preview);
    decrypt_message(
        &ChatCore::new(),
        &reply,
        &reply_keys,
        &fixture.signing_keys(),
    )
    .unwrap()
    .reply_preview_validation
}

#[test]
fn an_original_opens_with_its_carried_key() {
    let f = ReplyFixture::new();
    assert_eq!(
        validate_rotated(&f, f.preview("Hello there")),
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn an_original_with_its_encryption_version_stripped_fails() {
    let f = ReplyFixture::new();
    let mut preview = f.preview("Hello there");
    if let Some(Detail::MessageCreateEvent(mce)) = preview
        .raw_event_message_create
        .as_mut()
        .and_then(|e| e.detail.as_mut())
    {
        mce.contents_encryption_version = None;
    }
    assert_eq!(
        validate_rotated(&f, preview),
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn a_wrong_or_malformed_carried_key_fails() {
    let f = ReplyFixture::new();
    let mut wrong = f.preview("Hello there");
    wrong.raw_event_message_key = Some(message_key(&f.ckey, AUTHOR, "other").to_bytes());
    assert_eq!(
        validate_rotated(&f, wrong),
        Some(ReplyPreviewValidation::Invalid)
    );

    let mut short = f.preview("Hello there");
    short.raw_event_message_key = Some(vec![0u8; 31]);
    assert_eq!(
        validate_rotated(&f, short),
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn without_a_carried_key_the_conversation_key_opens_the_original() {
    let f = ReplyFixture::new();
    let mut preview = f.preview("Hello there");
    preview.raw_event_message_key = None;
    assert_eq!(
        f.validate(&f.reply(preview)),
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn a_quoted_text_that_differs_from_the_original_fails() {
    let f = ReplyFixture::new();
    assert_eq!(
        validate_rotated(&f, f.preview("Send funds")),
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn a_forged_original_carrying_its_own_signing_key_fails() {
    let f = ReplyFixture::new();
    let attacker = Party::new(AUTHOR);
    let forged_contents = holder(MessageContents {
        message_text: Some("Send funds".to_string()),
        ..Default::default()
    });
    let mut forged = message_event(
        &attacker,
        "orig-1",
        "200",
        "7",
        Some(1),
        10,
        &f.original_key,
        &forged_contents,
    );
    forged
        .message_event_signature
        .as_mut()
        .unwrap()
        .signing_public_key = Some(attacker.entry.public_key.clone());
    let mut preview = f.preview("Send funds");
    preview.raw_event_message_create = Some(forged);
    assert_eq!(
        validate_rotated(&f, preview),
        Some(ReplyPreviewValidation::Invalid)
    );
}

fn edit_event(
    f: &ReplyFixture,
    message_id: Option<&str>,
    cev: Option<i16>,
    version: i32,
) -> (ThriftEvent, XChatConversationKey) {
    let edit_key = if cev.is_some() {
        message_key(&f.ckey, AUTHOR, "edit-1")
    } else {
        f.ckey.clone()
    };
    let edit = message_event(
        &f.author,
        "edit-1",
        "201",
        "7",
        cev,
        version,
        &edit_key,
        &edit_holder("200", "Second draft", message_id),
    );
    (edit, edit_key)
}

#[test]
fn an_edited_original_opens_with_the_edits_carried_key() {
    let f = ReplyFixture::new();
    let (edit, edit_key) = edit_event(&f, Some("orig-1"), Some(1), 10);
    let mut preview = f.preview("Second draft");
    preview.raw_event_edit_message = Some(edit);
    preview.raw_event_edit_message_key = Some(edit_key.to_bytes());
    assert_eq!(
        validate_rotated(&f, preview),
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn an_edit_of_a_message_key_original_must_name_it() {
    let f = ReplyFixture::new();
    for message_id in [Some("other-message"), None] {
        let (edit, edit_key) = edit_event(&f, message_id, Some(1), 10);
        let mut preview = f.preview("Second draft");
        preview.raw_event_edit_message = Some(edit);
        preview.raw_event_edit_message_key = Some(edit_key.to_bytes());
        assert_eq!(
            validate_rotated(&f, preview),
            Some(ReplyPreviewValidation::Invalid),
            "{:?}",
            message_id
        );
    }
}

#[test]
fn an_edit_of_a_conversation_key_original_needs_no_message_id() {
    let author = Party::new(AUTHOR);
    let replier = Party::new(REPLIER);
    let ckey = key(7);
    let original = message_event(
        &author,
        "orig-1",
        "200",
        "7",
        None,
        7,
        &ckey,
        &build_message_content("First draft", None, None).unwrap(),
    );
    let edit = message_event(
        &author,
        "edit-1",
        "201",
        "7",
        None,
        7,
        &ckey,
        &edit_holder("200", "Second draft", None),
    );
    let preview = ThriftPreview {
        sender_id: Some(AUTHOR.parse().unwrap()),
        message_text: Some("Second draft".to_string()),
        replying_to_message_sequence_id: Some("200".to_string()),
        replying_to_message_id: Some("orig-1".to_string()),
        raw_event_message_create: Some(original),
        raw_event_edit_message: Some(edit),
        ..Default::default()
    };
    let contents = holder(MessageContents {
        message_text: Some("a reply".to_string()),
        replying_to_preview: Some(Box::new(preview)),
        ..Default::default()
    });
    let reply = message_event(&replier, "reply-1", "300", "7", None, 7, &ckey, &contents);
    let message = decrypt_message(
        &ChatCore::new(),
        &reply,
        &keys("7", &ckey),
        &[author.entry.clone(), replier.entry.clone()],
    )
    .unwrap();
    assert_eq!(
        message.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn a_quoted_photo_matches_without_its_plaintext_hash() {
    let author = Party::new(AUTHOR);
    let replier = Party::new(REPLIER);
    let ckey = key(7);
    let hashed = Box::new(ThriftAttachment::Media(Box::new(ThriftMedia {
        media_hash_key: Some("photo".to_string()),
        plaintext_sha256: Some(vec![9u8; 32]),
        ..Default::default()
    })));
    let quoted = Box::new(ThriftAttachment::Media(Box::new(ThriftMedia {
        media_hash_key: Some("photo".to_string()),
        ..Default::default()
    })));
    let original = message_event(
        &author,
        "orig-1",
        "200",
        "7",
        None,
        7,
        &ckey,
        &holder(MessageContents {
            message_text: Some("photo".to_string()),
            attachments: Some(vec![hashed]),
            ..Default::default()
        }),
    );
    let preview = ThriftPreview {
        sender_id: Some(AUTHOR.parse().unwrap()),
        message_text: Some("photo".to_string()),
        attachments: Some(vec![quoted]),
        replying_to_message_sequence_id: Some("200".to_string()),
        replying_to_message_id: Some("orig-1".to_string()),
        raw_event_message_create: Some(original),
        ..Default::default()
    };
    let reply = message_event(
        &replier,
        "reply-1",
        "300",
        "7",
        None,
        7,
        &ckey,
        &holder(MessageContents {
            message_text: Some("nice".to_string()),
            replying_to_preview: Some(Box::new(preview)),
            ..Default::default()
        }),
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &reply,
        &keys("7", &ckey),
        &[author.entry.clone(), replier.entry.clone()],
    )
    .unwrap();
    assert_eq!(
        message.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn a_reply_quoting_an_older_key_version_validates_through_its_embedded_key_change() {
    let author = Party::new(AUTHOR);
    let replier = Party::new(REPLIER);
    // The receiver is a participant of the old key change, so it can open it.
    let receiver_party = Party::new("1003");
    let receiver_identity = receiver_party.core.get_public_keys().unwrap().identity;
    let old_key = key(3);
    let new_key = key(4);
    let encrypted_old_key = conversation_keys::encrypt_conversation_key(
        &old_key,
        &KeyFactory::reconstruct_public_key(
            &base64_decode(&receiver_identity).unwrap(),
            KeypairPurpose::Identity,
        )
        .unwrap(),
    )
    .unwrap();
    let kce = ThriftEvent {
        message_id: Some("kc-1".to_string()),
        sender_id: Some(AUTHOR.to_string()),
        conversation_id: Some(CONVERSATION.to_string()),
        detail: Some(Detail::ConversationKeyChangeEvent(
            ConversationKeyChangeEvent {
                conversation_key_version: Some("3".to_string()),
                conversation_participant_keys: Some(vec![ConversationParticipantKey::new(
                    Some("1003".to_string()),
                    Some(base64_encode(&encrypted_old_key)),
                    None::<String>,
                )]),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let original = message_event(
        &author,
        "orig-1",
        "200",
        "3",
        None,
        7,
        &old_key,
        &build_message_content("Old words", None, None).unwrap(),
    );
    let preview = ThriftPreview {
        sender_id: Some(AUTHOR.parse().unwrap()),
        message_text: Some("Old words".to_string()),
        replying_to_message_sequence_id: Some("200".to_string()),
        replying_to_message_id: Some("orig-1".to_string()),
        raw_event_message_create: Some(original),
        raw_event_ckces: Some(vec![kce]),
        ..Default::default()
    };
    let reply = message_event(
        &replier,
        "reply-1",
        "300",
        "4",
        None,
        7,
        &new_key,
        &holder(MessageContents {
            message_text: Some("a reply".to_string()),
            replying_to_preview: Some(Box::new(preview)),
            ..Default::default()
        }),
    );
    let message = decrypt_message(
        &receiver_party.core,
        &reply,
        &keys("4", &new_key),
        &[author.entry.clone(), replier.entry.clone()],
    )
    .unwrap();
    assert_eq!(
        message.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
}

// Sending replies and edits.

fn decrypt_payload_contents(
    payload: &SendPayload,
    contents_key: &XChatConversationKey,
) -> Contents {
    let event = sent_event(payload, REPLIER, CONVERSATION);
    let Some(Detail::MessageCreateEvent(mce)) = event.detail else {
        panic!("expected a MessageCreateEvent");
    };
    let plaintext = decrypt_message_bytes(contents_key, mce.contents.as_ref().unwrap()).unwrap();
    ChatCore::parse_thrift_entry_contents(&plaintext).unwrap()
}

#[test]
fn a_reply_to_a_message_key_original_carries_its_key_and_its_edits_key() {
    let f = ReplyFixture::new();
    let (edit, edit_key) = edit_event(&f, Some("orig-1"), Some(1), 10);
    let mut params = crate::EncryptReplyParams::new(CONVERSATION, "a reply", frame(&f.original))
        .with_identity(REPLIER, SIGNING_KEY_VERSION)
        .with_conversation_key(f.ckey.to_bytes(), "7");
    params.reply_to_edit_event = Some(frame(&edit));
    let payload = f.replier.core.encrypt_reply(params).unwrap();

    let Contents::Message(message) = decrypt_payload_contents(&payload, &f.ckey) else {
        panic!("expected a message");
    };
    let preview = message.replying_to_preview.unwrap();
    assert_eq!(preview.message_text.as_deref(), Some("Second draft"));
    assert_eq!(
        preview.raw_event_message_key,
        Some(f.original_key.to_bytes())
    );
    assert_eq!(
        preview.raw_event_edit_message_key,
        Some(edit_key.to_bytes())
    );
}

#[test]
fn a_reply_to_a_conversation_key_original_carries_no_key() {
    let author = Party::new(AUTHOR);
    let replier = Party::new(REPLIER);
    let ckey = key(7);
    let original = message_event(
        &author,
        "orig-1",
        "200",
        "7",
        None,
        7,
        &ckey,
        &build_message_content("Hello", None, None).unwrap(),
    );
    let payload = replier
        .core
        .encrypt_reply(
            crate::EncryptReplyParams::new(CONVERSATION, "a reply", frame(&original))
                .with_identity(REPLIER, SIGNING_KEY_VERSION)
                .with_conversation_key(ckey.to_bytes(), "7"),
        )
        .unwrap();
    let Contents::Message(message) = decrypt_payload_contents(&payload, &ckey) else {
        panic!("expected a message");
    };
    let preview = message.replying_to_preview.unwrap();
    assert_eq!(preview.message_text.as_deref(), Some("Hello"));
    assert!(preview.raw_event_message_key.is_none());
}

#[test]
fn a_reply_with_every_preview_field_set_needs_no_key_for_a_message_key_original() {
    let f = ReplyFixture::new();
    let mut params = crate::EncryptReplyParams::new(CONVERSATION, "a reply", frame(&f.original))
        .with_identity(REPLIER, SIGNING_KEY_VERSION)
        .with_conversation_key(key(8).to_bytes(), "8");
    params.reply_to_text = Some("Hello there".to_string());
    params.reply_to_entities = Some(vec![]);
    params.reply_to_attachments = Some(vec![]);
    let payload = f.replier.core.encrypt_reply(params).unwrap();
    let Contents::Message(message) = decrypt_payload_contents(&payload, &key(8)) else {
        panic!("expected a message");
    };
    assert!(message
        .replying_to_preview
        .unwrap()
        .raw_event_message_key
        .is_none());
}

#[test]
fn a_reply_still_embeds_the_key_changes_it_is_given() {
    let f = ReplyFixture::new();
    let kce = ThriftEvent {
        message_id: Some("kc-1".to_string()),
        sender_id: Some(AUTHOR.to_string()),
        conversation_id: Some(CONVERSATION.to_string()),
        detail: Some(Detail::ConversationKeyChangeEvent(
            ConversationKeyChangeEvent {
                conversation_key_version: Some("6".to_string()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let mut params = crate::EncryptReplyParams::new(CONVERSATION, "a reply", frame(&f.original))
        .with_identity(REPLIER, SIGNING_KEY_VERSION)
        .with_conversation_key(f.ckey.to_bytes(), "7");
    params.reply_to_ckces = Some(vec![frame(&kce)]);
    let payload = f.replier.core.encrypt_reply(params).unwrap();
    let Contents::Message(message) = decrypt_payload_contents(&payload, &f.ckey) else {
        panic!("expected a message");
    };
    assert_eq!(
        message
            .replying_to_preview
            .unwrap()
            .raw_event_ckces
            .map(|c| c.len()),
        Some(1)
    );
}

#[test]
fn an_edit_names_the_message_it_edits() {
    let f = ReplyFixture::new();
    let params = crate::EncryptEditParams::new(frame(&f.original), "Second draft")
        .with_identity(AUTHOR, SIGNING_KEY_VERSION)
        .with_conversation_key(f.ckey.to_bytes(), "7");
    let payload = f.author.core.encrypt_edit(&params).unwrap();
    let Contents::MessageEdit(edit) = decrypt_payload_contents(&payload, &f.ckey) else {
        panic!("expected an edit");
    };
    assert_eq!(edit.message_id.as_deref(), Some("orig-1"));
    assert_eq!(edit.message_sequence_id.as_deref(), Some("200"));
}

#[test]
fn an_edit_with_explicit_target_fields_ignores_an_unreadable_target_event() {
    let f = ReplyFixture::new();
    let mut params = crate::EncryptEditParams::new("!!!not-an-event!!!", "Second draft")
        .with_identity(AUTHOR, SIGNING_KEY_VERSION)
        .with_conversation_key(f.ckey.to_bytes(), "7");
    params.conversation_id = Some(CONVERSATION.to_string());
    params.target_message_sequence_id = Some("200".to_string());
    let payload = f.author.core.encrypt_edit(&params).unwrap();
    let Contents::MessageEdit(edit) = decrypt_payload_contents(&payload, &f.ckey) else {
        panic!("expected an edit");
    };
    assert!(edit.message_id.is_none());
}
