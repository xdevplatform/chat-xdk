//! Replies and reactions: round trips, targets taken from the original
//! event, and reply-preview validation.

use super::*;

#[test]
fn encrypt_reply_signature_verifies_on_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let mut reply_params = crate::EncryptReplyParams::new("conv-1", "a reply", "")
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    reply_params.reply_to_sequence_id = Some("seq-99".into());
    let payload = core.encrypt_reply(&reply_params).unwrap();
    let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert!(msg.verified, "self-signed reply must verify");
            assert_eq!(msg.text(), Some("a reply"));
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn encrypt_add_reaction_signature_verifies_on_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let mut params = crate::EncryptReactionParams::new("", "thumbs")
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.conversation_id = Some("conv-1".into());
    params.target_message_sequence_id = Some("seq-42".into());
    let payload = core.encrypt_add_reaction(&params).unwrap();
    let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert!(msg.verified, "self-signed reaction must verify");
            match &msg.content {
                MessageContent::Reaction {
                    emoji,
                    target_message_sequence_id,
                } => {
                    assert_eq!(emoji, "thumbs");
                    assert_eq!(target_message_sequence_id, "seq-42");
                }
                other => panic!("expected Reaction, got {:?}", other),
            }
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn encrypt_remove_reaction_signature_verifies_on_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let mut params = crate::EncryptReactionParams::new("", "thumbs")
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.conversation_id = Some("conv-1".into());
    params.target_message_sequence_id = Some("seq-42".into());
    let payload = core.encrypt_remove_reaction(&params).unwrap();
    let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert!(msg.verified, "self-signed reaction-remove must verify");
            match &msg.content {
                MessageContent::ReactionRemoved {
                    emoji,
                    target_message_sequence_id,
                } => {
                    assert_eq!(emoji, "thumbs");
                    assert_eq!(target_message_sequence_id, "seq-42");
                }
                other => panic!("expected ReactionRemoved, got {:?}", other),
            }
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

// Event-based replies and reactions + reply-preview validation

/// Two-party setup: returns (receiver core, sender identities) where both
/// senders' signing keys are known to the receiver.
fn reply_test_setup() -> (ChatCore, XChatConversationKey, Vec<SigningKeyEntry>) {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    // Both participants sign with the same test keypair; only the
    // user ids differ, which is what key selection filters on.
    let signing_keys = vec![
        signing_key_entry_for(&reg, "4001"),
        signing_key_entry_for(&reg, "4002"),
    ];
    (core, ckey, signing_keys)
}

fn original_event_b64(core: &ChatCore, ckey: &XChatConversationKey, text: &str) -> String {
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", text)
                .with_identity("4002", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    wrap_signed_payload_with_seq(&payload, "4002", "conv-1", "seq-orig")
}

fn decrypt_reply(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    reply_payload: &SendPayload,
    signing_keys: &[SigningKeyEntry],
) -> Message {
    let reply_b64 = wrap_signed_payload_with_seq(reply_payload, "4001", "conv-1", "seq-reply");
    let conv_keys = [("9001".to_string(), ckey.clone())].into_iter().collect();
    match core
        .decrypt_event_with(&reply_b64, &conv_keys, signing_keys)
        .unwrap()
    {
        Event::Message(msg) => *msg,
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn encrypt_reply_derives_preview_from_raw_event_and_validates() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "original words");

    let reply_payload = core
        .encrypt_reply(
            &crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(msg.text(), Some("the reply"));
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
    match &msg.content {
        MessageContent::Text {
            replying_to_preview: Some(preview),
            ..
        } => {
            assert_eq!(preview.message_text.as_deref(), Some("original words"));
            assert_eq!(
                preview.replying_to_message_sequence_id.as_deref(),
                Some("seq-orig")
            );
        }
        other => panic!("expected Text with preview, got {:?}", other),
    }
}

#[test]
fn forged_preview_text_is_marked_invalid() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "what was actually said");

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_text = Some("words never sent".into());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn forged_preview_sender_is_marked_invalid() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "hello");

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_sender_id = Some("424242".to_string());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn tampered_raw_event_signature_is_marked_invalid() {
    let (core, ckey, signing_keys) = reply_test_setup();

    // Corrupt the original's signature before embedding it: the sender
    // path never verifies it, the receiver must.
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "genuine text")
                .with_identity("4002", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    let mut tampered = payload.clone();
    let mut sig = base64_decode_or_empty(&tampered.signature);
    sig[0] ^= 0x01;
    tampered.signature = STANDARD_NO_PAD.encode(&sig);
    let orig_b64 = wrap_signed_payload_with_seq(&tampered, "4002", "conv-1", "seq-orig");

    let reply_payload = core
        .encrypt_reply(
            &crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Invalid)
    );
}

/// How a reply quoting `original` with each preview text in `previews`
/// validates.
fn preview_text_validations(original: &str, previews: &[&str]) -> Vec<ReplyPreviewValidation> {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, original);
    previews
        .iter()
        .map(|preview| {
            let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", &*orig_b64)
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001");
            params.reply_to_text = Some(preview.to_string());
            let reply_payload = core.encrypt_reply(&params).unwrap();
            decrypt_reply(&core, &ckey, &reply_payload, &signing_keys)
                .reply_preview_validation
                .unwrap()
        })
        .collect()
}

#[test]
fn a_preview_quotes_the_first_140_characters_exactly() {
    let original = format!("{} and more", "word ".repeat(30));
    let first_140: String = original.chars().take(140).collect();
    assert_eq!(
        preview_text_validations(
            &original,
            &[&original, &first_140, &first_140[..139], "word word"]
        ),
        [
            ReplyPreviewValidation::Valid,
            ReplyPreviewValidation::Valid,
            ReplyPreviewValidation::Invalid,
            ReplyPreviewValidation::Invalid,
        ]
    );
    // A short message is quoted whole.
    assert_eq!(
        preview_text_validations("I will not", &["I will not", "I will"]),
        [
            ReplyPreviewValidation::Valid,
            ReplyPreviewValidation::Invalid
        ]
    );
}

#[test]
fn preview_characters_are_counted_in_utf16_code_units() {
    // The emoji's two code units straddle the limit: the 140th is its first
    // half, so only that half is compared.
    let start = "a".repeat(139);
    let original = format!("{start}\u{1F600} and more");
    assert_eq!(
        preview_text_validations(
            &original,
            &[
                &format!("{start}\u{1F600}"),
                &format!("{start}\u{1F603}"),
                &start,
                &format!("{start}b"),
            ]
        ),
        [
            ReplyPreviewValidation::Valid,
            ReplyPreviewValidation::Valid,
            ReplyPreviewValidation::Invalid,
            ReplyPreviewValidation::Invalid,
        ]
    );
}

#[test]
fn text_override_still_derives_entities_from_the_original() {
    let (core, ckey, signing_keys) = reply_test_setup();

    let original = format!("#topic {}", "word ".repeat(40));
    let mut orig_params = crate::EncryptMessageParams::new("conv-1", &*original)
        .with_identity("4002", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    orig_params.entities = Some(vec![crate::EntityDescriptor::new(0, 6, "hashtag")]);
    let orig_payload = core.encrypt_message(&orig_params).unwrap();
    let orig_b64 = wrap_signed_payload_with_seq(&orig_payload, "4002", "conv-1", "seq-orig");

    // A text override must not suppress deriving the remaining preview
    // fields from the decrypted original.
    let first_140: String = original.chars().take(140).collect();
    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_text = Some(first_140.clone());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
    match &msg.content {
        MessageContent::Text {
            replying_to_preview: Some(preview),
            ..
        } => {
            assert_eq!(preview.message_text.as_deref(), Some(first_140.as_str()));
            let entities = preview.entities.as_ref().expect("derived entities");
            assert_eq!(entities.len(), 1);
        }
        other => panic!("expected Text with preview, got {:?}", other),
    }
}

#[test]
fn a_preview_carries_the_quoted_entities_exactly() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let text = "#topic and @someone";
    let quoted = vec![
        crate::EntityDescriptor::new(0, 6, "hashtag"),
        crate::EntityDescriptor::new(11, 19, "mention"),
    ];
    let mut orig_params = crate::EncryptMessageParams::new("conv-1", text)
        .with_identity("4002", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    orig_params.entities = Some(quoted.clone());
    let orig_payload = core.encrypt_message(&orig_params).unwrap();
    let orig_b64 = wrap_signed_payload_with_seq(&orig_payload, "4002", "conv-1", "seq-orig");
    let plain_b64 = original_event_b64(&core, &ckey, text);

    let validate = |original: &str, entities: Option<Vec<crate::EntityDescriptor>>| {
        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", original)
            .with_identity("4001", "61")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_entities = entities;
        let reply_payload = core.encrypt_reply(&params).unwrap();
        decrypt_reply(&core, &ckey, &reply_payload, &signing_keys).reply_preview_validation
    };
    let valid = Some(ReplyPreviewValidation::Valid);
    let invalid = Some(ReplyPreviewValidation::Invalid);
    assert_eq!(validate(&orig_b64, None), valid, "derived");
    assert_eq!(validate(&orig_b64, Some(quoted.clone())), valid, "the same");
    assert_eq!(
        validate(&orig_b64, Some(quoted[..1].to_vec())),
        invalid,
        "a subset"
    );
    assert_eq!(validate(&orig_b64, Some(vec![])), invalid, "none of them");
    assert_eq!(
        validate(&plain_b64, None),
        valid,
        "a message without entities"
    );
    assert_eq!(
        validate(&plain_b64, Some(vec![])),
        invalid,
        "an empty list where the message carries none"
    );
}

#[test]
fn a_preview_without_text_quotes_only_a_message_without_text() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let quote = |original: &str| {
        let orig_b64 = original_event_b64(&core, &ckey, original);
        let raw = ChatCore::parse_event_b64(&orig_b64).unwrap();
        let preview = crate::thrift::product::ReplyingToPreview {
            sender_id: Some(4002),
            replying_to_message_sequence_id: raw.sequence_id.clone(),
            replying_to_message_id: raw.message_id.clone(),
            raw_event_message_create: Some(raw),
            ..Default::default()
        };
        let content = crate::pipeline::build_message_content_with_preview(
            "the reply",
            preview,
            None,
            None,
            None,
        )
        .unwrap();
        let signing = core.get_signing_keypair_arc().unwrap();
        let payload =
            crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
                &ckey,
                &signing.private,
                "reply-1",
                "4001",
                "conv-1",
                &content,
                "9001",
                "61",
            ))
            .unwrap();
        decrypt_reply(&core, &ckey, &payload, &signing_keys).reply_preview_validation
    };
    assert_eq!(quote("words"), Some(ReplyPreviewValidation::Invalid));
    assert_eq!(quote(""), Some(ReplyPreviewValidation::Valid));
}

#[test]
fn preview_without_raw_event_passes_through_unvalidated() {
    let (core, ckey, signing_keys) = reply_test_setup();

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", "")
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_sequence_id = Some("seq-orig".into());
    params.reply_to_text = Some("whatever".into());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(msg.reply_preview_validation, None);
}

/// Build a signed, encrypted edit event for `original_seq`, framed as the
/// backend delivers it.
fn edit_event_b64(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    sender: &str,
    original_b64: &str,
    updated_text: &str,
    edit_seq: &str,
) -> String {
    let original = ChatCore::parse_event_b64(original_b64).unwrap();
    let edit = crate::thrift::product::MessageEdit::new(
        original.sequence_id,
        Some(updated_text.to_string()),
        None,
        original.message_id,
    );
    let holder = crate::thrift::product::MessageEntryHolder::new(Some(Box::new(
        crate::thrift::product::MessageEntryContents::MessageEdit(Box::new(edit)),
    )));
    let content_bytes = serialize_thrift(&holder).unwrap();
    let signing = core.get_signing_keypair_arc().unwrap();
    let message_id = ChatCore::generate_message_id();
    let payload = crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
        ckey,
        &signing.private,
        &message_id,
        sender,
        "conv-1",
        &content_bytes,
        "9001",
        "61",
    ))
    .unwrap();
    wrap_signed_payload_with_seq(&payload, sender, "conv-1", edit_seq)
}

#[test]
fn reply_to_edited_original_derives_and_validates_the_edited_text() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
    let edit_b64 = edit_event_b64(
        &core,
        &ckey,
        "4002",
        &orig_b64,
        "the new wording",
        "seq-edit",
    );

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_edit_event = Some(edit_b64);
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
    match &msg.content {
        MessageContent::Text {
            replying_to_preview: Some(preview),
            ..
        } => {
            // The preview quotes what the message says after the edit.
            assert_eq!(preview.message_text.as_deref(), Some("the new wording"));
        }
        other => panic!("expected Text with preview, got {:?}", other),
    }
}

#[test]
fn preview_claiming_pre_edit_text_is_marked_invalid() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
    let edit_b64 = edit_event_b64(
        &core,
        &ckey,
        "4002",
        &orig_b64,
        "the new wording",
        "seq-edit",
    );

    // A preview that embeds the edit but quotes the pre-edit text is
    // misattributing the message's current contents.
    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_edit_event = Some(edit_b64);
    params.reply_to_text = Some("the first wording".into());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn edit_by_a_different_sender_is_marked_invalid() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
    // Same signing key, different claimed author than the original.
    let edit_b64 = edit_event_b64(
        &core,
        &ckey,
        "4001",
        &orig_b64,
        "the new wording",
        "seq-edit",
    );

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_edit_event = Some(edit_b64);
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Invalid)
    );
}

#[test]
fn encrypt_reaction_derives_target_from_event() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "react to me");

    let params = crate::EncryptReactionParams::new(orig_b64, "👍")
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    let payload = core.encrypt_add_reaction(&params).unwrap();

    let react_b64 = wrap_signed_payload_with_seq(&payload, "4001", "conv-1", "seq-react");
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    match core
        .decrypt_event_with(&react_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => match &msg.content {
            MessageContent::Reaction {
                emoji,
                target_message_sequence_id,
            } => {
                assert_eq!(emoji, "👍");
                assert_eq!(target_message_sequence_id, "seq-orig");
            }
            other => panic!("expected Reaction, got {:?}", other),
        },
        other => panic!("expected Message, got {:?}", other),
    }
}
