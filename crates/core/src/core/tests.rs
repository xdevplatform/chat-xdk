use super::*;
use crate::pipeline::serialize_thrift;
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{
    ClearConversationOptions, ConversationDeleteEvent as ThriftConvDel,
    ConversationKeyChangeEvent as ThriftCKCE, ConversationMetadataChange,
    ConversationMetadataChangeEvent as ThriftCMCE, ConversationParticipantKey, DeleteMessageAction,
    DisableScreenCaptureBlocking, DisableScreenCaptureDetection, EnableScreenCaptureBlocking,
    EnableScreenCaptureDetection, FailureType as ThriftFailureType,
    GrokSearchResponseEvent as ThriftGSRE, GroupAdminAddChange, GroupAdminRemoveChange,
    GroupAvatarUrlChange, GroupChangeEvent as ThriftGCE, GroupCreate, GroupInviteDisable,
    GroupInviteEnable, GroupJoinReject, GroupJoinRequest, GroupMemberAddChange,
    GroupMemberRemoveChange, GroupTitleChange, MarkConversationReadEvent as ThriftMCRE,
    MarkConversationUnreadEvent as ThriftMCUE, MemberAccountDeleteEvent as ThriftMADE,
    MessageCreateEvent as ThriftMCE, MessageDeleteEvent as ThriftMDE, MessageDurationChange,
    MessageDurationRemove, MessageEvent as ThriftMessageEvent, MessageEventDetail as ThriftDetail,
    MessageFailureEvent as ThriftMFE, MessageTypingEvent as ThriftMTE, MuteConversation,
    RateLimitTier as ThriftRateLimitTier, UnmuteConversation,
};

/// Build a base64-encoded MessageEvent wrapping a MessageCreateEvent.
///
/// When `conversation_key_version` is `None` the MCE is unencrypted and
/// `content_bytes` should be raw (plaintext) Thrift `MessageEntryHolder`.
/// When it is `Some`, `content_bytes` should be ciphertext produced by
/// `encrypt_message()`.
fn build_test_message_event(
    content_bytes: &[u8],
    conversation_key_version: Option<&str>,
) -> String {
    let mce = ThriftMCE::new(
        Some(content_bytes.to_vec()),
        conversation_key_version.map(|s| s.to_string()),
        Some(true),   // should_notify
        None::<i64>,  // ttl_msec
        None::<i64>,  // delivered_at_msec
        None::<bool>, // is_pending_public_key
        None::<crate::thrift::event::EventQueuePriority>,
        None::<Vec<crate::thrift::event::AdditionalAction>>,
        None,
        None,
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),         // sequence_id
        Some("msg-1".to_string()),         // message_id
        Some("910003".to_string()),        // sender_id
        Some("conv-1".to_string()),        // conversation_id
        None::<String>,                    // conversation_token
        Some("1700000000000".to_string()), // created_at_msec
        Some(ThriftDetail::MessageCreateEvent(mce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>, // previous_sequence_id
        None::<bool>,   // is_trusted
        None::<String>, // conversation_event_counter
    );
    let bytes = serialize_thrift(&event).expect("serialize MessageEvent");
    base64_encode(&bytes)
}

/// Build plaintext Thrift content bytes for a simple text message.
fn build_plaintext_content(text: &str) -> Vec<u8> {
    crate::pipeline::build_message_content(text, None, None, None).expect("build_message_content")
}

/// A message signed by encrypt_message must verify against the sender's
/// signing key via decrypt_event. Catches send/verify payload or
/// signature-version mismatches.
#[test]
fn encrypt_message_signature_verifies_on_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello v7")
                .with_identity("4001", "1733889755256")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();

    // The SendPayload.encoded_message_create_event is the MCE; wrap it in a full
    // MessageEvent with the embedded signature, like the backend does.
    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let mce = parse_message_event(&mce_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            // encoded_message_create_event is just the MCE struct, not a MessageEvent.
            let cursor = Cursor::new(mce_bytes.clone());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .ok()
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        })
        .expect("parse MCE");

    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some(payload.message_id.clone()),
        Some("4001".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "1733889755256",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert!(msg.verified, "self-signed v7 message must verify");
            assert_eq!(msg.text(), Some("hello v7"));
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

/// An edit produced by `encrypt_edit` must decrypt and verify like any
/// other message, surfacing the target sequence id, replacement text, and
/// entities. Catches producer/consumer divergence on the edit wire shape.
#[test]
fn encrypt_edit_round_trips_through_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let mut params = crate::EncryptEditParams::new("", "read https://example.com")
        .with_identity("4001", "1733889755256")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.conversation_id = Some("conv-1".into());
    params.target_message_sequence_id = Some("seq-orig".into());
    params.entities = Some(vec![crate::types::EntityDescriptor::new(5, 24, "url")]);
    let payload = core.encrypt_edit(&params).unwrap();

    let event_b64 = wrap_signed_payload_with_seq(&payload, "4001", "conv-1", "seq-edit");
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "1733889755256",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert!(msg.verified, "self-signed edit must verify");
            match msg.content {
                MessageContent::Edit {
                    target_message_sequence_id,
                    target_message_id,
                    updated_text,
                    entities,
                } => {
                    assert_eq!(target_message_sequence_id, "seq-orig");
                    // A v0 edit names its target by sequence id only.
                    assert_eq!(target_message_id, None);
                    assert_eq!(updated_text, "read https://example.com");
                    let entities = entities.expect("entities survive the round trip");
                    assert_eq!(entities.len(), 1);
                    assert_eq!(entities[0].start_index, Some(5));
                    assert_eq!(entities[0].end_index, Some(24));
                }
                other => panic!("expected Edit content, got {:?}", other),
            }
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

fn sample_quick_reply_request() -> QuickReply {
    QuickReply::Request {
        request: QuickReplyRequest::Options {
            options: QuickReplyOptionsRequest {
                id: Some("qr-1".into()),
                options: Some(vec![
                    QuickReplyOption {
                        id: Some("yes".into()),
                        label: Some("Yes".into()),
                        metadata: Some("m-yes".into()),
                        description: Some("Confirm".into()),
                    },
                    QuickReplyOption {
                        id: Some("no".into()),
                        label: Some("No".into()),
                        metadata: None,
                        description: None,
                    },
                ]),
            },
        },
    }
}

fn sample_quick_reply_response() -> QuickReply {
    QuickReply::Response {
        response: QuickReplyResponse::Options {
            options: QuickReplyOptionsResponse {
                request_id: Some("qr-1".into()),
                metadata: Some("m-yes".into()),
                selected_option_id: Some("yes".into()),
            },
        },
    }
}

/// Encrypt with the given quick reply (or none), decrypt, and return the
/// decrypted text content's quick reply.
fn quick_reply_round_trip(quick_reply: Option<QuickReply>, reply: bool) -> Option<QuickReply> {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let payload = if reply {
        let mut params = crate::EncryptReplyParams::new("conv-1", "Yes", "")
            .with_identity("4001", "1733889755256")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_sequence_id = Some("seq-orig".into());
        params.reply_to_sender_id = Some("42".to_string());
        params.reply_to_text = Some("Continue?".into());
        params.quick_reply = quick_reply;
        core.encrypt_reply(&params).unwrap()
    } else {
        let mut params = crate::EncryptMessageParams::new("conv-1", "Continue?")
            .with_identity("4001", "1733889755256")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.quick_reply = quick_reply;
        core.encrypt_message(&params).unwrap()
    };

    let event_b64 = wrap_signed_payload_with_seq(&payload, "4001", "conv-1", "seq-qr");
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "1733889755256",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    match core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => {
            assert!(msg.verified);
            match msg.content {
                MessageContent::Text { quick_reply, .. } => quick_reply,
                other => panic!("expected Text content, got {:?}", other),
            }
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn encrypt_message_quick_reply_request_round_trips_through_decrypt() {
    let sent = sample_quick_reply_request();
    assert_eq!(
        quick_reply_round_trip(Some(sent.clone()), false),
        Some(sent)
    );
}

#[test]
fn encrypt_message_quick_reply_response_round_trips_through_decrypt() {
    let sent = sample_quick_reply_response();
    assert_eq!(
        quick_reply_round_trip(Some(sent.clone()), false),
        Some(sent)
    );
}

#[test]
fn encrypt_reply_quick_reply_round_trips_through_decrypt() {
    let sent = sample_quick_reply_response();
    assert_eq!(quick_reply_round_trip(Some(sent.clone()), true), Some(sent));
}

#[test]
fn encrypt_without_quick_reply_decrypts_without_one() {
    assert_eq!(quick_reply_round_trip(None, false), None);
    assert_eq!(quick_reply_round_trip(None, true), None);
}

#[test]
fn quick_reply_json_round_trips_in_the_shape_bindings_send() {
    for sent in [sample_quick_reply_request(), sample_quick_reply_response()] {
        let json = serde_json::to_value(&sent).unwrap();
        let parsed: QuickReply = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, sent);
    }
    let parsed: QuickReply = serde_json::from_str(
        r#"{"response":{"options":{"request_id":"qr-1","selected_option_id":"yes"}}}"#,
    )
    .unwrap();
    assert_eq!(
        parsed,
        QuickReply::Response {
            response: QuickReplyResponse::Options {
                options: QuickReplyOptionsResponse {
                    request_id: Some("qr-1".into()),
                    metadata: None,
                    selected_option_id: Some("yes".into()),
                },
            },
        }
    );
}

#[test]
fn quick_reply_json_rejects_both_request_and_response() {
    let both =
        r#"{"request":{"options":{"id":"qr-1"}},"response":{"options":{"request_id":"qr-1"}}}"#;
    assert!(serde_json::from_str::<QuickReply>(both).is_err());
    assert!(serde_json::from_str::<QuickReply>("{}").is_err());
}

/// The SDK mints the message id: for a message without files,
/// `encrypt_message` returns a fresh UUID in `SendPayload.message_id` on
/// every call, and callers cannot supply one. (That the returned id is the
/// one actually signed is proven by the verify-on-decrypt tests, which
/// embed `payload.message_id` in the event.)
#[test]
fn encrypt_message_generates_a_unique_uuid_message_id() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let encrypt = || {
        core.encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap()
        .message_id
    };

    let first = encrypt();
    let second = encrypt();
    assert!(
        uuid::Uuid::parse_str(&first).is_ok(),
        "message id must be a UUID, got {first:?}"
    );
    assert_ne!(first, second, "each call must mint a distinct message id");
}

/// A URL card attachment with encrypted banner/favicon images survives an
/// encrypt → decrypt round trip: the receive side must surface the image
/// hashes both on the parsed attachment and in `media_hashes` (so callers
/// can download and decrypt the blobs).
#[test]
fn url_card_with_banner_round_trips_through_encrypt_decrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "1733889755256"))
        .unwrap();
    let mut params = crate::EncryptMessageParams::new("conv-1", "Check this out")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.attachments = Some(vec![crate::AttachmentDescriptor::Url {
        url: "https://example.com/product".to_string(),
        display_title: Some("Example Product".to_string()),
        banner_image: Some(crate::types::UrlAttachmentImageDescriptor {
            media_hash_key: "banner-hash".to_string(),
            filesize_bytes: 24_000,
            filename: "banner.jpg".to_string(),
            width: Some(1200),
            height: Some(630),
        }),
        favicon_image: Some(crate::types::UrlAttachmentImageDescriptor {
            media_hash_key: "favicon-hash".to_string(),
            filesize_bytes: 1_200,
            filename: "favicon.ico".to_string(),
            width: None,
            height: None,
        }),
    }]);
    let payload = core.encrypt_message(&params).unwrap();

    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let cursor = Cursor::new(mce_bytes);
    let mut raw = TBinaryInputProtocol::new(cursor, true);
    let mut p = BoundedProtocol::new(&mut raw);
    let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
        .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        .expect("parse MCE");

    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some(payload.message_id.clone()),
        Some("4001".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [SigningKeyEntry::new(
        "4001",
        "1733889755256",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    let event = core
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap();
    let Event::Message(msg) = event else {
        panic!("expected Message");
    };
    assert!(msg.verified);
    assert_eq!(msg.text(), Some("Check this out"));

    // The flattened attachment info carries both image hashes.
    let AttachmentInfo::Url(info) = &msg.attachments[0] else {
        panic!("expected Url attachment info, got {:?}", msg.attachments);
    };
    assert_eq!(info.url.as_deref(), Some("https://example.com/product"));
    assert_eq!(info.display_title.as_deref(), Some("Example Product"));
    assert_eq!(
        info.banner_image_media_hash_key.as_deref(),
        Some("banner-hash")
    );
    assert_eq!(
        info.favicon_image_media_hash_key.as_deref(),
        Some("favicon-hash")
    );

    // media_hashes lists both blobs for download + decrypt_file.
    let hashes: Vec<(&str, &str)> = msg
        .media_hashes
        .iter()
        .map(|h| (h.source.as_str(), h.media_hash_key.as_str()))
        .collect();
    assert!(hashes.contains(&("url_banner", "banner-hash")));
    assert!(hashes.contains(&("url_favicon", "favicon-hash")));

    // The full-fidelity content attachment keeps the image metadata.
    let MessageContent::Text { attachments, .. } = &msg.content else {
        panic!("expected Text content");
    };
    let Some(MessageAttachment::Url { url }) = attachments.as_deref().map(|a| &a[0]) else {
        panic!("expected Url attachment in content");
    };
    let banner = url.banner_image_media_hash_key.as_ref().expect("banner");
    assert_eq!(banner.media_hash_key.as_deref(), Some("banner-hash"));
    assert_eq!(banner.filesize_bytes, Some(24_000));
    assert_eq!(banner.filename.as_deref(), Some("banner.jpg"));
    let dims = banner.dimensions.as_ref().expect("dimensions");
    assert_eq!(dims.width, Some(1200));
    assert_eq!(dims.height, Some(630));
}

/// A signing key must only verify events from its own user. Passing every
/// participant's keys to `decrypt_event` (as callers commonly do) must not
/// let one participant's valid key verify an event claiming another
/// participant as sender.
#[test]
fn decrypt_event_rejects_signature_from_wrong_participant() {
    let attacker = ChatCore::new();
    let attacker_reg = attacker.generate_keypairs().unwrap();
    let victim = ChatCore::new();
    let victim_reg = victim.generate_keypairs().unwrap();

    // Attacker signs a message that claims the victim as sender.
    let ckey = attacker.generate_conversation_key().unwrap();
    let payload = attacker
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "forged")
                .with_identity("4003", "62")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();

    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let cursor = Cursor::new(mce_bytes);
    let mut raw = TBinaryInputProtocol::new(cursor, true);
    let mut p = BoundedProtocol::new(&mut raw);
    let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
        .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        .expect("parse MCE");

    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some(payload.message_id.clone()),
        Some("4003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();

    // Batch-style key list: one entry per participant. The attacker's own
    // entry carries the version the forged signature names, so selecting
    // by version alone would wrongly verify this event.
    let signing_keys = [
        SigningKeyEntry::new(
            "4003",
            "victim-pkv",
            &victim_reg.public_key.signing_public_key,
            &victim_reg.public_key.public_key,
            &victim_reg.public_key.identity_public_key_signature,
        ),
        SigningKeyEntry::new(
            "4004",
            "62",
            &attacker_reg.public_key.signing_public_key,
            &attacker_reg.public_key.public_key,
            &attacker_reg.public_key.identity_public_key_signature,
        ),
    ];

    let err = attacker
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .expect_err("forged sender must not verify");
    assert!(
        err.to_string().contains("could not be verified"),
        "expected unverifiable-signature rejection, got: {}",
        err
    );

    // Relaxed policy still must not report the forgery as verified.
    let lenient = ChatCore::new();
    lenient.set_reject_unverified(false);
    match lenient
        .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => assert!(!msg.verified, "forged sender must not verify"),
        other => panic!("expected Message, got {:?}", other),
    }
}

/// Whatever conversation-id form the caller signs with — bare recipient
/// id, hyphen pair in either order, or the colon form — the signature must
/// verify against the canonical id the backend embeds in fanned-out events.
#[test]
fn encrypt_message_verifies_from_any_conversation_id_form() {
    let sender = "1843439638876491776";
    let recipient = "1215441834412953600";
    let canonical = "1215441834412953600:1843439638876491776";
    let input_forms = [
        recipient,
        "1215441834412953600-1843439638876491776",
        "1843439638876491776-1215441834412953600",
        canonical,
    ];

    for form in input_forms {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();
        let payload = core
            .encrypt_message(
                &crate::EncryptMessageParams::new(form, "any form")
                    .with_identity(sender, "1733889755256")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();

        let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
        let cursor = Cursor::new(mce_bytes);
        let mut raw = TBinaryInputProtocol::new(cursor, true);
        let mut p = BoundedProtocol::new(&mut raw);
        let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
            .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            .expect("parse MCE");

        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some(payload.message_id.clone()),
            Some(sender.to_string()),
            Some(canonical.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
            None,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry::new(
            sender,
            "1733889755256",
            &reg.public_key.signing_public_key,
            &reg.public_key.public_key,
            &reg.public_key.identity_public_key_signature,
        )];

        let event = core
            .decrypt_event_with(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(
                    msg.verified,
                    "form {form:?} must verify against {canonical}"
                );
            }
            other => panic!("expected Message for form {form:?}, got {other:?}"),
        }
    }
}

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

// Unencrypted MCE tests

#[test]
fn decrypt_event_unencrypted_mce_with_none_key_returns_message() {
    let core = ChatCore::new();
    // generate_keypairs loads keys into the manager so verify works
    core.generate_keypairs().unwrap();
    // Unencrypted messages have no signature; allow them through.
    core.set_reject_unverified(false);

    let content = build_plaintext_content("Hello unencrypted!");
    let event_b64 = build_test_message_event(&content, None);

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Hello unencrypted!"));
            assert!(
                msg.conversation_key_version.is_none(),
                "conversation_key_version should be None"
            );
            assert!(!msg.verified, "verified should be false");
            assert_eq!(msg.should_notify, Some(true));
            assert_eq!(msg.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_unencrypted_mce_with_key_still_works() {
    // Even if the caller passes a conversation key, the SDK should
    // recognise the MCE is unencrypted and skip decryption.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(false);

    let content = build_plaintext_content("Plaintext with key present");
    let event_b64 = build_test_message_event(&content, None);

    // Unencrypted MCE — key map is unused, any map works
    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Plaintext with key present"));
            assert!(msg.conversation_key_version.is_none());
            assert!(!msg.verified);
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_unencrypted_mce_reject_unverified_errors() {
    // Unencrypted MCEs carry no signature, so under reject_unverified
    // (the default) they are unverifiable and must be rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("No sig");
    let event_b64 = build_test_message_event(&content, None);

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "unencrypted message must be rejected under reject_unverified"
    );
}

#[test]
fn decrypt_event_encrypted_mce_without_key_errors() {
    // An encrypted MCE with no signing keys and reject_unverified=true
    // (default) should be rejected at the signature check before
    // reaching the missing-key error.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("will be 'encrypted'");
    let event_b64 = build_test_message_event(&content, Some("3"));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err());

    // With reject_unverified=false, the signature check passes and
    // we get the missing conversation key error instead.
    let core2 = ChatCore::new();
    core2.generate_keypairs().unwrap();
    core2.set_reject_unverified(false);

    let result2 = core2.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result2.is_err());
    let err_msg = format!("{}", result2.unwrap_err());
    assert!(
        err_msg.contains("no matching key found"),
        "Error should mention missing key, got: {}",
        err_msg
    );
}

#[test]
fn decrypt_event_unencrypted_mce_empty_content_returns_unknown() {
    // An MCE with no contents at all (None) should return Unknown,
    // regardless of encryption status.
    let mce = ThriftMCE::new(
        None::<Vec<u8>>, // no contents
        None::<String>,  // no key version
        Some(true),
        None::<i64>,
        None::<i64>,
        None::<bool>,
        None::<crate::thrift::event::EventQueuePriority>,
        None::<Vec<crate::thrift::event::AdditionalAction>>,
        None,
        None,
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::MessageCreateEvent(mce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).unwrap();
    let event_b64 = base64_encode(&bytes);

    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    assert!(
        matches!(result, Event::Unknown(_)),
        "MCE with no contents should return Unknown"
    );
}

#[test]
fn decrypt_event_unencrypted_mce_preserves_metadata() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(false);

    let content = build_plaintext_content("metadata check");
    let event_b64 = build_test_message_event(&content, None);

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert_eq!(msg.meta.sequence_id.as_deref(), Some("seq-1"));
            assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
            assert_eq!(msg.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(msg.meta.created_at_msec, Some(1700000000000));
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_encrypted_mce_roundtrip() {
    // Verify the normal encrypted path still works end-to-end.
    // Disable reject_unverified since we don't supply signing keys.
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let plaintext = build_plaintext_content("Encrypted roundtrip");

    // Encrypt the content the same way the pipeline does.
    let encrypted = crate::crypto::encryption::encrypt_message(&ckey, &plaintext).unwrap();
    let event_b64 = build_test_message_event(&encrypted, Some("42"));

    let event = core
        .decrypt_event_with(
            &event_b64,
            &[("42".to_string(), ckey.clone())].into_iter().collect(),
            &[],
        )
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Encrypted roundtrip"));
            assert_eq!(msg.conversation_key_version.as_deref(), Some("42"));
            // No trusted signing key provided → verified is false
            assert!(!msg.verified);
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

// Signature passthrough tests — events with missing fields should not
// be blocked by reject_unverified

/// Build a base64-encoded MessageEvent wrapping an arbitrary detail.
fn build_test_event(detail: ThriftDetail) -> String {
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(detail),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).expect("serialize");
    base64_encode(&bytes)
}

#[test]
fn reject_unverified_rejects_group_title_change_without_signing_keys() {
    // GroupTitleChange with no signing keys — reject_unverified=true
    // must reject it (not silently pass it through).
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupTitleChange(
            GroupTitleChange::new(
                Some(encrypted_metadata(&key, "New Title")),
                Some("7".to_string()),
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));
    let keys = HashMap::from([("7".to_string(), key)]);

    let result = core.decrypt_event_with(&event_b64, &keys, &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");

    // With reject_unverified=false it passes through with verified=false.
    core.set_reject_unverified(false);
    let event = core.decrypt_event_with(&event_b64, &keys, &[]).unwrap();
    match event {
        Event::GroupChange(gc) => {
            assert!(!gc.verified);
            assert!(
                matches!(gc.change, GroupChange::TitleChanged { ref new_title } if *new_title == text("New Title"))
            );
        }
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn reject_unverified_rejects_group_member_add_without_signing_keys() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberAdd(
            GroupMemberAddChange::new(
                Some(vec!["new-member".to_string()]),
                Some(vec!["member-1".to_string()]),
                Some(vec!["admin-1".to_string()]),
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                None::<Vec<String>>,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");
}

#[test]
fn reject_unverified_rejects_message_delete_without_signing_keys() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let del = ThriftMDE::new(
        Some(vec!["seq-99".to_string()]),
        None::<DeleteMessageAction>,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned MessageDelete");
}

#[test]
fn reject_unverified_rejects_group_change_with_no_inner_change() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(true);

    let gc = ThriftGCE::new(None::<crate::thrift::event::GroupChange>, None);
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err(), "Should reject unsigned GroupChange");
}

/// `generate_keypairs` produces a bidirectional cross-signature.
///
/// - `identity_public_key_signature`: signing key signs identity SPKI
/// - `signing_public_key_signature`:  identity key signs signing SPKI
///
/// Both signatures must verify against the corresponding public key.
#[test]
fn generate_keypairs_produces_bidirectional_cross_signatures() {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use p256::PublicKey;

    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();
    let reg = &payload.public_key;

    // Decode public keys
    let identity_spki_bytes =
        crate::protocol::serialization::base64_decode(&reg.public_key).unwrap();
    let signing_spki_bytes =
        crate::protocol::serialization::base64_decode(&reg.signing_public_key).unwrap();

    let identity_pk =
        PublicKey::from_public_key_der(&identity_spki_bytes).expect("identity SPKI should parse");
    let signing_pk =
        PublicKey::from_public_key_der(&signing_spki_bytes).expect("signing SPKI should parse");

    let identity_vk = VerifyingKey::from(identity_pk);
    let signing_vk = VerifyingKey::from(signing_pk);

    // 1. Verify identity_public_key_signature: signing key signed identity SPKI
    let id_sig_bytes =
        crate::protocol::serialization::base64_decode(&reg.identity_public_key_signature).unwrap();
    let id_sig = Signature::from_slice(&id_sig_bytes)
        .expect("identity_public_key_signature should be valid raw r||s");
    signing_vk
        .verify(&identity_spki_bytes, &id_sig)
        .expect("signing key should verify identity SPKI signature");

    // 2. Verify signing_public_key_signature: identity key signed signing SPKI
    let spk_sig_b64 = reg
        .signing_public_key_signature
        .as_ref()
        .expect("signing_public_key_signature should be Some");
    let spk_sig_bytes = crate::protocol::serialization::base64_decode(spk_sig_b64).unwrap();
    let spk_sig = Signature::from_slice(&spk_sig_bytes)
        .expect("signing_public_key_signature should be valid raw r||s");
    identity_vk
        .verify(&signing_spki_bytes, &spk_sig)
        .expect("identity key should verify signing SPKI signature");
}

/// Base64 ciphertext of `value` under `key`, as a group change carries
/// a title or description.
fn encrypted_metadata(key: &XChatConversationKey, value: &str) -> String {
    base64_encode(&crate::crypto::encryption::encrypt_message(key, value.as_bytes()).unwrap())
}

fn text(value: &str) -> GroupText {
    GroupText::Text {
        text: value.to_string(),
    }
}

#[test]
fn decrypt_reads_the_title_a_title_change_sends() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    for title in ["Board: layoffs, Q3", "Équipe 🚀", "x"] {
        let prepared = core
            .prepare_group_title_change(
                &crate::GroupTitleChangeParams::new("g100", title)
                    .with_identity("910004", "1")
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        assert_ne!(prepared.encrypted_value, title);
        assert_eq!(
            core.decrypt(&prepared.encrypted_value, &key).unwrap(),
            title
        );
    }
}

#[test]
fn decrypt_wrong_key_fails() {
    let core = ChatCore::new();
    let key1 = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let key2 = XChatConversationKey::from_bytes(vec![0x43u8; 32]).unwrap();
    let ciphertext_b64 = encrypted_metadata(&key1, "secret");
    assert!(core.decrypt(&ciphertext_b64, &key2).is_err());
}

#[test]
fn decrypt_event_typing_event() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let typing = ThriftMTE::new(Some("conv-1".to_string()), None, None, None, None);
    let event_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Typing(t) => {
            assert_eq!(t.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(t.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(t.meta.sequence_id.as_deref(), Some("seq-1"));
        }
        other => panic!("Expected Event::Typing, got {:?}", other),
    }
}

#[test]
fn decrypt_event_mark_conversation_read() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let read = ThriftMCRE::new(Some("seq-50".to_string()), Some(1700000050000i64), None);
    let event_b64 = build_test_event(ThriftDetail::MarkConversationReadEvent(read));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ReadReceipt(r) => {
            assert_eq!(r.seen_until_sequence_id.as_deref(), Some("seq-50"));
            assert_eq!(r.seen_at_msec, Some(1700000050000));
            assert!(!r.verified);
            assert_eq!(r.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::ReadReceipt, got {:?}", other),
    }
}

#[test]
fn decrypt_event_mark_conversation_unread() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let unread = ThriftMCUE::new(Some("seq-42".to_string()));
    let event_b64 = build_test_event(ThriftDetail::MarkConversationUnreadEvent(unread));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MarkedUnread(u) => {
            assert_eq!(u.seen_until_sequence_id.as_deref(), Some("seq-42"));
            assert!(!u.verified);
        }
        other => panic!("Expected Event::MarkedUnread, got {:?}", other),
    }
}

#[test]
fn decrypt_event_message_delete_for_self() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let del = ThriftMDE::new(
        Some(vec!["seq-10".to_string(), "seq-11".to_string()]),
        Some(DeleteMessageAction::DELETE_FOR_SELF),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MessageDeleted(md) => {
            assert_eq!(md.sequence_ids, vec!["seq-10", "seq-11"]);
            assert!(!md.delete_for_all);
            assert!(!md.verified);
        }
        other => panic!("Expected Event::MessageDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_message_delete_for_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let del = ThriftMDE::new(
        Some(vec!["seq-20".to_string()]),
        Some(DeleteMessageAction::DELETE_FOR_ALL),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MessageDeleted(md) => {
            assert_eq!(md.sequence_ids, vec!["seq-20"]);
            assert!(md.delete_for_all);
        }
        other => panic!("Expected Event::MessageDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_conversation_delete_with_clear_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let conv_del = ThriftConvDel::new(
        Some("conv-99".to_string()),
        Some(ClearConversationOptions::new(
            Some(true),
            Some(1700000000000i64),
        )),
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ConversationDeleted(cd) => {
            assert!(cd.clear_all_messages);
            assert!(!cd.verified);
        }
        other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_conversation_delete_without_clear_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let conv_del = ThriftConvDel::new(
        Some("conv-100".to_string()),
        None::<ClearConversationOptions>,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ConversationDeleted(cd) => {
            assert!(!cd.clear_all_messages);
        }
        other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_internal_error() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INTERNAL_ERROR),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::InternalError);
            assert_eq!(f.rate_limit_tier, None);
            assert_eq!(f.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_rate_limit_tier() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RATE_LIMIT_UPSELL),
        Some(ThriftRateLimitTier::PREMIUM),
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::RateLimitUpsell);
            assert_eq!(f.rate_limit_tier, Some(RateLimitTier::Premium));
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_contents_too_large() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::CONTENTS_TOO_LARGE),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::ContentsTooLarge);
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_too_many_messages() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::TOO_MANY_MESSAGES),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::TooManyMessages),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_invalid_sender_signature() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INVALID_SENDER_SIGNATURE),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::InvalidSenderSignature),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_non_latest_ckey_version() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::NON_LATEST_CKEY_VERSION),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::NonLatestKeyVersion),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_recipient_not_trusted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientNotTrusted),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_recipient_key_changed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RECIPIENT_KEY_HAS_CHANGED),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientKeyChanged),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_empty_detail() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::EMPTY_DETAIL),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::EmptyDetail),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_none_type_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(None::<ThriftFailureType>, None::<ThriftRateLimitTier>);
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::Unknown),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_member_account_delete() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let member_del = ThriftMADE::new(Some("deleted-user-42".to_string()), None);
    let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MemberDeleted(md) => {
            assert_eq!(md.member_id, "deleted-user-42");
            assert_eq!(md.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::MemberDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_member_account_delete_no_member_id() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let member_del = ThriftMADE::new(None::<String>, None);
    let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MemberDeleted(md) => {
            assert_eq!(md.member_id, ""); // defaults to empty
        }
        other => panic!("Expected Event::MemberDeleted, got {:?}", other),
    }
}

// GroupChange sub-variants

fn group_create_event(title: &str, conversation_key_version: Option<&str>) -> String {
    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupCreate(
            GroupCreate::new(
                Some(vec!["m1".to_string(), "m2".to_string()]),
                Some(vec!["a1".to_string()]),
                Some(title.to_string()),
                Some("https://ton.x.com/xchat_media/g1/avatar".to_string()),
                conversation_key_version.map(str::to_string),
                None::<bool>,
                None::<i64>,
                None,
            ),
        )),
        None,
    );
    build_test_event(ThriftDetail::GroupChangeEvent(gc))
}

fn received_group_change(
    core: &ChatCore,
    event_b64: &str,
    keys: &HashMap<String, XChatConversationKey>,
) -> GroupChange {
    match core.decrypt_event_with(event_b64, keys, &[]).unwrap() {
        Event::GroupChange(gc) => gc.change,
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_group_create() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let encrypted_title = encrypted_metadata(&key, "Test Group");
    let event_b64 = group_create_event(&encrypted_title, Some("1"));
    let created = |keys: &HashMap<String, XChatConversationKey>| match received_group_change(
        &core, &event_b64, keys,
    ) {
        GroupChange::Created {
            member_ids,
            admin_ids,
            title,
            avatar_url,
            conversation_key_version,
        } => (
            member_ids,
            admin_ids,
            title,
            avatar_url,
            conversation_key_version,
        ),
        other => panic!("Expected GroupChange::Created, got {:?}", other),
    };

    // Without the key the create names, the title is unavailable and the
    // rest of the create still reads.
    let (member_ids, admin_ids, title, avatar_url, version) = created(&HashMap::new());
    assert_eq!(member_ids, ["m1", "m2"]);
    assert_eq!(admin_ids, ["a1"]);
    assert_eq!(
        title,
        Some(GroupText::Unavailable {
            raw: encrypted_title
        })
    );
    assert_eq!(
        avatar_url.as_deref(),
        Some("https://ton.x.com/xchat_media/g1/avatar")
    );
    assert_eq!(version.as_deref(), Some("1"));

    let (_, _, title, avatar_url, _) = created(&HashMap::from([("1".to_string(), key)]));
    assert_eq!(title, Some(text("Test Group")));
    assert_eq!(
        avatar_url.as_deref(),
        Some("https://ton.x.com/xchat_media/g1/avatar")
    );
}

#[test]
fn decrypt_event_group_titles_without_ciphertext_read_as_carried() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let keys = HashMap::from([("1".to_string(), key)]);
    let title = |event_b64: &str| match received_group_change(&core, event_b64, &keys) {
        GroupChange::Created { title, .. } => title,
        other => panic!("Expected GroupChange::Created, got {:?}", other),
    };

    // A create that names no key version carries its title as plaintext.
    assert_eq!(
        title(&group_create_event("Plain Group", None)),
        Some(text("Plain Group"))
    );
    // A plaintext title that names a key version, as 0.5.x apps sent it,
    // doesn't decrypt even with the key; the event carries it in `raw`.
    assert_eq!(
        title(&group_create_event("Plain Group", Some("1"))),
        Some(GroupText::Unavailable {
            raw: "Plain Group".to_string()
        })
    );
}

#[test]
fn decrypt_event_group_change_avatar_changed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAvatarChange(
            GroupAvatarUrlChange::new(
                Some("https://ton.x.com/xchat_media/g1/avatar".to_string()),
                Some("2".to_string()),
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    // The URL is not encrypted, so it reads without any conversation key.
    match received_group_change(&core, &event_b64, &HashMap::new()) {
        GroupChange::AvatarChanged {
            new_avatar_url,
            conversation_key_version,
        } => {
            assert_eq!(new_avatar_url, "https://ton.x.com/xchat_media/g1/avatar");
            assert_eq!(conversation_key_version.as_deref(), Some("2"));
        }
        other => panic!("Expected AvatarChanged, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_admins_added() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAdminAdd(
            GroupAdminAddChange::new(Some(vec!["admin-new".to_string()])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::AdminsAdded { ref admin_ids } => {
                assert_eq!(admin_ids, &["admin-new"]);
            }
            other => panic!("Expected AdminsAdded, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_admins_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAdminRemove(
            GroupAdminRemoveChange::new(Some(vec!["admin-old".to_string()])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::AdminsRemoved { ref admin_ids } => {
                assert_eq!(admin_ids, &["admin-old"]);
            }
            other => panic!("Expected AdminsRemoved, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_members_added() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberAdd(
            GroupMemberAddChange::new(
                Some(vec!["new-member".to_string()]),
                Some(vec!["m1".to_string(), "m2".to_string()]),
                Some(vec!["a1".to_string()]),
                Some("Title".to_string()),
                Some("avatar".to_string()),
                Some("v3".to_string()),
                Some(30000i64),
                None::<Vec<String>>,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::MembersAdded {
                ref member_ids,
                ref current_member_ids,
                ref current_admin_ids,
            } => {
                assert_eq!(member_ids, &["new-member"]);
                assert_eq!(current_member_ids, &["m1", "m2"]);
                assert_eq!(current_admin_ids, &["a1"]);
            }
            other => panic!("Expected MembersAdded, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_members_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberRemove(
            GroupMemberRemoveChange::new(Some(vec!["removed-user".to_string()]), None),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::MembersRemoved { ref member_ids } => {
                assert_eq!(member_ids, &["removed-user"]);
            }
            other => panic!("Expected MembersRemoved, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_invite_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupInviteEnable(
            GroupInviteEnable::new(
                Some(1700000100000i64),
                Some("https://invite.link".to_string()),
                None::<String>,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::InviteEnabled {
                ref invite_url,
                expires_at_msec,
            } => {
                assert_eq!(invite_url, "https://invite.link");
                assert_eq!(expires_at_msec, Some(1700000100000));
            }
            other => panic!("Expected InviteEnabled, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_invite_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupInviteDisable(
            GroupInviteDisable::new(Some("admin-1".to_string())),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::InviteDisabled { ref disabled_by } => {
                assert_eq!(disabled_by.as_deref(), Some("admin-1"));
            }
            other => panic!("Expected InviteDisabled, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_join_requested() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupJoinRequest(
            GroupJoinRequest::new(Some("requester-1".to_string())),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::JoinRequested { ref user_id } => {
                assert_eq!(user_id, "requester-1");
            }
            other => panic!("Expected JoinRequested, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_join_rejected() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupJoinReject(
            GroupJoinReject::new(Some(vec![
                "rejected-1".to_string(),
                "rejected-2".to_string(),
            ])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::JoinRejected { ref user_ids } => {
                assert_eq!(user_ids, &["rejected-1", "rejected-2"]);
            }
            other => panic!("Expected JoinRejected, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

// ConversationMetadataChangeEvent (SettingsChange) sub-variants

#[test]
fn decrypt_event_settings_change_message_duration() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MessageDurationChange(MessageDurationChange::new(
        Some(60000i64),
        Some(true),
    ));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => match sc.change {
            SettingsChange::MessageDuration {
                ttl_msec,
                apply_to_all,
            } => {
                assert_eq!(ttl_msec, 60000);
                assert!(apply_to_all);
            }
            other => panic!("Expected MessageDuration, got {:?}", other),
        },
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_message_duration_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MessageDurationRemove(MessageDurationRemove::new(
        Some(30000i64),
    ));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::MessageDurationRemoved));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_muted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MuteConversation(MuteConversation::new(Some(vec![
        "conv-1".to_string(),
    ])));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Muted));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_unmuted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change =
        ConversationMetadataChange::UnmuteConversation(UnmuteConversation::new(Some(vec![
            "conv-1".to_string(),
        ])));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Unmuted));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_detection_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::EnableScreenCaptureDetection(
        EnableScreenCaptureDetection::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureDetectionEnabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_detection_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::DisableScreenCaptureDetection(
        DisableScreenCaptureDetection::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureDetectionDisabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_blocking_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::EnableScreenCaptureBlocking(
        EnableScreenCaptureBlocking::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureBlockingEnabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_blocking_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::DisableScreenCaptureBlocking(
        DisableScreenCaptureBlocking::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureBlockingDisabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_none_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let cmce = ThriftCMCE::new(None::<ConversationMetadataChange>);
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Unknown));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

// Unknown/missing detail → Event::Unknown

#[test]
fn decrypt_event_no_detail_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    // Build event with no detail (detail = None)
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        None::<ThriftDetail>, // no detail
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).expect("serialize");
    let event_b64 = base64_encode(&bytes);

    let result = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match result {
        Event::Unknown(u) => {
            assert!(u.event_type_id.is_none());
            assert_eq!(u.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::Unknown, got {:?}", other),
    }
}

#[test]
fn decrypt_event_grok_search_response_returns_unknown() {
    // GrokSearchResponseEvent is handled by the catch-all `_` branch
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let grok = ThriftGSRE::new(Some("search-1".to_string()));
    let event_b64 = build_test_event(ThriftDetail::GrokSearchResponseEvent(grok));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Unknown(u) => {
            assert!(u.event_type_id.is_none());
        }
        other => panic!(
            "Expected Event::Unknown for GrokSearchResponse, got {:?}",
            other
        ),
    }
}

// KeyChange event via decrypt_event

#[test]
fn decrypt_event_key_change() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let kce = ThriftCKCE::new(
        Some("v42".to_string()),
        Some(vec![
            ConversationParticipantKey::new(
                Some("910004".to_string()),
                Some("encrypted-key-1".to_string()),
                Some("pkv-1".to_string()),
            ),
            ConversationParticipantKey::new(
                Some("910007".to_string()),
                Some("encrypted-key-2".to_string()),
                Some("63".to_string()),
            ),
        ]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::KeyChange(kc) => {
            assert_eq!(kc.conversation_key_version, "v42");
            assert_eq!(kc.conversation_participant_keys.len(), 2);
            assert_eq!(kc.conversation_participant_keys[0].user_id, "910004");
            assert_eq!(
                kc.conversation_participant_keys[0].encrypted_conversation_key,
                "encrypted-key-1"
            );
            assert_eq!(kc.conversation_participant_keys[1].user_id, "910007");
            assert!(!kc.verified);
        }
        other => panic!("Expected Event::KeyChange, got {:?}", other),
    }
}

/// A KeyChange whose signature was produced by `sign_key_change` must
/// verify on `decrypt_event` — even with an empty conversation-key map,
/// because the SDK self-decrypts the plaintext key from the event's own
/// participant entry (encrypted to our identity key). Guards the v7
/// plaintext-ckey verification path end to end (default reject_unverified).
#[test]
fn decrypt_event_key_change_verifies_signature() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    let pubkeys = core.get_public_keys().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let ckey_version = "1733889755256";

    // Encrypt the conversation key for ourselves so the SDK can
    // self-decrypt it from the event to rebuild the signed payload.
    let recipients = [RecipientInput {
        user_id: "910003".to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap();

    // Sign the key change (v7 signs the plaintext conversation key).
    let sig = core
        .sign_key_change(
            "pkv-self",
            "msg-1",
            "910003",
            "conv-1",
            ckey_version,
            ckey.encoded(),
        )
        .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            Some("pkv-self".to_string()),
        )]),
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(sig.message_event_signature.signature.clone()),
        Some(sig.message_event_signature.public_key_version.clone()),
        Some(sig.message_event_signature.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
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
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let signing_keys = [SigningKeyEntry::new(
        "910003",
        "pkv-self",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )];

    // Empty key map forces the self-decrypt path.
    let decrypted = core
        .decrypt_event_with(&event_b64, &Default::default(), &signing_keys)
        .unwrap();
    match decrypted {
        Event::KeyChange(kc) => {
            assert!(kc.verified, "CKCE signature must verify via self-decrypt");
            assert_eq!(kc.conversation_key_version, ckey_version);
        }
        other => panic!("Expected Event::KeyChange, got {:?}", other),
    }
}

// decrypt_events (batch) tests

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

// extract_conversation_keys tests

#[test]
fn extract_conversation_keys_empty_events() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core.extract_conversation_keys(&[]);
    assert!(result.is_empty());
    assert!(result.latest_version.is_none());
    assert_eq!(result.len(), 0);
}

#[test]
fn extract_conversation_keys_no_keys_loaded() {
    let core = ChatCore::new();
    // Don't generate keys — no identity key loaded

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));
    let result = core.extract_conversation_keys(&[&typing_b64]);
    assert!(result.is_empty());
}

#[test]
fn extract_conversation_keys_skips_non_key_events() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let typing = ThriftMTE::new(None::<String>, None, None, None, None);
    let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INTERNAL_ERROR),
        None::<ThriftRateLimitTier>,
    );
    let failure_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let result = core.extract_conversation_keys(&[&typing_b64, &failure_b64]);
    assert!(result.is_empty());
}

#[test]
fn extract_conversation_keys_skips_malformed_b64() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core.extract_conversation_keys(&["not-valid-base64!!!"]);
    assert!(result.is_empty());
}

#[test]
fn registered_key_version_selects_matching_participant_entry_and_skips_others() {
    // With a registered key version, participant-key entries targeting a
    // different version are skipped instead of trial-decrypted: an entry
    // matching the version is used even when an earlier decryptable entry
    // exists, and an event with only mismatched entries yields no key.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "64"))
        .unwrap();

    let pubkeys = core.get_public_keys().unwrap();
    let encrypt_for_self = |ckey: &XChatConversationKey| {
        let recipients = [RecipientInput {
            user_id: "910003".to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "unused".to_string(),
        }];
        core.encrypt_conversation_key_for_recipients(ckey, &recipients)
            .unwrap()[0]
            .encrypted_conversation_key
            .clone()
    };

    // Both entries decrypt with our identity key but carry different
    // conversation keys, so the extracted key reveals which entry was used.
    let ckey_mismatch = core.generate_conversation_key().unwrap();
    let ckey_match = core.generate_conversation_key().unwrap();

    let entry = |ckey_b64: String, version: &str| {
        ConversationParticipantKey::new(
            Some("910003".to_string()),
            Some(ckey_b64),
            Some(version.to_string()),
        )
    };

    let kce = ThriftCKCE::new(
        Some("42".to_string()),
        Some(vec![
            entry(encrypt_for_self(&ckey_mismatch), "not-V"),
            entry(encrypt_for_self(&ckey_match), "64"),
        ]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

    let result = core.extract_conversation_keys(&[&event_b64]);
    let extracted = result.get("42").expect("matching-version entry adopted");
    assert_eq!(extracted.encoded(), ckey_match.encoded());

    // Mismatched-only event: the key must not be adopted.
    let kce_mismatch_only = ThriftCKCE::new(
        Some("43".to_string()),
        Some(vec![entry(encrypt_for_self(&ckey_mismatch), "not-V")]),
        None,
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce_mismatch_only));
    let result = core.extract_conversation_keys(&[&event_b64]);
    assert!(result.is_empty());
}

// export_keys / import_keys tests

#[test]
fn export_import_keys_roundtrip() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    // Export keys
    let exported = core.export_keys().unwrap();
    assert!(!exported.is_empty());

    // Get public keys before lock
    let public_keys_before = core.get_public_keys().unwrap();

    // Lock (clear keys)
    core.lock();
    assert!(!core.has_identity_key());
    assert!(!core.is_unlocked());

    // Import keys
    core.import_keys(&ImportKeysParams::new(exported.to_vec()))
        .unwrap();
    assert!(core.has_identity_key());
    assert!(core.is_unlocked());

    // Verify keys match
    let public_keys_after = core.get_public_keys().unwrap();
    assert_eq!(public_keys_before.identity, public_keys_after.identity);
    assert_eq!(public_keys_before.signing, public_keys_after.signing);
}

#[test]
fn import_keys_invalid_format_errors() {
    let core = ChatCore::new();

    // Wrong size: not 32 or 64 bytes
    let result = core.import_keys(&ImportKeysParams::new([0u8; 16].to_vec()));
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Invalid key format"));
}

#[test]
fn caller_input_errors_are_invalid_input() {
    use crate::error::ErrorKind;
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("111", "1"))
        .unwrap();
    let signature = core.sign(b"data").unwrap();
    let signing_key = &reg.public_key.signing_public_key;

    let kinds = [
        core.import_keys(&ImportKeysParams::new(vec![0u8; 16]))
            .unwrap_err()
            .kind(),
        core.encrypt_message(
            &crate::EncryptMessageParams::new("111:222", "hi")
                .with_conversation_key(vec![0u8; 3], "1"),
        )
        .unwrap_err()
        .kind(),
        core.prepare_conversation_key_change(&ConversationKeyChangeParams::new(vec![]))
            .unwrap_err()
            .kind(),
        core.verify("not base64!", &signature, b"data")
            .unwrap_err()
            .kind(),
        core.verify(signing_key, &signature[..10], b"data")
            .unwrap_err()
            .kind(),
        core.verify_key_binding("not base64!", signing_key, "AAAA")
            .unwrap_err()
            .kind(),
        core.matches_registered_key("not base64!")
            .unwrap_err()
            .kind(),
        core.prepare_message_delete(&MessageDeleteParams::new("1,2", vec!["5".into()], true))
            .unwrap_err()
            .kind(),
    ];
    for kind in kinds {
        assert_eq!(kind, ErrorKind::InvalidInput);
    }
    assert!(core.verify(signing_key, &signature, b"data").unwrap());

    core.lock();
    let locked = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("111:222", "hi")
                .with_conversation_key(vec![0u8; 32], "1"),
        )
        .unwrap_err();
    assert_eq!(locked.kind(), ErrorKind::InvalidState);
}

#[test]
fn export_keys_without_keys_errors() {
    let core = ChatCore::new();

    let result = core.export_keys();
    assert!(result.is_err());
}

// Key management state tests

#[test]
fn is_unlocked_and_has_identity_key() {
    let core = ChatCore::new();

    // No keys loaded
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());

    // Generate keys
    core.generate_keypairs().unwrap();
    assert!(core.is_unlocked());
    assert!(core.has_identity_key());

    // Lock
    core.lock();
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());
}

#[test]
fn get_public_keys_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.get_public_keys().is_err());
}

#[test]
fn get_public_key_fingerprint_works() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let fingerprint = core.get_public_key_fingerprint().unwrap();
    assert!(!fingerprint.is_empty());
    // URL-safe base64 of SHA-256 (32 bytes → 43 chars without padding)
    assert_eq!(fingerprint.len(), 43);
}

#[test]
fn get_public_key_fingerprint_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.get_public_key_fingerprint().is_err());
}

#[test]
fn verify_key_binding_roundtrip() {
    // identity_public_key_signature = signing key signing the
    // SPKI-encoded identity key (raw r||s). The registration payload
    // carries the SPKI-encoded keys — the same format the X API
    // returns on the public keys endpoint.
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let signing_spki = payload.public_key.signing_public_key.clone();
    let sig = payload.public_key.identity_public_key_signature.clone();

    // Valid binding verifies.
    let ok = core
        .verify_key_binding(&identity_spki, &signing_spki, &sig)
        .unwrap();
    assert!(ok, "valid key binding should verify");

    // Wrong identity key fails.
    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    let bad = core
        .verify_key_binding(&other_payload.public_key.public_key, &signing_spki, &sig)
        .unwrap();
    assert!(!bad, "binding with wrong identity key must fail");
}

#[test]
fn matches_registered_key_accepts_both_encodings() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    // SPKI/DER form — what the X API returns for a registered key.
    let spki = payload.public_key.public_key;
    assert!(core.matches_registered_key(&spki).unwrap());

    // Raw SEC1 point — what get_public_keys returns.
    let raw = core.get_public_keys().unwrap().identity;
    assert!(core.matches_registered_key(&raw).unwrap());
}

#[test]
fn matches_registered_key_rejects_other_key() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    assert!(!core
        .matches_registered_key(&other_payload.public_key.public_key)
        .unwrap());
}

#[test]
fn matches_registered_key_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.matches_registered_key("AAAA").is_err());
}

#[test]
fn matches_registered_key_invalid_base64_errors() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    assert!(core.matches_registered_key("not base64!!").is_err());
}

#[test]
fn matches_registered_key_garbage_bytes_is_false() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    // Valid base64 of bytes that are not a public key in either encoding.
    let garbage = base64_encode(&[0u8; 65]);
    assert!(!core.matches_registered_key(&garbage).unwrap());
}

#[test]
fn generate_keypairs_returns_registration_payload() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    assert!(!payload.public_key.public_key.is_empty());
    assert!(!payload.public_key.signing_public_key.is_empty());
    assert!(!payload.public_key.identity_public_key_signature.is_empty());
    assert_eq!(payload.public_key.registration_method, "CustomPin");
    assert!(payload.public_key.public_key_fingerprint.is_some());
    assert!(payload.public_key.signing_public_key_signature.is_some());
}

// Conversation key encryption/decryption roundtrip

#[test]
fn generate_and_decrypt_conversation_key() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let public_keys = core.get_public_keys().unwrap();

    let recipients = vec![RecipientInput {
        user_id: "self".to_string(),
        public_key: public_keys.identity.clone(),
        key_version: "v1".to_string(),
    }];

    let encrypted = core
        .encrypt_conversation_key_for_recipients(&ckey, &recipients)
        .unwrap();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].user_id, "self");

    let decrypted = core
        .decrypt_conversation_key(&encrypted[0].encrypted_conversation_key)
        .unwrap();
    assert_eq!(decrypted.encoded(), ckey.encoded());
}

// prepare_conversation_key_change tests

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

/// The one action signature of a prepared delete or read receipt.
fn only_action(prepared: PreparedAction) -> crate::signatures::ActionSignature {
    assert_eq!(prepared.action_signatures.len(), 1);
    prepared.action_signatures.into_iter().next().unwrap()
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

// sign / verify tests

#[test]
fn sign_and_verify_roundtrip() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let data = b"Hello, world!";
    let signature = core.sign(data).unwrap();
    assert!(!signature.is_empty());

    let public_keys = core.get_public_keys().unwrap();
    let verified = core.verify(&public_keys.signing, &signature, data).unwrap();
    assert!(verified);

    // Wrong data should not verify
    let bad_verified = core
        .verify(&public_keys.signing, &signature, b"wrong data")
        .unwrap();
    assert!(!bad_verified);
}

#[test]
fn sign_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.sign(b"data").is_err());
}

// File encryption tests

/// A core with keys and the session identity of user 1000.
fn sending_core() -> ChatCore {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("1000", "1"))
        .unwrap();
    core
}

/// The outgoing event of a message `core` sends under key version "1"
/// whose only attachment is the file `media_hash_key`, and the key map
/// that opens it.
fn sent_file_message(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    media_hash_key: &str,
) -> (String, HashMap<String, XChatConversationKey>) {
    let mut params = crate::EncryptMessageParams::new("1000:2000", "a file")
        .with_conversation_key(ckey.to_bytes(), "1");
    params.attachments = Some(vec![crate::AttachmentDescriptor::Media {
        media_hash_key: media_hash_key.to_string(),
        width: 4,
        height: 3,
        filesize_bytes: 64,
        filename: "photo.png".to_string(),
        media_type: None,
        duration_millis: None,
    }]);
    let payload = core.encrypt_message(&params).unwrap();
    (
        payload.event_b64,
        [("1".to_string(), ckey.clone())].into_iter().collect(),
    )
}

#[test]
fn encrypt_decrypt_file_roundtrip() {
    let core = sending_core();
    let ckey = core.generate_conversation_key().unwrap();
    let (event, keys) = sent_file_message(&core, &ckey, "hash-1");

    let plaintext = b"file data for media encryption test";
    let encrypted = core
        .encrypt_file(
            &EncryptFileParams::new(plaintext.to_vec(), event.clone(), "hash-1")
                .with_conversation_key(ckey.to_bytes(), "1"),
        )
        .unwrap();
    assert_ne!(&encrypted[..], plaintext);

    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(encrypted, event, keys, "hash-1"))
        .unwrap();
    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn encrypt_decrypt_file_empty() {
    let core = sending_core();
    let ckey = core.generate_conversation_key().unwrap();
    let (event, keys) = sent_file_message(&core, &ckey, "hash-1");

    let encrypted = core
        .encrypt_file(
            &EncryptFileParams::new(Vec::new(), event.clone(), "hash-1")
                .with_conversation_key(ckey.to_bytes(), "1"),
        )
        .unwrap();
    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(encrypted, event, keys, "hash-1"))
        .unwrap();
    assert!(decrypted.is_empty());
}

// ChatCore::default() test

#[test]
fn chatcore_default_is_new() {
    let core = ChatCore::default();
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());
}

// decrypt_event with invalid base64 errors

#[test]
fn decrypt_event_invalid_base64_errors() {
    let core = ChatCore::new();
    let result = core.decrypt_event_with("not_valid_base64!!!", &Default::default(), &[]);
    assert!(result.is_err());
}

// convert_failure_type coverage

#[test]
fn convert_failure_type_all_variants() {
    use crate::thrift::event::FailureType as TFT;
    for (thrift, expected) in [
        (TFT::EMPTY_DETAIL, FailureType::EmptyDetail),
        (TFT::INTERNAL_ERROR, FailureType::InternalError),
        (TFT::CONTENTS_TOO_LARGE, FailureType::ContentsTooLarge),
        (TFT::TOO_MANY_MESSAGES, FailureType::TooManyMessages),
        (
            TFT::INVALID_SENDER_SIGNATURE,
            FailureType::InvalidSenderSignature,
        ),
        (
            TFT::NON_LATEST_CKEY_VERSION,
            FailureType::NonLatestKeyVersion,
        ),
        (
            TFT::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION,
            FailureType::RecipientNotTrusted,
        ),
        (
            TFT::RECIPIENT_KEY_HAS_CHANGED,
            FailureType::RecipientKeyChanged,
        ),
        (
            TFT::ONLY_ENCRYPTED_MESSAGES_ALLOWED,
            FailureType::OnlyEncryptedMessagesAllowed,
        ),
        (TFT::REQUESTER_NOT_ADMIN, FailureType::RequesterNotAdmin),
        (TFT::FLAGGED_AS_SPAM, FailureType::FlaggedAsSpam),
        (TFT::RATE_LIMIT_UPSELL, FailureType::RateLimitUpsell),
        (
            TFT::SIGNATURE_FAILED_TO_VERIFY_AGAINST_PUBLIC_KEY,
            FailureType::SignatureFailedToVerifyAgainstPublicKey,
        ),
        (TFT::GENERIC_ERROR, FailureType::GenericError),
        (
            TFT::SENDER_NOT_GROUP_MEMBER,
            FailureType::SenderNotGroupMember,
        ),
        (
            TFT::INVALID_SIGNATURE_VERSION,
            FailureType::InvalidSignatureVersion,
        ),
        (TFT::INVALID_PIN_REQUEST, FailureType::InvalidPinRequest),
        (TFT::TOO_MANY_PINS, FailureType::TooManyPins),
    ] {
        assert_eq!(convert_failure_type(Some(&thrift)), expected);
    }
    assert_eq!(convert_failure_type(Some(&TFT(99))), FailureType::Unknown);
    assert_eq!(convert_failure_type(None), FailureType::Unknown);
}

#[test]
fn convert_rate_limit_tier_all_variants() {
    use crate::thrift::event::RateLimitTier as TRT;
    for (thrift, expected) in [
        (TRT::FREE, RateLimitTier::Free),
        (TRT::VERIFIED_PHONE, RateLimitTier::VerifiedPhone),
        (TRT::PREMIUM, RateLimitTier::Premium),
        (TRT::PREMIUM_PLUS, RateLimitTier::PremiumPlus),
        (TRT::PREMIUM_BUSINESS, RateLimitTier::PremiumBusiness),
    ] {
        assert_eq!(convert_rate_limit_tier(Some(&thrift)), Some(expected));
    }
    assert_eq!(
        convert_rate_limit_tier(Some(&TRT(99))),
        Some(RateLimitTier::Unknown)
    );
    assert_eq!(convert_rate_limit_tier(None), None);
}

#[test]
fn group_change_none_returns_unknown() {
    let change = ChatCore::new().group_change(None, None, &HashMap::new());
    assert!(matches!(change, GroupChange::Unknown));
}

// convert_settings_change coverage

#[test]
fn convert_settings_change_none_returns_unknown() {
    let change = convert_settings_change(None);
    assert!(matches!(change, SettingsChange::Unknown));
}

// ConversationKeyResult accessors

#[test]
fn conversation_key_result_accessors() {
    let ckey = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), ckey.clone());

    let result = ConversationKeyResult {
        keys,
        latest_version: Some("v1".to_string()),
    };

    assert!(!result.is_empty());
    assert_eq!(result.len(), 1);
    assert!(result.get("v1").is_some());
    assert!(result.get("v2").is_none());
    assert!(result.latest_key().is_some());
}

#[test]
fn conversation_key_result_latest_key_none() {
    let result = ConversationKeyResult {
        keys: HashMap::new(),
        latest_version: None,
    };

    assert!(result.is_empty());
    assert!(result.latest_key().is_none());
}

// decrypt_conversation_key without keys errors

#[test]
fn decrypt_conversation_key_without_identity_errors() {
    let core = ChatCore::new();
    let result = core.decrypt_conversation_key("AAAA");
    assert!(result.is_err());
}

// verify_key_binding negative cases

/// A tampered `identity_public_key_signature` must not verify.
#[test]
fn verify_key_binding_tampered_signature_fails() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let signing_spki = payload.public_key.signing_public_key.clone();

    // Flip a byte in the raw signature bytes and re-encode.
    let mut sig_bytes = base64_decode(&payload.public_key.identity_public_key_signature).unwrap();
    sig_bytes[0] ^= 0xFF;
    let tampered_sig = base64_encode(&sig_bytes);

    let ok = core
        .verify_key_binding(&identity_spki, &signing_spki, &tampered_sig)
        .unwrap();
    assert!(!ok, "tampered signature must not verify");
}

/// A valid signature verified against the wrong *signing* key must fail.
#[test]
fn verify_key_binding_mismatched_signing_key_fails() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let sig = payload.public_key.identity_public_key_signature.clone();

    // A different keypair's signing key did not produce this signature.
    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    let wrong_signing_spki = other_payload.public_key.signing_public_key.clone();

    let bad = core
        .verify_key_binding(&identity_spki, &wrong_signing_spki, &sig)
        .unwrap();
    assert!(!bad, "binding with wrong signing key must fail");
}

/// Sanity: the binding produced by `generate_keypairs` verifies.
#[test]
fn verify_key_binding_valid_passes() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let ok = core
        .verify_key_binding(
            &payload.public_key.public_key,
            &payload.public_key.signing_public_key,
            &payload.public_key.identity_public_key_signature,
        )
        .unwrap();
    assert!(ok, "valid binding from generate_keypairs should verify");
}

// Helpers for signed-message roundtrips

/// Wrap a `SendPayload` (the MCE + signature produced by an `encrypt_*`
/// call) into a full base64 `MessageEvent` with the embedded signature,
/// mirroring what the backend delivers. `message_id`/`sender_id`/
/// `conversation_id` must match the values passed to the `encrypt_*`
/// call so the signature payload reconstructs identically.
fn wrap_signed_payload(
    payload: &SendPayload,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
) -> String {
    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let mce = parse_message_event(&mce_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            let cursor = Cursor::new(mce_bytes.clone());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .ok()
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        })
        .expect("parse MCE");

    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some(message_id.to_string()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

/// Build a `ConversationKeyChangeEvent` (base64) that carries `ckey`
/// self-encrypted to the loaded identity key, so that
/// `extract_conversation_keys` can recover it. `reg_version` is the
/// participant entry's key version, which must match the signing-key
/// version when one is set.
fn build_self_keychange_event(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    ckey_version: &str,
    sender_id: &str,
    reg_version: Option<String>,
) -> String {
    let pubkeys = core.get_public_keys().unwrap();
    let recipients = [RecipientInput {
        user_id: sender_id.to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(ckey, &recipients)
        .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some(sender_id.to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            reg_version,
        )]),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-kc".to_string()),
        Some("msg-kc".to_string()),
        Some(sender_id.to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
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

/// Like `build_self_keychange_event`, but embeds a v7
/// `MessageEventSignature` produced by `sign_key_change`, mirroring
/// what a legitimate client publishes.
fn build_signed_self_keychange_event(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    ckey_version: &str,
    sender_id: &str,
    signing_key_version: &str,
    reg_version: Option<String>,
) -> String {
    let pubkeys = core.get_public_keys().unwrap();
    let recipients = [RecipientInput {
        user_id: sender_id.to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(ckey, &recipients)
        .unwrap();

    let action_sig = core
        .sign_key_change(
            signing_key_version,
            "msg-kc",
            sender_id,
            "conv-1",
            ckey_version,
            ckey.encoded(),
        )
        .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some(sender_id.to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            reg_version,
        )]),
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(action_sig.message_event_signature.signature.clone()),
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
        Some(sender_id.to_string()),
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
}

fn signing_key_entry_for(reg: &PublicKeyRegistrationPayload, user_id: &str) -> SigningKeyEntry {
    SigningKeyEntry::new(
        user_id,
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )
}

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

// Signature versions below the floor are rejected

/// Build a signed message event but overwrite the embedded
/// signature_version with `version`.
fn build_message_event_with_sig_version(core: &ChatCore, version: &str) -> (String, String) {
    let ckey = core.generate_conversation_key().unwrap();
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "downgrade probe")
                .with_identity("4001", "61")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    let mut event_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");

    // Re-parse and rewrite the signature_version field.
    let bytes = base64_decode(&event_b64).unwrap();
    let mut event = parse_message_event(&bytes).unwrap();
    if let Some(sig) = event.message_event_signature.as_mut() {
        sig.signature_version = Some(version.to_string());
    }
    event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    let ckey_b64 = STANDARD_NO_PAD.encode(ckey.encoded());
    (event_b64, ckey_b64)
}

#[test]
fn signature_version_below_floor_is_rejected() {
    let core = ChatCore::new(); // default reject_unverified = true
    let reg = core.generate_keypairs().unwrap();
    let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "1");

    let ckey =
        XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    let result = core.decrypt_event_with(&event_b64, &conv_keys, &signing_keys);
    let err = result.expect_err("v1 signature must be rejected");
    assert!(
        err.to_string().contains("no longer accepted"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn signature_version_below_floor_never_verifies_in_permissive_mode() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    let reg = core.generate_keypairs().unwrap();
    let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "0");

    let ckey =
        XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
    let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
    let signing_keys = [signing_key_entry_for(&reg, "910003")];

    match core.decrypt_event_with(&event_b64, &conv_keys, &signing_keys) {
        Ok(Event::Message(msg)) => {
            assert!(!msg.verified, "below-floor version must never verify")
        }
        Ok(other) => panic!("expected Message, got {:?}", other),
        Err(e) => panic!("permissive mode should pass through unverified: {}", e),
    }
}

#[test]
fn signature_version_at_floor_is_processed() {
    let author = super::test_support::Party::new("4001");
    let ckey = author.core.generate_conversation_key().unwrap();
    let event = super::test_support::message_event(
        &author,
        "m-1",
        "100",
        "9001",
        None,
        crate::signatures::MIN_SIGNATURE_VERSION,
        &ckey,
        &crate::pipeline::build_message_content("at the floor", None, None, None).unwrap(),
    );
    let message = super::test_support::decrypt_message(
        &ChatCore::new(),
        &event,
        &[("9001".to_string(), ckey)].into_iter().collect(),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
}

// Default reject_unverified=true rejects unverifiable events

#[test]
fn reject_unverified_rejects_keychange_without_matching_signing_key() {
    // Default reject_unverified=true. A signed KeyChange with no
    // matching signing key cannot be verified and must be rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let kce = ThriftCKCE::new(
        Some("ckv-1".to_string()),
        None::<Vec<ConversationParticipantKey>>,
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some("AAAA".to_string()),
        Some("61".to_string()),
        Some("7".to_string()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
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
    let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

    // No matching signing key supplied → rejected.
    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "KeyChange with no matching signing key must be rejected"
    );
}

#[test]
fn reject_unverified_rejects_unencrypted_message_by_default() {
    // An unencrypted message (no conversation_key_version) carries no
    // signature, so under the default reject_unverified it is rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("plaintext");
    let event_b64 = build_test_message_event(&content, None);

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "unencrypted message must be rejected under default reject_unverified"
    );
}

// ChatCore-level roundtrips: reply / add-reaction / remove-reaction

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

// Session identity

/// Like `wrap_signed_payload` but with an explicit sequence id, for tests
/// that reference a message by sequence (replies, reactions).
fn wrap_signed_payload_with_seq(
    payload: &SendPayload,
    sender_id: &str,
    conversation_id: &str,
    sequence_id: &str,
) -> String {
    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let mce = parse_message_event(&mce_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            let cursor = Cursor::new(mce_bytes.clone());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .ok()
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        })
        .expect("parse MCE");
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some(sequence_id.to_string()),
        Some(payload.message_id.clone()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

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

/// Encrypt must fail loudly on attachment combinations first-party
/// clients cannot render (temporary client-compat guard) and must not
/// produce ciphertext for them, while multi image/gif/video stays allowed.
#[test]
fn encrypt_message_rejects_disallowed_attachment_combos() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let media = |mt: Option<i32>| crate::AttachmentDescriptor::Media {
        media_hash_key: format!("hash-{mt:?}"),
        width: 100,
        height: 100,
        filesize_bytes: 1000,
        filename: "file".into(),
        media_type: mt,
        duration_millis: None,
    };
    let url = || crate::AttachmentDescriptor::Url {
        url: "https://example.com".into(),
        display_title: None,
        banner_image: None,
        favicon_image: None,
    };
    let params_with = |attachments: Vec<crate::AttachmentDescriptor>| {
        let mut p = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1");
        p.attachments = Some(attachments);
        p
    };

    // Mixed media + URL card is rejected before any ciphertext exists.
    let err = core
        .encrypt_message(&params_with(vec![media(Some(1)), url()]))
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err}");
    assert!(err.to_string().contains("attachment combination"));

    // Two URL cards are rejected.
    let err = core
        .encrypt_message(&params_with(vec![url(), url()]))
        .unwrap_err();
    assert!(err.to_string().contains("attachment combination"));

    // Multiple image/gif/video media stay allowed.
    core.encrypt_message(&params_with(vec![
        media(Some(1)),
        media(Some(2)),
        media(Some(3)),
    ]))
    .unwrap();

    // A lone non-multi attachment (file media) stays allowed.
    core.encrypt_message(&params_with(vec![media(Some(5))]))
        .unwrap();
}

#[test]
fn encrypt_reply_rejects_disallowed_attachment_combos() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let ckey = core.generate_conversation_key().unwrap();

    let mut params = crate::EncryptReplyParams::new("conv-1", "hi", "")
        .with_identity("910003", "61")
        .with_conversation_key(ckey.to_bytes(), "1");
    params.reply_to_sequence_id = Some("seq-1".into());
    params.attachments = Some(vec![
        crate::AttachmentDescriptor::Post {
            rest_id: Some("1".into()),
            post_url: None,
        },
        crate::AttachmentDescriptor::Media {
            media_hash_key: "hash".into(),
            width: 100,
            height: 100,
            filesize_bytes: 1000,
            filename: "pic.jpg".into(),
            media_type: Some(1),
            duration_millis: None,
        },
    ]);
    let err = core.encrypt_reply(&params).unwrap_err();
    assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err}");
    assert!(err.to_string().contains("attachment combination"));
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

// Conversation-key and signing-key caches

#[test]
fn cache_resolves_verified_latest_key_for_encrypt() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);

    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "4001",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    // No key passed: it resolves from the cache at the verified version.
    let payload = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "cached"))
        .unwrap();
    assert_eq!(payload.conversation_key_version, "1001");

    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");
    let conv_keys = [("1001".to_string(), ckey)].into_iter().collect();
    match core
        .decrypt_event_with(&msg_b64, &conv_keys, &signing_keys)
        .unwrap()
    {
        Event::Message(msg) => assert_eq!(msg.text(), Some("cached")),
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn files_take_the_messages_key_from_the_cache_too() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);
    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "4001",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "4001")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    let mut params = crate::EncryptMessageParams::new("conv-1", "a photo");
    params.attachments = Some(vec![AttachmentDescriptor::Media {
        media_hash_key: "photo".into(),
        width: 1,
        height: 1,
        filesize_bytes: 10,
        filename: "photo.jpg".into(),
        media_type: Some(1),
        duration_millis: None,
    }]);
    let payload = core.encrypt_message(&params).unwrap();

    // No key passed: the file takes the cached key, as its message did.
    let encrypted = core
        .encrypt_file(&EncryptFileParams::new(
            b"photo bytes".to_vec(),
            payload.event_b64.clone(),
            "photo",
        ))
        .unwrap();
    let keys = [("1001".to_string(), ckey.clone())].into_iter().collect();
    let decrypted = core
        .decrypt_file(&DecryptFileParams::new(
            encrypted,
            payload.event_b64.clone(),
            keys,
            "photo",
        ))
        .unwrap();
    assert_eq!(decrypted, b"photo bytes");

    let err = core
        .encrypt_file(
            &EncryptFileParams::new(b"photo".to_vec(), payload.event_b64, "photo")
                .with_conversation_key(ckey.to_bytes(), "1002"),
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("conversation_key_version '1002' is not the message's key version '1001'"),
        "{err}"
    );
}

#[test]
fn cache_is_off_by_default() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "61"))
        .unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_signed_self_keychange_event(
        &core,
        &ckey,
        "1001",
        "910003",
        "61",
        Some("61".to_string()),
    );
    let signing_keys = [signing_key_entry_for(&reg, "910003")];
    core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);

    let err = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "no cache"))
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
}

#[test]
fn unverified_key_change_never_becomes_an_encryption_key() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("910003", "61"))
        .unwrap();
    core.set_cache_keys(true);

    // Adopted-for-decryption key change with an unverifiable signature.
    let ckey = core.generate_conversation_key().unwrap();
    let kc_b64 = build_self_keychange_event(&core, &ckey, "2002", "910003", Some("61".to_string()));
    let signing_keys = [signing_key_entry_for(&reg, "910003")];
    let result = core.decrypt_events_with(&[kc_b64.as_str()], &signing_keys);
    assert!(result.conversation_keys.keys.contains_key("2002"));

    let err = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "must fail"))
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
}

#[test]
fn cache_never_moves_below_the_verified_high_water() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    core.set_cache_keys(true);
    let signing_keys = [signing_key_entry_for(&reg, "4001")];

    let newer = core.generate_conversation_key().unwrap();
    let kc_newer = build_signed_self_keychange_event(
        &core,
        &newer,
        "2000",
        "4001",
        "61",
        Some("61".to_string()),
    );
    core.decrypt_events_with(&[kc_newer.as_str()], &signing_keys);

    // A validly signed but older key change replayed later must not
    // displace the newer cached key.
    let older = core.generate_conversation_key().unwrap();
    let kc_older = build_signed_self_keychange_event(
        &core,
        &older,
        "1000",
        "4001",
        "61",
        Some("61".to_string()),
    );
    core.decrypt_events_with(&[kc_older.as_str()], &signing_keys);

    let payload = core
        .encrypt_message(&crate::EncryptMessageParams::new("conv-1", "fresh"))
        .unwrap();
    assert_eq!(payload.conversation_key_version, "2000");
}

#[test]
fn signing_key_store_is_used_when_the_argument_is_omitted() {
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let payload = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("conv-1", "hello")
                .with_conversation_key(ckey.to_bytes(), "9001"),
        )
        .unwrap();
    let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "4001", "conv-1");
    let conv_keys: HashMap<String, XChatConversationKey> =
        [("9001".to_string(), ckey)].into_iter().collect();

    // Without stored keys an empty slice still fails verification.
    assert!(core.decrypt_event_with(&msg_b64, &conv_keys, &[]).is_err());

    core.set_signing_keys(&[signing_key_entry_for(&reg, "4001")]);
    match core.decrypt_event_with(&msg_b64, &conv_keys, &[]).unwrap() {
        Event::Message(msg) => {
            assert!(msg.verified);
            assert_eq!(msg.text(), Some("hello"));
        }
        other => panic!("expected Message, got {:?}", other),
    }
}

#[test]
fn cached_key_debug_output_is_redacted() {
    let key = KeyFactory::generate_conversation_key().unwrap();
    let cached = CachedConversationKey { version: 1, key };
    let debug = format!("{:?}", cached);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("bytes"));
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

#[test]
fn truncated_preview_text_is_valid() {
    let (core, ckey, signing_keys) = reply_test_setup();
    let orig_b64 = original_event_b64(&core, &ckey, "a long original message body");

    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_text = Some("a long original".into());
    let reply_payload = core.encrypt_reply(&params).unwrap();

    let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
    assert_eq!(
        msg.reply_preview_validation,
        Some(ReplyPreviewValidation::Valid)
    );
}

#[test]
fn text_override_still_derives_entities_from_the_original() {
    let (core, ckey, signing_keys) = reply_test_setup();

    let mut orig_params = crate::EncryptMessageParams::new("conv-1", "#topic original")
        .with_identity("4002", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    orig_params.entities = Some(vec![crate::EntityDescriptor::new(0, 6, "hashtag")]);
    let orig_payload = core.encrypt_message(&orig_params).unwrap();
    let orig_b64 = wrap_signed_payload_with_seq(&orig_payload, "4002", "conv-1", "seq-orig");

    // A prefix text override must not suppress deriving the remaining
    // preview fields from the decrypted original.
    let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
        .with_identity("4001", "61")
        .with_conversation_key(ckey.to_bytes(), "9001");
    params.reply_to_text = Some("#topic".into());
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
            assert_eq!(preview.message_text.as_deref(), Some("#topic"));
            let entities = preview.entities.as_ref().expect("derived entities");
            assert_eq!(entities.len(), 1);
        }
        other => panic!("expected Text with preview, got {:?}", other),
    }
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
