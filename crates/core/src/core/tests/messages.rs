//! Messages, edits and quick replies: encrypt → decrypt round trips, the
//! message ids and signatures they carry, and the entities, files and
//! attachment combinations a message may not send.

use super::*;

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
fn every_send_rejects_an_unknown_or_empty_entity_type() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    for entity_type in ["bogus", ""] {
        let entities = vec![
            EntityDescriptor::new(0, 2, "mention"),
            EntityDescriptor::new(3, 8, entity_type),
        ];
        let message = crate::EncryptMessageParams::new("conv-1", "hi there")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_entities(entities.clone());
        let reply = crate::EncryptReplyParams::new("conv-1", "hi there", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_entities(entities.clone());
        let preview = crate::EncryptReplyParams::new("conv-1", "hi there", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_reply_to_entities(entities.clone());
        let mut edit = crate::EncryptEditParams::new("", "hi there")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_entities(entities);
        edit.conversation_id = Some("conv-1".into());
        edit.target_message_sequence_id = Some("seq-1".into());
        for err in [
            core.encrypt_message(&message).unwrap_err(),
            core.encrypt_reply(&reply).unwrap_err(),
            core.encrypt_reply(&preview).unwrap_err(),
            core.encrypt_edit(&edit).unwrap_err(),
        ] {
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
            assert_eq!(
                err.to_string(),
                format!(
                    "Invalid entity_type '{entity_type}': pass url, mention, hashtag, cashtag, \
                     email, address or phone_number"
                )
            );
        }
    }
}

#[test]
fn entity_offsets_are_a_range_of_the_texts_utf8_bytes() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    // "héllo @bob" is 11 bytes of UTF-8 (10 characters); "@bob" is bytes 7..11.
    let text = "héllo @bob";
    let mention = |start: i32, end: i32| vec![EntityDescriptor::new(start, end, "mention")];
    let message = |entities| {
        crate::EncryptMessageParams::new("conv-1", text)
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_entities(entities)
    };
    let reply = |entities| {
        crate::EncryptReplyParams::new("conv-1", text, "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_entities(entities)
    };
    let preview = |entities| {
        crate::EncryptReplyParams::new("conv-1", "hi", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_reply_to_text(text)
            .with_reply_to_entities(entities)
    };
    let edit = |entities| {
        let mut edit = crate::EncryptEditParams::new("", text)
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_entities(entities);
        edit.conversation_id = Some("conv-1".into());
        edit.target_message_sequence_id = Some("seq-1".into());
        edit
    };

    core.encrypt_message(&message(mention(7, 11))).unwrap();
    core.encrypt_reply(&reply(mention(7, 11))).unwrap();
    core.encrypt_edit(&edit(mention(7, 11))).unwrap();
    // A preview quotes the start of the original, whose entities may index
    // past the preview's own text.
    core.encrypt_reply(&preview(mention(7, 40))).unwrap();

    let past_the_end = "Invalid entity offsets 7..12: end is past the end of the text, which is \
                        11 bytes of UTF-8";
    for err in [
        core.encrypt_message(&message(mention(7, 12))).unwrap_err(),
        core.encrypt_reply(&reply(mention(7, 12))).unwrap_err(),
        core.encrypt_edit(&edit(mention(7, 12))).unwrap_err(),
    ] {
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), past_the_end);
    }
    for (start, end, problem) in [
        (-1, 4, "offsets count bytes of the UTF-8 text, from 0"),
        (0, -1, "offsets count bytes of the UTF-8 text, from 0"),
        (5, 3, "end is before start"),
    ] {
        let expected = format!("Invalid entity offsets {start}..{end}: {problem}");
        for err in [
            core.encrypt_message(&message(mention(start, end)))
                .unwrap_err(),
            core.encrypt_reply(&reply(mention(start, end))).unwrap_err(),
            core.encrypt_reply(&preview(mention(start, end)))
                .unwrap_err(),
            core.encrypt_edit(&edit(mention(start, end))).unwrap_err(),
        ] {
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), expected);
        }
    }
}

#[test]
fn every_send_rejects_an_empty_link_a_post_without_an_id_and_negative_dimensions() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let media = |width: i64, height: i64| crate::AttachmentDescriptor::Media {
        media_hash_key: "photo".into(),
        width,
        height,
        filesize_bytes: 1000,
        filename: "photo.jpg".into(),
        media_type: Some(1),
        duration_millis: None,
    };
    let card = |url: &str, banner: Option<UrlAttachmentImageDescriptor>| {
        crate::AttachmentDescriptor::Url {
            url: url.into(),
            display_title: None,
            banner_image: banner,
            favicon_image: None,
        }
    };
    let post = |rest_id: Option<&str>, post_url: Option<&str>| crate::AttachmentDescriptor::Post {
        rest_id: rest_id.map(str::to_string),
        post_url: post_url.map(str::to_string),
    };
    let banner = |width: i64, height: i64| {
        UrlAttachmentImageDescriptor::new("banner", 1000, "banner.png")
            .with_dimensions(width, height)
    };
    let no_url = "a URL card's url is empty: pass the link the card shows";
    let no_post =
        "a post attachment has neither rest_id nor post_url: pass the post's id or its URL";
    let negative = |key: &str, side: &str, value: i64| {
        format!("media_hash_key '{key}' has {side} {value}: pass the {side} in pixels, 0 or more")
    };
    let cases = [
        (card("", None), no_url.to_string()),
        (post(None, None), no_post.to_string()),
        (post(Some(""), Some("")), no_post.to_string()),
        (media(-1, 100), negative("photo", "width", -1)),
        (media(100, -2), negative("photo", "height", -2)),
        (
            card("https://example.com", Some(banner(-5, 100))),
            negative("banner", "width", -5),
        ),
        (
            card("https://example.com", Some(banner(100, -5))),
            negative("banner", "height", -5),
        ),
    ];
    for (attachment, expected) in cases {
        let message = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_attachments(vec![attachment.clone()]);
        let reply = crate::EncryptReplyParams::new("conv-1", "hi", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_attachments(vec![attachment]);
        for err in [
            core.encrypt_message(&message).unwrap_err(),
            core.encrypt_reply(&reply).unwrap_err(),
        ] {
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), expected);
        }
    }
    for attachment in [
        post(Some("1"), None),
        post(None, Some("https://x.com/a/status/1")),
        media(0, 0),
        card("https://example.com", Some(banner(0, 0))),
    ] {
        let message = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_attachments(vec![attachment]);
        core.encrypt_message(&message).unwrap();
    }
}

#[test]
fn every_send_rejects_a_file_without_a_name_or_a_size() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("4001", "61"))
        .unwrap();
    let ckey = core.generate_conversation_key().unwrap();
    let media = |filesize_bytes: i64, filename: &str| crate::AttachmentDescriptor::Media {
        media_hash_key: "photo".into(),
        width: 100,
        height: 100,
        filesize_bytes,
        filename: filename.into(),
        media_type: Some(1),
        duration_millis: None,
    };
    let card = |banner: Option<UrlAttachmentImageDescriptor>,
                favicon: Option<UrlAttachmentImageDescriptor>| {
        crate::AttachmentDescriptor::Url {
            url: "https://example.com".into(),
            display_title: Some("Example".into()),
            banner_image: banner,
            favicon_image: favicon,
        }
    };
    let image = UrlAttachmentImageDescriptor::new;
    let no_name = |key: &str| {
        format!("media_hash_key '{key}' has an empty filename: pass the file's original name")
    };
    let no_size = |key: &str, size: i64| {
        format!(
            "media_hash_key '{key}' has filesize_bytes {size}: pass the encrypted file's size, \
             which encrypted_file_size gives"
        )
    };
    let cases = [
        (media(1000, ""), no_name("photo")),
        (media(0, "photo.jpg"), no_size("photo", 0)),
        (media(-1, "photo.jpg"), no_size("photo", -1)),
        (
            card(Some(image("banner", 1000, "")), None),
            no_name("banner"),
        ),
        (
            card(Some(image("banner", 0, "banner.png")), None),
            no_size("banner", 0),
        ),
        (
            card(None, Some(image("favicon", 0, "favicon.png"))),
            no_size("favicon", 0),
        ),
    ];
    for (attachment, expected) in cases {
        let message = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_attachments(vec![attachment.clone()]);
        let reply = crate::EncryptReplyParams::new("conv-1", "hi", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-1")
            .with_attachments(vec![attachment]);
        for err in [
            core.encrypt_message(&message).unwrap_err(),
            core.encrypt_reply(&reply).unwrap_err(),
        ] {
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), expected);
        }
    }
}
