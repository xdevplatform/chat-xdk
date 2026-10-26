//! Regenerates `tests/fixtures/sdk_vectors.json`.
//!
//! Key material, ids, and versions are fixed, so key-derived fields and the
//! ECDSA signature (RFC 6979, deterministic) are stable across runs. The
//! event vectors embed randomized ECIES/XSalsa20 output, so their bytes
//! differ per run — determinism for consumers comes from committing the
//! generated artifact, which every binding suite then verifies against.
//!
//!   cargo run -p chat-xdk-core --features internals --example gen_sdk_vectors > tests/fixtures/sdk_vectors.json

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::key_factory::KeyFactory;
use chat_xdk_core::crypto::keys::KeypairPurpose;
use chat_xdk_core::internals::{self, FixtureAttachment};
use chat_xdk_core::keys::conversation_keys::encrypt_conversation_key;
use chat_xdk_core::signatures::build_ckey_change_signature;
use chat_xdk_core::{
    AttachmentDescriptor, ChatCore, EncryptMessageParams, GroupDescriptionChangeParams,
};
use chat_xdk_core::{ImportKeysParams, SetIdentityParams};
use serde_json::json;

// Identities and versions embedded in the event vectors. Verifiers need the
// same values, so they are emitted alongside the events.
const EVENT_SENDER_ID: &str = "1111";
const EVENT_CONVERSATION_ID: &str = "1111:2222";
const EVENT_CONVERSATION_KEY_VERSION: &str = "1001";
const EVENT_SIGNING_KEY_VERSION: &str = "1";
const EVENT_RECIPIENT_KEY_VERSION: &str = "1";
const EVENT_MESSAGE_TEXT: &str = "fixture event message";
const EVENT_REPLY_TEXT: &str = "fixture reply message";
const EVENT_REPLY_FORGED_PREVIEW_TEXT: &str = "forged preview text";
const EVENT_GARBAGE: &str = "!!!not-an-event!!!";
const EVENT_GROUP_ID: &str = "g1111";
const EVENT_GROUP_DESCRIPTION: &str = "fixture group description, encrypted";

// Raw Thrift enum values embedded in the failure vector; suites assert the
// decoded names ("RateLimitUpsell" / "Premium", camelCased in JS).
const EVENT_FAILURE_TYPE_RATE_LIMIT_UPSELL: i32 = 12;
const EVENT_RATE_LIMIT_TIER_PREMIUM: i32 = 3;

// Per-message key known answers. The message-key events and media below are
// encrypted directly under the known message and attachment keys, so a suite
// that decrypts them with only the conversation key derived the same keys.
const MK_CONVERSATION_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MK_CONVERSATION_KEY_VERSION: &str = "2002";
const MK_SENDER_ID: &str = "1876543210987654321";
const MK_MESSAGE_ID: &str = "9d8c7b6a-5f4e-4d3c-8b2a-190807060504";
const MK_MESSAGE_KEY_HEX: &str = "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084";
const MK_FIRST_ATTACHMENT_KEY_HEX: &str =
    "1ef86545f91f8a3078e276949f7555df2ca584e9c6509b261a558a2e618a1b4b";
const MK_SECOND_ATTACHMENT_KEY_HEX: &str =
    "8a7bc01f2ff35c661140da68606b2370cecc13810f245d791aeb8ba6b40d4ea8";
const MK_MESSAGE_TEXT: &str = "fixture message-key message";
const MK_MEDIA_HASH_KEYS: [&str; 2] = ["fixture-media-1", "fixture-media-2"];
const MK_SHORT_CONVERSATION_KEY_HEX: &str =
    "c3a1f0e2d4b6987a5c3e1f0d2b4a6987c3a1f0e2d4b6987a5c3e1f0d2b4a6987";
const MK_SHORT_CONVERSATION_KEY_VERSION: &str = "3003";
const MK_SHORT_SENDER_ID: &str = "12";
const MK_SHORT_MESSAGE_ID: &str = "00000000-0000-4000-8000-000000000001";
const MK_SHORT_MESSAGE_KEY_HEX: &str =
    "685bd4a20c7efb64c99147ab5854560c72eac9a826b04880b64e1951d4ef4cc7";
const MK_SHORT_MESSAGE_TEXT: &str = "fixture short-sender message";
const MK_SHORT_ATTACHMENT_KEY_HEX: &str =
    "4f7d8ca1ef7cb1319743204496358333126086d0a23bdae26bbe5186ba8de093";
const MK_SHORT_MEDIA_HASH_KEY: &str = "fixture-short-media";
const MK_REPLY_TEXT: &str = "fixture reply to a message-key message";

// Media vectors. The link-card message reuses the known-answer sender and
// message id, so its card, the second attachment, is under the known second
// attachment key.
const LINK_CARD_TEXT: &str = "fixture link-card message";
const LINK_CARD_URL: &str = "https://example.com/fixture";
const LINK_CARD_PHOTO_HASH_KEY: &str = "fixture-link-photo";
const LINK_CARD_BANNER_HASH_KEY: &str = "fixture-link-banner";
const LINK_CARD_FAVICON_HASH_KEY: &str = "fixture-link-favicon";
const CKEY_MEDIA_TEXT: &str = "fixture conversation-key media message";
const CKEY_MEDIA_HASH_KEY: &str = "fixture-conversation-key-media";
const UNENCRYPTED_MESSAGE_ID: &str = "plain-msg-1";
const UNENCRYPTED_TEXT: &str = "fixture unencrypted message";
const UNENCRYPTED_MEDIA_HASH_KEY: &str = "fixture-plain-media";

// A known signature over a v10 message payload that signs
// contents_encryption_version 1; it must not verify once that is "null".
const PAYLOAD_MESSAGE_V10_CEV1: &str = "MessageCreateEvent,11111111-2222-3333-4444-555555555555,1491585161162473473,2:1491585161162473473,5,SGVsbG8,1,signature_version=10";
const PAYLOAD_MESSAGE_V10: &str = "MessageCreateEvent,11111111-2222-3333-4444-555555555555,1491585161162473473,2:1491585161162473473,5,SGVsbG8,null,signature_version=10";
const SIGNATURE_V10_CEV1_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+t366VDnLsZibo8mWYxvPQDuALQPpSydiQnR6GgvlHWaL2hjFuGhB6bkwqOgQMgpLNmtTd4sPVaXjxIkNLmKDg==";
const SIGNATURE_V10_CEV1_B64: &str =
    "W5rdZk1q13OBfVCSwyaWF+jTSotcS0Xrae24qOxntrrda81+BneKT8b3s0ZNHORaFd+QnzcQlzYNDSTF5vjn9A==";

fn hex_key(hex_str: &str) -> chat_xdk_core::crypto::keys::XChatConversationKey {
    KeyFactory::reconstruct_conversation_key(&hex::decode(hex_str).expect("hex key"))
        .expect("32-byte key")
}

fn encrypt_media(key_hex: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    chat_xdk_core::crypto::encryption::encrypt_file(&hex_key(key_hex), plaintext, &mut out)
        .expect("encrypt media");
    out
}

fn main() {
    // These are intentionally tiny scalars (1 and 2) so they're obviously valid P-256 keys.
    let identity_private: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let signing_private: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 2;
        b
    };
    let mut private_concat = Vec::with_capacity(64);
    private_concat.extend_from_slice(&identity_private);
    private_concat.extend_from_slice(&signing_private);

    let identity_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&identity_private, KeypairPurpose::Identity)
            .expect("valid identity key");
    let signing_kp =
        KeyFactory::get_keypair_from_private_key_bytes(&signing_private, KeypairPurpose::Signing)
            .expect("valid signing key");

    let message_utf8 = "chat-xdk test vector message";
    let signature =
        KeyFactory::sign(&signing_kp.private, message_utf8.as_bytes()).expect("sign should work");

    // Fixed 32-byte conversation key used for round-trip tests (ciphertext is
    // randomized) and as the key carried by the event vectors below.
    let conversation_key: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 3;
        b
    };

    // Plaintext used for XChaCha round-trip tests (ciphertext randomized).
    let plaintext = b"Hello, XCHAT!";

    // Binding signature the X API serves with a user's public keys: the
    // signing key signs the identity public key bytes as sent on the wire.
    let identity_binding_signature =
        KeyFactory::sign(&signing_kp.private, identity_kp.public.encoded())
            .expect("binding signature");

    // Event vectors: a signed KeyChange carrying the fixed conversation key
    // encrypted to the fixture identity, and a signed message encrypted
    // under that key, both framed as backend events.
    let ckey = KeyFactory::reconstruct_conversation_key(&conversation_key)
        .expect("valid conversation key");
    let encrypted_ckey =
        encrypt_conversation_key(&ckey, &identity_kp.public).expect("ECIES-encrypt ckey");
    let kc_signature = build_ckey_change_signature(
        &signing_kp.private,
        EVENT_SIGNING_KEY_VERSION,
        "kc-msg-1",
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        EVENT_CONVERSATION_KEY_VERSION,
        ckey.encoded(),
    )
    .expect("sign key change");
    let event_key_change_b64 = internals::frame_signed_key_change(
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        EVENT_CONVERSATION_KEY_VERSION,
        EVENT_SENDER_ID,
        &B64.encode(&encrypted_ckey),
        EVENT_RECIPIENT_KEY_VERSION,
        &kc_signature,
    )
    .expect("frame key change event");

    let core = ChatCore::new();
    core.import_keys(&ImportKeysParams::new(private_concat.to_vec()))
        .expect("import keys");
    let payload = core
        .encrypt_message(
            &EncryptMessageParams::new(EVENT_CONVERSATION_ID, EVENT_MESSAGE_TEXT)
                .with_identity(EVENT_SENDER_ID, EVENT_SIGNING_KEY_VERSION)
                .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION),
        )
        .expect("encrypt message");
    let event_message_b64 = internals::frame_send_payload(
        &payload,
        &payload.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame message event");

    // Reply vectors: a reply embedding the raw original event, once with the
    // derived (matching) preview and once with a forged preview text, so
    // binding suites can check both validation outcomes.
    core.set_identity(&SetIdentityParams::new(
        EVENT_SENDER_ID,
        EVENT_SIGNING_KEY_VERSION,
    ))
    .unwrap();
    let reply_valid = core
        .encrypt_reply(
            &chat_xdk_core::EncryptReplyParams::new(
                EVENT_CONVERSATION_ID,
                EVENT_REPLY_TEXT,
                event_message_b64.clone(),
            )
            .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION),
        )
        .expect("encrypt valid reply");
    let event_reply_valid_b64 = internals::frame_send_payload(
        &reply_valid,
        &reply_valid.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame valid reply event");

    let forged_params = chat_xdk_core::EncryptReplyParams::new(
        EVENT_CONVERSATION_ID,
        EVENT_REPLY_TEXT,
        event_message_b64.clone(),
    )
    .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION)
    .with_reply_to_text(EVENT_REPLY_FORGED_PREVIEW_TEXT);
    let reply_forged = core
        .encrypt_reply(&forged_params)
        .expect("encrypt forged reply");
    let event_reply_forged_b64 = internals::frame_send_payload(
        &reply_forged,
        &reply_forged.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame forged reply event");

    // Group description vector: a signed description change whose
    // description is encrypted under the fixture conversation key, so every
    // suite can check decrypt_event returns it decrypted.
    let description_change = core
        .prepare_group_description_change(
            &GroupDescriptionChangeParams::new(EVENT_GROUP_ID, EVENT_GROUP_DESCRIPTION)
                .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION),
        )
        .expect("prepare group description change");
    let event_group_description_b64 = internals::frame_action_signature(
        &description_change.action_signatures[0],
        EVENT_SENDER_ID,
        EVENT_GROUP_ID,
    )
    .expect("frame group description change");

    // Failure vector: an unsigned RATE_LIMIT_UPSELL failure carrying the
    // PREMIUM tier, so every suite can pin the decoded failure metadata.
    let event_failure_b64 = internals::frame_failure_event(
        "failure-msg-1",
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        EVENT_FAILURE_TYPE_RATE_LIMIT_UPSELL,
        Some(EVENT_RATE_LIMIT_TIER_PREMIUM),
    )
    .expect("frame failure event");

    // Message-key vectors: a v10 message from the known-answer sender with
    // two media attachments without ids, the media encrypted under the
    // known attachment keys, a signed key change carrying its conversation
    // key, a v11 message from a short sender id with one media attachment,
    // and a reply under the fixture conversation key that carries the
    // quoted message's key.
    let event_message_key_b64 = internals::frame_message_key_event(
        &signing_kp.private,
        EVENT_SIGNING_KEY_VERSION,
        MK_SENDER_ID,
        EVENT_CONVERSATION_ID,
        MK_MESSAGE_ID,
        MK_CONVERSATION_KEY_VERSION,
        &hex_key(MK_MESSAGE_KEY_HEX),
        MK_MESSAGE_TEXT,
        &MK_MEDIA_HASH_KEYS.map(FixtureAttachment::Media),
        10,
    )
    .expect("frame message-key event");
    let media_first_plaintext: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
    let media_second_plaintext = b"fixture media two".to_vec();
    let media_first_encrypted = encrypt_media(MK_FIRST_ATTACHMENT_KEY_HEX, &media_first_plaintext);
    let media_second_encrypted =
        encrypt_media(MK_SECOND_ATTACHMENT_KEY_HEX, &media_second_plaintext);

    let mk_ckey = hex_key(MK_CONVERSATION_KEY_HEX);
    let mk_kc_signature = build_ckey_change_signature(
        &signing_kp.private,
        EVENT_SIGNING_KEY_VERSION,
        "kc-msg-2",
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        MK_CONVERSATION_KEY_VERSION,
        mk_ckey.encoded(),
    )
    .expect("sign message-key key change");
    let event_key_change_message_key_b64 = internals::frame_signed_key_change(
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        MK_CONVERSATION_KEY_VERSION,
        EVENT_SENDER_ID,
        &B64.encode(encrypt_conversation_key(&mk_ckey, &identity_kp.public).expect("ECIES")),
        EVENT_RECIPIENT_KEY_VERSION,
        &mk_kc_signature,
    )
    .expect("frame message-key key change");

    let event_message_key_short_b64 = internals::frame_message_key_event(
        &signing_kp.private,
        EVENT_SIGNING_KEY_VERSION,
        MK_SHORT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        MK_SHORT_MESSAGE_ID,
        MK_SHORT_CONVERSATION_KEY_VERSION,
        &hex_key(MK_SHORT_MESSAGE_KEY_HEX),
        MK_SHORT_MESSAGE_TEXT,
        &[FixtureAttachment::Media(MK_SHORT_MEDIA_HASH_KEY)],
        11,
    )
    .expect("frame short-sender message-key event");
    let media_short_plaintext = b"fixture short-sender media".to_vec();
    let media_short_encrypted = encrypt_media(MK_SHORT_ATTACHMENT_KEY_HEX, &media_short_plaintext);

    // Media vectors: a link card next to a photo, a conversation-key message
    // with one media attachment, and an unencrypted message with one.
    let event_link_card_b64 = internals::frame_message_key_event(
        &signing_kp.private,
        EVENT_SIGNING_KEY_VERSION,
        MK_SENDER_ID,
        EVENT_CONVERSATION_ID,
        MK_MESSAGE_ID,
        MK_CONVERSATION_KEY_VERSION,
        &hex_key(MK_MESSAGE_KEY_HEX),
        LINK_CARD_TEXT,
        &[
            FixtureAttachment::Media(LINK_CARD_PHOTO_HASH_KEY),
            FixtureAttachment::LinkCard {
                url: LINK_CARD_URL,
                banner: LINK_CARD_BANNER_HASH_KEY,
                favicon: LINK_CARD_FAVICON_HASH_KEY,
            },
        ],
        10,
    )
    .expect("frame link-card event");
    let media_banner_plaintext = b"fixture link-card banner".to_vec();
    let media_favicon_plaintext = b"fixture link-card favicon".to_vec();
    let media_banner_encrypted =
        encrypt_media(MK_SECOND_ATTACHMENT_KEY_HEX, &media_banner_plaintext);
    let media_favicon_encrypted =
        encrypt_media(MK_SECOND_ATTACHMENT_KEY_HEX, &media_favicon_plaintext);

    let ckey_media_params = EncryptMessageParams::new(EVENT_CONVERSATION_ID, CKEY_MEDIA_TEXT)
        .with_identity(EVENT_SENDER_ID, EVENT_SIGNING_KEY_VERSION)
        .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION)
        .with_attachments(vec![AttachmentDescriptor::Media {
            media_hash_key: CKEY_MEDIA_HASH_KEY.to_string(),
            width: 4,
            height: 3,
            filesize_bytes: 1500,
            filename: "fixture.jpg".to_string(),
            media_type: Some(1),
            duration_millis: None,
        }]);
    let ckey_media_payload = core
        .encrypt_message(&ckey_media_params)
        .expect("encrypt conversation-key media message");
    let event_conversation_key_media_b64 = internals::frame_send_payload(
        &ckey_media_payload,
        &ckey_media_payload.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame conversation-key media message");
    let media_conversation_key_plaintext: Vec<u8> = (0..1500u32).map(|i| (i % 241) as u8).collect();
    let mut media_conversation_key_encrypted = Vec::new();
    chat_xdk_core::crypto::encryption::encrypt_file(
        &ckey,
        media_conversation_key_plaintext.as_slice(),
        &mut media_conversation_key_encrypted,
    )
    .expect("encrypt conversation-key media");

    let event_unencrypted_b64 = internals::frame_unencrypted_message_event(
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
        UNENCRYPTED_MESSAGE_ID,
        UNENCRYPTED_TEXT,
        &[FixtureAttachment::Media(UNENCRYPTED_MEDIA_HASH_KEY)],
    )
    .expect("frame unencrypted message");

    // The replier holds the quoted message's conversation key only in its
    // key cache, so the reply carries the derived message key and embeds
    // no key change.
    let replier = ChatCore::new();
    replier
        .import_keys(
            &ImportKeysParams::new(private_concat.to_vec())
                .with_signing_key_version(EVENT_RECIPIENT_KEY_VERSION),
        )
        .expect("import keys");
    replier
        .set_identity(&SetIdentityParams::new(
            EVENT_SENDER_ID,
            EVENT_SIGNING_KEY_VERSION,
        ))
        .unwrap();
    replier.set_cache_keys(true);
    let fixture_signing_keys = [chat_xdk_core::SigningKeyEntry::new(
        EVENT_SENDER_ID,
        EVENT_SIGNING_KEY_VERSION,
        B64.encode(signing_kp.public.encoded()),
        B64.encode(identity_kp.public.encoded()),
        B64.encode(&identity_binding_signature),
    )];
    let cached = replier.decrypt_events(
        chat_xdk_core::DecryptEventsParams::new(vec![event_key_change_message_key_b64.clone()])
            .with_signing_keys(fixture_signing_keys.to_vec()),
    );
    assert!(cached.errors.is_empty(), "{:?}", cached.errors);
    let reply_message_key = replier
        .encrypt_reply(
            &chat_xdk_core::EncryptReplyParams::new(
                EVENT_CONVERSATION_ID,
                MK_REPLY_TEXT,
                event_message_key_b64.clone(),
            )
            .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION),
        )
        .expect("encrypt reply to message-key message");
    let event_reply_message_key_b64 = internals::frame_send_payload(
        &reply_message_key,
        &reply_message_key.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame reply to message-key message");

    let mut obj = json!({
        "identity_private_b64": B64.encode(identity_private),
        "signing_private_b64": B64.encode(signing_private),
        "private_keys_concat_b64": B64.encode(private_concat),
        "message_utf8": message_utf8,
        "conversation_key_b64": B64.encode(conversation_key),
        "plaintext_b64": B64.encode(plaintext),
        "identity_public_b64": B64.encode(identity_kp.public.encoded()),
        "signing_public_b64": B64.encode(signing_kp.public.encoded()),
        "signature_b64": B64.encode(signature),
        "identity_public_key_signature_b64": B64.encode(identity_binding_signature),
        "event_failure_b64": event_failure_b64,
        "event_group_description_b64": event_group_description_b64,
        "event_group_description": EVENT_GROUP_DESCRIPTION,
        "event_group_id": EVENT_GROUP_ID,
        "event_key_change_b64": event_key_change_b64,
        "event_message_b64": event_message_b64,
        "event_reply_valid_b64": event_reply_valid_b64,
        "event_reply_forged_b64": event_reply_forged_b64,
        "event_reply_text": EVENT_REPLY_TEXT,
        "event_reply_forged_preview_text": EVENT_REPLY_FORGED_PREVIEW_TEXT,
        "event_garbage_b64": EVENT_GARBAGE,
        "event_sender_id": EVENT_SENDER_ID,
        "event_conversation_id": EVENT_CONVERSATION_ID,
        "event_conversation_key_version": EVENT_CONVERSATION_KEY_VERSION,
        "event_signing_key_version": EVENT_SIGNING_KEY_VERSION,
        "event_recipient_key_version": EVENT_RECIPIENT_KEY_VERSION,
        "event_message_text": EVENT_MESSAGE_TEXT,
    });
    let message_key_vectors = json!({
        "message_key_conversation_key_hex": MK_CONVERSATION_KEY_HEX,
        "message_key_conversation_key_version": MK_CONVERSATION_KEY_VERSION,
        "message_key_sender_id": MK_SENDER_ID,
        "message_key_message_id": MK_MESSAGE_ID,
        "message_key_hex": MK_MESSAGE_KEY_HEX,
        "message_key_first_attachment_key_hex": MK_FIRST_ATTACHMENT_KEY_HEX,
        "message_key_second_attachment_key_hex": MK_SECOND_ATTACHMENT_KEY_HEX,
        "message_key_short_conversation_key_hex": MK_SHORT_CONVERSATION_KEY_HEX,
        "message_key_short_conversation_key_version": MK_SHORT_CONVERSATION_KEY_VERSION,
        "message_key_short_sender_id": MK_SHORT_SENDER_ID,
        "message_key_short_message_id": MK_SHORT_MESSAGE_ID,
        "message_key_short_hex": MK_SHORT_MESSAGE_KEY_HEX,
        "event_message_key_b64": event_message_key_b64,
        "event_message_key_text": MK_MESSAGE_TEXT,
        "event_message_key_short_b64": event_message_key_short_b64,
        "event_message_key_short_text": MK_SHORT_MESSAGE_TEXT,
        "event_key_change_message_key_b64": event_key_change_message_key_b64,
        "event_reply_message_key_b64": event_reply_message_key_b64,
        "event_reply_message_key_text": MK_REPLY_TEXT,
        "payload_message_v10_cev1": PAYLOAD_MESSAGE_V10_CEV1,
        "payload_message_v10": PAYLOAD_MESSAGE_V10,
        "signature_v10_cev1_public_key_b64": SIGNATURE_V10_CEV1_PUBLIC_KEY_B64,
        "signature_v10_cev1_b64": SIGNATURE_V10_CEV1_B64,
    });
    let media_vectors = json!({
        "message_key_short_attachment_key_hex": MK_SHORT_ATTACHMENT_KEY_HEX,
        "media_first_hash_key": MK_MEDIA_HASH_KEYS[0],
        "media_first_encrypted_b64": B64.encode(&media_first_encrypted),
        "media_first_plaintext_b64": B64.encode(&media_first_plaintext),
        "media_second_hash_key": MK_MEDIA_HASH_KEYS[1],
        "media_second_encrypted_b64": B64.encode(&media_second_encrypted),
        "media_second_plaintext_b64": B64.encode(&media_second_plaintext),
        "media_short_hash_key": MK_SHORT_MEDIA_HASH_KEY,
        "media_short_encrypted_b64": B64.encode(&media_short_encrypted),
        "media_short_plaintext_b64": B64.encode(&media_short_plaintext),
        "event_link_card_b64": event_link_card_b64,
        "media_banner_hash_key": LINK_CARD_BANNER_HASH_KEY,
        "media_banner_encrypted_b64": B64.encode(&media_banner_encrypted),
        "media_banner_plaintext_b64": B64.encode(&media_banner_plaintext),
        "media_favicon_hash_key": LINK_CARD_FAVICON_HASH_KEY,
        "media_favicon_encrypted_b64": B64.encode(&media_favicon_encrypted),
        "media_favicon_plaintext_b64": B64.encode(&media_favicon_plaintext),
        "event_conversation_key_media_b64": event_conversation_key_media_b64,
        "media_conversation_key_hash_key": CKEY_MEDIA_HASH_KEY,
        "media_conversation_key_encrypted_b64": B64.encode(&media_conversation_key_encrypted),
        "media_conversation_key_plaintext_b64": B64.encode(&media_conversation_key_plaintext),
        "event_unencrypted_b64": event_unencrypted_b64,
        "media_unencrypted_hash_key": UNENCRYPTED_MEDIA_HASH_KEY,
    });
    for vectors in [message_key_vectors, media_vectors] {
        if let (Some(all), serde_json::Value::Object(extra)) = (obj.as_object_mut(), vectors) {
            all.extend(extra);
        }
    }

    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
