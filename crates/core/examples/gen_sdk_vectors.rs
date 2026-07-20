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
use chat_xdk_core::internals;
use chat_xdk_core::keys::conversation_keys::encrypt_conversation_key;
use chat_xdk_core::signatures::build_ckey_change_signature;
use chat_xdk_core::{ChatCore, EncryptMessageParams};
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
    core.import_keys(&private_concat).expect("import keys");
    let payload = core
        .encrypt_message(
            EncryptMessageParams::new(EVENT_CONVERSATION_ID, EVENT_MESSAGE_TEXT)
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
    core.set_identity(EVENT_SENDER_ID, EVENT_SIGNING_KEY_VERSION);
    let reply_valid = core
        .encrypt_reply(
            chat_xdk_core::EncryptReplyParams::new(
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

    let mut forged_params = chat_xdk_core::EncryptReplyParams::new(
        EVENT_CONVERSATION_ID,
        EVENT_REPLY_TEXT,
        event_message_b64.clone(),
    )
    .with_conversation_key(conversation_key.to_vec(), EVENT_CONVERSATION_KEY_VERSION);
    forged_params.reply_to_text = Some(EVENT_REPLY_FORGED_PREVIEW_TEXT.to_string());
    let reply_forged = core
        .encrypt_reply(forged_params)
        .expect("encrypt forged reply");
    let event_reply_forged_b64 = internals::frame_send_payload(
        &reply_forged,
        &reply_forged.message_id,
        EVENT_SENDER_ID,
        EVENT_CONVERSATION_ID,
    )
    .expect("frame forged reply event");

    let obj = json!({
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

    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
