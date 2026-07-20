//! Offline tests for the Rust example's crypto core.
//!
//! These drive the REAL `chat_xdk_core` binding through the same `ChatCore` the
//! bot uses — no mocking. They prove an actual encrypt -> decrypt round-trip and
//! that the binding reproduces the committed key vectors.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{EntityDescriptor, PublicKeyInput};
use chatbot_rs::chat_core::{prep_to_request, ChatCore, ReplyOptions};
use serde_json::Value;

fn load_vectors() -> Value {
    // examples/rust -> repo root is two directories up.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sdk_vectors.json");
    let data = std::fs::read_to_string(&path).expect("read sdk_vectors.json");
    serde_json::from_str(&data).expect("parse sdk_vectors.json")
}

fn loaded_core(v: &Value) -> ChatCore {
    let mut core = ChatCore::new();
    core.load_keys(v["private_keys_concat_b64"].as_str().unwrap(), "1")
        .expect("load_keys");
    core.set_identity(v["event_sender_id"].as_str().unwrap());
    core
}

fn conversation_key(v: &Value) -> XChatConversationKey {
    let raw = B64
        .decode(v["conversation_key_b64"].as_str().unwrap())
        .unwrap();
    XChatConversationKey::from_bytes(raw).unwrap()
}

#[test]
fn load_keys_matches_fixture_public_keys() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let keys = core.public_keys().expect("public_keys");
    assert_eq!(keys.identity, v["identity_public_b64"].as_str().unwrap());
    assert_eq!(keys.signing, v["signing_public_b64"].as_str().unwrap());
}

#[test]
fn generic_encrypt_decrypt_roundtrip() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    let plaintext = "hello from the rust example";
    let ciphertext = core.encrypt(plaintext, &key).expect("encrypt");
    assert_ne!(ciphertext, plaintext);
    assert_eq!(core.decrypt(&ciphertext, &key).expect("decrypt"), plaintext);
}

#[test]
fn conversation_key_prepare_and_decrypt_roundtrip() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let prepared = core
        .prepare_conversation_key_change(
            &[PublicKeyInput {
                user_id: "me".to_string(),
                public_key: v["identity_public_b64"].as_str().unwrap().to_string(),
                key_version: "1".to_string(),
            }],
            Some("conv-1"),
        )
        .expect("prepare_conversation_key_change");
    let expected = prepared
        .conversation_key
        .as_ref()
        .unwrap()
        .encoded()
        .to_vec();
    let decrypted = core
        .decrypt_conversation_key(&prepared.participant_keys[0].encrypted_key)
        .expect("decrypt_conversation_key");
    assert_eq!(decrypted.encoded(), expected.as_slice());
}

#[test]
fn encrypt_reply_produces_sendable_payload() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    let body = core
        .encrypt_reply(
            "6789:12345",
            "pong",
            &key,
            "1710000000000",
            ReplyOptions::default(),
        )
        .expect("encrypt_reply");
    assert!(!body.encoded_message_create_event.is_empty());
    assert!(!body.encoded_message_event_signature.is_empty());
    assert!(!body.message_id.is_empty());
}

#[test]
fn decrypt_batch_empty_is_safe() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let result = core.decrypt_batch(&[], &[]);
    assert!(result.messages.is_empty());
}

#[test]
fn decrypt_one_rejects_garbage() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let err = core.decrypt_one("not-valid-base64!!!", &Default::default(), &[]);
    assert!(err.is_err());
}

fn fixture_public_keys(v: &Value) -> Vec<PublicKeyInput> {
    vec![PublicKeyInput {
        user_id: "1000".to_string(),
        public_key: v["identity_public_b64"].as_str().unwrap().to_string(),
        key_version: "1".to_string(),
    }]
}

fn sorted_keys(obj: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = obj
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn prep_to_request_maps_the_rest_shape() {
    // The mapper output is exactly what the X API's write endpoints take;
    // a drifted field name here breaks every flow in the live e2e.
    let v = load_vectors();
    let core = loaded_core(&v);
    let keys = fixture_public_keys(&v);
    let prep = core
        .prepare_conversation_key_change(&keys, Some("1000:2000"))
        .expect("prepare_conversation_key_change");
    let signing = core.public_keys().expect("public_keys").signing;
    let body = prep_to_request(&prep, &signing);

    assert_eq!(
        body["conversation_key_version"].as_str().unwrap(),
        prep.conversation_key_version
    );
    let pks = body["conversation_participant_keys"].as_array().unwrap();
    assert_eq!(pks.len(), 1);
    assert_eq!(
        sorted_keys(&pks[0]),
        [
            "encrypted_conversation_key",
            "public_key_version",
            "user_id"
        ]
    );
    let sigs = body["action_signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 1);
    let sig = &sigs[0];
    assert_eq!(
        sig["message_id"].as_str().unwrap(),
        prep.action_signatures[0].message_id
    );
    assert!(!sig["encoded_message_event_detail"]
        .as_str()
        .unwrap()
        .is_empty());
    let inner = &sig["message_event_signature"];
    assert_eq!(inner["signing_public_key"].as_str().unwrap(), signing);
    assert!(!inner["signature"].as_str().unwrap().is_empty());
    assert!(!inner["public_key_version"].as_str().unwrap().is_empty());
    // CKCE signature payloads are withheld (they embed the plaintext key).
    assert!(sig.get("signature_payload").is_none());
}

#[test]
fn prepare_group_create_yields_two_signatures() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let keys = fixture_public_keys(&v);
    let prep = core
        .prepare_group_create(&keys, "g123", &["1000".to_string()], &["1000".to_string()])
        .expect("prepare_group_create");
    assert_eq!(prep.action_signatures.len(), 2);
    assert_eq!(prep.conversation_key.as_ref().unwrap().encoded().len(), 32);
}

#[test]
fn encrypt_reaction_produces_sendable_payload() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    // React by raw event: the target's conversation id and sequence id come
    // from the fixture event itself.
    let body = core
        .encrypt_reaction(
            true,
            v["event_message_b64"].as_str().unwrap(),
            "\u{1f44d}",
            &key,
            "1",
        )
        .expect("encrypt_reaction");
    let json = serde_json::to_value(&body).unwrap();
    assert_eq!(
        sorted_keys(&json),
        [
            "encoded_message_create_event",
            "encoded_message_event_signature",
            "message_id"
        ]
    );
}

#[test]
fn threaded_reply_with_entities_and_ttl() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    // Thread by raw event: the preview is derived from the fixture event and
    // the event is embedded for receiver-side validation. The key version
    // must be the one the fixture event was encrypted under.
    let body = core
        .encrypt_reply(
            v["event_conversation_id"].as_str().unwrap(),
            "@user hello",
            &key,
            v["event_conversation_key_version"].as_str().unwrap(),
            ReplyOptions {
                reply_to_event: Some(v["event_message_b64"].as_str().unwrap().to_string()),
                reply_to_ckces: None,
                entities: Some(vec![EntityDescriptor {
                    start: 0,
                    end: 5,
                    entity_type: "mention".to_string(),
                }]),
                attachments: None,
                ttl_msec: Some(60_000),
            },
        )
        .expect("encrypt_reply");
    assert!(!body.encoded_message_create_event.is_empty());
}

#[test]
fn media_stream_encrypt_decrypt_roundtrip() {
    // The chunked stream path the media flow uses: multi-chunk payload in,
    // identical bytes out, and truncation is detected.
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    let plaintext: Vec<u8> = (0..300_000u32)
        .map(|i| ((i * 31 + 7) % 256) as u8)
        .collect();

    let ciphertext = core.encrypt_media(&plaintext, &key).expect("encrypt_media");
    assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());
    assert_eq!(
        core.decrypt_media(&ciphertext, &key)
            .expect("decrypt_media"),
        plaintext
    );

    assert!(core
        .decrypt_media(&ciphertext[..ciphertext.len() - 4], &key)
        .is_err());
}
