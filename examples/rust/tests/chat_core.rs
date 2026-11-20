//! Offline tests for the Rust example's crypto core.
//!
//! These drive the REAL `chat_xdk_core` binding through the same `ChatCore` the
//! bot uses — no mocking. They prove an actual encrypt -> decrypt round-trip and
//! that the binding reproduces the committed key vectors. The X API is the one
//! thing faked: a directory of users' public keys and one page of events.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{
    AttachmentDescriptor, EntityDescriptor, MissingSigningKey, PreparedConversationChange,
    PublicKeyInput, PublicKeyRecord,
};
use chatbot_rs::bot::Bot;
use chatbot_rs::chat_core::{
    prep_to_request, removal_to_request, ChatCore, ReplyOptions, SendBody,
};
use chatbot_rs::x_api::{ChatApi, EventItem};
use common::{delivered, key_change_and_message, party, public_keys_of, texts};
use serde_json::{json, Value};

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
    core.set_identity(v["event_sender_id"].as_str().unwrap())
        .expect("set_identity");
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
fn set_identity_needs_the_registered_version() {
    // Freshly generated keys have no registered version yet, so the bot
    // cannot sign as itself until load_keys or set_registered_version
    // provides one.
    let core = ChatCore::new();
    core.generate_and_register().expect("generate_and_register");
    let err = core.set_identity("12345").unwrap_err();
    assert!(
        err.to_string().contains("signing key version unknown"),
        "{err}"
    );
}

#[test]
fn group_title_change_encrypts_the_title_it_signs() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    let title = "hello from the rust example";
    let prepared = core
        .prepare_group_title_change("g123", title, &key, "1")
        .expect("prepare_group_title_change");
    assert_ne!(prepared.encrypted_value, title);
    assert_eq!(prepared.conversation_key_version, "1");
    assert_eq!(
        core.decrypt(&prepared.encrypted_value, &key)
            .expect("decrypt"),
        title
    );
}

#[test]
fn conversation_key_prepare_and_decrypt_roundtrip() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let prepared = core
        .prepare_conversation_key_change(
            &[PublicKeyInput::new(
                "910002",
                v["identity_public_b64"].as_str().unwrap(),
                "1",
            )],
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
        .decrypt_conversation_key(
            &prepared.conversation_participant_keys[0].encrypted_conversation_key,
        )
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
            ReplyOptions::default().with_conversation_key(&key, "1710000000000"),
        )
        .expect("encrypt_reply");
    assert!(!body.encoded_message_create_event.is_empty());
    assert!(!body.encoded_message_event_signature.is_empty());
    assert!(!body.message_id.is_empty());
    assert!(!body.xdk_version.is_empty());
}

#[test]
fn decrypt_batch_empty_is_safe() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let result = core.decrypt_batch(&[]);
    assert!(result.events.is_empty());
}

#[test]
fn decrypt_one_rejects_garbage() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let err = core.decrypt_one("not-valid-base64!!!", &Default::default());
    assert!(err.is_err());
}

fn fixture_public_keys(v: &Value) -> Vec<PublicKeyInput> {
    vec![PublicKeyInput::new(
        "1000",
        v["identity_public_b64"].as_str().unwrap(),
        "1",
    )]
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
    let body = prep_to_request(&prep);

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
}

#[test]
fn removal_to_request_rotates_for_members_who_stay() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let keys = fixture_public_keys(&v);
    let removed = "2000".to_string();
    let prep = core
        .prepare_group_members_remove(&keys, "g123", &[removed.clone()], &[])
        .expect("prepare_group_members_remove");
    let body = removal_to_request(&[removed.clone()], &prep);

    assert_eq!(body["user_ids"], json!([removed]));
    let sigs = body["action_signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2);
    let rotation = &body["group_key_rotation_data"];
    assert_eq!(
        rotation["conversation_key_version"].as_str().unwrap(),
        prep.conversation_key_version
    );
    let pks = rotation["conversation_participant_keys"]
        .as_array()
        .unwrap();
    assert_eq!(pks.len(), 1);
    assert_eq!(pks[0]["user_id"].as_str().unwrap(), "1000");
    assert_eq!(
        sorted_keys(&pks[0]),
        [
            "encrypted_conversation_key",
            "public_key_version",
            "user_id"
        ]
    );
    assert!(body.get("conversation_key_version").is_none());
    assert!(body.get("conversation_participant_keys").is_none());
}

#[test]
fn prepare_group_create_yields_two_signatures() {
    let v = load_vectors();
    let core = loaded_core(&v);
    let keys = fixture_public_keys(&v);
    let title = "hello from the rust example";
    let prep = core
        .prepare_group_create(
            &keys,
            "g123",
            &["1000".to_string()],
            &["1000".to_string()],
            Some(title),
        )
        .expect("prepare_group_create");
    assert_eq!(prep.action_signatures.len(), 2);
    let key = prep.conversation_key.as_ref().unwrap();
    assert_eq!(key.encoded().len(), 32);
    // The title goes out encrypted under the new key: the group_name the
    // create request sends.
    let encrypted_title = prep.encrypted_title.as_deref().expect("encrypted title");
    assert_eq!(core.decrypt(encrypted_title, key).expect("decrypt"), title);
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
            "message_id",
            "xdk_version"
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
            ReplyOptions {
                reply_to_event: Some(v["event_message_b64"].as_str().unwrap().to_string()),
                reply_to_ckces: None,
                entities: Some(vec![EntityDescriptor::new(0, 5, "mention")]),
                attachments: None,
                quick_reply: None,
                ttl_msec: Some(60_000),
                ..Default::default()
            }
            .with_conversation_key(&key, v["event_conversation_key_version"].as_str().unwrap()),
        )
        .expect("encrypt_reply");
    assert!(!body.encoded_message_create_event.is_empty());
}

#[test]
fn media_encrypt_decrypt_roundtrip() {
    // The message-first media flow: the message names the file by the media
    // hash key its upload started with, the file is encrypted from the
    // message's event_b64 in chunks, and it decrypts through that event. A
    // truncated file is detected.
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = conversation_key(&v);
    let keys = HashMap::from([("1".to_string(), key.clone())]);
    let plaintext: Vec<u8> = (0..300_000u32)
        .map(|i| ((i * 31 + 7) % 256) as u8)
        .collect();
    let encrypted_size = chat_xdk_core::utils::encrypted_file_size(plaintext.len() as u64)
        .expect("encrypted_file_size");
    let body = core
        .encrypt_reply(
            "1000:2000",
            "a photo",
            ReplyOptions {
                attachments: Some(vec![AttachmentDescriptor::Media {
                    media_hash_key: "photo".to_string(),
                    width: 4,
                    height: 3,
                    filesize_bytes: encrypted_size as i64,
                    filename: "photo.bin".to_string(),
                    media_type: Some(5),
                    duration_millis: None,
                    plaintext_sha256: None,
                }]),
                ..Default::default()
            }
            .with_conversation_key(&key, "1"),
        )
        .expect("encrypt_reply (media)");
    assert!(!body.event_b64.is_empty());

    let ciphertext = core
        .encrypt_media(&plaintext, &body.event_b64, &key, "1", "photo")
        .expect("encrypt_media");
    assert_eq!(ciphertext.len() as u64, encrypted_size);
    assert_eq!(
        core.decrypt_media(&ciphertext, &body.event_b64, &keys, "photo")
            .expect("decrypt_media"),
        plaintext
    );
    let err = core
        .decrypt_media(
            &ciphertext[..ciphertext.len() - 4],
            &body.event_b64,
            &keys,
            "photo",
        )
        .unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
}

#[test]
fn media_from_the_fixture_message_opens() {
    // Media encrypted by another client opens through its message's event.
    let v = load_vectors();
    let core = loaded_core(&v);
    let key = XChatConversationKey::from_bytes(
        chat_xdk_core::utils::hex_to_bytes(v["message_key_conversation_key_hex"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let keys = HashMap::from([(
        v["message_key_conversation_key_version"]
            .as_str()
            .unwrap()
            .to_string(),
        key,
    )]);
    let b64 = |field: String| B64.decode(v[field.as_str()].as_str().unwrap()).unwrap();
    for name in ["first", "second"] {
        assert_eq!(
            core.decrypt_media(
                &b64(format!("media_{name}_encrypted_b64")),
                v["event_message_key_b64"].as_str().unwrap(),
                &keys,
                v[format!("media_{name}_hash_key").as_str()]
                    .as_str()
                    .unwrap(),
            )
            .expect("decrypt_media"),
            b64(format!("media_{name}_plaintext_b64")),
        );
    }
}

/// The group the tests' key changes and messages belong to.
const GROUP: &str = "g900";

/// The X API as the bot sees it, offline: users' public keys, one page of
/// events, and a record of the keys it was asked for and the messages it
/// was sent.
#[derive(Default)]
struct FakeApi {
    /// Each user's public-key records, by user id.
    directory: HashMap<String, Vec<PublicKeyRecord>>,
    /// The data events of the page.
    events: Vec<EventItem>,
    /// The key events of the page.
    key_events: Vec<String>,
    /// The users whose public keys were asked for, in order.
    asked: Arc<Mutex<Vec<String>>>,
    /// Each message sent: its conversation and its body.
    sent: Arc<Mutex<Vec<(String, SendBody)>>>,
}

impl ChatApi for FakeApi {
    fn get_my_user_id(&self) -> Result<String, String> {
        Err("the fake API has no account".to_string())
    }

    fn get_public_keys(&self, user_id: &str) -> Result<Vec<PublicKeyRecord>, String> {
        self.asked.lock().unwrap().push(user_id.to_string());
        self.directory
            .get(user_id)
            .cloned()
            .ok_or_else(|| format!("no public keys for user {user_id}"))
    }

    fn get_events(
        &self,
        _conversation_id: &str,
        _max_results: u32,
        _pagination_token: Option<&str>,
    ) -> Result<(Vec<EventItem>, Vec<String>, Option<String>), String> {
        Ok((self.events.clone(), self.key_events.clone(), None))
    }

    fn send_message(&self, conversation_id: &str, body: &SendBody) -> Result<(), String> {
        self.sent
            .lock()
            .unwrap()
            .push((conversation_id.to_string(), body.clone()));
        Ok(())
    }

    fn get_feature_switches(&self, _url: &str) -> Option<(u16, Vec<u8>)> {
        None
    }
}

/// Have `core` fetch the public keys it lacks from a fake X API that holds
/// `directory`, the way the bot has it fetch them from the X API. Returns
/// the users whose keys the SDK then asks for, in order.
fn fetch_public_keys_from(
    core: &ChatCore,
    directory: HashMap<String, Vec<PublicKeyRecord>>,
) -> Arc<Mutex<Vec<String>>> {
    let api = FakeApi {
        directory,
        ..Default::default()
    };
    let asked = Arc::clone(&api.asked);
    core.fetch_public_keys_with(move |user_id| api.get_public_keys(user_id));
    asked
}

/// The users a prepared change encrypts its key to, sorted.
fn recipients(prepared: &PreparedConversationChange) -> Vec<&str> {
    let mut user_ids: Vec<&str> = prepared
        .conversation_participant_keys
        .iter()
        .map(|key| key.user_id.as_str())
        .collect();
    user_ids.sort_unstable();
    user_ids
}

#[test]
fn decrypt_batch_fetches_the_keys_of_the_member_who_made_a_key_change() {
    // An admin rotates a group's key and a member sends a message under it:
    // the admin signed the key change and sent no message on the page.
    let (admin, member, bot) = (party("5001"), party("5002"), party("5003"));
    let (key_change, message) = key_change_and_message(
        &admin,
        &[&admin, &member, &bot],
        &member,
        GROUP,
        "hello group",
    );
    let events = [key_change.as_str(), message.as_str()];

    // With nothing to fetch public keys with, the result names the signing
    // key each event lacked. The key change does not verify: its key is
    // dropped and the message does not decrypt.
    let unverified = bot.core.decrypt_batch(&events);
    assert!(unverified.events.is_empty());
    assert_eq!(
        unverified.missing_signing_keys,
        HashMap::from([
            (0, MissingSigningKey::new("5001", "1")),
            (1, MissingSigningKey::new("5002", "1")),
        ])
    );

    // The SDK fetches the keys of both senders, the admin's as well, and
    // decrypts the page with them.
    let asked = fetch_public_keys_from(&bot.core, public_keys_of(&[&admin, &member]));
    let result = bot.core.decrypt_batch(&events);
    assert_eq!(*asked.lock().unwrap(), ["5001", "5002"]);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.missing_signing_keys.is_empty());
    assert!(result.unverified_key_changes.is_empty());
    assert_eq!(texts(&result), [None, Some("hello group")]);

    // The SDK stored the keys: the next page needs no fetch.
    bot.core.decrypt_batch(&events);
    assert_eq!(asked.lock().unwrap().len(), 2);
}

#[test]
fn a_failed_public_key_fetch_leaves_the_other_users_keys_arriving() {
    let (admin, member, bot) = (party("5001"), party("5002"), party("5003"));
    let (key_change, message) = key_change_and_message(
        &admin,
        &[&admin, &member, &bot],
        &member,
        GROUP,
        "hello group",
    );
    let events = [key_change.as_str(), message.as_str()];

    // The X API holds the admin's keys alone: the member's fetch fails.
    let asked = fetch_public_keys_from(&bot.core, public_keys_of(&[&admin]));
    let result = bot.core.decrypt_batch(&events);
    assert_eq!(*asked.lock().unwrap(), ["5001", "5002"]);

    // The key change verifies with the admin's keys, and the result names
    // the key the member's message still lacks.
    assert!(result.unverified_key_changes.is_empty());
    assert_eq!(texts(&result), [None::<&str>]);
    assert_eq!(
        result.missing_signing_keys,
        HashMap::from([(1, MissingSigningKey::new("5002", "1"))])
    );

    // The SDK remembers the lookup that brought no key: the next page does
    // not repeat it.
    bot.core.decrypt_batch(&events);
    assert_eq!(asked.lock().unwrap().len(), 2);
}

#[test]
fn prepare_calls_fetch_the_public_keys_they_are_not_passed() {
    let (admin, member) = (party("5001"), party("5002"));
    let asked = fetch_public_keys_from(&admin.core, public_keys_of(&[&admin, &member]));

    // A one-to-one named by the other user's id: the SDK fetches the
    // identity keys of both users.
    let direct = admin
        .core
        .prepare_conversation_key_change(&[], Some("5002"))
        .expect("prepare_conversation_key_change");
    assert_eq!(direct.conversation_id, "5001:5002");
    assert_eq!(recipients(&direct), ["5001", "5002"]);
    assert_eq!(*asked.lock().unwrap(), ["5001", "5002"]);

    // The SDK stored the keys: the group calls, which name their members,
    // need no fetch.
    let members = [admin.user_id.clone(), member.user_id.clone()];
    let created = admin
        .core
        .prepare_group_create(&[], GROUP, &members, &members[..1], None)
        .expect("prepare_group_create");
    assert_eq!(recipients(&created), ["5001", "5002"]);
    let removed = admin
        .core
        .prepare_group_members_remove(&[], GROUP, &members[1..], &members[..1])
        .expect("prepare_group_members_remove");
    assert_eq!(recipients(&removed), ["5001"]);
    assert_eq!(asked.lock().unwrap().len(), 2);
}

#[test]
fn the_bot_replies_to_a_message_under_a_key_change_whose_signer_sent_no_message() {
    let (admin, member, bot) = (party("5001"), party("5002"), party("5003"));
    let (key_change, message) = key_change_and_message(
        &admin,
        &[&admin, &member, &bot],
        &member,
        GROUP,
        "hello group",
    );
    let directory = public_keys_of(&[&admin, &member, &bot]);

    // The page as the X API returns it: the message in its data, the key
    // change apart, among its key events.
    let api = FakeApi {
        directory: directory.clone(),
        events: vec![EventItem {
            encoded_event: message,
            sender_id: member.user_id.clone(),
            id: "2100000000000000001".to_string(),
        }],
        key_events: vec![key_change.clone()],
        ..Default::default()
    };
    let (asked, sent) = (Arc::clone(&api.asked), Arc::clone(&api.sent));
    let mut chatbot = Bot::new(bot.core, api, bot.user_id).expect("Bot::new");
    chatbot.poll_once(GROUP).expect("poll_once");

    // The bot's SDK fetched the keys of the admin, who sent no message, and
    // of the member, and the bot answered the member's message.
    assert_eq!(*asked.lock().unwrap(), ["5001", "5002"]);
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let (conversation_id, body) = &sent[0];
    assert_eq!(conversation_id.as_str(), GROUP);

    // The member reads the reply under the key of the key change.
    let reply = delivered(&body.event_b64, "2100000000000000002");
    fetch_public_keys_from(&member.core, directory);
    let read = member
        .core
        .decrypt_batch(&[key_change.as_str(), reply.as_str()]);
    assert!(read.errors.is_empty(), "{:?}", read.errors);
    assert_eq!(texts(&read), [None, Some("You said: hello group")]);
}
