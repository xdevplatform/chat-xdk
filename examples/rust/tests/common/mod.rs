//! What the example's offline tests share: users with fresh keys, and a
//! group's events as the X API delivers them.

// Each test file is a crate of its own and uses some of these helpers.
#![allow(dead_code)]

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::signatures::ActionSignature;
use chat_xdk_core::{DecryptEventsResult, PublicKeyInput, PublicKeyRecord};
use chatbot_rs::chat_core::{message_text, ChatCore, ReplyOptions};

/// A Thrift string field: its id, then the value's length and bytes.
fn thrift_string(id: u16, value: &str) -> Vec<u8> {
    let mut field = vec![11];
    field.extend(id.to_be_bytes());
    field.extend((value.len() as u32).to_be_bytes());
    field.extend(value.as_bytes());
    field
}

/// `event_b64` as delivered: with the sequence id the server assigns,
/// prepended as Thrift string field 1.
pub fn delivered(event_b64: &str, sequence_id: &str) -> String {
    let mut event = thrift_string(1, sequence_id);
    event.extend(B64.decode(event_b64).unwrap());
    B64.encode(event)
}

/// A signed action as delivered: the event the server relays for `action`,
/// an entry of a prepared change's `action_signatures`, from `sender_id` in
/// `conversation_id`, with the sequence id the server assigns.
pub fn delivered_action(
    action: &ActionSignature,
    sender_id: &str,
    conversation_id: &str,
    sequence_id: &str,
) -> String {
    let signed = &action.message_event_signature;
    let mut event = thrift_string(1, sequence_id);
    event.extend(thrift_string(2, &action.message_id));
    event.extend(thrift_string(3, sender_id));
    event.extend(thrift_string(4, conversation_id));
    event.extend([12, 0, 7]);
    event.extend(B64.decode(&action.encoded_message_event_detail).unwrap());
    event.extend([12, 0, 9]);
    event.extend(thrift_string(1, &signed.signature));
    event.extend(thrift_string(2, &signed.public_key_version));
    event.extend(thrift_string(3, &signed.signature_version));
    event.extend([0, 0]);
    B64.encode(event)
}

/// A core with fresh keys as a user, and the keys others hold for it.
pub struct Party {
    pub core: ChatCore,
    pub user_id: String,
    /// The record the X API returns for the user's public keys.
    pub record: PublicKeyRecord,
    pub public_key: PublicKeyInput,
}

/// A user with fresh keys.
pub fn party(user_id: &str) -> Party {
    party_with_keys(user_id).0
}

/// A user with fresh keys, and the private-key blob that loads those keys
/// into another chat. The keys are registered under version "1".
pub fn party_with_keys(user_id: &str) -> (Party, String) {
    let mut core = ChatCore::new();
    let (payload, private_keys_b64) = core.generate_and_register().expect("generate_and_register");
    core.load_keys(&private_keys_b64, "1").expect("load_keys");
    core.set_identity(user_id).expect("set_identity");
    let registration = payload.public_key;
    let party = Party {
        core,
        user_id: user_id.to_string(),
        record: PublicKeyRecord::new(
            "1",
            registration.public_key.as_str(),
            registration.signing_public_key.as_str(),
            registration.identity_public_key_signature.as_str(),
        ),
        public_key: PublicKeyInput::new(user_id, registration.public_key.as_str(), "1"),
    };
    (party, private_keys_b64)
}

/// The X API's public keys of `parties`: each user's records, by user id.
pub fn public_keys_of(parties: &[&Party]) -> HashMap<String, Vec<PublicKeyRecord>> {
    parties
        .iter()
        .map(|party| (party.user_id.clone(), vec![party.record.clone()]))
        .collect()
}

/// The page that follows a key rotation of the group `conversation_id`: the
/// key change `admin` made for `members`, which `admin` signed, and the
/// message `author` then sent under the new key, both as delivered.
pub fn key_change_and_message(
    admin: &Party,
    members: &[&Party],
    author: &Party,
    conversation_id: &str,
    text: &str,
) -> (String, String) {
    let public_keys: Vec<PublicKeyInput> = members
        .iter()
        .map(|member| member.public_key.clone())
        .collect();
    let prepared = admin
        .core
        .prepare_conversation_key_change(&public_keys, Some(conversation_id))
        .expect("prepare_conversation_key_change");
    let key = prepared
        .conversation_key
        .as_ref()
        .expect("conversation key");
    let key_change = delivered_action(
        &prepared.action_signatures[0],
        &admin.user_id,
        conversation_id,
        "2100000000000000000",
    );
    let options =
        ReplyOptions::default().with_conversation_key(key, &prepared.conversation_key_version);
    let body = author
        .core
        .encrypt_reply(conversation_id, text, options)
        .expect("encrypt_reply");
    (
        key_change,
        delivered(&body.event_b64, "2100000000000000001"),
    )
}

/// The text of each event a batch decrypted; `None` for an event that is
/// not a text message.
pub fn texts(result: &DecryptEventsResult) -> Vec<Option<&str>> {
    result
        .events
        .iter()
        .map(|decrypted| message_text(&decrypted.event))
        .collect()
}
