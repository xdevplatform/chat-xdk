//! Compatibility with the released 0.5.0 and 0.5.2: their sends decrypt and
//! verify here, and v0 sends match theirs on the wire for the same inputs.
//!
//! The fixtures come from tests/compat_v05/generate_fixtures.py run against the
//! released packages; tests/compat_v05/verify_with_v05.py checks the other
//! direction (the released packages read v0 sends) in CI.

use super::test_support::frame;
use super::*;
use crate::pipeline::serialize_thrift;
use crate::thrift::event::{
    MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail as Detail,
    MessageEventSignature,
};
use serde_json::Value;

const FIXTURES: [(&str, &str); 2] = [
    (
        "0.5.0",
        include_str!("../../../../tests/fixtures/compat_v0_5_0.json"),
    ),
    (
        "0.5.2",
        include_str!("../../../../tests/fixtures/compat_v0_5_2.json"),
    ),
];

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {key} missing"))
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    base64_decode(text(value, key)).unwrap()
}

fn read<T: TSerializable>(data: &[u8]) -> T {
    let mut raw = TBinaryInputProtocol::new(Cursor::new(data), true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    T::read_from_in_protocol(&mut protocol).unwrap()
}

fn conversation_key(fixture: &Value) -> XChatConversationKey {
    XChatConversationKey::from_bytes(bytes(fixture, "conversation_key_b64")).unwrap()
}

fn conversation_keys(fixture: &Value) -> HashMap<String, XChatConversationKey> {
    [(
        text(fixture, "conversation_key_version").to_string(),
        conversation_key(fixture),
    )]
    .into_iter()
    .collect()
}

/// The event the backend relays for a 0.5 send: its `MessageCreateEvent` and
/// `MessageEventSignature` exactly as 0.5 serialized them.
fn relayed(fixture: &Value, send: &Value) -> ThriftEvent {
    ThriftEvent {
        message_id: Some(text(send, "message_id").to_string()),
        sender_id: Some(text(fixture, "sender_id").to_string()),
        conversation_id: Some(text(fixture, "conversation_id").to_string()),
        sequence_id: Some("200".to_string()),
        detail: Some(Detail::MessageCreateEvent(read(&bytes(
            send,
            "encrypted_content",
        )))),
        message_event_signature: Some(read(&bytes(send, "encoded_event_signature"))),
        ..Default::default()
    }
}

#[test]
fn sends_from_0_5_decrypt_and_verify() {
    for (version, json) in FIXTURES {
        let fixture: Value = serde_json::from_str(json).unwrap();
        assert_eq!(text(&fixture, "chatxdk_version"), version);
        let signing_key: SigningKeyEntry =
            serde_json::from_value(fixture["signing_key"].clone()).unwrap();
        for send in fixture["sends"].as_array().unwrap() {
            let kind = text(send, "kind");
            assert_eq!(text(send, "signature_version"), "7", "{version} {kind}");
            let event = ChatCore::new()
                .decrypt_event(
                    DecryptEventParams::new(
                        frame(&relayed(&fixture, send)),
                        conversation_keys(&fixture),
                    )
                    .with_signing_keys(vec![signing_key.clone()]),
                )
                .unwrap_or_else(|e| panic!("{version} {kind}: {e}"));
            let json = serde_json::to_string(&event).unwrap();
            assert!(
                json.contains("\"verified\":true"),
                "{version} {kind}: {json}"
            );
            assert!(
                json.contains(text(send, "expected")),
                "{version} {kind}: {json}"
            );
        }

        let file = &fixture["file"];
        let mut opened = Vec::new();
        crate::crypto::encryption::decrypt_file(
            &conversation_key(&fixture),
            bytes(file, "ciphertext_b64").as_slice(),
            &mut opened,
        )
        .unwrap_or_else(|e| panic!("{version} file: {e}"));
        assert_eq!(opened, bytes(file, "plaintext_b64"), "{version} file");
    }
}

/// The same send made here with every feature switch off.
fn v0_send(core: &ChatCore, fixture: &Value, kind: &str) -> SendPayload {
    let conversation = text(fixture, "conversation_id").to_string();
    let target = text(fixture, "target_sequence_id").to_string();
    let target_event = text(fixture, "target_event_b64");
    let key = bytes(fixture, "conversation_key_b64");
    let version = text(fixture, "conversation_key_version");
    let reaction = |emoji: &str| {
        let mut params =
            EncryptReactionParams::new("", emoji).with_conversation_key(key.clone(), version);
        params.target_event = None;
        params.conversation_id = Some(conversation.clone());
        params.target_message_sequence_id = Some(target.clone());
        params
    };
    let payload = match kind {
        "message" => core.encrypt_message(
            &EncryptMessageParams::new(conversation.clone(), "hello from 0.5")
                .with_conversation_key(key.clone(), version),
        ),
        "message_with_entities" => {
            let mut params = EncryptMessageParams::new(conversation.clone(), "see https://x.com")
                .with_conversation_key(key.clone(), version);
            params.entities = Some(vec![EntityDescriptor::new(4, 17, "url")]);
            core.encrypt_message(&params)
        }
        "reaction_add" => core.encrypt_add_reaction(&reaction("\u{1f44d}")),
        "reaction_remove" => core.encrypt_remove_reaction(&reaction("\u{1f44d}")),
        "edit" => {
            let mut params = EncryptEditParams::new("", "edited text")
                .with_conversation_key(key.clone(), version);
            params.target_event = None;
            params.conversation_id = Some(conversation.clone());
            params.target_message_sequence_id = Some(target.clone());
            core.encrypt_edit(&params)
        }
        "message_with_file" => {
            let mut params = EncryptMessageParams::new(conversation.clone(), "a file")
                .with_conversation_key(key.clone(), version);
            params.attachments = Some(vec![serde_json::from_value(
                fixture["media_attachment"].clone(),
            )
            .unwrap()]);
            core.encrypt_message(&params)
        }
        "reply" => {
            let mut params = EncryptReplyParams::new(conversation.clone(), "a reply", "")
                .with_conversation_key(key.clone(), version);
            params.reply_to_sequence_id = Some(target.clone());
            params.reply_to_sender_id = Some(text(fixture, "sender_id").parse().unwrap());
            params.reply_to_text = Some("hello from 0.5".to_string());
            core.encrypt_reply(&params)
        }
        "reply_from_event" => core.encrypt_reply(
            &EncryptReplyParams::new(conversation.clone(), "a reply to the event", target_event)
                .with_conversation_key(key.clone(), version),
        ),
        "edit_from_event" => core.encrypt_edit(
            &EncryptEditParams::new(target_event, "edited from the event")
                .with_conversation_key(key.clone(), version),
        ),
        other => panic!("unknown fixture kind {other}"),
    };
    payload.unwrap()
}

#[test]
fn v0_sends_match_0_5_on_the_wire() {
    for (version, json) in FIXTURES {
        let fixture: Value = serde_json::from_str(json).unwrap();
        let core = ChatCore::new();
        core.import_keys(&ImportKeysParams::new(
            bytes(&fixture, "private_keys_b64").to_vec(),
        ))
        .unwrap();
        core.set_identity(&SetIdentityParams::new(
            text(&fixture, "sender_id"),
            text(&fixture, "signing_key_version"),
        ))
        .unwrap();
        assert!(!core.feature_enabled(crate::features::V1_SEND));
        let ckey = conversation_key(&fixture);
        let signing_key: SigningKeyEntry =
            serde_json::from_value(fixture["signing_key"].clone()).unwrap();

        for send in fixture["sends"].as_array().unwrap() {
            let kind = text(send, "kind");
            let ours = v0_send(&core, &fixture, kind);
            assert_eq!(
                ours.signature_info.signature_version,
                text(send, "signature_version"),
                "{version} {kind}"
            );

            let mut theirs_create: MessageCreateEvent = read(&bytes(send, "encrypted_content"));
            let mut ours_create: MessageCreateEvent =
                read(&base64_decode(&ours.encoded_message_create_event).unwrap());
            assert_eq!(ours_create.contents_encryption_version, None);
            let ours_contents = ours_create.contents.take().unwrap();
            let theirs_contents = theirs_create.contents.take().unwrap();
            assert_eq!(
                decrypt_message_bytes(&ckey, &ours_contents).unwrap(),
                decrypt_message_bytes(&ckey, &theirs_contents).unwrap(),
                "{version} {kind}: decrypted contents"
            );
            assert_eq!(
                serialize_thrift(&ours_create).unwrap(),
                serialize_thrift(&theirs_create).unwrap(),
                "{version} {kind}: MessageCreateEvent outside its contents"
            );

            let mut theirs_signature: MessageEventSignature =
                read(&bytes(send, "encoded_event_signature"));
            let mut ours_signature: MessageEventSignature =
                read(&base64_decode(&ours.encoded_message_event_signature).unwrap());
            theirs_signature.signature = None;
            ours_signature.signature = None;
            assert_eq!(
                serialize_thrift(&ours_signature).unwrap(),
                serialize_thrift(&theirs_signature).unwrap(),
                "{version} {kind}: MessageEventSignature outside the signature"
            );

            let signed_like_0_5 = format!(
                "MessageCreateEvent,{},{},{},{},{}",
                ours.message_id,
                text(&fixture, "sender_id"),
                text(&fixture, "conversation_id"),
                text(&fixture, "conversation_key_version"),
                STANDARD_NO_PAD.encode(&ours_contents)
            );
            assert!(
                ChatCore::new()
                    .verify(
                        &signing_key.public_key,
                        &STANDARD_NO_PAD.decode(&ours.signature).unwrap(),
                        signed_like_0_5.as_bytes(),
                    )
                    .unwrap(),
                "{version} {kind}: signature over the 0.5 payload"
            );
        }
    }
}
