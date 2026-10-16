//! Helpers shared by the protocol test modules: participants that sign with
//! their own `ChatCore`, and signed events built from explicit payloads.

use super::*;
use crate::crypto::encryption::encrypt_message;
use crate::pipeline::serialize_thrift;
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{
    MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail as Detail,
    MessageEventSignature,
};
use crate::thrift::product::{
    MediaAttachment as ThriftMedia, MessageAttachment as ThriftAttachment, MessageContents,
    MessageEntryContents as Contents,
};

pub(super) const SIGNING_KEY_VERSION: &str = "1";
pub(super) const CONVERSATION: &str = "2:1491585161162473473";

/// Known-answer inputs and outputs of the message and attachment key
/// derivations.
pub(super) const KAT_CONVERSATION_KEY: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub(super) const KAT_KEY_SENDER: &str = "1876543210987654321";
pub(super) const KAT_KEY_MESSAGE_ID: &str = "9d8c7b6a-5f4e-4d3c-8b2a-190807060504";
pub(super) const KAT_MESSAGE_KEY: &str =
    "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084";
pub(super) const KAT_FIRST_ATTACHMENT_KEY: &str =
    "1ef86545f91f8a3078e276949f7555df2ca584e9c6509b261a558a2e618a1b4b";
pub(super) const KAT_SECOND_ATTACHMENT_KEY: &str =
    "8a7bc01f2ff35c661140da68606b2370cecc13810f245d791aeb8ba6b40d4ea8";

/// A participant signing with its own `ChatCore`'s signing key.
pub(super) struct Party {
    pub(super) core: ChatCore,
    pub(super) user_id: String,
    pub(super) entry: SigningKeyEntry,
}

impl Party {
    pub(super) fn new(user_id: &str) -> Self {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let entry = SigningKeyEntry {
            user_id: user_id.to_string(),
            public_key_version: SIGNING_KEY_VERSION.to_string(),
            public_key: reg.public_key.signing_public_key,
            identity_public_key: reg.public_key.public_key,
            identity_public_key_signature: reg.public_key.identity_public_key_signature,
        };
        Self {
            core,
            user_id: user_id.to_string(),
            entry,
        }
    }

    /// A signature over `payload`, labeled with signature version `version`.
    pub(super) fn sign(&self, payload: &str, version: i32) -> MessageEventSignature {
        let signature = self.core.sign(payload.as_bytes()).unwrap();
        MessageEventSignature {
            signature: Some(STANDARD_NO_PAD.encode(signature)),
            public_key_version: Some(SIGNING_KEY_VERSION.to_string()),
            signature_version: Some(version.to_string()),
            ..Default::default()
        }
    }
}

pub(super) fn key(byte: u8) -> XChatConversationKey {
    XChatConversationKey::from_bytes(vec![byte; 32]).unwrap()
}

pub(super) fn hex_key(hex_str: &str) -> XChatConversationKey {
    XChatConversationKey::from_bytes(hex::decode(hex_str).unwrap()).unwrap()
}

pub(super) fn message_key(
    conversation_key: &XChatConversationKey,
    sender_id: &str,
    message_id: &str,
) -> XChatConversationKey {
    message_keys::derive_message_key(conversation_key, sender_id, message_id).unwrap()
}

/// Serialized `MessageEntryHolder` for message `contents`.
pub(super) fn holder(contents: MessageContents) -> Vec<u8> {
    serialize_thrift(&MessageEntryHolder::new(Some(Box::new(Contents::Message(
        Box::new(contents),
    )))))
    .unwrap()
}

pub(super) fn media(hash: &str, attachment_id: Option<&str>) -> Box<ThriftAttachment> {
    Box::new(ThriftAttachment::Media(Box::new(ThriftMedia {
        media_hash_key: Some(hash.to_string()),
        filename: Some(format!("{}.jpg", hash)),
        attachment_id: attachment_id.map(str::to_string),
        ..Default::default()
    })))
}

/// A v10 message-key message from the known-answer sender, under key
/// version "7", carrying two media attachments without ids (`photo-a` and
/// `photo-b`), encrypted under the known message key.
pub(super) fn known_answer_media_message(author: &Party) -> ThriftEvent {
    let contents = holder(MessageContents {
        message_text: Some("two photos".to_string()),
        attachments: Some(vec![media("photo-a", None), media("photo-b", None)]),
        ..Default::default()
    });
    message_event(
        author,
        KAT_KEY_MESSAGE_ID,
        "100",
        "7",
        Some(1),
        10,
        &hex_key(KAT_MESSAGE_KEY),
        &contents,
    )
}

pub(super) fn keys(
    version: &str,
    key: &XChatConversationKey,
) -> HashMap<String, XChatConversationKey> {
    [(version.to_string(), key.clone())].into_iter().collect()
}

pub(super) fn frame(event: &ThriftEvent) -> String {
    base64_encode(&serialize_thrift(event).unwrap())
}

/// The event the backend relays for a `SendPayload` from `sender_id`.
pub(super) fn sent_event(
    payload: &SendPayload,
    sender_id: &str,
    conversation_id: &str,
) -> ThriftEvent {
    let bytes = base64_decode(&payload.encrypted_content).unwrap();
    let mut raw = TBinaryInputProtocol::new(Cursor::new(bytes), true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    let mce = MessageCreateEvent::read_from_in_protocol(&mut protocol).unwrap();
    ThriftEvent {
        message_id: Some(payload.message_id.clone()),
        sender_id: Some(sender_id.to_string()),
        conversation_id: Some(conversation_id.to_string()),
        detail: Some(Detail::MessageCreateEvent(mce)),
        message_event_signature: Some(MessageEventSignature {
            signature: Some(payload.signature.clone()),
            public_key_version: Some(payload.signature_info.public_key_version.clone()),
            signature_version: Some(payload.signature_info.signature_version.clone()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(super) fn envelope(
    message_id: &str,
    sender: &Party,
    sequence_id: &str,
    detail: Detail,
    signature: MessageEventSignature,
) -> ThriftEvent {
    ThriftEvent {
        sequence_id: Some(sequence_id.to_string()),
        message_id: Some(message_id.to_string()),
        sender_id: Some(sender.user_id.clone()),
        conversation_id: Some(CONVERSATION.to_string()),
        created_at_msec: Some("1700000000000".to_string()),
        detail: Some(detail),
        message_event_signature: Some(signature),
        ..Default::default()
    }
}

/// The signed payload of a `MessageCreateEvent` at `version` (2 or later).
pub(super) fn message_payload(
    message_id: &str,
    sender_id: &str,
    key_version: &str,
    contents: &[u8],
    contents_encryption_version: Option<i16>,
    version: i32,
) -> String {
    let mut payload = format!(
        "MessageCreateEvent,{},{},{},{},{}",
        message_id,
        sender_id,
        CONVERSATION,
        key_version,
        STANDARD_NO_PAD.encode(contents)
    );
    if version >= 10 {
        let cev = contents_encryption_version.map_or("null".to_string(), |v| v.to_string());
        payload.push_str(&format!(",{}", cev));
    }
    if version >= 9 {
        payload.push_str(&format!(",signature_version={}", version));
    }
    payload
}

/// A `MessageCreateEvent` from `author` whose contents are `plaintext`
/// encrypted under `contents_key`, signed at `version`.
#[allow(clippy::too_many_arguments)]
pub(super) fn message_event(
    author: &Party,
    message_id: &str,
    sequence_id: &str,
    key_version: &str,
    contents_encryption_version: Option<i16>,
    version: i32,
    contents_key: &XChatConversationKey,
    plaintext: &[u8],
) -> ThriftEvent {
    let contents = encrypt_message(contents_key, plaintext).unwrap();
    let payload = message_payload(
        message_id,
        &author.user_id,
        key_version,
        &contents,
        contents_encryption_version,
        version,
    );
    let detail = Detail::MessageCreateEvent(MessageCreateEvent {
        contents: Some(contents),
        conversation_key_version: Some(key_version.to_string()),
        should_notify: Some(true),
        contents_encryption_version,
        ..Default::default()
    });
    envelope(
        message_id,
        author,
        sequence_id,
        detail,
        author.sign(&payload, version),
    )
}

pub(super) fn decrypt_message(
    receiver: &ChatCore,
    event: &ThriftEvent,
    conversation_keys: &HashMap<String, XChatConversationKey>,
    signing_keys: &[SigningKeyEntry],
) -> Result<Box<Message>, SdkError> {
    match receiver.decrypt_event_with(&frame(event), conversation_keys, signing_keys)? {
        Event::Message(message) => Ok(message),
        other => panic!("expected a message, got {:?}", other),
    }
}
