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

pub(super) const SIGNING_KEY_VERSION: &str = "1";
pub(super) const CONVERSATION: &str = "2:1491585161162473473";

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
    match receiver.decrypt_event(&frame(event), conversation_keys, signing_keys)? {
        Event::Message(message) => Ok(message),
        other => panic!("expected a message, got {:?}", other),
    }
}
