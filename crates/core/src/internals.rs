//! Hidden helpers for repo tooling — **not part of the public API**.
//!
//! The vector generator (`examples/gen_sdk_vectors.rs`) and the fuzz targets
//! (`fuzz/`) live outside this crate but need two crate-private capabilities:
//! framing an encrypted payload in the backend `MessageEvent` envelope that
//! `decrypt_event(s)` consumes, and reaching the bounded untrusted-parse
//! entry point directly. This module exposes exactly those, `#[doc(hidden)]`
//! so the supported API surface stays what `ChatCore` / `Chat` define.
//! Application code must not use it.

use crate::error::SdkError;
use crate::pipeline::serialize_thrift;
use crate::protocol::safe_reader::BoundedProtocol;
use crate::protocol::serialization::{base64_decode, base64_encode};
use crate::signatures::ActionSignature;
use crate::thrift::event::{
    ConversationKeyChangeEvent, ConversationParticipantKey, MessageEvent, MessageEventDetail,
    MessageEventSignature,
};
use crate::types::SendPayload;
use std::io::Cursor;
use thrift::protocol::{TBinaryInputProtocol, TSerializable};

/// Frame a Thrift detail + signature into the base64 `MessageEvent` envelope
/// the backend delivers on the events endpoint.
fn frame_event(
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    detail: MessageEventDetail,
    signature: MessageEventSignature,
) -> Result<String, SdkError> {
    let event = MessageEvent::new(
        Some("1".to_string()),
        Some(message_id.to_string()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(detail),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(signature),
        None::<String>,
        None::<bool>,
    );
    Ok(base64_encode(&serialize_thrift(&event)?))
}

/// Wrap an `encrypt_message`-family [`SendPayload`] in the backend
/// `MessageEvent` envelope (base64), embedding the payload's own signature so
/// `decrypt_event(s)` can verify it. `message_id`/`sender_id`/`conversation_id`
/// must match the values the payload was encrypted and signed with.
pub fn frame_send_payload(
    payload: &SendPayload,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
) -> Result<String, SdkError> {
    let content_bytes = base64_decode(&payload.encrypted_content)?;
    // `encrypted_content` is either a full MessageEvent (take its detail) or a
    // bare MessageCreateEvent (wrap it in the detail union).
    let detail = crate::core::parse_message_event(&content_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            let cursor = Cursor::new(content_bytes.as_slice());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut protocol = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut protocol)
                .ok()
                .map(MessageEventDetail::MessageCreateEvent)
        })
        .ok_or_else(|| SdkError::Parse("SendPayload encrypted_content did not parse".into()))?;

    let signature = MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    frame_event(message_id, sender_id, conversation_id, detail, signature)
}

/// Build a signed `ConversationKeyChangeEvent` in the backend `MessageEvent`
/// envelope (base64) carrying one participant entry. `signature` must come
/// from `build_ckey_change_signature` over the same message/conversation ids
/// and conversation-key version.
#[allow(clippy::too_many_arguments)]
pub fn frame_signed_key_change(
    sender_id: &str,
    conversation_id: &str,
    conversation_key_version: &str,
    participant_user_id: &str,
    encrypted_conversation_key_b64: &str,
    participant_public_key_version: &str,
    signature: &ActionSignature,
) -> Result<String, SdkError> {
    let kce = ConversationKeyChangeEvent::new(
        Some(conversation_key_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some(participant_user_id.to_string()),
            Some(encrypted_conversation_key_b64.to_string()),
            Some(participant_public_key_version.to_string()),
        )]),
        None,
        None,
    );
    let sig_struct = MessageEventSignature::new(
        Some(signature.signature.clone()),
        Some(signature.public_key_version.clone()),
        Some(signature.signature_version.clone()),
        None,
        None,
    );
    frame_event(
        &signature.message_id,
        sender_id,
        conversation_id,
        MessageEventDetail::ConversationKeyChangeEvent(kce),
        sig_struct,
    )
}

/// Bounded untrusted parse of a raw backend event — the entry every base64
/// event goes through before any crypto. Exposed for fuzzing; must never
/// panic, whatever the input.
pub fn parse_message_event_bytes(data: &[u8]) -> Result<(), SdkError> {
    crate::core::parse_message_event(data).map(|_| ())
}

/// Bounded parse of decrypted message content (`MessageEntryHolder`),
/// including any reply preview with embedded raw events. Exposed for
/// fuzzing; must never panic, whatever the input.
pub fn parse_message_content_bytes(data: &[u8]) -> Result<(), SdkError> {
    crate::core::parse_message_content(data).map(|_| ())
}
