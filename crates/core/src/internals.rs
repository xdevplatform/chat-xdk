//! Hidden helpers for repo tooling — **not part of the public API**.
//!
//! The vector generator (`examples/gen_sdk_vectors.rs`) and the fuzz targets
//! (`fuzz/`) live outside this crate but need two crate-private capabilities:
//! framing an event in the backend `MessageEvent` envelope that
//! `decrypt_event(s)` consumes, and reaching the bounded untrusted-parse
//! entry point directly. This module exposes exactly those, `#[doc(hidden)]`
//! so the supported API surface stays what `ChatCore` / `Chat` define.
//! Application code must not use it.

use crate::crypto::encryption::encrypt_message;
use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{XChatConversationKey, XChatPrivateKey};
use crate::error::SdkError;
use crate::pipeline::{build_message_content, serialize_thrift};
use crate::protocol::safe_reader::BoundedProtocol;
use crate::protocol::serialization::{base64_decode, base64_encode};
use crate::signatures::ActionSignature;
use crate::thrift::event::{
    ConversationKeyChangeEvent, ConversationParticipantKey, FailureType, MessageCreateEvent,
    MessageEvent, MessageEventDetail, MessageEventSignature, MessageFailureEvent, RateLimitTier,
};
use crate::thrift::product::{
    MediaAttachment, MessageAttachment, UrlAttachment, UrlAttachmentImage,
};
use crate::types::SendPayload;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use std::io::Cursor;
use thrift::protocol::{TBinaryInputProtocol, TSerializable};

/// Frame a Thrift detail into the base64 `MessageEvent` envelope the backend
/// delivers on the events endpoint. `signature` is `None` for event types
/// that are unsigned by protocol (typing, failure, member-account-delete).
fn frame_event(
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    detail: MessageEventDetail,
    signature: Option<MessageEventSignature>,
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
        signature,
        None::<String>,
        None::<bool>,
        None::<String>,
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
    let content_bytes = base64_decode(&payload.encoded_message_create_event)?;
    // `encoded_message_create_event` is either a full MessageEvent (take its detail) or a
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
        .ok_or_else(|| {
            SdkError::Parse("SendPayload encoded_message_create_event did not parse".into())
        })?;

    let signature = MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    frame_event(
        message_id,
        sender_id,
        conversation_id,
        detail,
        Some(signature),
    )
}

/// An attachment of a framed message, without an attachment id.
pub enum FixtureAttachment<'a> {
    /// A media attachment with this media hash key.
    Media(&'a str),
    /// A link card whose banner and favicon carry these media hash keys.
    LinkCard {
        url: &'a str,
        banner: &'a str,
        favicon: &'a str,
    },
}

#[allow(clippy::vec_box)]
fn fixture_attachments(attachments: &[FixtureAttachment]) -> Vec<Box<MessageAttachment>> {
    let image = |hash: &str| {
        Some(Box::new(UrlAttachmentImage {
            media_hash_key: Some(hash.to_string()),
            ..Default::default()
        }))
    };
    attachments
        .iter()
        .map(|attachment| {
            Box::new(match attachment {
                FixtureAttachment::Media(hash) => {
                    MessageAttachment::Media(Box::new(MediaAttachment {
                        media_hash_key: Some(hash.to_string()),
                        filename: Some(format!("{}.bin", hash)),
                        ..Default::default()
                    }))
                }
                FixtureAttachment::LinkCard {
                    url,
                    banner,
                    favicon,
                } => MessageAttachment::Url(Box::new(UrlAttachment {
                    url: Some(url.to_string()),
                    banner_image_media_hash_key: image(banner),
                    favicon_image_media_hash_key: image(favicon),
                    ..Default::default()
                })),
            })
        })
        .collect()
}

/// Build a signed `MessageCreateEvent` in the backend `MessageEvent` envelope
/// (base64) whose contents use a per-message key: a text message carrying
/// `attachments`, encrypted under `message_key` with
/// `contents_encryption_version` 1, and signed at `signature_version` over
/// the payload verifiers rebuild.
#[allow(clippy::too_many_arguments)]
pub fn frame_message_key_event(
    signing_key: &XChatPrivateKey,
    signing_key_version: &str,
    sender_id: &str,
    conversation_id: &str,
    message_id: &str,
    conversation_key_version: &str,
    message_key: &XChatConversationKey,
    text: &str,
    attachments: &[FixtureAttachment],
    signature_version: i32,
) -> Result<String, SdkError> {
    let content = build_message_content(text, None, Some(fixture_attachments(attachments)), None)?;
    let detail = MessageEventDetail::MessageCreateEvent(MessageCreateEvent {
        contents: Some(encrypt_message(message_key, &content)?),
        conversation_key_version: Some(conversation_key_version.to_string()),
        should_notify: Some(true),
        contents_encryption_version: Some(1),
        ..Default::default()
    });
    let unsigned = MessageEvent {
        message_id: Some(message_id.to_string()),
        sender_id: Some(sender_id.to_string()),
        conversation_id: Some(conversation_id.to_string()),
        message_event_signature: Some(MessageEventSignature {
            signature_version: Some(signature_version.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let payload = crate::core::build_event_signature_payload(&unsigned, &detail, None)
        .ok_or_else(|| SdkError::Parse("no signature payload for the event".into()))?;
    let signature = KeyFactory::sign(signing_key, &payload)?;
    let signature = MessageEventSignature::new(
        Some(STANDARD_NO_PAD.encode(signature)),
        Some(signing_key_version.to_string()),
        Some(signature_version.to_string()),
        None,
        None,
    );
    frame_event(
        message_id,
        sender_id,
        conversation_id,
        detail,
        Some(signature),
    )
}

/// Frame an unencrypted, unsigned `MessageCreateEvent` (no conversation key
/// version) carrying `text` and `attachments` in plaintext, in the backend
/// `MessageEvent` envelope (base64).
pub fn frame_unencrypted_message_event(
    sender_id: &str,
    conversation_id: &str,
    message_id: &str,
    text: &str,
    attachments: &[FixtureAttachment],
) -> Result<String, SdkError> {
    let content = build_message_content(text, None, Some(fixture_attachments(attachments)), None)?;
    let detail = MessageEventDetail::MessageCreateEvent(MessageCreateEvent {
        contents: Some(content),
        should_notify: Some(true),
        ..Default::default()
    });
    frame_event(message_id, sender_id, conversation_id, detail, None)
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
    let signed = &signature.message_event_signature;
    let sig_struct = MessageEventSignature::new(
        Some(signed.signature.clone()),
        Some(signed.public_key_version.clone()),
        Some(signed.signature_version.clone()),
        None,
        None,
    );
    frame_event(
        &signature.message_id,
        sender_id,
        conversation_id,
        MessageEventDetail::ConversationKeyChangeEvent(kce),
        Some(sig_struct),
    )
}

/// Frame an unsigned `MessageFailureEvent` in the backend `MessageEvent`
/// envelope (base64). Failure events carry no signature by protocol, so the
/// output is fully deterministic. `failure_type` and `rate_limit_tier` are
/// raw Thrift enum values.
pub fn frame_failure_event(
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    failure_type: i32,
    rate_limit_tier: Option<i32>,
) -> Result<String, SdkError> {
    let failure = MessageFailureEvent::new(
        Some(FailureType::from(failure_type)),
        rate_limit_tier.map(RateLimitTier::from),
    );
    frame_event(
        message_id,
        sender_id,
        conversation_id,
        MessageEventDetail::MessageFailureEvent(failure),
        None,
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
