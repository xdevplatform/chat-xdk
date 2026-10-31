//! Shared message-encryption pipeline for API-compatible sends.
//!
//! These functions are **not** behind a feature gate so they can be used by
//! both the native `Chat` struct (which requires `juicebox`) and the WASM
//! bindings (which manage keys in JavaScript).

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

use crate::crypto::encryption::encrypt_message;
use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{XChatConversationKey, XChatPrivateKey};
use crate::crypto::message_keys;
use crate::error::SdkError;
use crate::protocol::serialization::{base64_decode, base64_encode};
use crate::signatures::{MESSAGE_SIGNATURE_VERSION, SIGNATURE_VERSION};
use crate::thrift::event::{
    MessageCreateEvent, MessageEvent, MessageEventDetail, MessageEventSignature,
    MessageSigningKeyInfo,
};
use crate::thrift::product::{
    AddressRichTextContent, CashtagRichTextContent, EmailRichTextContent, HashtagRichTextContent,
    MediaAttachment as ThriftMediaAttachmentStruct, MediaDimensions as ThriftMediaDimensions,
    MediaType as ThriftMediaType, MentionRichTextContent,
    MessageAttachment as ThriftMessageAttachment, MessageContents, MessageEdit,
    MessageEntryContents, MessageEntryHolder, MessageReactionAdd, MessageReactionRemove,
    PhoneNumberRichTextContent, PostAttachment as ThriftPostAttachment,
    QuickReply as ThriftQuickReply, QuickReplyOption as ThriftQuickReplyOption,
    QuickReplyOptionsRequest as ThriftQuickReplyOptionsRequest,
    QuickReplyOptionsResponse as ThriftQuickReplyOptionsResponse,
    QuickReplyRequest as ThriftQuickReplyRequest, QuickReplyResponse as ThriftQuickReplyResponse,
    ReplyingToPreview as ThriftReplyingToPreview, RichTextContent as ThriftRichTextContent,
    RichTextEntity as ThriftRichTextEntity, UrlAttachment as ThriftUrlAttachment,
    UrlAttachmentImage as ThriftUrlAttachmentImage, UrlRichTextContent,
};
use crate::types::{
    AttachmentDescriptor, EntityDescriptor, QuickReply, QuickReplyRequest, QuickReplyResponse,
    SendPayload, SignatureInfo,
};

use std::io::Cursor;
use thrift::protocol::{TBinaryOutputProtocol, TSerializable};

// Thrift serialization

/// Serialize any Thrift type to binary bytes.
pub fn serialize_thrift<T: TSerializable>(value: &T) -> Result<Vec<u8>, SdkError> {
    let mut buffer = Vec::new();
    let mut cursor = Cursor::new(&mut buffer);
    {
        let mut protocol = TBinaryOutputProtocol::new(&mut cursor, true);
        value
            .write_to_out_protocol(&mut protocol)
            .map_err(|e| SdkError::Parse(format!("Thrift serialize error: {}", e)))?;
    }
    Ok(buffer)
}

// Encrypt + sign pipeline

/// The wire format of an outgoing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendVersion {
    /// The 0.5.x format, readable by every SDK version: contents encrypted
    /// under the conversation key, no `contents_encryption_version`, signed at
    /// [`SIGNATURE_VERSION`].
    #[default]
    V0,
    /// Per-message keys: contents encrypted under the key derived from the
    /// conversation key, the sender id, and the message id, marked with
    /// `contents_encryption_version` 1, signed at [`MESSAGE_SIGNATURE_VERSION`].
    V1,
}

/// The author and signing-key version of an event a send embeds, such as a
/// reply's quoted original, for the X API to fill in that author's signing
/// key for recipients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedSigner {
    pub sender_id: i64,
    pub public_key_version: i64,
}

impl EmbeddedSigner {
    /// The signer of `event`, when it carries a numeric sender id and
    /// signing-key version.
    pub(crate) fn of(event: &MessageEvent) -> Option<Self> {
        Some(Self {
            sender_id: event.sender_id.as_deref()?.parse().ok()?,
            public_key_version: event
                .message_event_signature
                .as_ref()?
                .public_key_version
                .as_deref()?
                .parse()
                .ok()?,
        })
    }
}

/// Parameters for [`encrypt_and_sign`].
///
/// Use [`new()`](Self::new) for required fields, then chain optional setters.
pub struct EncryptAndSignParams<'a> {
    pub conversation_key: &'a XChatConversationKey,
    pub signing_key: &'a XChatPrivateKey,
    pub message_id: &'a str,
    pub sender_id: &'a str,
    pub conversation_id: &'a str,
    pub content_bytes: &'a [u8],
    pub conversation_key_version: &'a str,
    pub signing_key_version: &'a str,
    /// Whether to send a push notification. `None` defaults to `true`.
    pub should_notify: Option<bool>,
    /// Optional TTL in milliseconds for disappearing messages.
    pub ttl_msec: Option<i64>,
    /// Wire format to send in; defaults to [`SendVersion::V0`].
    pub send_version: SendVersion,
    /// The signers of the events the contents embed (a reply's quoted
    /// original and edit), listed in a v1 send's signature.
    pub embedded_signers: Vec<EmbeddedSigner>,
}

impl<'a> EncryptAndSignParams<'a> {
    /// Create params with required fields; optional fields default to `None`
    /// and the send version to [`SendVersion::V0`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conversation_key: &'a XChatConversationKey,
        signing_key: &'a XChatPrivateKey,
        message_id: &'a str,
        sender_id: &'a str,
        conversation_id: &'a str,
        content_bytes: &'a [u8],
        conversation_key_version: &'a str,
        signing_key_version: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            signing_key,
            message_id,
            sender_id,
            conversation_id,
            content_bytes,
            conversation_key_version,
            signing_key_version,
            should_notify: None,
            ttl_msec: None,
            send_version: SendVersion::V0,
            embedded_signers: Vec::new(),
        }
    }

    /// Set the wire format to send in (default: [`SendVersion::V0`]).
    pub fn send_version(mut self, send_version: SendVersion) -> Self {
        self.send_version = send_version;
        self
    }

    /// Set the signers of the events the contents embed.
    pub fn embedded_signers(mut self, signers: Vec<EmbeddedSigner>) -> Self {
        self.embedded_signers = signers;
        self
    }

    /// Set whether to send a push notification (default: `true`).
    #[allow(dead_code)]
    pub fn should_notify(mut self, notify: bool) -> Self {
        self.should_notify = Some(notify);
        self
    }

    /// Set the TTL in milliseconds for disappearing messages.
    #[allow(dead_code)]
    pub fn ttl_msec(mut self, ttl: i64) -> Self {
        self.ttl_msec = Some(ttl);
        self
    }
}

/// Normalize a conversation id to the canonical form used in event signatures.
///
/// Join two numeric user ids into the canonical one-to-one conversation id:
/// ordered numerically (smaller first) and colon-separated. Ids compare by
/// length then lexically, which equals numeric order for decimal strings of
/// any size and stays deterministic even for ids with leading zeros.
pub(crate) fn join_sorted_pair(a: &str, b: &str) -> String {
    let a_first = (a.len(), a) <= (b.len(), b);
    if a_first {
        format!("{a}:{b}")
    } else {
        format!("{b}:{a}")
    }
}

/// Rewrite a caller-supplied conversation id into the canonical form that
/// events carry and signatures cover: the two participant user ids ordered
/// numerically and colon-separated.
///
/// Callers hold one-to-one ids in several shapes — `<userA>:<userB>` from
/// events, `<userA>-<userB>` from conversation listings and REST URL paths
/// (in either order), or just the other participant's bare user id (the form
/// the REST paths themselves accept). All of them canonicalize to the same
/// `min:max` string; a bare id is paired with `sender_id`, matching how the
/// backend derives the id from the request path and the authenticated user.
/// Signing any other form would produce a signature no verifier can match.
///
/// Only all-digit ids are rewritten: group ids and anything else pass
/// through unchanged. Group conversation ids always carry the `g` prefix,
/// so an all-digit id can only name a user pair or a single user — pairing
/// a bare id with the sender can never corrupt a group id.
pub(crate) fn canonical_conversation_id<'a>(
    id: &'a str,
    sender_id: &str,
) -> std::borrow::Cow<'a, str> {
    if let Some((a, b)) = id.split_once([':', '-']) {
        if is_digits(a) && is_digits(b) {
            return std::borrow::Cow::Owned(join_sorted_pair(a, b));
        }
        return std::borrow::Cow::Borrowed(id);
    }
    if is_digits(id) && is_digits(sender_id) {
        return std::borrow::Cow::Owned(join_sorted_pair(id, sender_id));
    }
    std::borrow::Cow::Borrowed(id)
}

/// Encrypt pre-built content bytes and sign for the API.
///
/// This is the shared pipeline used by all `encrypt_*` methods, sending in
/// the format `params.send_version` selects:
///
/// - [`SendVersion::V0`] encrypts the content under the conversation key and
///   signs at [`SIGNATURE_VERSION`], exactly as 0.5.x did.
/// - [`SendVersion::V1`] encrypts it under the message key derived from the
///   conversation key, the sender id, and the message id, marks the
///   `MessageCreateEvent` with the `contents_encryption_version` that tells
///   recipients to derive the same key, and signs at
///   [`MESSAGE_SIGNATURE_VERSION`].
///
/// Returns a ready-to-send [`SendPayload`].
pub fn encrypt_and_sign(params: EncryptAndSignParams<'_>) -> Result<SendPayload, SdkError> {
    let should_notify = params.should_notify.unwrap_or(true);
    validate_sender_id(params.sender_id)?;
    validate_conversation_key_version(params.conversation_key_version)?;

    let (encrypted, contents_encryption_version, signature_version) = match params.send_version {
        SendVersion::V0 => (
            encrypt_message(params.conversation_key, params.content_bytes)?,
            None,
            SIGNATURE_VERSION.to_string(),
        ),
        SendVersion::V1 => {
            let message_key = message_keys::derive_message_key(
                params.conversation_key,
                params.sender_id,
                params.message_id,
            )?;
            (
                encrypt_message(&message_key, params.content_bytes)?,
                Some(message_keys::SEND_CONTENTS_ENCRYPTION_VERSION),
                MESSAGE_SIGNATURE_VERSION.to_string(),
            )
        }
    };
    let event = MessageCreateEvent::new(
        Some(encrypted),
        Some(params.conversation_key_version.to_string()),
        Some(should_notify),
        params.ttl_msec,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        contents_encryption_version,
    );
    let event_bytes = serialize_thrift(&event)?;

    // The conversation id is signed in its canonical, colon-separated form —
    // the form carried inside fanned-out events and reconstructed by verifiers.
    // Callers commonly hold the hyphen-separated form from conversation listing
    // and URL paths, or the bare recipient id the REST paths accept, so
    // normalize here to keep signatures verifiable regardless of input form.
    let conversation_id = canonical_conversation_id(params.conversation_id, params.sender_id);
    // The payload comes from the builder verification uses, so what is signed
    // is exactly what recipients rebuild from the delivered event.
    let detail = MessageEventDetail::MessageCreateEvent(event);
    let mut outgoing = MessageEvent {
        message_id: Some(params.message_id.to_string()),
        sender_id: Some(params.sender_id.to_string()),
        conversation_id: Some(conversation_id.into_owned()),
        message_event_signature: Some(MessageEventSignature::new(
            None,
            None,
            Some(signature_version.clone()),
            None,
            None,
        )),
        ..Default::default()
    };
    let payload =
        crate::core::build_event_signature_payload(&outgoing, &detail, None).ok_or_else(|| {
            SdkError::InvalidInput("Signature payload contains comma-separated component".into())
        })?;

    let signature = KeyFactory::sign(params.signing_key, &payload)?;
    let signature_b64 = STANDARD_NO_PAD.encode(&signature);
    let signing_key_infos = match params.send_version {
        SendVersion::V0 => None,
        SendVersion::V1 => Some(signing_key_infos(&params)),
    };
    let signature_struct = MessageEventSignature::new(
        Some(signature_b64.clone()),
        Some(params.signing_key_version.to_string()),
        Some(signature_version.clone()),
        None,
        signing_key_infos,
    );
    let signature_bytes = serialize_thrift(&signature_struct)?;
    let encoded_message_event_signature = base64_encode(&signature_bytes);
    outgoing.detail = Some(detail);
    outgoing.message_event_signature = Some(signature_struct);
    let event_b64 = base64_encode(&serialize_thrift(&outgoing)?);

    Ok(SendPayload {
        message_id: params.message_id.to_string(),
        event_b64,
        encoded_message_create_event: base64_encode(&event_bytes),
        signature: signature_b64,
        encoded_message_event_signature,
        signature_info: SignatureInfo {
            public_key_version: params.signing_key_version.to_string(),
            signature_version,
        },
        conversation_key_version: params.conversation_key_version.to_string(),
        should_notify,
        xdk_version: crate::XDK_VERSION.to_string(),
    })
}

/// The signing keys a v1 send asks the X API to fill in for recipients: those
/// of the events its contents embed, then the sender's own, each listed once,
/// by member id and signing-key version.
fn signing_key_infos(params: &EncryptAndSignParams<'_>) -> Vec<MessageSigningKeyInfo> {
    let own = params
        .sender_id
        .parse()
        .ok()
        .zip(params.signing_key_version.parse().ok())
        .map(|(sender_id, public_key_version)| EmbeddedSigner {
            sender_id,
            public_key_version,
        });
    let mut signers: Vec<EmbeddedSigner> = Vec::new();
    for signer in params.embedded_signers.iter().copied().chain(own) {
        if !signers.contains(&signer) {
            signers.push(signer);
        }
    }
    signers
        .into_iter()
        .map(|signer| {
            MessageSigningKeyInfo::new(
                Some(signer.sender_id.to_string()),
                Some(signer.public_key_version.to_string()),
                None::<String>,
            )
        })
        .collect()
}

/// Whether `conversation_id`, in any form a caller holds it, names a
/// one-to-one conversation rather than a group.
pub(crate) fn is_one_to_one(conversation_id: &str, sender_id: &str) -> bool {
    canonical_conversation_id(conversation_id, sender_id)
        .split_once(':')
        .is_some_and(|(a, b)| is_digits(a) && is_digits(b))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// Check that `user_id` is a user id in canonical decimal form: digits only,
/// no leading zero, a positive 64-bit integer. User ids are signed as given,
/// while recipients rebuild payloads from the numeric ids on the delivered
/// events (and derive message keys from the sender's), so any other spelling
/// yields something no recipient can verify. `field` names the input in the
/// error.
pub(crate) fn validate_user_id(field: &str, user_id: &str) -> Result<(), SdkError> {
    let canonical = user_id
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .map(|id| id.to_string());
    if canonical.as_deref() == Some(user_id) {
        Ok(())
    } else {
        Err(SdkError::InvalidInput(format!(
            "Invalid {field} '{user_id}': pass a numeric user id (digits only)"
        )))
    }
}

/// Check every id of a user id list with [`validate_user_id`].
pub(crate) fn validate_user_ids(field: &str, user_ids: &[String]) -> Result<(), SdkError> {
    user_ids
        .iter()
        .try_for_each(|user_id| validate_user_id(field, user_id))
}

fn validate_sender_id(sender_id: &str) -> Result<(), SdkError> {
    validate_user_id("sender_id", sender_id)
}

/// Check that `version` is a key version as the X API returns it: a
/// non-negative integer in canonical decimal form (digits only, no leading
/// zero). Signing-key versions (`public_key_version`) and conversation key
/// versions both take this form; recipients look keys up by the version as
/// carried, while signatures cover its integer value. `field` names the input
/// in the error.
pub(crate) fn validate_key_version(field: &str, version: &str) -> Result<(), SdkError> {
    let canonical = version
        .parse::<i64>()
        .ok()
        .filter(|v| *v >= 0)
        .map(|v| v.to_string());
    if canonical.as_deref() == Some(version) {
        Ok(())
    } else {
        Err(SdkError::InvalidInput(format!(
            "Invalid {field} '{version}': pass the key version as the X API returns it, \
             an integer in digits"
        )))
    }
}

fn validate_conversation_key_version(version: &str) -> Result<(), SdkError> {
    validate_key_version("conversation_key_version", version)
}

// Content builders

/// Build text message content, optionally with entities, attachments, and a
/// quick reply.
#[allow(clippy::vec_box)]
pub fn build_message_content(
    text: &str,
    entities: Option<Vec<Box<ThriftRichTextEntity>>>,
    attachments: Option<Vec<Box<ThriftMessageAttachment>>>,
    quick_reply: Option<Box<ThriftQuickReply>>,
) -> Result<Vec<u8>, SdkError> {
    let content = MessageContents::new(
        Some(text.to_string()),
        entities,
        attachments,
        None,
        None,
        None,
        quick_reply,
        None,
        None,
    );
    let holder = MessageEntryHolder::new(Some(Box::new(MessageEntryContents::Message(Box::new(
        content,
    )))));
    serialize_thrift(&holder)
}

/// Build text message content carrying a pre-built reply preview.
#[allow(clippy::vec_box)]
pub fn build_message_content_with_preview(
    text: &str,
    preview: ThriftReplyingToPreview,
    entities: Option<Vec<Box<ThriftRichTextEntity>>>,
    attachments: Option<Vec<Box<ThriftMessageAttachment>>>,
    quick_reply: Option<Box<ThriftQuickReply>>,
) -> Result<Vec<u8>, SdkError> {
    let content = MessageContents::new(
        Some(text.to_string()),
        entities,
        attachments,
        Some(Box::new(preview)),
        None,
        None,
        quick_reply,
        None,
        None,
    );
    let holder = MessageEntryHolder::new(Some(Box::new(MessageEntryContents::Message(Box::new(
        content,
    )))));
    serialize_thrift(&holder)
}

/// Build a reaction-add content payload.
pub fn build_reaction_add_content(
    target_message_sequence_id: &str,
    emoji: &str,
) -> Result<Vec<u8>, SdkError> {
    let content = MessageReactionAdd::new(
        Some(target_message_sequence_id.to_string()),
        Some(emoji.to_string()),
        None,
    );
    let holder = MessageEntryHolder::new(Some(Box::new(MessageEntryContents::ReactionAdd(
        Box::new(content),
    ))));
    serialize_thrift(&holder)
}

/// Build a message-edit content payload. `target_message_id` is the edited
/// message's own id, which names it within the edit's signed contents.
pub fn build_message_edit_content(
    target_message_sequence_id: &str,
    updated_text: &str,
    entities: Option<&[EntityDescriptor]>,
    target_message_id: Option<&str>,
) -> Result<Vec<u8>, SdkError> {
    // MessageEdit carries entities unboxed, unlike MessageContents.
    let entities = entities
        .map(|entities| build_thrift_entities(entities, Some(updated_text)))
        .transpose()?
        .map(|entities| entities.into_iter().map(|e| *e).collect::<Vec<_>>());
    let content = MessageEdit::new(
        Some(target_message_sequence_id.to_string()),
        Some(updated_text.to_string()),
        entities,
        target_message_id.map(str::to_string),
    );
    let holder = MessageEntryHolder::new(Some(Box::new(MessageEntryContents::MessageEdit(
        Box::new(content),
    ))));
    serialize_thrift(&holder)
}

/// Build a reaction-remove content payload.
pub fn build_reaction_remove_content(
    target_message_sequence_id: &str,
    emoji: &str,
) -> Result<Vec<u8>, SdkError> {
    let content = MessageReactionRemove::new(
        Some(target_message_sequence_id.to_string()),
        Some(emoji.to_string()),
        None,
    );
    let holder = MessageEntryHolder::new(Some(Box::new(MessageEntryContents::ReactionRemove(
        Box::new(content),
    ))));
    serialize_thrift(&holder)
}

// Entity / Attachment descriptor → Thrift converters

/// Convert [`EntityDescriptor`]s into Thrift `RichTextEntity` objects. An
/// entity type the protocol doesn't have, an empty one included, fails with
/// an error naming it, and so do offsets that aren't a range of the text:
/// `start` and `end` count bytes of the text's UTF-8 encoding, `start`
/// inclusive and `end` exclusive, so `0 <= start <= end`, and `end` is at
/// most the length of `text`, the text the entities index, when given.
#[allow(clippy::vec_box)]
pub fn build_thrift_entities(
    descs: &[EntityDescriptor],
    text: Option<&str>,
) -> Result<Vec<Box<ThriftRichTextEntity>>, SdkError> {
    descs
        .iter()
        .map(|d| {
            let content = match d.entity_type.as_str() {
                "url" => ThriftRichTextContent::Url(Box::new(UrlRichTextContent::new())),
                "mention" => {
                    ThriftRichTextContent::Mention(Box::new(MentionRichTextContent::new()))
                }
                "hashtag" => {
                    ThriftRichTextContent::Hashtag(Box::new(HashtagRichTextContent::new()))
                }
                "cashtag" => {
                    ThriftRichTextContent::Cashtag(Box::new(CashtagRichTextContent::new()))
                }
                "email" => ThriftRichTextContent::Email(Box::new(EmailRichTextContent::new())),
                "address" => {
                    ThriftRichTextContent::Address(Box::new(AddressRichTextContent::new()))
                }
                "phone_number" | "phoneNumber" => {
                    ThriftRichTextContent::PhoneNumber(Box::new(PhoneNumberRichTextContent::new()))
                }
                other => {
                    return Err(SdkError::InvalidInput(format!(
                        "Invalid entity_type '{other}': pass url, mention, hashtag, cashtag, \
                         email, address or phone_number"
                    )))
                }
            };
            validate_entity_offsets(d, text)?;
            Ok(Box::new(ThriftRichTextEntity::new(
                Some(d.start),
                Some(d.end),
                Some(Box::new(content)),
            )))
        })
        .collect()
}

/// Check that an entity's offsets are a range of `text`, in bytes of its
/// UTF-8 encoding: `0 <= start <= end <= text.len()`, the last bound only
/// when the text is given.
fn validate_entity_offsets(entity: &EntityDescriptor, text: Option<&str>) -> Result<(), SdkError> {
    let (start, end) = (entity.start, entity.end);
    let invalid = |problem: String| {
        SdkError::InvalidInput(format!("Invalid entity offsets {start}..{end}: {problem}"))
    };
    if start < 0 || end < 0 {
        return Err(invalid(
            "offsets count bytes of the UTF-8 text, from 0".into(),
        ));
    }
    if end < start {
        return Err(invalid("end is before start".into()));
    }
    match text {
        Some(text) if end as usize > text.len() => Err(invalid(format!(
            "end is past the end of the text, which is {} bytes of UTF-8",
            text.len()
        ))),
        _ => Ok(()),
    }
}

/// Most attachments a single message may carry.
const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;

/// Reject attachment lists that receiving clients cannot render.
///
/// Temporary compatibility guard, not a protocol rule: a message may carry
/// multiple attachments only when every one is image/gif/video media, capped
/// at [`MAX_ATTACHMENTS_PER_MESSAGE`]. Any other attachment — audio, file,
/// svg, or unrecognized media types, URL cards, posts — must be the message's
/// only attachment. Relax or delete this once clients render heterogeneous
/// lists; the wire format already carries them.
pub fn validate_attachment_descriptors(descs: &[AttachmentDescriptor]) -> Result<(), SdkError> {
    if descs.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(SdkError::InvalidInput(format!(
            "too many attachments: at most {MAX_ATTACHMENTS_PER_MESSAGE} per message"
        )));
    }
    let multiple_supported = |d: &AttachmentDescriptor| match d {
        AttachmentDescriptor::Media { media_type, .. } => {
            // A missing media_type is sent as IMAGE (see build_thrift_attachments).
            let mt = media_type.map_or(ThriftMediaType::IMAGE, ThriftMediaType::from);
            mt == ThriftMediaType::IMAGE
                || mt == ThriftMediaType::GIF
                || mt == ThriftMediaType::VIDEO
        }
        AttachmentDescriptor::Url { .. } | AttachmentDescriptor::Post { .. } => false,
    };
    if descs.len() <= 1 || descs.iter().all(multiple_supported) {
        Ok(())
    } else {
        Err(SdkError::InvalidInput(
            "disallowed attachment combination: multiple attachments must all be image/gif/video \
             media; any other attachment type must be the message's only attachment"
                .into(),
        ))
    }
}

/// Convert [`AttachmentDescriptor`]s into Thrift `MessageAttachment` objects.
#[allow(clippy::vec_box)]
pub fn build_thrift_attachments(
    descs: &[AttachmentDescriptor],
) -> Vec<Box<ThriftMessageAttachment>> {
    descs
        .iter()
        .map(|d| match d {
            AttachmentDescriptor::Media {
                media_hash_key,
                width,
                height,
                filesize_bytes,
                filename,
                media_type,
                duration_millis,
                plaintext_sha256,
            } => {
                let dimensions = ThriftMediaDimensions::new(Some(*width), Some(*height));
                let resolved_media_type = match media_type {
                    Some(i) => ThriftMediaType::from(*i),
                    None => ThriftMediaType::IMAGE,
                };
                // Callers validate first (validate_plaintext_sha256s).
                let plaintext_sha256 = plaintext_sha256
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .and_then(|v| base64_decode(v).ok());
                let media = ThriftMediaAttachmentStruct::new(
                    Some(media_hash_key.clone()),
                    Some(Box::new(dimensions)),
                    Some(Box::new(resolved_media_type)),
                    *duration_millis,
                    Some(*filesize_bytes),
                    Some(filename.clone()),
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    plaintext_sha256,
                );
                Box::new(ThriftMessageAttachment::Media(Box::new(media)))
            }
            AttachmentDescriptor::Url {
                url,
                display_title,
                banner_image,
                favicon_image,
            } => {
                let url_att = ThriftUrlAttachment::new(
                    Some(url.clone()),
                    banner_image.as_ref().map(build_thrift_url_image),
                    favicon_image.as_ref().map(build_thrift_url_image),
                    display_title.clone(),
                    None::<String>,
                );
                Box::new(ThriftMessageAttachment::Url(Box::new(url_att)))
            }
            AttachmentDescriptor::Post { rest_id, post_url } => {
                let post =
                    ThriftPostAttachment::new(rest_id.clone(), post_url.clone(), None::<String>);
                Box::new(ThriftMessageAttachment::Post(Box::new(post)))
            }
        })
        .collect()
}

/// Convert an outgoing message's own [`AttachmentDescriptor`]s for
/// `send_version`: v1 names each attachment by the id its key derives from
/// ([`build_message_attachments`]); v0 sends them without ids, as 0.5.x did.
#[allow(clippy::vec_box)]
pub fn build_outgoing_attachments(
    descs: &[AttachmentDescriptor],
    message_id: &str,
    send_version: SendVersion,
) -> Vec<Box<ThriftMessageAttachment>> {
    match send_version {
        SendVersion::V0 => build_thrift_attachments(descs),
        SendVersion::V1 => build_message_attachments(descs, message_id),
    }
}

/// Convert an outgoing v1 message's own [`AttachmentDescriptor`]s, giving
/// each the id its key derives from: the message id for the first attachment
/// and `<message id>#<index>` for later ones, the ids recipients resolve for
/// an attachment that carries none.
#[allow(clippy::vec_box)]
pub fn build_message_attachments(
    descs: &[AttachmentDescriptor],
    message_id: &str,
) -> Vec<Box<ThriftMessageAttachment>> {
    let mut attachments = build_thrift_attachments(descs);
    for (index, attachment) in attachments.iter_mut().enumerate() {
        let id = Some(message_keys::resolve_attachment_id(None, message_id, index));
        match attachment.as_mut() {
            ThriftMessageAttachment::Media(media) => media.attachment_id = id,
            ThriftMessageAttachment::Url(card) => card.attachment_id = id,
            ThriftMessageAttachment::Post(post) => post.attachment_id = id,
            _ => {}
        }
    }
    attachments
}

/// A file an attachment references: a media attachment's, or a URL card's
/// banner or favicon.
struct FileRef<'a> {
    media_hash_key: &'a str,
    filesize_bytes: i64,
    filename: &'a str,
    width: Option<i64>,
    height: Option<i64>,
}

/// The files the descriptors reference, in order: a media attachment's, and
/// a URL card's banner then favicon.
fn files(descs: &[AttachmentDescriptor]) -> Vec<FileRef<'_>> {
    descs
        .iter()
        .flat_map(|desc| match desc {
            AttachmentDescriptor::Media {
                media_hash_key,
                filesize_bytes,
                filename,
                width,
                height,
                ..
            } => vec![FileRef {
                media_hash_key,
                filesize_bytes: *filesize_bytes,
                filename,
                width: Some(*width),
                height: Some(*height),
            }],
            AttachmentDescriptor::Url {
                banner_image,
                favicon_image,
                ..
            } => [banner_image, favicon_image]
                .into_iter()
                .flatten()
                .map(|image| FileRef {
                    media_hash_key: &image.media_hash_key,
                    filesize_bytes: image.filesize_bytes,
                    filename: &image.filename,
                    width: image.width,
                    height: image.height,
                })
                .collect(),
            AttachmentDescriptor::Post { .. } => Vec::new(),
        })
        .collect()
}

/// The media hash keys of the files the descriptors reference, in order: a
/// media attachment's, and a URL card's banner then favicon.
pub(crate) fn file_media_hash_keys(descs: &[AttachmentDescriptor]) -> Vec<&str> {
    files(descs)
        .into_iter()
        .map(|file| file.media_hash_key)
        .collect()
}

/// Check the fields of the attachments a message sends: a URL card has a
/// url, a post a `rest_id` or a `post_url`, and every file one references
/// has a media hash key, a filename, a size above 0 and no negative width or
/// height, with no two attachments referencing the same media hash key, and
/// a media attachment's `plaintext_sha256`, when set, is a base64 SHA-256. A
/// file is uploaded once, under its media hash key, encrypted under the key
/// of the one attachment that references it, and receivers discard a file
/// sent without its name or size.
pub(crate) fn validate_attachment_fields(descs: &[AttachmentDescriptor]) -> Result<(), SdkError> {
    let mut seen = std::collections::HashSet::new();
    for desc in descs {
        match desc {
            AttachmentDescriptor::Url { url, .. } if url.is_empty() => {
                return Err(SdkError::InvalidInput(
                    "a URL card's url is empty: pass the link the card shows".into(),
                ));
            }
            AttachmentDescriptor::Post { rest_id, post_url }
                if rest_id.as_deref().unwrap_or("").is_empty()
                    && post_url.as_deref().unwrap_or("").is_empty() =>
            {
                return Err(SdkError::InvalidInput(
                    "a post attachment has neither rest_id nor post_url: pass the post's id or \
                     its URL"
                        .into(),
                ));
            }
            _ => {}
        }
        let own = files(std::slice::from_ref(desc));
        for file in &own {
            let media_hash_key = file.media_hash_key;
            if media_hash_key.is_empty() {
                return Err(SdkError::InvalidInput(
                    "an attachment's media_hash_key is empty: pass the media hash key the \
                     file's upload started with"
                        .into(),
                ));
            }
            if file.filename.is_empty() {
                return Err(SdkError::InvalidInput(format!(
                    "media_hash_key '{media_hash_key}' has an empty filename: pass the file's \
                     original name"
                )));
            }
            if file.filesize_bytes <= 0 {
                return Err(SdkError::InvalidInput(format!(
                    "media_hash_key '{media_hash_key}' has filesize_bytes {}: pass the \
                     encrypted file's size, which encrypted_file_size gives",
                    file.filesize_bytes
                )));
            }
            for (side, value) in [("width", file.width), ("height", file.height)] {
                if let Some(value) = value.filter(|value| *value < 0) {
                    return Err(SdkError::InvalidInput(format!(
                        "media_hash_key '{media_hash_key}' has {side} {value}: pass the {side} in \
                         pixels, 0 or more"
                    )));
                }
            }
        }
        let mut keys: Vec<&str> = own.iter().map(|file| file.media_hash_key).collect();
        // A card's banner and favicon share the card's key, so they may
        // share one upload.
        keys.dedup();
        for media_hash_key in keys {
            if !seen.insert(media_hash_key) {
                return Err(SdkError::InvalidInput(format!(
                    "media_hash_key '{media_hash_key}' is in more than one attachment: upload \
                     the file once for each attachment"
                )));
            }
        }
    }
    validate_plaintext_sha256s(descs)
}

/// Check that each media attachment's `plaintext_sha256`, when set, is the
/// base64 of a SHA-256: 32 bytes.
pub(crate) fn validate_plaintext_sha256s(descs: &[AttachmentDescriptor]) -> Result<(), SdkError> {
    for desc in descs {
        let AttachmentDescriptor::Media {
            media_hash_key,
            plaintext_sha256: Some(hash),
            ..
        } = desc
        else {
            continue;
        };
        if hash.is_empty() {
            continue;
        }
        if base64_decode(hash).map(|bytes| bytes.len()).ok() != Some(32) {
            return Err(SdkError::InvalidInput(format!(
                "media_hash_key '{media_hash_key}' has plaintext_sha256 '{hash}': pass the \
                 base64 SHA-256 of the file's plaintext bytes (32 bytes)"
            )));
        }
    }
    Ok(())
}

/// Convert a [`UrlAttachmentImageDescriptor`] into a Thrift `UrlAttachmentImage`.
///
/// Emit the dimensions struct only when at least one side is known; an
/// all-absent struct is omitted entirely rather than sent as zeros.
fn build_thrift_url_image(
    desc: &crate::types::UrlAttachmentImageDescriptor,
) -> Box<ThriftUrlAttachmentImage> {
    let dimensions = if desc.width.is_some() || desc.height.is_some() {
        Some(Box::new(ThriftMediaDimensions::new(
            desc.width,
            desc.height,
        )))
    } else {
        None
    };
    Box::new(ThriftUrlAttachmentImage::new(
        Some(desc.media_hash_key.clone()),
        Some(desc.filesize_bytes),
        Some(desc.filename.clone()),
        dimensions,
    ))
}

/// Convert a [`QuickReply`] into a Thrift `QuickReply`.
pub fn build_thrift_quick_reply(quick_reply: &QuickReply) -> Box<ThriftQuickReply> {
    let thrift = match quick_reply {
        QuickReply::Request {
            request: QuickReplyRequest::Options { options },
        } => {
            let items = options.options.as_ref().map(|items| {
                items
                    .iter()
                    .map(|o| {
                        ThriftQuickReplyOption::new(
                            o.id.clone(),
                            o.label.clone(),
                            o.metadata.clone(),
                            o.description.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            });
            ThriftQuickReply::Request(ThriftQuickReplyRequest::Options(
                ThriftQuickReplyOptionsRequest::new(options.id.clone(), items),
            ))
        }
        QuickReply::Response {
            response: QuickReplyResponse::Options { options },
        } => ThriftQuickReply::Response(ThriftQuickReplyResponse::Options(
            ThriftQuickReplyOptionsResponse::new(
                options.request_id.clone(),
                options.metadata.clone(),
                options.selected_option_id.clone(),
            ),
        )),
    };
    Box::new(thrift)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_factory::KeyFactory;
    use crate::crypto::keys::KeypairPurpose;

    fn test_keys() -> (XChatConversationKey, XChatPrivateKey) {
        let ckey = KeyFactory::generate_conversation_key().unwrap();
        let signing = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        (ckey, signing.private.clone())
    }

    #[test]
    fn test_encrypt_and_sign_basic() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hello!", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();

        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_message_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "1");
        assert!(payload.should_notify);
    }

    #[test]
    fn test_encrypt_and_sign_with_options() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hello!", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        )
        .should_notify(false)
        .ttl_msec(30_000);

        let payload = encrypt_and_sign(params).unwrap();
        assert!(!payload.should_notify);
    }

    #[test]
    fn test_encrypt_and_sign_rejects_comma_in_ids() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hello!", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg,1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let result = encrypt_and_sign(params);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_message_content_plain_text() {
        let content = build_message_content("Hello, World!", None, None, None).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_entities() {
        let entities = build_thrift_entities(
            &[
                EntityDescriptor::new(0, 23, "url"),
                EntityDescriptor::new(25, 30, "mention"),
                EntityDescriptor::new(32, 40, "hashtag"),
            ],
            None,
        )
        .unwrap();
        let content = build_message_content(
            "https://example.com @user #topic",
            Some(entities),
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_all_entity_types() {
        let entities = build_thrift_entities(
            &[
                EntityDescriptor::new(0, 5, "url"),
                EntityDescriptor::new(6, 11, "mention"),
                EntityDescriptor::new(12, 17, "hashtag"),
                EntityDescriptor::new(18, 23, "cashtag"),
                EntityDescriptor::new(24, 40, "email"),
                EntityDescriptor::new(41, 55, "address"),
                EntityDescriptor::new(56, 66, "phone_number"),
            ],
            None,
        )
        .unwrap();
        assert_eq!(entities.len(), 7);
    }

    /// Build a reply preview for the content-builder tests.
    #[allow(clippy::vec_box)]
    fn test_preview(
        sequence_id: &str,
        sender_id: Option<i64>,
        text: Option<&str>,
        entities: Option<Vec<Box<ThriftRichTextEntity>>>,
        attachments: Option<Vec<Box<ThriftMessageAttachment>>>,
    ) -> ThriftReplyingToPreview {
        ThriftReplyingToPreview::new(
            sender_id,
            text.map(|s| s.to_string()),
            entities.map(|v| v.into_iter().map(|b| *b).collect::<Vec<_>>()),
            attachments,
            None::<String>,
            Some(sequence_id.to_string()),
            None::<String>,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_build_message_content_with_preview() {
        let content = build_message_content_with_preview(
            "This is a reply",
            test_preview("seq-123", Some(12345), Some("Original message"), None, None),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_reaction_add_content() {
        let content = build_reaction_add_content("seq-123", "👍").unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_reaction_remove_content() {
        let content = build_reaction_remove_content("seq-123", "👍").unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_media_attachment() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "hash123".to_string(),
            width: 1920,
            height: 1080,
            media_type: Some(1), // image
            duration_millis: None,
            plaintext_sha256: None,
            filesize_bytes: 150000,
            filename: "photo.jpg".to_string(),
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_url_attachment() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: Some("Example".to_string()),
            banner_image: None,
            favicon_image: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_post_attachment() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: Some("123456".to_string()),
            post_url: Some("https://x.com/user/status/123456".to_string()),
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_full_encrypt_sign_produces_valid_base64() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Test message", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();

        use base64::{engine::general_purpose::STANDARD, Engine};
        assert!(STANDARD
            .decode(&payload.encoded_message_create_event)
            .is_ok());
        assert!(STANDARD
            .decode(&payload.encoded_message_event_signature)
            .is_ok());
    }

    // build_thrift_attachments — URL attachments

    #[test]
    fn test_build_url_attachment_without_display_title() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://example.com/page".to_string(),
            display_title: None,
            banner_image: None,
            favicon_image: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_url_attachment_with_display_title() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://x.com".to_string(),
            display_title: Some("X (formerly Twitter)".to_string()),
            banner_image: None,
            favicon_image: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_url_attachment_with_banner_and_favicon() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://example.com/product".to_string(),
            display_title: Some("Example Product".to_string()),
            banner_image: Some(crate::types::UrlAttachmentImageDescriptor {
                media_hash_key: "banner-hash".to_string(),
                filesize_bytes: 24_000,
                filename: "banner.jpg".to_string(),
                width: Some(1200),
                height: Some(630),
            }),
            favicon_image: Some(crate::types::UrlAttachmentImageDescriptor {
                media_hash_key: "favicon-hash".to_string(),
                filesize_bytes: 1_200,
                filename: "favicon.ico".to_string(),
                width: None,
                height: None,
            }),
        }]);
        assert_eq!(attachments.len(), 1);
        let ThriftMessageAttachment::Url(url_att) = attachments[0].as_ref() else {
            panic!("expected Url attachment");
        };
        let banner = url_att
            .banner_image_media_hash_key
            .as_ref()
            .expect("banner image present");
        assert_eq!(banner.media_hash_key.as_deref(), Some("banner-hash"));
        assert_eq!(banner.filesize_bytes, Some(24_000));
        assert_eq!(banner.filename.as_deref(), Some("banner.jpg"));
        let dims = banner.dimensions.as_ref().expect("banner dimensions");
        assert_eq!(dims.width, Some(1200));
        assert_eq!(dims.height, Some(630));

        let favicon = url_att
            .favicon_image_media_hash_key
            .as_ref()
            .expect("favicon image present");
        assert_eq!(favicon.media_hash_key.as_deref(), Some("favicon-hash"));
        assert_eq!(favicon.filesize_bytes, Some(1_200));
        assert_eq!(favicon.filename.as_deref(), Some("favicon.ico"));
        // No sides supplied — the dimensions struct is omitted entirely.
        assert!(favicon.dimensions.is_none());
    }

    // build_thrift_attachments — Post attachments

    #[test]
    fn test_build_post_attachment_with_both_fields() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: Some("1234567890".to_string()),
            post_url: Some("https://x.com/user/status/1234567890".to_string()),
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_post_attachment_rest_id_only() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: Some("9876543210".to_string()),
            post_url: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_post_attachment_post_url_only() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: None,
            post_url: Some("https://x.com/user/status/111".to_string()),
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_post_attachment_no_fields() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: None,
            post_url: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    // build_thrift_attachments — Media edge cases

    #[test]
    fn test_build_media_attachment_no_media_type_defaults_to_image() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "hash_abc".to_string(),
            width: 800,
            height: 600,
            filesize_bytes: 50000,
            filename: "image.png".to_string(),
            media_type: None, // should default to IMAGE
            duration_millis: None,
            plaintext_sha256: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_media_attachment_video_with_duration() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "video_hash".to_string(),
            width: 1280,
            height: 720,
            filesize_bytes: 5_000_000,
            filename: "clip.mp4".to_string(),
            media_type: Some(3), // video
            duration_millis: Some(15000),
            plaintext_sha256: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    #[test]
    fn test_build_media_attachment_gif() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "gif_hash".to_string(),
            width: 320,
            height: 240,
            filesize_bytes: 200_000,
            filename: "funny.gif".to_string(),
            media_type: Some(2), // gif
            duration_millis: Some(3000),
            plaintext_sha256: None,
        }]);
        assert_eq!(attachments.len(), 1);
    }

    // build_thrift_attachments — mixed

    #[test]
    fn test_build_mixed_attachments() {
        let attachments = build_thrift_attachments(&[
            AttachmentDescriptor::Media {
                media_hash_key: "hash1".to_string(),
                width: 100,
                height: 100,
                filesize_bytes: 1000,
                filename: "thumb.jpg".to_string(),
                media_type: Some(1),
                duration_millis: None,
                plaintext_sha256: None,
            },
            AttachmentDescriptor::Url {
                url: "https://example.com".to_string(),
                display_title: Some("Example".to_string()),
                banner_image: None,
                favicon_image: None,
            },
            AttachmentDescriptor::Post {
                rest_id: Some("tweet-1".to_string()),
                post_url: Some("https://x.com/u/status/1".to_string()),
            },
        ]);
        assert_eq!(attachments.len(), 3);
    }

    #[test]
    fn test_build_empty_attachments() {
        let attachments = build_thrift_attachments(&[]);
        assert!(attachments.is_empty());
    }

    // validate_attachment_descriptors — first-party client compat matrix

    fn media_desc(media_type: Option<i32>) -> AttachmentDescriptor {
        AttachmentDescriptor::Media {
            media_hash_key: "hash".to_string(),
            width: 100,
            height: 100,
            filesize_bytes: 1000,
            filename: "file".to_string(),
            media_type,
            duration_millis: None,
            plaintext_sha256: None,
        }
    }

    fn url_desc() -> AttachmentDescriptor {
        AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: None,
            banner_image: None,
            favicon_image: None,
        }
    }

    fn post_desc() -> AttachmentDescriptor {
        AttachmentDescriptor::Post {
            rest_id: Some("1".to_string()),
            post_url: None,
        }
    }

    #[test]
    fn validate_attachments_allows_multi_visual_media_and_singles() {
        // Image=1, gif=2, video=3 may appear together up to the cap; a
        // missing media_type is treated as image.
        let allowed: Vec<Vec<AttachmentDescriptor>> = vec![
            vec![],
            vec![
                media_desc(Some(1)),
                media_desc(Some(2)),
                media_desc(Some(3)),
            ],
            vec![media_desc(None), media_desc(Some(1))],
            vec![media_desc(Some(1)); 10],
            vec![url_desc()],
            vec![post_desc()],
            vec![media_desc(Some(4))],
            vec![media_desc(Some(5))],
            vec![media_desc(Some(6))],
        ];
        for descs in &allowed {
            assert!(
                validate_attachment_descriptors(descs).is_ok(),
                "expected allowed: {descs:?}"
            );
        }
    }

    #[test]
    fn validate_attachments_rejects_multi_non_visual_combinations() {
        // Audio=4, file=5, svg=6, unknown media types, URL cards, and posts
        // must be the sole attachment.
        let rejected: Vec<Vec<AttachmentDescriptor>> = vec![
            vec![url_desc(), url_desc()],
            vec![media_desc(Some(1)), url_desc()],
            vec![media_desc(Some(5)), media_desc(Some(1))],
            vec![media_desc(Some(4)), media_desc(Some(4))],
            vec![media_desc(Some(6)), media_desc(Some(1))],
            vec![media_desc(Some(99)), media_desc(Some(1))],
            vec![post_desc(), media_desc(Some(1))],
            vec![post_desc(), url_desc()],
        ];
        for descs in &rejected {
            let err = validate_attachment_descriptors(descs)
                .expect_err(&format!("expected rejected: {descs:?}"));
            assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err}");
            assert!(
                err.to_string().contains("attachment combination"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn validate_attachments_rejects_more_than_the_cap() {
        let descs = vec![media_desc(Some(1)); 11];
        let err = validate_attachment_descriptors(&descs).unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err}");
        assert!(
            err.to_string().contains("too many attachments"),
            "got: {err}"
        );
    }

    // build_thrift_entities — edge cases

    #[test]
    fn an_unknown_or_empty_entity_type_fails_naming_it() {
        for etype in ["unknown_type", "", "URL", "phone number"] {
            let err =
                build_thrift_entities(&[EntityDescriptor::new(0, 5, etype)], None).unwrap_err();
            assert!(matches!(err, SdkError::InvalidInput(_)), "{etype:?}: {err}");
            assert_eq!(
                err.to_string(),
                format!(
                    "Invalid entity_type '{etype}': pass url, mention, hashtag, cashtag, email, \
                     address or phone_number"
                )
            );
        }
    }

    #[test]
    fn test_build_entities_phone_number_camel_case() {
        let entities =
            build_thrift_entities(&[EntityDescriptor::new(0, 14, "phoneNumber")], None).unwrap();
        assert_eq!(
            entities.len(),
            1,
            "phoneNumber (camelCase) should be accepted"
        );
    }

    #[test]
    fn one_unknown_entity_type_fails_the_whole_list() {
        let err = build_thrift_entities(
            &[
                EntityDescriptor::new(0, 5, "url"),
                EntityDescriptor::new(6, 11, "bogus"),
                EntityDescriptor::new(12, 17, "mention"),
            ],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("'bogus'"), "{err}");
    }

    #[test]
    fn test_build_entities_empty_input() {
        let entities = build_thrift_entities(&[], None).unwrap();
        assert!(entities.is_empty());
    }

    #[test]
    fn test_build_entities_all_types_individually() {
        // Tests each branch individually to ensure all type strings resolve
        for etype in [
            "url",
            "mention",
            "hashtag",
            "cashtag",
            "email",
            "address",
            "phone_number",
            "phoneNumber",
        ] {
            let entities =
                build_thrift_entities(&[EntityDescriptor::new(0, 10, etype)], None).unwrap();
            assert_eq!(entities.len(), 1, "Entity type '{etype}'");
        }
    }

    // build_message_content — edge cases

    #[test]
    fn test_build_message_content_empty_text() {
        let content = build_message_content("", None, None, None).unwrap();
        assert!(
            !content.is_empty(),
            "Even empty text should produce a Thrift payload"
        );
    }

    #[test]
    fn test_build_message_content_special_characters() {
        let content = build_message_content(
            "Hello 🌍! Ünïcödé & <html> \"quotes\" \n\tnewlines",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_very_long_text() {
        let long_text = "A".repeat(10_000);
        let content = build_message_content(&long_text, None, None, None).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_entities_and_attachments() {
        let entities = build_thrift_entities(&[EntityDescriptor::new(0, 23, "url")], None).unwrap();
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://example.com".to_string(),
            display_title: Some("Example".to_string()),
            banner_image: None,
            favicon_image: None,
        }]);
        let content = build_message_content(
            "https://example.com text",
            Some(entities),
            Some(attachments),
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_only_attachments() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "hash".to_string(),
            width: 640,
            height: 480,
            filesize_bytes: 100_000,
            filename: "pic.jpg".to_string(),
            media_type: Some(1),
            duration_millis: None,
            plaintext_sha256: None,
        }]);
        let content =
            build_message_content("Check this out", None, Some(attachments), None).unwrap();
        assert!(!content.is_empty());
    }

    // build_message_content_with_preview — with entities / attachments

    #[test]
    fn test_build_message_content_with_preview_and_entities() {
        let entities =
            build_thrift_entities(&[EntityDescriptor::new(0, 5, "mention")], None).unwrap();
        let content = build_message_content_with_preview(
            "@user yes!",
            test_preview(
                "seq-456",
                Some(99999),
                Some("Original question?"),
                None,
                None,
            ),
            Some(entities),
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_and_attachments() {
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "reply_media".to_string(),
            width: 500,
            height: 500,
            filesize_bytes: 75_000,
            filename: "reply.png".to_string(),
            media_type: Some(1),
            duration_millis: None,
            plaintext_sha256: None,
        }]);
        let content = build_message_content_with_preview(
            "Here's a photo reply",
            test_preview("seq-789", Some(11111), Some("Send me a pic"), None, None),
            None,
            Some(attachments),
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_entities() {
        let reply_entities =
            build_thrift_entities(&[EntityDescriptor::new(0, 6, "hashtag")], None).unwrap();
        let content = build_message_content_with_preview(
            "Replying to tagged msg",
            test_preview(
                "seq-200",
                Some(33333),
                Some("#topic original message"),
                Some(reply_entities),
                None,
            ),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_attachments() {
        let reply_attachments = build_thrift_attachments(&[AttachmentDescriptor::Post {
            rest_id: Some("tweet-42".to_string()),
            post_url: Some("https://x.com/u/status/42".to_string()),
        }]);
        let content = build_message_content_with_preview(
            "Re: that post",
            test_preview(
                "seq-300",
                Some(44444),
                Some("Check out this post"),
                None,
                Some(reply_attachments),
            ),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_no_optional_fields() {
        let content = build_message_content_with_preview(
            "Reply text",
            test_preview("seq-400", None, None, None, None),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_all_fields() {
        let entities =
            build_thrift_entities(&[EntityDescriptor::new(0, 5, "mention")], None).unwrap();
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://reply-link.com".to_string(),
            display_title: None,
            banner_image: None,
            favicon_image: None,
        }]);
        let reply_entities =
            build_thrift_entities(&[EntityDescriptor::new(0, 20, "url")], None).unwrap();
        let reply_attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "orig_media".to_string(),
            width: 400,
            height: 300,
            filesize_bytes: 30_000,
            filename: "original.jpg".to_string(),
            media_type: Some(1),
            duration_millis: None,
            plaintext_sha256: None,
        }]);
        let content = build_message_content_with_preview(
            "@user check https://reply-link.com",
            test_preview(
                "seq-500",
                Some(55555),
                Some("https://original.com was great"),
                Some(reply_entities),
                Some(reply_attachments),
            ),
            Some(entities),
            Some(attachments),
            None,
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    // encrypt_and_sign — error / edge branches

    #[test]
    fn test_encrypt_and_sign_rejects_a_sender_id_that_is_not_a_user_id() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None, None).unwrap();

        for sender_id in ["sender,1", "sender-1", "+12", "012", "0", "-5", " 12", ""] {
            let params = EncryptAndSignParams::new(
                &ckey,
                &signing_key,
                "msg-1",
                sender_id,
                "conv-1",
                &content,
                "1",
                "1",
            );
            let err = encrypt_and_sign(params).unwrap_err();
            assert!(
                matches!(err, SdkError::InvalidInput(_)),
                "{sender_id}: {err}"
            );
            let err_msg = err.to_string();
            assert!(
                err_msg.starts_with(&format!("Invalid sender_id '{sender_id}'")),
                "{sender_id}: {err_msg}"
            );
        }
    }

    #[test]
    fn test_encrypt_and_sign_rejects_comma_in_conversation_id() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv,1", // comma in conversation id
            &content,
            "1",
            "1",
        );
        assert!(encrypt_and_sign(params).is_err());
    }

    #[test]
    fn test_canonical_conversation_id_normalizes_one_to_one() {
        let sender = "111";
        // Hyphen- and colon-separated pairs are rewritten to numeric-sorted
        // colon form regardless of the order the caller joined them in.
        assert_eq!(canonical_conversation_id("111-222", sender), "111:222");
        assert_eq!(canonical_conversation_id("222-111", sender), "111:222");
        assert_eq!(canonical_conversation_id("222:111", sender), "111:222");
        assert_eq!(canonical_conversation_id("111:222", sender), "111:222");
        // Numeric ordering, not lexical: 9 sorts before 10.
        assert_eq!(canonical_conversation_id("10-9", sender), "9:10");
        // Length-then-lexical ordering keeps leading-zero ids deterministic:
        // both orderings of the same pair canonicalize identically.
        assert_eq!(canonical_conversation_id("01-1", sender), "1:01");
        assert_eq!(canonical_conversation_id("1-01", sender), "1:01");
        // Numeric ordering holds beyond u128 (39 digits): the shorter
        // all-nines id sorts before the longer one even though it is
        // lexically greater.
        let nines = "9".repeat(39);
        let one_e39 = format!("1{}", "0".repeat(39));
        assert_eq!(
            canonical_conversation_id(&format!("{one_e39}-{nines}"), sender),
            format!("{nines}:{one_e39}")
        );
        assert_eq!(
            canonical_conversation_id(&format!("{nines}-{one_e39}"), sender),
            format!("{nines}:{one_e39}")
        );
        // A bare user id is the other participant; pair it with the sender.
        assert_eq!(canonical_conversation_id("222", "111"), "111:222");
        assert_eq!(canonical_conversation_id("111", "222"), "111:222");
        // Bare own id forms the self-conversation pair.
        assert_eq!(canonical_conversation_id("111", "111"), "111:111");
        // Group and non-numeric ids are left untouched.
        assert_eq!(
            canonical_conversation_id("g2031597666757378493", sender),
            "g2031597666757378493"
        );
        assert_eq!(canonical_conversation_id("conv-1", sender), "conv-1");
        assert_eq!(canonical_conversation_id("g123-456", sender), "g123-456");
        // A bare id is never paired with a non-numeric sender.
        assert_eq!(canonical_conversation_id("222", "sender-1"), "222");
    }

    #[test]
    fn test_encrypt_and_sign_rejects_a_key_version_that_is_not_an_integer() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None, None).unwrap();

        for version in ["1,2", "v1", "01", "+1", " 1", ""] {
            let params = EncryptAndSignParams::new(
                &ckey,
                &signing_key,
                "msg-1",
                "4001",
                "conv-1",
                &content,
                version,
                "1",
            );
            let err_msg = encrypt_and_sign(params).unwrap_err().to_string();
            assert!(
                err_msg.contains(&format!("Invalid conversation_key_version '{version}'")),
                "{version}: {err_msg}"
            );
        }
    }

    #[test]
    fn test_encrypt_and_sign_signature_info_fields() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Fields check", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-42",
            "4099",
            "conv-77",
            &content,
            "5",
            "3",
        );
        let payload = encrypt_and_sign(params).unwrap();
        assert_eq!(payload.signature_info.public_key_version, "3");
        assert_eq!(payload.signature_info.signature_version, "7");
        assert_eq!(payload.conversation_key_version, "5");
        assert!(payload.should_notify); // default
        assert_eq!(payload.xdk_version, crate::XDK_VERSION);

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-42",
            "4099",
            "conv-77",
            &content,
            "5",
            "3",
        )
        .send_version(SendVersion::V1);
        let payload = encrypt_and_sign(params).unwrap();
        assert_eq!(payload.signature_info.signature_version, "10");
    }

    #[test]
    fn test_encrypt_and_sign_empty_content() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("", None, None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-empty",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.signature.is_empty());
    }

    #[test]
    fn test_encrypt_and_sign_two_calls_produce_different_ciphertext() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Same message", None, None, None).unwrap();

        let params1 = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload1 = encrypt_and_sign(params1).unwrap();

        let params2 = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "4001",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload2 = encrypt_and_sign(params2).unwrap();

        // Random nonce means different ciphertext each time
        assert_ne!(
            payload1.encoded_message_create_event, payload2.encoded_message_create_event,
            "Two encryptions of the same content should differ due to random nonce"
        );
    }

    // Reaction content

    #[test]
    fn test_build_reaction_add_content_with_emoji_sequence() {
        // Multi-codepoint emoji
        let content = build_reaction_add_content("seq-10", "👨‍👩‍👧‍👦").unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_reaction_remove_content_with_emoji_sequence() {
        let content = build_reaction_remove_content("seq-10", "❤️").unwrap();
        assert!(!content.is_empty());
    }
}
