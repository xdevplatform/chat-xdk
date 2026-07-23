//! Shared message-encryption pipeline for API-compatible sends.
//!
//! These functions are **not** behind a feature gate so they can be used by
//! both the native `Chat` struct (which requires `juicebox`) and the WASM
//! bindings (which manage keys in JavaScript).

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

use crate::crypto::encryption::encrypt_message;
use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{XChatConversationKey, XChatPrivateKey};
use crate::error::SdkError;
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{MessageCreateEvent, MessageEventSignature};
use crate::thrift::product::{
    AddressRichTextContent, CashtagRichTextContent, EmailRichTextContent, HashtagRichTextContent,
    MediaAttachment as ThriftMediaAttachmentStruct, MediaDimensions as ThriftMediaDimensions,
    MediaType as ThriftMediaType, MentionRichTextContent,
    MessageAttachment as ThriftMessageAttachment, MessageContents, MessageEntryContents,
    MessageEntryHolder, MessageReactionAdd, MessageReactionRemove, PhoneNumberRichTextContent,
    PostAttachment as ThriftPostAttachment, ReplyingToPreview as ThriftReplyingToPreview,
    RichTextContent as ThriftRichTextContent, RichTextEntity as ThriftRichTextEntity,
    UrlAttachment as ThriftUrlAttachment, UrlAttachmentImage as ThriftUrlAttachmentImage,
    UrlRichTextContent,
};
use crate::types::{AttachmentDescriptor, EntityDescriptor, SendPayload, SignatureInfo};

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
}

impl<'a> EncryptAndSignParams<'a> {
    /// Create params with required fields; optional fields default to `None`.
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
        }
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
    fn is_digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
    }
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
/// This is the shared pipeline used by all `encrypt_*` methods.
/// It takes already-serialized Thrift content bytes, encrypts them,
/// builds the `MessageCreateEvent` and `MessageEventSignature` Thrift
/// structures, signs, and returns a ready-to-send [`SendPayload`].
pub fn encrypt_and_sign(params: EncryptAndSignParams<'_>) -> Result<SendPayload, SdkError> {
    let should_notify = params.should_notify.unwrap_or(true);

    // 1. Encrypt content
    let encrypted = encrypt_message(params.conversation_key, params.content_bytes)?;

    // 2. Build MessageCreateEvent Thrift
    let event = MessageCreateEvent::new(
        Some(encrypted.clone()),
        Some(params.conversation_key_version.to_string()),
        Some(should_notify),
        params.ttl_msec,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let event_bytes = serialize_thrift(&event)?;

    // 3. Build signature payload.
    //
    // The conversation id is signed in its canonical, colon-separated form —
    // the form carried inside fanned-out events and reconstructed by verifiers.
    // Callers commonly hold the hyphen-separated form from conversation listing
    // and URL paths, or the bare recipient id the REST paths accept, so
    // normalize here to keep signatures verifiable regardless of input form.
    let conversation_id = canonical_conversation_id(params.conversation_id, params.sender_id);
    let contents_b64_no_pad = STANDARD_NO_PAD.encode(&encrypted);
    let components = [
        "MessageCreateEvent",
        params.message_id,
        params.sender_id,
        conversation_id.as_ref(),
        params.conversation_key_version,
        contents_b64_no_pad.as_str(),
    ];
    if components.iter().any(|c| c.contains(',')) {
        return Err(SdkError::Parse(
            "Signature payload contains comma-separated component".into(),
        ));
    }
    let payload = components.join(",").into_bytes();

    // 4. Sign
    let signature = KeyFactory::sign(params.signing_key, &payload)?;
    let signature_b64 = STANDARD_NO_PAD.encode(&signature);

    // 5. Build MessageEventSignature Thrift
    let signature_struct = MessageEventSignature::new(
        Some(signature_b64.clone()),
        Some(params.signing_key_version.to_string()),
        Some(crate::signatures::SIGNATURE_VERSION.to_string()),
        None,
        None,
    );
    let signature_bytes = serialize_thrift(&signature_struct)?;
    let encoded_event_signature = base64_encode(&signature_bytes);

    Ok(SendPayload {
        message_id: params.message_id.to_string(),
        encrypted_content: base64_encode(&event_bytes),
        signature: signature_b64,
        encoded_event_signature,
        signature_info: SignatureInfo {
            public_key_version: params.signing_key_version.to_string(),
            signature_version: crate::signatures::SIGNATURE_VERSION.to_string(),
        },
        conversation_key_version: params.conversation_key_version.to_string(),
        should_notify,
    })
}

// Content builders

/// Build text message content, optionally with entities and attachments.
#[allow(clippy::vec_box)]
pub fn build_message_content(
    text: &str,
    entities: Option<Vec<Box<ThriftRichTextEntity>>>,
    attachments: Option<Vec<Box<ThriftMessageAttachment>>>,
) -> Result<Vec<u8>, SdkError> {
    let content = MessageContents::new(
        Some(text.to_string()),
        entities,
        attachments,
        None,
        None,
        None,
        None,
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
) -> Result<Vec<u8>, SdkError> {
    let content = MessageContents::new(
        Some(text.to_string()),
        entities,
        attachments,
        Some(Box::new(preview)),
        None,
        None,
        None,
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

/// Convert [`EntityDescriptor`]s into Thrift `RichTextEntity` objects.
#[allow(clippy::vec_box)]
pub fn build_thrift_entities(descs: &[EntityDescriptor]) -> Vec<Box<ThriftRichTextEntity>> {
    descs
        .iter()
        .filter_map(|d| {
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
                _ => return None,
            };
            Some(Box::new(ThriftRichTextEntity::new(
                Some(d.start),
                Some(d.end),
                Some(Box::new(content)),
            )))
        })
        .collect()
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
        return Err(SdkError::InvalidState(format!(
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
        Err(SdkError::InvalidState(
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
            } => {
                let dimensions = ThriftMediaDimensions::new(Some(*width), Some(*height));
                let resolved_media_type = match media_type {
                    Some(i) => ThriftMediaType::from(*i),
                    None => ThriftMediaType::IMAGE,
                };
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
        let content = build_message_content("Hello!", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();

        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "1");
        assert!(payload.should_notify);
    }

    #[test]
    fn test_encrypt_and_sign_with_options() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hello!", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
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
        let content = build_message_content("Hello!", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg,1",
            "sender-1",
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
        let content = build_message_content("Hello, World!", None, None).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_entities() {
        let entities = build_thrift_entities(&[
            EntityDescriptor {
                start: 0,
                end: 23,
                entity_type: "url".to_string(),
            },
            EntityDescriptor {
                start: 25,
                end: 30,
                entity_type: "mention".to_string(),
            },
            EntityDescriptor {
                start: 32,
                end: 40,
                entity_type: "hashtag".to_string(),
            },
        ]);
        let content =
            build_message_content("https://example.com @user #topic", Some(entities), None)
                .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_all_entity_types() {
        let entities = build_thrift_entities(&[
            EntityDescriptor {
                start: 0,
                end: 5,
                entity_type: "url".to_string(),
            },
            EntityDescriptor {
                start: 6,
                end: 11,
                entity_type: "mention".to_string(),
            },
            EntityDescriptor {
                start: 12,
                end: 17,
                entity_type: "hashtag".to_string(),
            },
            EntityDescriptor {
                start: 18,
                end: 23,
                entity_type: "cashtag".to_string(),
            },
            EntityDescriptor {
                start: 24,
                end: 40,
                entity_type: "email".to_string(),
            },
            EntityDescriptor {
                start: 41,
                end: 55,
                entity_type: "address".to_string(),
            },
            EntityDescriptor {
                start: 56,
                end: 66,
                entity_type: "phone_number".to_string(),
            },
        ]);
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
        )
    }

    #[test]
    fn test_build_message_content_with_preview() {
        let content = build_message_content_with_preview(
            "This is a reply",
            test_preview("seq-123", Some(12345), Some("Original message"), None, None),
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
        let content = build_message_content("Test message", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();

        use base64::{engine::general_purpose::STANDARD, Engine};
        assert!(STANDARD.decode(&payload.encrypted_content).is_ok());
        assert!(STANDARD.decode(&payload.encoded_event_signature).is_ok());
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
            assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
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
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
        assert!(
            err.to_string().contains("too many attachments"),
            "got: {err}"
        );
    }

    // build_thrift_entities — edge cases

    #[test]
    fn test_build_entities_unknown_type_filtered() {
        let entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 5,
            entity_type: "unknown_type".to_string(),
        }]);
        assert!(
            entities.is_empty(),
            "Unknown entity types should be filtered out"
        );
    }

    #[test]
    fn test_build_entities_phone_number_camel_case() {
        let entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 14,
            entity_type: "phoneNumber".to_string(),
        }]);
        assert_eq!(
            entities.len(),
            1,
            "phoneNumber (camelCase) should be accepted"
        );
    }

    #[test]
    fn test_build_entities_mixed_with_unknown_filtered() {
        let entities = build_thrift_entities(&[
            EntityDescriptor {
                start: 0,
                end: 5,
                entity_type: "url".to_string(),
            },
            EntityDescriptor {
                start: 6,
                end: 11,
                entity_type: "bogus".to_string(),
            },
            EntityDescriptor {
                start: 12,
                end: 17,
                entity_type: "mention".to_string(),
            },
        ]);
        assert_eq!(entities.len(), 2, "Only valid types should survive");
    }

    #[test]
    fn test_build_entities_empty_input() {
        let entities = build_thrift_entities(&[]);
        assert!(entities.is_empty());
    }

    #[test]
    fn test_build_entities_all_types_individually() {
        // Tests each branch individually to ensure all type strings resolve
        for (etype, expected_count) in [
            ("url", 1),
            ("mention", 1),
            ("hashtag", 1),
            ("cashtag", 1),
            ("email", 1),
            ("address", 1),
            ("phone_number", 1),
            ("phoneNumber", 1),
            ("invalid", 0),
        ] {
            let entities = build_thrift_entities(&[EntityDescriptor {
                start: 0,
                end: 10,
                entity_type: etype.to_string(),
            }]);
            assert_eq!(
                entities.len(),
                expected_count,
                "Entity type '{}' should produce {} entity(ies)",
                etype,
                expected_count
            );
        }
    }

    // build_message_content — edge cases

    #[test]
    fn test_build_message_content_empty_text() {
        let content = build_message_content("", None, None).unwrap();
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
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_very_long_text() {
        let long_text = "A".repeat(10_000);
        let content = build_message_content(&long_text, None, None).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_entities_and_attachments() {
        let entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 23,
            entity_type: "url".to_string(),
        }]);
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
        }]);
        let content = build_message_content("Check this out", None, Some(attachments)).unwrap();
        assert!(!content.is_empty());
    }

    // build_message_content_with_preview — with entities / attachments

    #[test]
    fn test_build_message_content_with_preview_and_entities() {
        let entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 5,
            entity_type: "mention".to_string(),
        }]);
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
        }]);
        let content = build_message_content_with_preview(
            "Here's a photo reply",
            test_preview("seq-789", Some(11111), Some("Send me a pic"), None, None),
            None,
            Some(attachments),
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_entities() {
        let reply_entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 6,
            entity_type: "hashtag".to_string(),
        }]);
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
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_build_message_content_with_preview_all_fields() {
        let entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 5,
            entity_type: "mention".to_string(),
        }]);
        let attachments = build_thrift_attachments(&[AttachmentDescriptor::Url {
            url: "https://reply-link.com".to_string(),
            display_title: None,
            banner_image: None,
            favicon_image: None,
        }]);
        let reply_entities = build_thrift_entities(&[EntityDescriptor {
            start: 0,
            end: 20,
            entity_type: "url".to_string(),
        }]);
        let reply_attachments = build_thrift_attachments(&[AttachmentDescriptor::Media {
            media_hash_key: "orig_media".to_string(),
            width: 400,
            height: 300,
            filesize_bytes: 30_000,
            filename: "original.jpg".to_string(),
            media_type: Some(1),
            duration_millis: None,
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
        )
        .unwrap();
        assert!(!content.is_empty());
    }

    // encrypt_and_sign — error / edge branches

    #[test]
    fn test_encrypt_and_sign_rejects_comma_in_sender_id() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender,1", // comma in sender id
            "conv-1",
            &content,
            "1",
            "1",
        );
        let result = encrypt_and_sign(params);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("comma"));
    }

    #[test]
    fn test_encrypt_and_sign_rejects_comma_in_conversation_id() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
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
    fn test_encrypt_and_sign_rejects_comma_in_key_version() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Hi", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
            "conv-1",
            &content,
            "1,2", // comma in key version
            "1",
        );
        assert!(encrypt_and_sign(params).is_err());
    }

    #[test]
    fn test_encrypt_and_sign_signature_info_fields() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Fields check", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-42",
            "sender-99",
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
    }

    #[test]
    fn test_encrypt_and_sign_empty_content() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("", None, None).unwrap();

        let params = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-empty",
            "sender-1",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload = encrypt_and_sign(params).unwrap();
        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.signature.is_empty());
    }

    #[test]
    fn test_encrypt_and_sign_two_calls_produce_different_ciphertext() {
        let (ckey, signing_key) = test_keys();
        let content = build_message_content("Same message", None, None).unwrap();

        let params1 = EncryptAndSignParams::new(
            &ckey,
            &signing_key,
            "msg-1",
            "sender-1",
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
            "sender-1",
            "conv-1",
            &content,
            "1",
            "1",
        );
        let payload2 = encrypt_and_sign(params2).unwrap();

        // Random nonce means different ciphertext each time
        assert_ne!(
            payload1.encrypted_content, payload2.encrypted_content,
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
