//! # Developer-Friendly Types
//!
//! These types map to the X Chat Thrift schema but are designed for ergonomic
//! use across language bindings.
//!
//! ## Event Types (from `MessageEventDetail` union)
//!
//! The main [`Event`] enum covers all event types you'll receive from webhooks:
//!
//! | Variant | Thrift Source | Description |
//! |---------|---------------|-------------|
//! | `Message` | `MessageCreateEvent` | A new message |
//! | `KeyChange` | `ConversationKeyChangeEvent` | Conversation key rotated |
//! | `GroupChange` | `GroupChangeEvent` | Group membership/settings changed |
//! | `MessageDeleted` | `MessageDeleteEvent` | Messages deleted |
//! | `ConversationDeleted` | `ConversationDeleteEvent` | Conversation deleted |
//! | `Typing` | `MessageTypingEvent` | Someone is typing |
//! | `ReadReceipt` | `MarkConversationReadEvent` | Conversation marked read |
//! | `Failure` | `MessageFailureEvent` | Message delivery failed |
//!
//! ## Message Content Types (from `MessageEntryContents` union)
//!
//! After decryption, message content can be:
//! - Text message
//! - Reaction (add/remove)
//! - Message edit
//! - Read/unread markers

use crate::signatures::ActionSignature;
#[cfg(feature = "js")]
use crate::signatures::JsActionSignature;
use serde::{Deserialize, Serialize};

/// An empty payload used by tag-only rich-text entity variants that carry no
/// additional data (e.g. a hashtag or mention marker).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct EmptyObject {}

/// A rich-text entity (mention, URL, hashtag, etc.) spanning a range of the
/// message text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct RichTextEntity {
    pub start_index: Option<i32>,
    pub end_index: Option<i32>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub content: Option<RichTextContent>,
}

/// The kind of a rich-text entity; each variant names the entity type and
/// carries its (currently empty) payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum RichTextContent {
    Hashtag {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        hashtag: EmptyObject,
    },
    Cashtag {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        cashtag: EmptyObject,
    },
    Mention {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        mention: EmptyObject,
    },
    Url {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        url: EmptyObject,
    },
    Email {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        email: EmptyObject,
    },
    Address {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        address: EmptyObject,
    },
    PhoneNumber {
        #[serde(rename = "phoneNumber")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        phone_number: EmptyObject,
    },
}

/// An attachment carried in decrypted message content. The variant determines
/// the attachment kind (media, post, URL card, unified card, or money).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum MessageAttachment {
    Media {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        media: MediaAttachment,
    },
    Post {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        post: PostAttachment,
    },
    Url {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        url: UrlAttachment,
    },
    UnifiedCard {
        // serde's enum `rename_all` does not cascade to struct-variant fields,
        // so this explicit rename is what the JsCamelCase macro re-camelCases
        // to `unifiedCard` for the JS output. Removing it leaks snake_case.
        #[serde(rename = "unified_card")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        unified_card: UnifiedCardAttachment,
    },
    Money {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        money: MoneyAttachment,
    },
}

/// Money attachment as it appears in decrypted message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MoneyAttachment {
    pub fallback_text: Option<String>,
    pub payload: Option<String>,
}

/// Post (tweet) attachment as it appears in decrypted message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PostAttachment {
    pub rest_id: Option<String>,
    pub post_url: Option<String>,
    pub attachment_id: Option<String>,
}

/// URL card attachment as it appears in decrypted message content, including
/// any preview images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UrlAttachment {
    pub url: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub banner_image_media_hash_key: Option<UrlAttachmentImage>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub favicon_image_media_hash_key: Option<UrlAttachmentImage>,
    pub display_title: Option<String>,
    pub attachment_id: Option<String>,
}

/// Unified card attachment as it appears in decrypted message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UnifiedCardAttachment {
    pub url: Option<String>,
    pub attachment_id: Option<String>,
}

/// A preview image (banner or favicon) referenced by a URL card attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UrlAttachmentImage {
    pub media_hash_key: Option<String>,
    pub filesize_bytes: Option<i64>,
    pub filename: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub dimensions: Option<MediaDimensions>,
}

/// Media attachment (image, gif, video, etc.) as it appears in decrypted
/// message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MediaAttachment {
    pub media_hash_key: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub dimensions: Option<MediaDimensions>,
    #[serde(rename = "type")]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub media_type: Option<MediaType>,
    pub duration_millis: Option<i64>,
    pub filesize_bytes: Option<i64>,
    pub filename: Option<String>,
    pub attachment_id: Option<String>,
    pub legacy_media_url_https: Option<String>,
    pub legacy_media_preview_url: Option<String>,
}

/// Media dimensions (width/height).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MediaDimensions {
    pub width: Option<i64>,
    pub height: Option<i64>,
}

/// The kind of a media attachment: a known type or an unrecognized numeric id
/// for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum MediaType {
    #[cfg_attr(feature = "js", js_camel(wrap))]
    Known(MediaTypeKnown),
    Unknown(i32),
}

/// Known media attachment kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MediaTypeKnown {
    Image,
    Gif,
    Video,
    Audio,
    File,
    Svg,
}

/// Preview of the message being replied to, embedded in a reply's content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ReplyingToPreview {
    pub sender_id: Option<String>,
    pub message_text: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub entities: Option<Vec<RichTextEntity>>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub attachments: Option<Vec<MessageAttachment>>,
    pub sender_display_name: Option<String>,
    pub replying_to_message_sequence_id: Option<String>,
    pub replying_to_message_id: Option<String>,
}

/// Metadata describing a forwarded message's original content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ForwardedMessage {
    pub message_text: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub entities: Option<Vec<RichTextEntity>>,
}

/// The app surface a message was sent from: a known surface or an unrecognized
/// numeric id for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum SentFromSurface {
    #[cfg_attr(feature = "js", js_camel(wrap))]
    Known(SentFromSurfaceKnown),
    Unknown(i32),
}

/// Known app surfaces a message can be sent from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SentFromSurfaceKnown {
    ConversationScreenComposer,
    NotificationReply,
    ShareSheet,
    PaymentsSupportComposer,
    MessageForwardSheet,
}

/// A quick-reply carried by a message: either a request offering options or a
/// response selecting one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum QuickReply {
    Request {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        request: QuickReplyRequest,
    },
    Response {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        response: QuickReplyResponse,
    },
}

/// A quick-reply request offering a set of selectable options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum QuickReplyRequest {
    Options {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        options: QuickReplyOptionsRequest,
    },
}

/// A quick-reply response selecting a previously offered option.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
pub enum QuickReplyResponse {
    Options {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        options: QuickReplyOptionsResponse,
    },
}

/// The options offered by a quick-reply request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct QuickReplyOptionsRequest {
    pub id: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub options: Option<Vec<QuickReplyOption>>,
}

/// The option selected in a quick-reply response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct QuickReplyOptionsResponse {
    pub request_id: Option<String>,
    pub metadata: Option<String>,
    pub selected_option_id: Option<String>,
}

/// A single selectable quick-reply option.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct QuickReplyOption {
    pub id: Option<String>,
    pub label: Option<String>,
    pub metadata: Option<String>,
    pub description: Option<String>,
}

/// A call-to-action button (label plus URL) attached to a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct CallToAction {
    pub label: Option<String>,
    pub url: Option<String>,
}

/// A decrypted event from the X Chat API.
///
/// This enum covers all event types from the `MessageEventDetail` Thrift union.
/// Use pattern matching to handle different event types in your webhook handler.
///
/// # Example
///
/// ```rust,ignore
/// match event {
///     Event::Message(msg) => {
///         println!("{}: {}", msg.sender_id, msg.text());
///     }
///     Event::KeyChange(kc) => {
///         // Store the new conversation key
///         let my_key = kc.find_key_for_user(&my_user_id);
///     }
///     Event::GroupChange(gc) => {
///         println!("Group updated: {:?}", gc.change);
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type")]
pub enum Event {
    /// A new message (text, reaction, edit, etc.)
    /// Maps to `MessageCreateEvent` in Thrift.
    Message(#[cfg_attr(feature = "js", js_camel(wrap))] Box<Message>),

    /// Conversation key was rotated.
    /// Maps to `ConversationKeyChangeEvent` in Thrift.
    KeyChange(#[cfg_attr(feature = "js", js_camel(wrap))] KeyChangeEvent),

    /// Group membership or settings changed.
    /// Maps to `GroupChangeEvent` in Thrift.
    GroupChange(#[cfg_attr(feature = "js", js_camel(wrap))] GroupChangeEvent),

    /// One or more messages were deleted.
    /// Maps to `MessageDeleteEvent` in Thrift.
    MessageDeleted(#[cfg_attr(feature = "js", js_camel(wrap))] MessageDeletedEvent),

    /// A conversation was deleted.
    /// Maps to `ConversationDeleteEvent` in Thrift.
    ConversationDeleted(#[cfg_attr(feature = "js", js_camel(wrap))] ConversationDeletedEvent),

    /// Someone is typing.
    /// Maps to `MessageTypingEvent` in Thrift.
    Typing(#[cfg_attr(feature = "js", js_camel(wrap))] TypingEvent),

    /// Conversation was marked as read.
    /// Maps to `MarkConversationReadEvent` in Thrift.
    ReadReceipt(#[cfg_attr(feature = "js", js_camel(wrap))] ReadReceiptEvent),

    /// Conversation was marked as unread.
    /// Maps to `MarkConversationUnreadEvent` in Thrift.
    MarkedUnread(#[cfg_attr(feature = "js", js_camel(wrap))] MarkedUnreadEvent),

    /// Message delivery failed.
    /// Maps to `MessageFailureEvent` in Thrift.
    Failure(#[cfg_attr(feature = "js", js_camel(wrap))] FailureEvent),

    /// Conversation settings changed (TTL, mute, etc.)
    /// Maps to `ConversationMetadataChangeEvent` in Thrift.
    SettingsChange(#[cfg_attr(feature = "js", js_camel(wrap))] SettingsChangeEvent),

    /// A member's account was deleted.
    /// Maps to `MemberAccountDeleteEvent` in Thrift.
    MemberDeleted(#[cfg_attr(feature = "js", js_camel(wrap))] MemberDeletedEvent),

    /// Unknown or unsupported event type.
    Unknown(#[cfg_attr(feature = "js", js_camel(wrap))] UnknownEvent),
}

/// A decrypted message.
///
/// This wraps `MessageCreateEvent` and the decrypted `MessageEntryContents`.
/// The `content` field tells you what type of message this is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct Message {
    /// Event metadata
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// The decrypted message content.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub content: MessageContent,

    /// Version of the conversation key used.
    pub key_version: Option<String>,

    /// Whether signature was verified.
    pub verified: bool,

    /// Whether push notification should be sent.
    pub should_notify: Option<bool>,

    /// Time-to-live for disappearing messages (milliseconds).
    pub ttl_msec: Option<i64>,

    /// Attachments included with the message (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub attachments: Vec<AttachmentInfo>,

    /// Media hash keys derived from attachments (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub media_hashes: Vec<MediaHashReference>,

    /// Outcome of validating the reply preview against the raw signed
    /// original event embedded in it. `None` when the message carries no
    /// preview or the preview carries no raw event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub reply_preview_validation: Option<ReplyPreviewValidation>,
}

/// Outcome of validating a reply preview against its embedded raw original
/// event: the raw event's signature is verified, its contents decrypted, and
/// the preview's claims compared to the decrypted original.
///
/// `Valid` authenticates the quoted content and authorship (the signature
/// covers the original's message id, sender, conversation, key version, and
/// ciphertext) but not the sequence-id anchor — sequence ids are unsigned
/// backend metadata, checked only for consistency with the embedded event's
/// own envelope. Anchor reply navigation on the signed
/// `replying_to_message_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub enum ReplyPreviewValidation {
    /// The raw event verified and the preview matches the original.
    Valid,
    /// The raw event failed verification, could not be decrypted, or the
    /// preview does not match the decrypted original. Treat the preview as
    /// untrusted.
    Invalid,
}

impl Message {
    /// Get the message text if this is a text message.
    pub fn text(&self) -> Option<&str> {
        match &self.content {
            MessageContent::Text { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Check if this is a text message.
    pub fn is_text(&self) -> bool {
        matches!(self.content, MessageContent::Text { .. })
    }

    /// Check if this is a reaction.
    pub fn is_reaction(&self) -> bool {
        matches!(
            self.content,
            MessageContent::Reaction { .. } | MessageContent::ReactionRemoved { .. }
        )
    }
}

/// The content of a decrypted message.
///
/// Maps to `MessageEntryContents` union in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "content_type")]
pub enum MessageContent {
    /// A text message.
    Text {
        /// The message text.
        text: String,
        /// Rich text entities in the message.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        entities: Option<Vec<RichTextEntity>>,
        /// Message attachments (media, urls, posts, etc).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        attachments: Option<Vec<MessageAttachment>>,
        /// Replying-to preview data.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        replying_to_preview: Option<ReplyingToPreview>,
        /// Forwarded message metadata.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        forwarded_message: Option<ForwardedMessage>,
        /// Surface the message was sent from.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        sent_from: Option<SentFromSurface>,
        /// Quick reply request/response details.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        quick_reply: Option<QuickReply>,
        /// Call-to-action buttons.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        ctas: Option<Vec<CallToAction>>,
    },

    /// A reaction was added.
    Reaction {
        /// The emoji.
        emoji: String,
        /// Sequence ID of the message being reacted to.
        target_message_id: String,
    },

    /// A reaction was removed.
    ReactionRemoved {
        /// The emoji.
        emoji: String,
        /// Sequence ID of the message.
        target_message_id: String,
    },

    /// A message was edited.
    Edit {
        /// Sequence ID of the edited message.
        target_message_id: String,
        /// The new text.
        new_text: String,
    },

    /// Conversation marked as read (encrypted marker).
    MarkRead,

    /// Conversation marked as unread (encrypted marker).
    MarkUnread,

    /// Unknown content type.
    Unknown {
        /// Raw content type ID if available.
        type_id: Option<i16>,
    },
}

/// A reference to a media hash key found in attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MediaHashReference {
    /// Where the media hash was found (e.g. "media", "url_banner", "url_favicon").
    pub source: String,
    /// The media hash key.
    pub media_hash_key: String,
}

/// A message attachment with media-related metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MediaAttachmentInfo {
    pub media_hash_key: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub dimensions: Option<MediaDimensionsInfo>,
    pub media_type: Option<String>,
    pub duration_millis: Option<i64>,
    pub filesize_bytes: Option<i64>,
    pub filename: Option<String>,
    pub attachment_id: Option<String>,
    pub legacy_media_url_https: Option<String>,
    pub legacy_media_preview_url: Option<String>,
}

/// Media dimensions (width/height).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MediaDimensionsInfo {
    pub width: Option<i64>,
    pub height: Option<i64>,
}

/// URL attachment metadata, including any media hashes for preview images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UrlAttachmentInfo {
    pub url: Option<String>,
    pub banner_image_media_hash_key: Option<String>,
    pub favicon_image_media_hash_key: Option<String>,
    pub display_title: Option<String>,
    pub attachment_id: Option<String>,
}

/// Post attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PostAttachmentInfo {
    pub rest_id: Option<String>,
    pub post_url: Option<String>,
    pub attachment_id: Option<String>,
}

/// Unified card attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UnifiedCardAttachmentInfo {
    pub url: Option<String>,
    pub attachment_id: Option<String>,
}

/// Money attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MoneyAttachmentInfo {
    pub fallback_text: Option<String>,
}

/// Attachments decoded from MessageContents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "attachment_type")]
pub enum AttachmentInfo {
    Media(#[cfg_attr(feature = "js", js_camel(wrap))] MediaAttachmentInfo),
    Url(#[cfg_attr(feature = "js", js_camel(wrap))] UrlAttachmentInfo),
    Post(#[cfg_attr(feature = "js", js_camel(wrap))] PostAttachmentInfo),
    UnifiedCard(#[cfg_attr(feature = "js", js_camel(wrap))] UnifiedCardAttachmentInfo),
    Money(#[cfg_attr(feature = "js", js_camel(wrap))] MoneyAttachmentInfo),
}

/// Conversation key rotation event.
///
/// When you receive this, find your entry in `participant_keys` and store
/// the new encrypted key.
///
/// Maps to `ConversationKeyChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct KeyChangeEvent {
    /// Event metadata.
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// New conversation key version.
    pub key_version: String,

    /// Whether the signature was verified.
    pub verified: bool,

    /// Encrypted keys for each participant.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub participant_keys: Vec<ParticipantKey>,
}

impl KeyChangeEvent {
    /// Find the encrypted key for a specific user.
    pub fn find_key_for_user(&self, user_id: &str) -> Option<&ParticipantKey> {
        self.participant_keys.iter().find(|k| k.user_id == user_id)
    }
}

/// An encrypted conversation key for a participant.
///
/// Maps to `ConversationParticipantKey` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ParticipantKey {
    /// The user's ID.
    pub user_id: String,

    /// Base64-encoded encrypted conversation key.
    pub encrypted_key: String,

    /// Version of the user's public key used for encryption.
    pub public_key_version: String,
}

/// Group membership or settings changed.
///
/// Maps to `GroupChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct GroupChangeEvent {
    /// Event metadata.
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// The specific change that occurred.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub change: GroupChange,
}

/// The type of group change.
///
/// Maps to `GroupChange` union in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "change_type")]
pub enum GroupChange {
    /// Group was created.
    Created {
        member_ids: Vec<String>,
        admin_ids: Vec<String>,
        title: Option<String>,
        avatar_url: Option<String>,
    },

    /// Group title changed.
    TitleChanged { new_title: String },

    /// Group avatar changed.
    AvatarChanged { new_avatar_url: String },

    /// Admins were added.
    AdminsAdded { admin_ids: Vec<String> },

    /// Admins were removed.
    AdminsRemoved { admin_ids: Vec<String> },

    /// Members were added.
    MembersAdded {
        /// IDs of the members that were just added.
        member_ids: Vec<String>,
        /// Full member list after the addition.
        current_member_ids: Vec<String>,
        /// Full admin list after the addition.
        current_admin_ids: Vec<String>,
    },

    /// Members were removed.
    MembersRemoved { member_ids: Vec<String> },

    /// Group invite link enabled.
    InviteEnabled {
        invite_url: String,
        expires_at_msec: Option<i64>,
    },

    /// Group invite link disabled.
    InviteDisabled { disabled_by: Option<String> },

    /// Someone requested to join.
    JoinRequested { user_id: String },

    /// Join request was rejected.
    JoinRejected { user_ids: Vec<String> },

    /// Unknown group change type.
    Unknown,
}

/// Messages were deleted.
///
/// Maps to `MessageDeleteEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MessageDeletedEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// IDs of deleted messages.
    pub message_ids: Vec<String>,

    /// Whether deleted for self only or for everyone.
    pub delete_for_all: bool,
}

/// Conversation was deleted.
///
/// Maps to `ConversationDeleteEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ConversationDeletedEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// Whether all messages were cleared.
    pub clear_all_messages: bool,
}

/// Someone is typing.
///
/// Maps to `MessageTypingEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct TypingEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,
}

/// Conversation was marked as read.
///
/// Maps to `MarkConversationReadEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ReadReceiptEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// Messages up to this ID were read.
    pub seen_until_id: Option<String>,

    /// When the conversation was marked read (milliseconds).
    pub seen_at_msec: Option<i64>,
}

/// Conversation was marked as unread.
///
/// Maps to `MarkConversationUnreadEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MarkedUnreadEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// Messages up to this ID were read.
    pub seen_until_id: Option<String>,
}

/// Message delivery failed.
///
/// Maps to `MessageFailureEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct FailureEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// The type of failure.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub failure: FailureType,
}

/// Why a message failed to deliver.
///
/// Maps to `FailureType` enum in Thrift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub enum FailureType {
    EmptyDetail,
    InternalError,
    ContentsTooLarge,
    TooManyMessages,
    InvalidSenderSignature,
    NonLatestKeyVersion,
    RecipientNotTrusted,
    RecipientKeyChanged,
    Unknown,
}

/// Conversation settings changed.
///
/// Maps to `ConversationMetadataChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct SettingsChangeEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// The setting that changed.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub change: SettingsChange,
}

/// A conversation setting change.
///
/// Maps to `ConversationMetadataChange` union in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "setting")]
pub enum SettingsChange {
    /// Disappearing message duration changed.
    MessageDuration { ttl_msec: i64, apply_to_all: bool },
    /// Disappearing messages disabled.
    MessageDurationRemoved,
    /// Conversation muted.
    Muted,
    /// Conversation unmuted.
    Unmuted,
    /// Screenshot detection enabled.
    ScreenCaptureDetectionEnabled,
    /// Screenshot detection disabled.
    ScreenCaptureDetectionDisabled,
    /// Screenshot blocking enabled.
    ScreenCaptureBlockingEnabled,
    /// Screenshot blocking disabled.
    ScreenCaptureBlockingDisabled,
    /// Unknown or unsupported setting change.
    Unknown,
}

/// A member's account was deleted.
///
/// Maps to `MemberAccountDeleteEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct MemberDeletedEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// The deleted member's ID.
    pub member_id: String,
}

/// Unknown or unsupported event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct UnknownEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Raw event type ID if known.
    pub event_type_id: Option<i16>,
}

/// Common metadata for all events.
///
/// Maps to fields on `MessageEvent` in Thrift.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct EventMeta {
    /// Unique sequence ID for ordering.
    pub sequence_id: Option<String>,

    /// Unique message/event ID.
    pub id: Option<String>,

    /// Sender's user ID.
    pub sender_id: Option<String>,

    /// Conversation ID.
    pub conversation_id: Option<String>,

    /// Timestamp in milliseconds.
    pub created_at_msec: Option<i64>,
}

/// Payload ready to send to the X API.
///
/// This is returned by [`crate::Chat::encrypt_message`] and can be serialized
/// directly to JSON for the API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct SendPayload {
    /// The generated message id (UUID) embedded in the signed event. Send it as
    /// the message's `message_id`, keep it to dedup and to anchor replies, and
    /// reuse the same encrypted payload on retries so an id is never minted twice.
    pub message_id: String,

    /// Base64-encoded encrypted content.
    pub encrypted_content: String,

    /// Base64-encoded signature.
    pub signature: String,

    /// Base64-encoded Thrift `MessageEventSignature` (for `encoded_message_event_signature`).
    ///
    /// The X API expects this value (not the raw signature bytes) when sending messages.
    pub encoded_event_signature: String,

    /// Signature metadata.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub signature_info: SignatureInfo,

    /// Conversation key version used.
    pub conversation_key_version: String,

    /// Whether to send push notification.
    #[serde(default = "default_true")]
    pub should_notify: bool,
}

fn default_true() -> bool {
    true
}

/// Signature information for a sent message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct SignatureInfo {
    /// Version of the signing key used.
    pub public_key_version: String,

    /// Signature protocol version.
    #[serde(default = "default_sig_version")]
    pub signature_version: String,
}

fn default_sig_version() -> String {
    crate::signatures::SIGNATURE_VERSION.to_string()
}

/// Describes a rich-text entity (URL, mention, hashtag, etc.) to embed in a
/// message.  The `start` and `end` byte offsets refer to the message text.
#[derive(Clone, Debug, PartialEq)]
pub struct EntityDescriptor {
    /// Start byte offset of the entity within the message text (inclusive).
    pub start: i32,
    /// End byte offset of the entity within the message text (exclusive).
    pub end: i32,
    /// One of: `"url"`, `"mention"`, `"hashtag"`, `"cashtag"`, `"email"`,
    /// `"address"`, `"phone_number"`. Unrecognized values are ignored.
    pub entity_type: String,
}

/// Describes an attachment to include in a message or reply-to preview.
///
/// The variant determines which attachment branch is produced when building
/// the content.
///
/// This is a caller-supplied input type. Its tag and field names use
/// snake_case (and the JsCamelCase macro is intentionally not applied) so the
/// keys line up with the protocol field names and the same descriptor shape can
/// be passed unchanged from every binding, including JS.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attachment_type", rename_all = "snake_case")]
pub enum AttachmentDescriptor {
    /// A media attachment (image, gif, video, etc.).
    Media {
        media_hash_key: String,
        width: i64,
        height: i64,
        filesize_bytes: i64,
        filename: String,
        /// Media type: 1=image, 2=gif, 3=video, 4=audio, 5=file, 6=svg.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_millis: Option<i64>,
    },
    /// A URL card attachment.
    ///
    /// Supplying `display_title` and `banner_image` makes receiving clients
    /// render a full clickable preview card without any unencrypted fetch:
    /// clients only auto-fetch missing card details for their own messages
    /// (an IP-leak guard), so a bare URL from another sender falls back to a
    /// plain link on some platforms. The banner/favicon images must be
    /// encrypted with `encrypt_stream` and uploaded to the conversation's
    /// media store first; reference them here by the returned media hash key.
    Url {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_title: Option<String>,
        /// Large preview image shown on top of the card.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        banner_image: Option<UrlAttachmentImageDescriptor>,
        /// Small site icon shown when no banner is available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        favicon_image: Option<UrlAttachmentImageDescriptor>,
    },
    /// A post / tweet attachment.
    Post {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rest_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        post_url: Option<String>,
    },
}

/// An encrypted preview image referenced by a URL card attachment
/// ([`AttachmentDescriptor::Url`]).
///
/// Like `AttachmentDescriptor`, this is a caller-supplied input type whose
/// field names stay snake_case in every binding so the same object shape can
/// be passed unchanged from each language.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UrlAttachmentImageDescriptor {
    /// Media hash key returned by the media upload for the encrypted image.
    pub media_hash_key: String,
    /// Size of the encrypted image in bytes.
    ///
    /// Required: receiving clients' shared ingest silently discards the
    /// whole preview image when this field is missing on the wire.
    pub filesize_bytes: i64,
    /// Original filename of the image (receivers use it to key the
    /// decrypted-file cache).
    ///
    /// Required: receiving clients' shared ingest silently discards the
    /// whole preview image when this field is missing on the wire.
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
}

/// Public keys returned by setup/get_public_keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeys {
    /// Base64-encoded identity public key (P-256, for ECDH).
    pub identity: String,

    /// Base64-encoded signing public key (P-256, for ECDSA).
    pub signing: String,

    /// Key version identifier.
    #[serde(default)]
    pub version: String,
}

/// Public key registration payload for the X API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PublicKeyRegistrationPayload {
    /// Public key registration object.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub public_key: PublicKeyRegistration,

    /// Version to register (optional if generate_version is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// When true, server generates a new version.
    #[serde(default)]
    pub generate_version: bool,
}

/// Public key registration fields expected by the X API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PublicKeyRegistration {
    /// Raw r||s ECDSA signature: the **signing** private key signs the
    /// SPKI-encoded **identity** public key.  Proves the signing key holder
    /// endorsed this identity key.
    pub identity_public_key_signature: String,

    /// Identity public key (base64 encoded).
    pub public_key: String,

    /// Fingerprint of the identity public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_fingerprint: Option<String>,

    /// Registration method (e.g. CustomPin, ManagedPin).
    pub registration_method: String,

    /// Signing public key (base64 encoded).
    pub signing_public_key: String,

    /// Raw r||s ECDSA signature: the **identity** private key signs the
    /// SPKI-encoded **signing** public key. Together with
    /// `identity_public_key_signature` this creates a bidirectional binding
    /// proving both keys were generated together.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_public_key_signature: Option<String>,
}

/// A signing key entry for `decrypt_event` and `decrypt_events`.
///
/// Pass the full set of known signing keys for participants; the SDK selects
/// the one matching the `public_key_version` embedded in the message signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct SigningKeyEntry {
    /// ID of the user that owns this signing key.
    pub user_id: String,
    /// Version of the user's public key from the X API (a snowflake/timestamp string).
    pub public_key_version: String,
    /// Base64-encoded signing public key (SEC1 or SPKI).
    pub public_key: String,
    /// Base64-encoded identity public key (SEC1 or SPKI) for this user.
    pub identity_public_key: String,
    /// Base64-encoded raw r||s signature proving the signing key is bound
    /// to the identity key. Returned by the X API on the public key response.
    pub identity_public_key_signature: String,
}

/// Result from `extract_conversation_keys`.
///
/// Contains the full key map plus convenience accessors for the latest key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct ConversationKeyResult {
    /// Map of key version → raw conversation key bytes.
    #[serde(skip)]
    pub keys: std::collections::HashMap<String, crate::crypto::keys::XChatConversationKey>,
    /// The latest (highest) key version, if any.
    pub latest_version: Option<String>,
}

impl ConversationKeyResult {
    /// Get a key by version.
    pub fn get(&self, version: &str) -> Option<&crate::crypto::keys::XChatConversationKey> {
        self.keys.get(version)
    }

    /// Get the latest conversation key.
    pub fn latest_key(&self) -> Option<&crate::crypto::keys::XChatConversationKey> {
        self.latest_version.as_ref().and_then(|v| self.keys.get(v))
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// A decrypted message with its verification status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct DecryptedMessage {
    /// The decrypted event.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub event: Event,
    /// Original base64 event string (for reference).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_b64: Option<String>,
}

/// Result from `decrypt_events` batch API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct DecryptEventsResult {
    /// Successfully decrypted messages.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub messages: Vec<DecryptedMessage>,
    /// Conversation keys extracted from key events.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub conversation_keys: ConversationKeyResult,
    /// Errors encountered during decryption (index → error message).
    pub errors: std::collections::HashMap<usize, String>,
}

/// A public key input entry for `prepare_conversation_key_change` /
/// `prepare_group_members_change`.
///
/// Represents a single public key version for a user, as returned by the X API
/// `GET /2/dm/encryption/public_keys` endpoint. Pass the full array; the SDK
/// will group by user and pick the latest version per user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PublicKeyInput {
    /// The user's ID.
    pub user_id: String,
    /// Base64-encoded identity public key (SEC1 or SPKI).
    pub public_key: String,
    /// Key version string from the X API.
    pub key_version: String,
}

/// A signed conversation-key change, ready to send to the X API.
///
/// Returned by both `prepare_conversation_key_change` and
/// `prepare_group_members_change`. Carries the new key (to keep locally), the
/// per-participant encrypted copies, and the action signature that lets
/// recipients verify the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct PreparedConversationChange {
    /// Conversation id the change applies to. Derived for a one-to-one,
    /// or the id passed in for a group.
    pub conversation_id: String,

    /// Raw conversation key bytes (32 bytes). Store this locally for encrypting messages.
    ///
    /// Excluded from serialization — this is secret key material that should
    /// never be sent to the server.
    #[serde(skip_serializing, skip_deserializing)]
    pub conversation_key: Option<crate::crypto::keys::XChatConversationKey>,

    /// Timestamp-based version string for this conversation key.
    pub conversation_key_version: String,

    /// Encrypted keys for each participant, ready to POST to the API.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub participant_keys: Vec<EncryptedKeyForRecipient>,

    /// Action signatures authenticating the change, ready to POST to the API.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub action_signatures: Vec<ActionSignature>,
}

/// A recipient entry for encrypting a conversation key per participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RecipientInput {
    /// Recipient's user ID.
    pub user_id: String,
    /// Base64-encoded identity public key (SEC1 or SPKI).
    pub public_key: String,
    /// Version of the recipient's public key (from the X API).
    pub key_version: String,
}

/// Encrypted conversation key for a recipient.
///
/// Used when creating a new conversation or rotating keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
pub struct EncryptedKeyForRecipient {
    /// Recipient's user ID.
    pub user_id: String,

    /// Base64-encoded encrypted conversation key.
    pub encrypted_key: String,

    /// Version of recipient's public key used.
    pub public_key_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_message(text: &str) -> Message {
        Message {
            meta: EventMeta::default(),
            content: MessageContent::Text {
                text: text.to_string(),
                entities: None,
                attachments: None,
                replying_to_preview: None,
                forwarded_message: None,
                sent_from: None,
                quick_reply: None,
                ctas: None,
            },
            key_version: None,
            verified: true,
            should_notify: Some(true),
            ttl_msec: None,
            attachments: vec![],
            media_hashes: vec![],
            reply_preview_validation: None,
        }
    }

    #[test]
    fn test_message_text() {
        let msg = text_message("Hello!");
        assert_eq!(msg.text(), Some("Hello!"));
        assert!(msg.is_text());
        assert!(!msg.is_reaction());
    }

    #[test]
    fn test_message_text_none_for_reaction() {
        let msg = Message {
            meta: EventMeta::default(),
            content: MessageContent::Reaction {
                emoji: "👍".to_string(),
                target_message_id: "seq-1".to_string(),
            },
            key_version: None,
            verified: true,
            should_notify: None,
            ttl_msec: None,
            attachments: vec![],
            media_hashes: vec![],
            reply_preview_validation: None,
        };
        assert_eq!(msg.text(), None);
        assert!(!msg.is_text());
        assert!(msg.is_reaction());
    }

    #[test]
    fn test_message_is_reaction_removed() {
        let msg = Message {
            meta: EventMeta::default(),
            content: MessageContent::ReactionRemoved {
                emoji: "👎".to_string(),
                target_message_id: "seq-2".to_string(),
            },
            key_version: None,
            verified: false,
            should_notify: None,
            ttl_msec: None,
            attachments: vec![],
            media_hashes: vec![],
            reply_preview_validation: None,
        };
        assert!(msg.is_reaction());
        assert!(!msg.is_text());
    }

    #[test]
    fn test_key_change_find_key_for_user() {
        let kc = KeyChangeEvent {
            meta: EventMeta::default(),
            key_version: "v1".to_string(),
            verified: true,
            participant_keys: vec![
                ParticipantKey {
                    user_id: "alice".to_string(),
                    encrypted_key: "key_a".to_string(),
                    public_key_version: "v1".to_string(),
                },
                ParticipantKey {
                    user_id: "bob".to_string(),
                    encrypted_key: "key_b".to_string(),
                    public_key_version: "v1".to_string(),
                },
            ],
        };

        assert_eq!(
            kc.find_key_for_user("alice").unwrap().encrypted_key,
            "key_a"
        );
        assert_eq!(kc.find_key_for_user("bob").unwrap().encrypted_key, "key_b");
        assert!(kc.find_key_for_user("charlie").is_none());
    }

    #[test]
    fn test_event_serde_roundtrip_message() {
        let event = Event::Message(Box::new(text_message("test")));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"Message\""));
        assert!(json.contains("\"content_type\":\"Text\""));
        assert!(json.contains("\"text\":\"test\""));

        let deserialized: Event = serde_json::from_str(&json).unwrap();
        if let Event::Message(msg) = deserialized {
            assert_eq!(msg.text(), Some("test"));
        } else {
            panic!("Expected Message event");
        }
    }

    #[test]
    fn test_event_serde_roundtrip_typing() {
        let event = Event::Typing(TypingEvent {
            meta: EventMeta {
                sender_id: Some("user-1".to_string()),
                ..Default::default()
            },
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"Typing\""));
        assert!(json.contains("\"sender_id\":\"user-1\""));
    }

    #[test]
    fn test_event_serde_roundtrip_key_change() {
        let event = Event::KeyChange(KeyChangeEvent {
            meta: EventMeta::default(),
            key_version: "v42".to_string(),
            verified: true,
            participant_keys: vec![],
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"KeyChange\""));
        assert!(json.contains("\"key_version\":\"v42\""));
    }

    #[test]
    fn test_send_payload_serde() {
        let payload = SendPayload {
            message_id: "mid".to_string(),
            encrypted_content: "enc".to_string(),
            signature: "sig".to_string(),
            encoded_event_signature: "esig".to_string(),
            signature_info: SignatureInfo {
                public_key_version: "v1".to_string(),
                signature_version: "4".to_string(),
            },
            conversation_key_version: "v1".to_string(),
            should_notify: true,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: SendPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.encrypted_content, "enc");
        assert_eq!(decoded.signature_info.signature_version, "4");
    }

    #[test]
    fn test_public_key_registration_serde() {
        let payload = PublicKeyRegistrationPayload {
            public_key: PublicKeyRegistration {
                identity_public_key_signature: "sig".to_string(),
                public_key: "pk".to_string(),
                public_key_fingerprint: None,
                registration_method: "CustomPin".to_string(),
                signing_public_key: "spk".to_string(),
                signing_public_key_signature: None,
            },
            version: Some("12345".to_string()),
            generate_version: true,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("public_key_fingerprint")); // skip_serializing_if
        assert!(json.contains("\"generate_version\":true"));
    }

    #[test]
    fn test_failure_type_serde() {
        let event = Event::Failure(FailureEvent {
            meta: EventMeta::default(),
            failure: FailureType::ContentsTooLarge,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ContentsTooLarge"));
    }

    #[test]
    fn test_group_change_serde() {
        let event = Event::GroupChange(GroupChangeEvent {
            meta: EventMeta::default(),
            verified: true,
            change: GroupChange::TitleChanged {
                new_title: "New Name".to_string(),
            },
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("TitleChanged"));
        assert!(json.contains("New Name"));
    }

    #[test]
    fn test_settings_change_serde() {
        let event = Event::SettingsChange(SettingsChangeEvent {
            meta: EventMeta::default(),
            verified: true,
            change: SettingsChange::MessageDuration {
                ttl_msec: 30000,
                apply_to_all: true,
            },
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("MessageDuration"));
        assert!(json.contains("30000"));
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_unified_card_attachment_is_camel_case() {
        let attachment = MessageAttachment::UnifiedCard {
            unified_card: UnifiedCardAttachment {
                url: Some("https://example.com".to_string()),
                attachment_id: None,
            },
        };
        let js: JsMessageAttachment = attachment.into();
        let json = serde_json::to_string(&js).unwrap();
        assert!(
            json.contains("unifiedCard"),
            "JS output must use camelCase key, got: {json}"
        );
        assert!(
            !json.contains("unified_card"),
            "JS output must not contain snake_case key, got: {json}"
        );
    }
}
