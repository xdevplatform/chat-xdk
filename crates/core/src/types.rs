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
#[non_exhaustive]
pub struct EmptyObject {}

/// A rich-text entity (mention, URL, hashtag, etc.) spanning a range of the
/// message text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct MoneyAttachment {
    pub fallback_text: Option<String>,
    pub payload: Option<String>,
}

/// Post (tweet) attachment as it appears in decrypted message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PostAttachment {
    pub rest_id: Option<String>,
    pub post_url: Option<String>,
    pub attachment_id: Option<String>,
}

/// URL card attachment as it appears in decrypted message content, including
/// any preview images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct UnifiedCardAttachment {
    pub url: Option<String>,
    pub attachment_id: Option<String>,
}

/// A preview image (banner or favicon) referenced by a URL card attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// Base64 SHA-256 of the file's plaintext bytes, when the sender
    /// included it: compare it with the SHA-256 of the decrypted file.
    pub plaintext_sha256: Option<String>,
}

/// Media dimensions (width/height).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MediaDimensions {
    pub width: Option<i64>,
    pub height: Option<i64>,
}

/// The kind of a media attachment: a known type or an unrecognized numeric id
/// for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
#[non_exhaustive]
pub enum MediaType {
    #[cfg_attr(feature = "js", js_camel(wrap))]
    Known(MediaTypeKnown),
    Unknown(i32),
}

/// Known media attachment kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum SentFromSurface {
    #[cfg_attr(feature = "js", js_camel(wrap))]
    Known(SentFromSurfaceKnown),
    Unknown(i32),
}

/// Known app surfaces a message can be sent from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum SentFromSurfaceKnown {
    ConversationScreenComposer,
    NotificationReply,
    ShareSheet,
    PaymentsSupportComposer,
    MessageForwardSheet,
}

/// A quick-reply carried by a message: either a request offering options or a
/// response selecting one.
///
/// Deserialization accepts exactly one of `request` or `response`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged, deny_unknown_fields)]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
#[non_exhaustive]
pub enum QuickReplyRequest {
    Options {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        options: QuickReplyOptionsRequest,
    },
}

/// A quick-reply response selecting a previously offered option.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(untagged)]
#[non_exhaustive]
pub enum QuickReplyResponse {
    Options {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        options: QuickReplyOptionsResponse,
    },
}

/// The options offered by a quick-reply request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct QuickReplyOptionsRequest {
    pub id: Option<String>,
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub options: Option<Vec<QuickReplyOption>>,
}

impl QuickReplyOptionsRequest {
    /// Create a request with no fields set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the request's id, which a response names as its `request_id`.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the options offered.
    pub fn with_options(mut self, options: Vec<QuickReplyOption>) -> Self {
        self.options = Some(options);
        self
    }
}

/// The option selected in a quick-reply response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct QuickReplyOptionsResponse {
    pub request_id: Option<String>,
    pub metadata: Option<String>,
    pub selected_option_id: Option<String>,
}

impl QuickReplyOptionsResponse {
    /// Create a response with no fields set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the id of the request this response answers.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Set the metadata of the selected option.
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }

    /// Set the id of the selected option.
    pub fn with_selected_option_id(mut self, selected_option_id: impl Into<String>) -> Self {
        self.selected_option_id = Some(selected_option_id.into());
        self
    }
}

/// A single selectable quick-reply option.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct QuickReplyOption {
    pub id: Option<String>,
    pub label: Option<String>,
    pub metadata: Option<String>,
    pub description: Option<String>,
}

impl QuickReplyOption {
    /// Create an option with no fields set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the option's id, which a response names as `selected_option_id`.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the option's label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the option's metadata, which a response echoes.
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }

    /// Set the option's description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// A call-to-action button (label plus URL) attached to a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
/// ```rust
/// # use chat_xdk_core::Event;
/// # fn handle(event: Event, my_user_id: &str) {
/// match event {
///     Event::Message(msg) => {
///         let sender = msg.meta.sender_id.as_deref().unwrap_or("");
///         println!("{}: {}", sender, msg.text().unwrap_or(""));
///     }
///     Event::KeyChange(kc) => {
///         // This user's entry of the new conversation key
///         let my_key = kc.find_key_for_user(my_user_id);
///     }
///     Event::GroupChange(gc) => {
///         println!("Group updated: {:?}", gc.change);
///     }
///     _ => {}
/// }
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type")]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Message {
    /// Event metadata
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// The decrypted message content.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub content: MessageContent,

    /// Version of the conversation key the message is encrypted under.
    pub conversation_key_version: Option<String>,

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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum MessageContent {
    /// A text message.
    #[non_exhaustive]
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
    #[non_exhaustive]
    Reaction {
        /// The emoji.
        emoji: String,
        /// The `sequence_id` of the message being reacted to.
        target_message_sequence_id: String,
    },

    /// A reaction was removed.
    #[non_exhaustive]
    ReactionRemoved {
        /// The emoji.
        emoji: String,
        /// The `sequence_id` of the message the reaction was on.
        target_message_sequence_id: String,
    },

    /// A message was edited.
    #[non_exhaustive]
    Edit {
        /// The `sequence_id` of the edited message.
        target_message_sequence_id: String,
        /// The signed message id of the edited message, which v1 edits
        /// carry; `None` for v0 edits.
        #[serde(skip_serializing_if = "Option::is_none")]
        target_message_id: Option<String>,
        /// The replacement text.
        updated_text: String,
        /// Rich text entities in the new text.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "js", js_camel(wrap))]
        entities: Option<Vec<RichTextEntity>>,
    },

    /// Conversation marked as read (encrypted marker).
    MarkRead,

    /// Conversation marked as unread (encrypted marker).
    MarkUnread,

    /// Unknown content type.
    #[non_exhaustive]
    Unknown {
        /// Raw content type ID if available.
        type_id: Option<i16>,
    },
}

/// A reference to a media hash key found in attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MediaHashReference {
    /// Where the media hash was found (e.g. "media", "url_banner", "url_favicon").
    pub source: String,
    /// The media hash key.
    pub media_hash_key: String,
}

/// A message attachment with media-related metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
    /// Base64 SHA-256 of the file's plaintext bytes, when the sender
    /// included it: compare it with the SHA-256 of the decrypted file.
    pub plaintext_sha256: Option<String>,
}

/// Media dimensions (width/height).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MediaDimensionsInfo {
    pub width: Option<i64>,
    pub height: Option<i64>,
}

/// URL attachment metadata, including any media hashes for preview images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct PostAttachmentInfo {
    pub rest_id: Option<String>,
    pub post_url: Option<String>,
    pub attachment_id: Option<String>,
}

/// Unified card attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct UnifiedCardAttachmentInfo {
    pub url: Option<String>,
    pub attachment_id: Option<String>,
}

/// Money attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MoneyAttachmentInfo {
    pub fallback_text: Option<String>,
}

/// Attachments decoded from MessageContents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "attachment_type")]
#[non_exhaustive]
pub enum AttachmentInfo {
    Media(#[cfg_attr(feature = "js", js_camel(wrap))] MediaAttachmentInfo),
    Url(#[cfg_attr(feature = "js", js_camel(wrap))] UrlAttachmentInfo),
    Post(#[cfg_attr(feature = "js", js_camel(wrap))] PostAttachmentInfo),
    UnifiedCard(#[cfg_attr(feature = "js", js_camel(wrap))] UnifiedCardAttachmentInfo),
    Money(#[cfg_attr(feature = "js", js_camel(wrap))] MoneyAttachmentInfo),
}

/// Conversation key rotation event.
///
/// When you receive this, find your entry in `conversation_participant_keys`
/// and store the new encrypted key.
///
/// Maps to `ConversationKeyChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct KeyChangeEvent {
    /// Event metadata.
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// New conversation key version.
    pub conversation_key_version: String,

    /// Whether the signature was verified.
    pub verified: bool,

    /// Encrypted keys for each participant.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub conversation_participant_keys: Vec<ConversationParticipantKey>,
}

impl KeyChangeEvent {
    /// Find the encrypted key for a specific user.
    pub fn find_key_for_user(&self, user_id: &str) -> Option<&ConversationParticipantKey> {
        self.conversation_participant_keys
            .iter()
            .find(|k| k.user_id == user_id)
    }
}

/// One participant's copy of a conversation key, encrypted to their identity
/// key: an entry of the X API's `conversation_participant_keys`, and Thrift's
/// `ConversationParticipantKey`. A prepared change carries these for its
/// request, and a received key change carries them as delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct ConversationParticipantKey {
    /// The participant's user id.
    pub user_id: String,

    /// Base64-encoded conversation key, encrypted to the participant's
    /// identity key.
    pub encrypted_conversation_key: String,

    /// Version of the participant's public key the conversation key is
    /// encrypted to.
    pub public_key_version: String,
}

/// Group membership or settings changed.
///
/// Maps to `GroupChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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

/// A group's title or description as a received event carries it.
///
/// Titles and descriptions travel encrypted under the conversation key the
/// event names. `Text` is the value decrypted, or the value an event that
/// names no key version carries as plaintext. `Unavailable` is a value the
/// SDK could not decrypt, because the key for its version is neither in the
/// key map nor cached or the value isn't ciphertext under it; `raw` is the
/// value as the event carries it. 0.5.x apps sent titles as plaintext while
/// naming a key version, so those arrive as `Unavailable` with the title in
/// `raw`: show `raw` when a title isn't decryptable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum GroupText {
    /// The decrypted text, or plaintext an event carries without a key
    /// version.
    #[non_exhaustive]
    Text { text: String },

    /// A value that did not decrypt, as the event carries it.
    #[non_exhaustive]
    Unavailable { raw: String },
}

/// The type of group change.
///
/// Maps to `GroupChange` union in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[serde(tag = "change_type")]
#[non_exhaustive]
pub enum GroupChange {
    /// Group was created. `title` is the group's title, when the create set
    /// one; `avatar_url` is an avatar media URL a create carries, whose image
    /// is encrypted under `conversation_key_version`, the key the create
    /// seeds.
    #[non_exhaustive]
    Created {
        member_ids: Vec<String>,
        admin_ids: Vec<String>,
        #[cfg_attr(feature = "js", js_camel(wrap))]
        title: Option<GroupText>,
        avatar_url: Option<String>,
        conversation_key_version: Option<String>,
    },

    /// Group title changed. A member removal's re-encryption of the title
    /// under the new key isn't a change: decrypt drops it.
    #[non_exhaustive]
    TitleChanged {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        new_title: GroupText,
    },

    /// Group avatar changed. `new_avatar_url` is the media URL of the new
    /// avatar image, whose bytes are encrypted under the conversation key
    /// for `conversation_key_version`.
    #[non_exhaustive]
    AvatarChanged {
        new_avatar_url: String,
        conversation_key_version: Option<String>,
    },

    /// Group description changed. A member removal's re-encryption of the
    /// description under the new key isn't a change: decrypt drops it.
    #[non_exhaustive]
    DescriptionChanged {
        #[cfg_attr(feature = "js", js_camel(wrap))]
        new_description: GroupText,
    },

    /// Admins were added.
    #[non_exhaustive]
    AdminsAdded { admin_ids: Vec<String> },

    /// Admins were removed.
    #[non_exhaustive]
    AdminsRemoved { admin_ids: Vec<String> },

    /// Members were added.
    #[non_exhaustive]
    MembersAdded {
        /// IDs of the members that were just added.
        member_ids: Vec<String>,
        /// Full member list after the addition.
        current_member_ids: Vec<String>,
        /// Full admin list after the addition.
        current_admin_ids: Vec<String>,
    },

    /// Members were removed.
    #[non_exhaustive]
    MembersRemoved { member_ids: Vec<String> },

    /// Group invite link enabled.
    #[non_exhaustive]
    InviteEnabled {
        invite_url: String,
        expires_at_msec: Option<i64>,
    },

    /// Group invite link disabled.
    #[non_exhaustive]
    InviteDisabled { disabled_by: Option<String> },

    /// Someone requested to join.
    #[non_exhaustive]
    JoinRequested { user_id: String },

    /// Join request was rejected.
    #[non_exhaustive]
    JoinRejected { user_ids: Vec<String> },

    /// Unknown group change type.
    Unknown,
}

/// Messages were deleted.
///
/// Maps to `MessageDeleteEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MessageDeletedEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// The `sequence_id`s of the deleted messages.
    pub sequence_ids: Vec<String>,

    /// Whether deleted for self only or for everyone.
    pub delete_for_all: bool,
}

/// Conversation was deleted.
///
/// Maps to `ConversationDeleteEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ReadReceiptEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// The `sequence_id` of the newest event read.
    pub seen_until_sequence_id: Option<String>,

    /// When the conversation was marked read (milliseconds).
    pub seen_at_msec: Option<i64>,
}

/// Conversation was marked as unread.
///
/// Maps to `MarkConversationUnreadEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MarkedUnreadEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// Whether the signature was verified.
    pub verified: bool,

    /// The `sequence_id` of the newest event read before the conversation
    /// was marked unread.
    pub seen_until_sequence_id: Option<String>,
}

/// Message delivery failed.
///
/// Maps to `MessageFailureEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct FailureEvent {
    #[serde(flatten)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub meta: EventMeta,

    /// The type of failure.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub failure: FailureType,

    /// The account tier whose message-request limit was reached.
    ///
    /// Set by the backend for [`FailureType::RateLimitUpsell`] failures; the
    /// SDK passes through whatever the event carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub rate_limit_tier: Option<RateLimitTier>,
}

/// Why a message failed to deliver.
///
/// Maps to `FailureType` enum in Thrift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub enum FailureType {
    EmptyDetail,
    InternalError,
    ContentsTooLarge,
    TooManyMessages,
    InvalidSenderSignature,
    NonLatestKeyVersion,
    RecipientNotTrusted,
    RecipientKeyChanged,
    OnlyEncryptedMessagesAllowed,
    RequesterNotAdmin,
    FlaggedAsSpam,
    RateLimitUpsell,
    SignatureFailedToVerifyAgainstPublicKey,
    GenericError,
    SenderNotGroupMember,
    InvalidSignatureVersion,
    InvalidPinRequest,
    TooManyPins,
    Unknown,
}

/// The account tier associated with a rate-limit upsell failure.
///
/// Maps to `RateLimitTier` enum in Thrift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub enum RateLimitTier {
    Free,
    VerifiedPhone,
    Premium,
    PremiumPlus,
    PremiumBusiness,
    Unknown,
}

/// Conversation settings changed.
///
/// Maps to `ConversationMetadataChangeEvent` in Thrift.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum SettingsChange {
    /// Disappearing message duration changed.
    #[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct SendPayload {
    /// The message id (UUID) the SDK generated and embedded in the signed
    /// event. Send it as the message's `message_id`, keep it to dedup and to
    /// anchor replies, and reuse the same encrypted payload on retries so an
    /// id is never minted twice.
    pub message_id: String,

    /// The outgoing message as a base64 event: what recipients receive,
    /// without the fields the server assigns. Pass it to `encrypt_file` or
    /// `file_encryptor` to encrypt the message's files, or to
    /// `decrypt_event` to read the message back.
    pub event_b64: String,

    /// Base64-encoded Thrift `MessageCreateEvent` carrying the encrypted
    /// contents: the send request's `encoded_message_create_event`.
    pub encoded_message_create_event: String,

    /// Base64-encoded signature.
    pub signature: String,

    /// Base64-encoded Thrift `MessageEventSignature`: the send request's
    /// `encoded_message_event_signature`, which takes this value rather than
    /// the raw signature bytes.
    pub encoded_message_event_signature: String,

    /// Signature metadata.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub signature_info: SignatureInfo,

    /// Conversation key version used.
    pub conversation_key_version: String,

    /// Whether to send push notification.
    #[serde(default = "default_true")]
    pub should_notify: bool,

    /// Version of the Chat XDK that built this payload.
    pub xdk_version: String,
}

fn default_true() -> bool {
    true
}

/// Signature information for a sent message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
/// message. `start` and `end` count bytes of the UTF-8 text the entity is
/// in, so `0 <= start <= end <= text.len()`; other offsets fail the call
/// with an `InvalidInput` error naming them. A reply preview's entities
/// index the quoted message's text, so their end isn't checked against the
/// preview's.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct EntityDescriptor {
    /// Byte offset of the entity's first byte in the UTF-8 text (inclusive).
    pub start: i32,
    /// Byte offset just past the entity's last byte in the UTF-8 text
    /// (exclusive).
    pub end: i32,
    /// One of: `"url"`, `"mention"`, `"hashtag"`, `"cashtag"`, `"email"`,
    /// `"address"`, `"phone_number"`. Any other value, an empty one
    /// included, fails the call with an `InvalidInput` error naming it.
    pub entity_type: String,
}

impl EntityDescriptor {
    /// Describe an entity of `entity_type` spanning `start..end` of the text.
    pub fn new(start: i32, end: i32, entity_type: impl Into<String>) -> Self {
        Self {
            start,
            end,
            entity_type: entity_type.into(),
        }
    }
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
#[non_exhaustive]
pub enum AttachmentDescriptor {
    /// A media attachment (image, gif, video, etc.).
    Media {
        media_hash_key: String,
        /// Width in pixels; a negative one fails the send with an
        /// `InvalidInput` error.
        width: i64,
        /// Height in pixels; a negative one fails the send with an
        /// `InvalidInput` error.
        height: i64,
        /// Size of the encrypted file in bytes: `encrypted_file_size` of the
        /// file's size. A size of 0 or less fails the send with an
        /// `InvalidInput` error.
        filesize_bytes: i64,
        /// Original filename. An empty one fails the send with an
        /// `InvalidInput` error.
        filename: String,
        /// Media type: 1=image, 2=gif, 3=video, 4=audio, 5=file, 6=svg.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_millis: Option<i64>,
        /// Base64 SHA-256 of the file's plaintext bytes, which recipients can
        /// check the decrypted file against. The message carries and signs
        /// it, and the message is built before its files are encrypted, so
        /// the caller hashes the file. One that is not the base64 of 32
        /// bytes fails the send with an `InvalidInput` error; an empty one
        /// is unset.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plaintext_sha256: Option<String>,
    },
    /// A URL card attachment.
    ///
    /// Supplying `display_title` and `banner_image` makes receiving clients
    /// render a full clickable preview card without any unencrypted fetch:
    /// clients only auto-fetch missing card details for their own messages
    /// (an IP-leak guard), so a bare URL from another sender falls back to a
    /// plain link on some platforms. The banner/favicon images are files of
    /// the message: start each image's upload to the conversation's media
    /// store, reference it here by the media hash key the upload started
    /// with, then encrypt it with `encrypt_file` or `file_encryptor` and the
    /// message's `event_b64` and finish the upload.
    Url {
        /// The link the card shows; an empty one fails the send with an
        /// `InvalidInput` error.
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
    /// A post / tweet attachment, named by its `rest_id`, its `post_url`, or
    /// both; one with neither fails the send with an `InvalidInput` error.
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
#[non_exhaustive]
pub struct UrlAttachmentImageDescriptor {
    /// Media hash key the image's upload started with.
    pub media_hash_key: String,
    /// Size of the encrypted image in bytes: `encrypted_file_size` of the
    /// image's size.
    ///
    /// Required: receiving clients' shared ingest silently discards the
    /// whole preview image when this field is missing on the wire, so a
    /// size of 0 or less fails the send with an `InvalidInput` error.
    pub filesize_bytes: i64,
    /// Original filename of the image (receivers use it to key the
    /// decrypted-file cache).
    ///
    /// Required: receiving clients' shared ingest silently discards the
    /// whole preview image when this field is missing on the wire, so an
    /// empty filename fails the send with an `InvalidInput` error.
    pub filename: String,
    /// Width in pixels, when known; a negative one fails the send with an
    /// `InvalidInput` error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<i64>,
    /// Height in pixels, when known; a negative one fails the send with an
    /// `InvalidInput` error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
}

impl UrlAttachmentImageDescriptor {
    /// Describe the image whose upload started with `media_hash_key`.
    pub fn new(
        media_hash_key: impl Into<String>,
        filesize_bytes: i64,
        filename: impl Into<String>,
    ) -> Self {
        Self {
            media_hash_key: media_hash_key.into(),
            filesize_bytes,
            filename: filename.into(),
            width: None,
            height: None,
        }
    }

    /// Set the image's width and height in pixels.
    pub fn with_dimensions(mut self, width: i64, height: i64) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }
}

/// Public keys returned by setup/get_public_keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PublicKeys {
    /// Base64-encoded identity public key (P-256, for ECDH).
    pub identity: String,

    /// Base64-encoded signing public key (P-256, for ECDSA).
    pub signing: String,
}

/// Public key registration payload for the X API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PublicKeyRegistrationPayload {
    /// Public key registration object.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub public_key: PublicKeyRegistration,
}

/// Public key registration fields expected by the X API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
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
#[non_exhaustive]
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

impl SigningKeyEntry {
    /// A signing key as the X API returns it for `user_id`.
    pub fn new(
        user_id: impl Into<String>,
        public_key_version: impl Into<String>,
        public_key: impl Into<String>,
        identity_public_key: impl Into<String>,
        identity_public_key_signature: impl Into<String>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            public_key_version: public_key_version.into(),
            public_key: public_key.into(),
            identity_public_key: identity_public_key.into(),
            identity_public_key_signature: identity_public_key_signature.into(),
        }
    }
}

/// Result from `extract_conversation_keys`.
///
/// Contains the full key map plus convenience accessors for the latest key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct ConversationKeyResult {
    /// Map of key version → raw conversation key bytes, over every
    /// conversation of the batch. A version that key changes of more than
    /// one conversation carry is left out, because a lookup by version alone
    /// cannot say which conversation's key it wants: read
    /// `keys_by_conversation`. For a batch of one conversation this holds
    /// every key.
    #[serde(skip)]
    pub keys: std::collections::HashMap<String, crate::crypto::keys::XChatConversationKey>,
    /// Map of conversation id → key version → raw conversation key bytes:
    /// each key under the conversation of the key change that carries it, so
    /// two conversations' keys at one version stay apart. A key change that
    /// carries no conversation id has its key in `keys` only.
    #[serde(skip)]
    pub keys_by_conversation: std::collections::HashMap<
        String,
        std::collections::HashMap<String, crate::crypto::keys::XChatConversationKey>,
    >,
    /// The version to encrypt with, when every event of the batch belongs to
    /// one conversation. From `decrypt_events`, the newest version whose key
    /// change verified, `None` until one verifies; from
    /// `extract_conversation_keys`, the highest version in the batch. `None`
    /// for a batch whose events belong to more than one conversation, where
    /// one version cannot name each conversation's key: read
    /// `latest_versions`.
    pub latest_version: Option<String>,
    /// The version to encrypt with for each conversation of the batch. From
    /// `decrypt_events`, the newest version whose key change verified; a
    /// conversation without one has no entry. From
    /// `extract_conversation_keys`, each conversation's highest version in
    /// the batch.
    ///
    /// Conversation ids, here and in `keys_by_conversation`, have the form
    /// events carry: a group's `g…` id, and a one-to-one's two user ids
    /// ordered numerically and colon-separated.
    #[serde(default)]
    pub latest_versions: std::collections::HashMap<String, String>,
}

impl ConversationKeyResult {
    /// Get a key of `keys` by version.
    pub fn get(&self, version: &str) -> Option<&crate::crypto::keys::XChatConversationKey> {
        self.keys.get(version)
    }

    /// Get the key of `conversation_id` at `version`: the key a key change of
    /// that conversation carries, whichever other conversations of the batch
    /// have a key at the same version.
    pub fn get_for(
        &self,
        conversation_id: &str,
        version: &str,
    ) -> Option<&crate::crypto::keys::XChatConversationKey> {
        self.keys_by_conversation.get(conversation_id)?.get(version)
    }

    /// Get the latest conversation key: the key of `keys` at
    /// `latest_version`.
    pub fn latest_key(&self) -> Option<&crate::crypto::keys::XChatConversationKey> {
        self.latest_version.as_ref().and_then(|v| self.keys.get(v))
    }

    /// Whether `keys` is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of keys in `keys`.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// One event `decrypt_events` decrypted, of any event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct DecryptedEvent {
    /// The decrypted event.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub event: Event,
    /// Original base64 event string (for reference).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_b64: Option<String>,
}

/// Why a key change's signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub enum UnverifiedKeyChangeReason {
    /// None of the signing keys the call verified with is the sender's at
    /// the key version the signature names: pass that user's public keys as
    /// signing keys and decrypt again.
    MissingSigningKey,
    /// The sender's signing key at the key version the signature names was
    /// among the signing keys, but its identity binding does not verify, so
    /// the call left it out: it is listed in `rejected_signing_keys`.
    /// Fetching the same entry again changes nothing.
    RejectedSigningKey,
    /// The signature does not verify against the sender's signing key.
    InvalidSignature,
    /// The key change carries no signature, or one this SDK cannot check:
    /// an unsupported signature version, or one below the first whose
    /// payload a recipient can rebuild.
    Unverifiable,
}

/// A key change in a `decrypt_events` batch whose key this identity
/// decrypted but whose signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct UnverifiedKeyChange {
    /// Why its signature did not verify.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub reason: UnverifiedKeyChangeReason,
    /// Whether its key was left out of `conversation_keys`, so the messages
    /// of its conversation under that key version did not decrypt. A key
    /// that was kept decrypts messages but never becomes the version to
    /// encrypt with.
    pub key_dropped: bool,
    /// The conversation the key change belongs to.
    pub conversation_id: Option<String>,
    /// The conversation key version the key change carries.
    pub conversation_key_version: String,
    /// The user who signed the key change: the member who made it.
    pub sender_id: Option<String>,
    /// The version of that user's signing key the signature names.
    pub public_key_version: Option<String>,
}

/// Why this identity could not decrypt the conversation key a key change
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub enum UndecryptableKeyChangeReason {
    /// No identity key is loaded: load or unlock the keys, then decrypt
    /// again.
    Locked,
    /// The key change holds no key for this chat's user, the user the
    /// session identity names; without a session identity, it holds no key
    /// at all. The user was not a member when the key change was made.
    NotARecipient,
    /// The key change holds keys for this chat's user, or for some user
    /// when no session identity names one, but none at this chat's key
    /// version: it was made for another registration of the user's keys.
    /// Check the key version given to `set_identity` or `import_keys`.
    OtherKeyVersion,
    /// A key the key change holds for this chat's key version does not
    /// decrypt under the loaded identity key: the loaded private key is not
    /// the one registered at that version.
    DecryptionFailed,
}

/// A key change in a `decrypt_events` batch whose conversation key this
/// identity could not decrypt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct UndecryptableKeyChange {
    /// Why its key could not be decrypted.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub reason: UndecryptableKeyChangeReason,
    /// The conversation the key change belongs to.
    pub conversation_id: Option<String>,
    /// The conversation key version the key change carries.
    pub conversation_key_version: String,
    /// The user who made the key change.
    pub sender_id: Option<String>,
}

/// A signing key a `decrypt_events` call left out of verification because
/// its identity binding does not verify: `identity_public_key_signature` is
/// not the signing key's signature over `identity_public_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct RejectedSigningKey {
    /// The entry's `user_id`.
    pub user_id: String,
    /// The entry's `public_key_version`.
    pub public_key_version: String,
}

/// A signing key a `decrypt_events` call did not have: an event's signature
/// names it, and it was not among the signing keys the call verified with.
/// Fetch the user's public keys (`GET /2/users/{id}/public_keys`) and give
/// them to the next call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MissingSigningKey {
    /// The user who sent the event, whose signing key it is.
    pub user_id: String,
    /// The version of that user's key the signature names.
    pub public_key_version: String,
}

impl MissingSigningKey {
    /// The signing key of `user_id` at `public_key_version`.
    pub fn new(user_id: impl Into<String>, public_key_version: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            public_key_version: public_key_version.into(),
        }
    }
}

/// One of a user's public keys, as the X API returns it in the `data` of
/// `GET /2/users/{id}/public_keys`.
///
/// A record deserializes from the API's own JSON: each field under its
/// snake_case name or the camelCase name the X API client libraries give
/// it, a `public_key_version` written as a string or a number, and any
/// other field, such as `juicebox_config`, ignored. A field that is absent
/// or null is empty, and [`crate::ChatCore::add_public_keys`] leaves out a
/// record that lacks one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct PublicKeyRecord {
    /// The version of this key (`public_key_version`).
    pub public_key_version: String,
    /// The user's identity public key (`public_key`), base64.
    pub public_key: String,
    /// The user's signing public key (`signing_public_key`), base64.
    pub signing_public_key: String,
    /// The signing key's signature over the identity key
    /// (`identity_public_key_signature`), base64: what binds the two.
    pub identity_public_key_signature: String,
}

impl PublicKeyRecord {
    /// A record of the four values the SDK reads.
    pub fn new(
        public_key_version: impl Into<String>,
        public_key: impl Into<String>,
        signing_public_key: impl Into<String>,
        identity_public_key_signature: impl Into<String>,
    ) -> Self {
        Self {
            public_key_version: public_key_version.into(),
            public_key: public_key.into(),
            signing_public_key: signing_public_key.into(),
            identity_public_key_signature: identity_public_key_signature.into(),
        }
    }
}

impl<'de> Deserialize<'de> for PublicKeyRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RecordVisitor;

        impl<'de> serde::de::Visitor<'de> for RecordVisitor {
            type Value = PublicKeyRecord;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a public key record from GET /2/users/{id}/public_keys")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut record = PublicKeyRecord::default();
                while let Some(name) = map.next_key::<String>()? {
                    let field = match name.as_str() {
                        "public_key_version" | "publicKeyVersion" => &mut record.public_key_version,
                        "public_key" | "publicKey" => &mut record.public_key,
                        "signing_public_key" | "signingPublicKey" => &mut record.signing_public_key,
                        "identity_public_key_signature" | "identityPublicKeySignature" => {
                            &mut record.identity_public_key_signature
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            continue;
                        }
                    };
                    // A record that carries a field under both of its names
                    // keeps the first value that is not empty.
                    let RecordValue(value) = map.next_value()?;
                    if field.is_empty() {
                        *field = value;
                    }
                }
                Ok(record)
            }
        }

        deserializer.deserialize_map(RecordVisitor)
    }
}

/// A value of a [`PublicKeyRecord`] field: a string, a whole number written
/// as a number, or nothing.
struct RecordValue(String);

impl<'de> Deserialize<'de> for RecordValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = RecordValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string, a whole number or null")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RecordValue(value.to_string()))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(RecordValue(value.to_string()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(RecordValue(value.to_string()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                // A JavaScript number arrives as a float; one that is not a
                // whole number is no key version.
                if value.fract() == 0.0 && (0.0..9.0e15).contains(&value) {
                    Ok(RecordValue((value as u64).to_string()))
                } else {
                    Ok(RecordValue(String::new()))
                }
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RecordValue(String::new()))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RecordValue(String::new()))
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_any(ValueVisitor)
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

/// Result from `decrypt_events` batch API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct DecryptEventsResult {
    /// The events that decrypted, in batch order, of every event type.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub events: Vec<DecryptedEvent>,
    /// Conversation keys extracted from key events.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub conversation_keys: ConversationKeyResult,
    /// Index → error message for each event left out of `events`: one that
    /// failed, or one decrypt drops, such as a member removal's title or
    /// description re-encrypted under the new key.
    pub errors: std::collections::HashMap<usize, String>,
    /// Index → the key change at that index of the batch, for each key
    /// change whose signature did not verify: why, and whether its key was
    /// dropped. Empty when every key change this identity decrypted
    /// verified.
    #[serde(default)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub unverified_key_changes: std::collections::HashMap<usize, UnverifiedKeyChange>,
    /// Index → the key change at that index of the batch, for each key
    /// change whose conversation key this identity could not decrypt: why.
    /// Such a key change gives the batch no key, so the messages of its
    /// conversation under its key version did not decrypt.
    #[serde(default)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub undecryptable_key_changes: std::collections::HashMap<usize, UndecryptableKeyChange>,
    /// Index → the signing key at that index of the signing keys the call
    /// verified with (the ones it was given, or the stored ones when it was
    /// given none), for each signing key it left out because its identity
    /// binding does not verify. An event signed with such a key does not
    /// verify.
    #[serde(default)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub rejected_signing_keys: std::collections::HashMap<usize, RejectedSigningKey>,
    /// Index → the signing key the event at that index of the batch names,
    /// for each event, of any signed type, whose sender's signing key at
    /// that version was not among the signing keys the call verified with.
    /// Under the default reject-unverified policy such an event is in
    /// `errors`; otherwise it is in `events`, unverified. A key change
    /// listed here is also in `unverified_key_changes` when this identity
    /// decrypted its key. [`crate::ChatCore::missing_public_keys`] reads
    /// the users to fetch keys for from this map.
    #[serde(default)]
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub missing_signing_keys: std::collections::HashMap<usize, MissingSigningKey>,
}

/// A public key input entry for `prepare_conversation_key_change`,
/// `prepare_group_create`, `prepare_group_members_change` and
/// `prepare_group_members_remove`.
///
/// Represents a single public key version for a user, as returned by the X API
/// `GET /2/users/{id}/public_keys` endpoint. Pass the full array; the SDK
/// will group by user and pick the latest version per user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PublicKeyInput {
    /// The user's ID.
    pub user_id: String,
    /// Base64-encoded identity public key (SEC1 or SPKI): the X API's
    /// `public_key`.
    pub identity_public_key: String,
    /// The key's version, as the X API returns it.
    pub public_key_version: String,
}

impl PublicKeyInput {
    /// A public key as the X API returns it for `user_id`.
    pub fn new(
        user_id: impl Into<String>,
        identity_public_key: impl Into<String>,
        public_key_version: impl Into<String>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            identity_public_key: identity_public_key.into(),
            public_key_version: public_key_version.into(),
        }
    }
}

/// Which screen-capture setting a [`crate::ScreenCaptureParams`] signs.
///
/// Blocking names are the ones X clients sign. Detection names are the event
/// names this SDK's verifier reconstructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub enum ScreenCaptureChange {
    /// `ConversationMetadataChangeEvent.EnableScreenCaptureBlocking`.
    BlockingEnabled,
    /// `ConversationMetadataChangeEvent.DisableScreenCaptureBlocking`.
    BlockingDisabled,
    /// `ConversationMetadataChangeEvent.EnableScreenCaptureDetection`.
    DetectionEnabled,
    /// `ConversationMetadataChangeEvent.DisableScreenCaptureDetection`.
    DetectionDisabled,
}

impl ScreenCaptureChange {
    /// Parse a binding's spelling of this change.
    ///
    /// Accepts the Rust/Python/Go/JVM/.NET variant name (`BlockingEnabled`)
    /// and the JS camelCase tag (`blockingEnabled`).
    pub fn parse(value: &str) -> Result<Self, crate::error::SdkError> {
        match value {
            "BlockingEnabled" | "blockingEnabled" => Ok(Self::BlockingEnabled),
            "BlockingDisabled" | "blockingDisabled" => Ok(Self::BlockingDisabled),
            "DetectionEnabled" | "detectionEnabled" => Ok(Self::DetectionEnabled),
            "DetectionDisabled" | "detectionDisabled" => Ok(Self::DetectionDisabled),
            other => Err(crate::error::SdkError::InvalidInput(format!(
                "Invalid screen capture change: '{other}'"
            ))),
        }
    }
}

/// A signed conversation-key change, ready to send to the X API.
///
/// Returned by `prepare_conversation_key_change`, `prepare_group_create`,
/// `prepare_group_members_change`, and `prepare_group_members_remove`.
/// Carries the new key (to keep locally), the per-participant encrypted
/// copies, and the action signatures that let recipients verify the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PreparedConversationChange {
    /// Conversation id the change applies to. Derived for a one-to-one,
    /// or the id passed in for a group.
    pub conversation_id: String,

    /// Raw conversation key bytes (32 bytes). Store this locally for encrypting messages.
    ///
    /// Every prepare call that returns this type sets it. It is excluded
    /// from serialization — this is secret key material that should never
    /// be sent to the server.
    #[serde(skip_serializing, skip_deserializing)]
    pub conversation_key: Option<crate::crypto::keys::XChatConversationKey>,

    /// Timestamp-based version string for this conversation key.
    pub conversation_key_version: String,

    /// Encrypted keys for each participant: the request's
    /// `conversation_participant_keys`, ready to POST to the API.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub conversation_participant_keys: Vec<ConversationParticipantKey>,

    /// Action signatures authenticating the change, ready to POST to the API.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub action_signatures: Vec<ActionSignature>,

    /// The group's title encrypted under the new conversation key, base64.
    /// Set by `prepare_group_create` (the request's `group_name`) and
    /// `prepare_group_members_change` (the request's `encrypted_title`) when
    /// their params carry a title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_title: Option<String>,

    /// The group's description encrypted under the new conversation key,
    /// base64, as the signed member add carries it. Set by
    /// `prepare_group_members_change` when its params carry a description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_description: Option<String>,
}

/// A signed group title or description change, ready to send to the X API.
///
/// Returned by `prepare_group_title_change` and
/// `prepare_group_description_change`, which encrypt the plaintext value
/// under the conversation key before signing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PreparedGroupMetadataChange {
    /// The value encrypted under the conversation key, base64: the title or
    /// description the request sends.
    pub encrypted_value: String,

    /// Version of the conversation key the value is encrypted under.
    pub conversation_key_version: String,

    /// The signed change, as the request's `action_signatures` entries.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub action_signatures: Vec<ActionSignature>,
}

/// Signed actions for a request that does not rotate a conversation key.
///
/// Returned by `prepare_message_delete`, `prepare_mark_conversation_read`,
/// and the group-action prepares other than `prepare_group_members_remove`
/// and the title and description changes.
/// `prepare_group_leave` returns one entry per signed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct PreparedAction {
    /// The signed action, as the request's `action_signatures` entries.
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
            conversation_key_version: None,
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
                target_message_sequence_id: "seq-1".to_string(),
            },
            conversation_key_version: None,
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
                target_message_sequence_id: "seq-2".to_string(),
            },
            conversation_key_version: None,
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
            conversation_key_version: "v1".to_string(),
            verified: true,
            conversation_participant_keys: vec![
                ConversationParticipantKey {
                    user_id: "alice".to_string(),
                    encrypted_conversation_key: "key_a".to_string(),
                    public_key_version: "v1".to_string(),
                },
                ConversationParticipantKey {
                    user_id: "bob".to_string(),
                    encrypted_conversation_key: "key_b".to_string(),
                    public_key_version: "v1".to_string(),
                },
            ],
        };

        assert_eq!(
            kc.find_key_for_user("alice")
                .unwrap()
                .encrypted_conversation_key,
            "key_a"
        );
        assert_eq!(
            kc.find_key_for_user("bob")
                .unwrap()
                .encrypted_conversation_key,
            "key_b"
        );
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

    fn key_change(version: &str) -> KeyChangeEvent {
        KeyChangeEvent {
            meta: EventMeta::default(),
            conversation_key_version: version.to_string(),
            verified: true,
            conversation_participant_keys: vec![ConversationParticipantKey {
                user_id: "2".to_string(),
                encrypted_conversation_key: "ekey".to_string(),
                public_key_version: "1".to_string(),
            }],
        }
    }

    #[test]
    fn test_event_serde_roundtrip_key_change() {
        let json = serde_json::to_value(Event::KeyChange(key_change("v42"))).unwrap();
        assert_eq!(json["type"], "KeyChange");
        assert_eq!(json["conversation_key_version"], "v42");
        assert_eq!(
            json["conversation_participant_keys"],
            serde_json::json!([{
                "user_id": "2",
                "encrypted_conversation_key": "ekey",
                "public_key_version": "1",
            }])
        );
    }

    #[test]
    fn test_message_names_its_conversation_key_version() {
        let mut message = text_message("hi");
        message.conversation_key_version = Some("7".to_string());
        let json = serde_json::to_value(Event::Message(Box::new(message))).unwrap();
        assert_eq!(json["conversation_key_version"], "7");
    }

    #[test]
    fn test_send_payload_serde() {
        let payload = SendPayload {
            message_id: "mid".to_string(),
            event_b64: "ev".to_string(),
            encoded_message_create_event: "enc".to_string(),
            signature: "sig".to_string(),
            encoded_message_event_signature: "esig".to_string(),
            signature_info: SignatureInfo {
                public_key_version: "v1".to_string(),
                signature_version: "4".to_string(),
            },
            conversation_key_version: "v1".to_string(),
            should_notify: true,
            xdk_version: "0.6.0".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"xdk_version\":\"0.6.0\""));
        // Serialized under the send request's field names.
        assert!(json.contains("\"encoded_message_create_event\":\"enc\""));
        assert!(json.contains("\"encoded_message_event_signature\":\"esig\""));
        let decoded: SendPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.event_b64, "ev");
        assert_eq!(decoded.encoded_message_create_event, "enc");
        assert_eq!(decoded.signature_info.signature_version, "4");
        assert_eq!(decoded.xdk_version, "0.6.0");
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
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("public_key_fingerprint")); // skip_serializing_if
        let decoded: PublicKeyRegistrationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.public_key.public_key, "pk");
    }

    #[test]
    fn test_failure_type_serde() {
        let event = Event::Failure(FailureEvent {
            meta: EventMeta::default(),
            failure: FailureType::RateLimitUpsell,
            rate_limit_tier: Some(RateLimitTier::Premium),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("RateLimitUpsell"));
        assert!(json.contains("\"rate_limit_tier\":\"Premium\""));
    }

    #[test]
    fn test_group_change_serde() {
        let event = Event::GroupChange(GroupChangeEvent {
            meta: EventMeta::default(),
            verified: true,
            change: GroupChange::TitleChanged {
                new_title: GroupText::Text {
                    text: "New Name".to_string(),
                },
            },
        });
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["change"]["change_type"], "TitleChanged");
        assert_eq!(
            json["change"]["new_title"],
            serde_json::json!({ "kind": "Text", "text": "New Name" })
        );

        let unavailable = GroupText::Unavailable {
            raw: "Old Name".to_string(),
        };
        let json = serde_json::to_value(&unavailable).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "Unavailable", "raw": "Old Name" })
        );
        assert_eq!(
            serde_json::from_value::<GroupText>(json).unwrap(),
            unavailable
        );
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

    #[cfg(feature = "js")]
    #[test]
    fn test_js_struct_variant_fields_are_camel_case() {
        let quick_reply = QuickReply::Response {
            response: QuickReplyResponse::Options {
                options: QuickReplyOptionsResponse {
                    request_id: Some("qr-1".to_string()),
                    metadata: None,
                    selected_option_id: Some("yes".to_string()),
                },
            },
        };
        let text = MessageContent::Text {
            text: "hi".to_string(),
            entities: None,
            attachments: None,
            replying_to_preview: Some(ReplyingToPreview {
                sender_id: Some("1".to_string()),
                message_text: None,
                entities: None,
                attachments: None,
                sender_display_name: None,
                replying_to_message_sequence_id: None,
                replying_to_message_id: None,
            }),
            forwarded_message: None,
            sent_from: Some(SentFromSurface::Unknown(9)),
            quick_reply: Some(quick_reply.clone()),
            ctas: None,
        };
        let json = serde_json::to_value(JsMessageContent::from(text)).unwrap();
        assert_eq!(json["contentType"], "text");
        assert!(json.get("replyingToPreview").is_some(), "got: {json}");
        assert_eq!(json["sentFrom"], 9);
        assert_eq!(
            json["quickReply"],
            serde_json::to_value(JsQuickReply::from(quick_reply)).unwrap()
        );
        assert_eq!(
            json["quickReply"]["response"]["options"]["requestId"],
            "qr-1"
        );

        let reaction = MessageContent::Reaction {
            emoji: "👍".to_string(),
            target_message_sequence_id: "seq-1".to_string(),
        };
        let json = serde_json::to_value(JsMessageContent::from(reaction)).unwrap();
        assert_eq!(json["targetMessageSequenceId"], "seq-1");

        let edit = MessageContent::Edit {
            target_message_sequence_id: "seq-1".to_string(),
            target_message_id: Some("6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f".to_string()),
            updated_text: "fixed".to_string(),
            entities: None,
        };
        let json = serde_json::to_value(JsMessageContent::from(edit)).unwrap();
        assert_eq!(json["targetMessageSequenceId"], "seq-1");
        assert_eq!(
            json["targetMessageId"],
            "6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f"
        );
        assert_eq!(json["updatedText"], "fixed");

        let change = GroupChange::TitleChanged {
            new_title: GroupText::Text {
                text: "New Name".to_string(),
            },
        };
        let json = serde_json::to_value(JsGroupChange::from(change)).unwrap();
        assert_eq!(json["changeType"], "titleChanged");
        assert_eq!(
            json["newTitle"],
            serde_json::json!({ "kind": "text", "text": "New Name" })
        );
        let change = GroupChange::Created {
            member_ids: vec!["1".to_string()],
            admin_ids: vec!["1".to_string()],
            title: Some(GroupText::Unavailable {
                raw: "Old Name".to_string(),
            }),
            avatar_url: None,
            conversation_key_version: Some("3".to_string()),
        };
        let json = serde_json::to_value(JsGroupChange::from(change)).unwrap();
        assert_eq!(
            json["title"],
            serde_json::json!({ "kind": "unavailable", "raw": "Old Name" })
        );
        assert_eq!(json["conversationKeyVersion"], "3");

        let setting = SettingsChange::MessageDuration {
            ttl_msec: 30000,
            apply_to_all: true,
        };
        let json = serde_json::to_value(JsSettingsChange::from(setting)).unwrap();
        assert_eq!(json["ttlMsec"], 30000);
        assert_eq!(json["applyToAll"], true);

        let snake = serde_json::to_string(&json).unwrap();
        assert!(
            !snake.contains('_'),
            "JS output must be camelCase, got: {snake}"
        );
    }

    fn prepared_change() -> PreparedConversationChange {
        PreparedConversationChange {
            conversation_id: "1:2".to_string(),
            conversation_key: None,
            conversation_key_version: "5".to_string(),
            conversation_participant_keys: vec![ConversationParticipantKey {
                user_id: "2".to_string(),
                encrypted_conversation_key: "ekey".to_string(),
                public_key_version: "1".to_string(),
            }],
            action_signatures: vec![],
            encrypted_title: None,
            encrypted_description: None,
        }
    }

    #[test]
    fn test_prepared_change_takes_the_request_field_names() {
        let json = serde_json::to_value(prepared_change()).unwrap();
        assert_eq!(
            json["conversation_participant_keys"],
            serde_json::json!([{
                "user_id": "2",
                "encrypted_conversation_key": "ekey",
                "public_key_version": "1",
            }])
        );
        assert_eq!(json["conversation_key_version"], "5");
        assert!(json.get("encrypted_title").is_none());
        assert!(json.get("encrypted_description").is_none());

        let mut added = prepared_change();
        added.encrypted_title = Some("ZW5jcnlwdGVkIHRpdGxl".to_string());
        added.encrypted_description = Some("ZW5jcnlwdGVkIGRlc2NyaXB0aW9u".to_string());
        let json = serde_json::to_value(added).unwrap();
        assert_eq!(json["encrypted_title"], "ZW5jcnlwdGVkIHRpdGxl");
        assert_eq!(
            json["encrypted_description"],
            "ZW5jcnlwdGVkIGRlc2NyaXB0aW9u"
        );
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_received_events_are_camel_case() {
        let json =
            serde_json::to_value(JsEvent::from(Event::KeyChange(key_change("v42")))).unwrap();
        assert_eq!(json["conversationKeyVersion"], "v42");
        assert_eq!(
            json["conversationParticipantKeys"],
            serde_json::json!([{
                "userId": "2",
                "encryptedConversationKey": "ekey",
                "publicKeyVersion": "1",
            }])
        );

        let mut message = text_message("hi");
        message.conversation_key_version = Some("7".to_string());
        let json = serde_json::to_value(JsEvent::from(Event::Message(Box::new(message)))).unwrap();
        assert_eq!(json["conversationKeyVersion"], "7");
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_screen_capture_change_is_camel_case() {
        let enabled = serde_json::to_value(JsScreenCaptureChange::from(
            ScreenCaptureChange::BlockingEnabled,
        ))
        .unwrap();
        assert_eq!(enabled, "blockingEnabled");
        let detection = serde_json::to_value(JsScreenCaptureChange::from(
            ScreenCaptureChange::DetectionDisabled,
        ))
        .unwrap();
        assert_eq!(detection, "detectionDisabled");
        let snake = serde_json::to_string(&detection).unwrap();
        assert!(
            !snake.contains('_'),
            "JS screen-capture tag must be camelCase, got: {snake}"
        );
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_prepared_change_is_camel_case() {
        let json =
            serde_json::to_value(JsPreparedConversationChange::from(prepared_change())).unwrap();
        assert_eq!(
            json["conversationParticipantKeys"],
            serde_json::json!([{
                "userId": "2",
                "encryptedConversationKey": "ekey",
                "publicKeyVersion": "1",
            }])
        );
    }

    fn unverified_key_change() -> UnverifiedKeyChange {
        UnverifiedKeyChange {
            reason: UnverifiedKeyChangeReason::MissingSigningKey,
            key_dropped: true,
            conversation_id: Some("g1".to_string()),
            conversation_key_version: "5".to_string(),
            sender_id: Some("2".to_string()),
            public_key_version: None,
        }
    }

    fn undecryptable_key_change() -> UndecryptableKeyChange {
        UndecryptableKeyChange {
            reason: UndecryptableKeyChangeReason::NotARecipient,
            conversation_id: Some("g1".to_string()),
            conversation_key_version: "5".to_string(),
            sender_id: None,
        }
    }

    fn rejected_signing_key() -> RejectedSigningKey {
        RejectedSigningKey {
            user_id: "2".to_string(),
            public_key_version: "7".to_string(),
        }
    }

    #[test]
    fn test_unverified_key_change_serde() {
        let json = serde_json::to_value(unverified_key_change()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "reason": "MissingSigningKey",
                "key_dropped": true,
                "conversation_id": "g1",
                "conversation_key_version": "5",
                "sender_id": "2",
                "public_key_version": null,
            })
        );
        assert_eq!(
            serde_json::from_value::<UnverifiedKeyChange>(json).unwrap(),
            unverified_key_change()
        );
        for (reason, name) in [
            (
                UnverifiedKeyChangeReason::RejectedSigningKey,
                "RejectedSigningKey",
            ),
            (
                UnverifiedKeyChangeReason::InvalidSignature,
                "InvalidSignature",
            ),
            (UnverifiedKeyChangeReason::Unverifiable, "Unverifiable"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
        }
    }

    #[test]
    fn test_undecryptable_key_change_and_rejected_signing_key_serde() {
        let json = serde_json::to_value(undecryptable_key_change()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "reason": "NotARecipient",
                "conversation_id": "g1",
                "conversation_key_version": "5",
                "sender_id": null,
            })
        );
        assert_eq!(
            serde_json::from_value::<UndecryptableKeyChange>(json).unwrap(),
            undecryptable_key_change()
        );
        for (reason, name) in [
            (UndecryptableKeyChangeReason::Locked, "Locked"),
            (
                UndecryptableKeyChangeReason::OtherKeyVersion,
                "OtherKeyVersion",
            ),
            (
                UndecryptableKeyChangeReason::DecryptionFailed,
                "DecryptionFailed",
            ),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
        }

        let json = serde_json::to_value(rejected_signing_key()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "user_id": "2", "public_key_version": "7" })
        );
        assert_eq!(
            serde_json::from_value::<RejectedSigningKey>(json).unwrap(),
            rejected_signing_key()
        );
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_unverified_key_change_is_camel_case() {
        let json =
            serde_json::to_value(JsUnverifiedKeyChange::from(unverified_key_change())).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "reason": "missingSigningKey",
                "keyDropped": true,
                "conversationId": "g1",
                "conversationKeyVersion": "5",
                "senderId": "2",
                "publicKeyVersion": null,
            })
        );
        for (reason, name) in [
            (
                UnverifiedKeyChangeReason::RejectedSigningKey,
                "rejectedSigningKey",
            ),
            (
                UnverifiedKeyChangeReason::InvalidSignature,
                "invalidSignature",
            ),
            (UnverifiedKeyChangeReason::Unverifiable, "unverifiable"),
        ] {
            let json = serde_json::to_value(JsUnverifiedKeyChangeReason::from(reason)).unwrap();
            assert_eq!(json, name);
        }
    }

    #[test]
    fn test_public_key_record_reads_the_api_record_under_either_casing() {
        let expected = PublicKeyRecord::new("7", "identity", "signing", "binding");

        // The API's own record, with its other fields.
        let snake: PublicKeyRecord = serde_json::from_value(serde_json::json!({
            "public_key_version": "7",
            "public_key": "identity",
            "signing_public_key": "signing",
            "identity_public_key_signature": "binding",
            "juicebox_config": { "max_guess_count": 20, "token_map": [] },
            "public_key_fingerprint": null,
        }))
        .unwrap();
        assert_eq!(snake, expected);

        // A client library's camelCase record, with the version as a number.
        let camel: PublicKeyRecord = serde_json::from_value(serde_json::json!({
            "publicKeyVersion": 7,
            "publicKey": "identity",
            "signingPublicKey": "signing",
            "identityPublicKeySignature": "binding",
        }))
        .unwrap();
        assert_eq!(camel, expected);

        // A record with both names of a field keeps the value that is set.
        let both: PublicKeyRecord = serde_json::from_value(serde_json::json!({
            "publicKeyVersion": null,
            "public_key_version": "7",
            "public_key": "identity",
            "publicKey": "other",
            "signing_public_key": "signing",
            "identity_public_key_signature": "binding",
        }))
        .unwrap();
        assert_eq!(both, expected);

        // What a record lacks is empty.
        let partial: PublicKeyRecord =
            serde_json::from_value(serde_json::json!({ "public_key_version": 1.5 })).unwrap();
        assert_eq!(partial, PublicKeyRecord::default());
    }

    #[cfg(feature = "js")]
    #[test]
    fn test_js_decrypt_events_result_keys_its_diagnostics_by_index() {
        let result = DecryptEventsResult {
            events: Vec::new(),
            conversation_keys: ConversationKeyResult {
                keys: std::collections::HashMap::new(),
                keys_by_conversation: std::collections::HashMap::new(),
                latest_version: None,
                latest_versions: [("g1".to_string(), "5".to_string())].into(),
            },
            errors: [(3, "no key".to_string())].into(),
            unverified_key_changes: [(3, unverified_key_change())].into(),
            undecryptable_key_changes: [(4, undecryptable_key_change())].into(),
            rejected_signing_keys: [(0, rejected_signing_key())].into(),
            missing_signing_keys: [(5, MissingSigningKey::new("9", "3"))].into(),
        };
        let json = serde_json::to_value(JsDecryptEventsResult::from(result)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "events": [],
                "conversationKeys": {
                    "latestVersion": null,
                    "latestVersions": { "g1": "5" },
                },
                "errors": { "3": "no key" },
                "unverifiedKeyChanges": {
                    "3": {
                        "reason": "missingSigningKey",
                        "keyDropped": true,
                        "conversationId": "g1",
                        "conversationKeyVersion": "5",
                        "senderId": "2",
                        "publicKeyVersion": null,
                    },
                },
                "undecryptableKeyChanges": {
                    "4": {
                        "reason": "notARecipient",
                        "conversationId": "g1",
                        "conversationKeyVersion": "5",
                        "senderId": null,
                    },
                },
                "rejectedSigningKeys": {
                    "0": { "userId": "2", "publicKeyVersion": "7" },
                },
                "missingSigningKeys": {
                    "5": { "userId": "9", "publicKeyVersion": "3" },
                },
            })
        );
        for (reason, name) in [
            (UndecryptableKeyChangeReason::Locked, "locked"),
            (
                UndecryptableKeyChangeReason::OtherKeyVersion,
                "otherKeyVersion",
            ),
            (
                UndecryptableKeyChangeReason::DecryptionFailed,
                "decryptionFailed",
            ),
        ] {
            let json = serde_json::to_value(JsUndecryptableKeyChangeReason::from(reason)).unwrap();
            assert_eq!(json, name);
        }
    }
}
