//! Parameter structs for the high-arity SDK methods.
//!
//! Each struct pairs a [`new()`] constructor taking only the required fields
//! with public fields for the optional ones, so call sites name every value
//! they set and new optional protocol fields can be added without breaking
//! existing callers:
//!
//! ```rust,ignore
//! chat.set_identity("my-user-id", signing_key_version);
//! let mut params = EncryptMessageParams::new(conversation_id, "Hello");
//! params.ttl_msec = Some(86_400_000);
//! // The SDK generates the message id; read it back from the result.
//! let payload = chat.encrypt_message(params)?;
//! let message_id = payload.message_id;
//! ```
//!
//! Identity fields (`sender_id`, `signing_key_version`) and key fields
//! (`conversation_key`, `conversation_key_version`) are optional overrides:
//! when unset they resolve from the session identity and the opt-in key
//! cache. An unset override and an explicit value produce byte-identical
//! signed output for the same logical inputs.

use zeroize::Zeroize;

use crate::error::SdkError;
use crate::types::{AttachmentDescriptor, EntityDescriptor, PublicKeyInput, QuickReply};

/// Convert an override string into storage form: an empty string means
/// "not set", so FFI layers that cannot express `Option` can pass `""`.
fn non_empty(s: impl Into<String>) -> Option<String> {
    let s = s.into();
    (!s.is_empty()).then_some(s)
}

/// Parameters for [`crate::ChatCore::encrypt_message`].
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output. No `PartialEq` is derived:
/// equality would byte-compare the key non-constant-time.
#[derive(Clone)]
pub struct EncryptMessageParams {
    /// ID of the conversation the message belongs to.
    pub conversation_id: String,
    /// The plaintext message text.
    pub text: String,
    /// User ID of the sender; resolves from the session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the message; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Raw 32-byte conversation key used to encrypt the message content;
    /// resolves from the key cache when unset (set together with
    /// `conversation_key_version`).
    pub conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key used for encryption; resolves from the
    /// key cache when unset (set together with `conversation_key`).
    pub conversation_key_version: Option<String>,
    /// Optional rich-text entities (URLs, mentions, etc.) to embed.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// Optional attachments (posts, URLs, media, etc.) to include in the message.
    pub attachments: Option<Vec<AttachmentDescriptor>>,
    /// Optional quick reply: a request offering selectable options, or a
    /// response selecting one.
    pub quick_reply: Option<QuickReply>,
    /// Whether to send a push notification. `None` defaults to `true`.
    pub should_notify: Option<bool>,
    /// Optional TTL in milliseconds for disappearing messages.
    pub ttl_msec: Option<i64>,
}

impl EncryptMessageParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            text: text.into(),
            sender_id: None,
            signing_key_version: None,
            conversation_key: None,
            conversation_key_version: None,
            entities: None,
            attachments: None,
            quick_reply: None,
            should_notify: None,
            ttl_msec: None,
        }
    }

    /// Set the explicit conversation key and its version.
    ///
    /// The two travel together: the version names the key the recipients use
    /// to decrypt, so setting one without the other is rejected at encrypt
    /// time.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = Some(conversation_key_version.into());
        self
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for EncryptMessageParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptMessageParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptMessageParams")
            .field("conversation_id", &self.conversation_id)
            .field("text", &self.text)
            .field("sender_id", &self.sender_id)
            .field("signing_key_version", &self.signing_key_version)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .field("entities", &self.entities)
            .field("attachments", &self.attachments)
            .field("quick_reply", &self.quick_reply)
            .field("should_notify", &self.should_notify)
            .field("ttl_msec", &self.ttl_msec)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::encrypt_reply`].
///
/// The preferred form passes `reply_to_event` — the base64 raw signed event
/// being replied to — and lets the SDK derive the reply preview from it. The
/// `reply_to_*` field overrides remain for callers that no longer hold the
/// raw event.
///
/// When `reply_to_event` is set, recipients validate each preview field
/// against the decrypted original, so an override that diverges from the
/// original (a non-prefix text, a different sender id) produces a preview
/// every recipient flags as invalid.
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output. No `PartialEq` is derived:
/// equality would byte-compare the key non-constant-time.
#[derive(Clone)]
pub struct EncryptReplyParams {
    /// ID of the conversation the reply belongs to.
    pub conversation_id: String,
    /// The plaintext reply text.
    pub text: String,
    /// Base64 of the raw signed event being replied to. The reply preview
    /// (sequence id, sender, text, entities, attachments) is derived from it
    /// and the raw event is embedded so recipients can validate the preview.
    pub reply_to_event: Option<String>,
    /// Base64 of the raw signed edit event, when the original was edited.
    pub reply_to_edit_event: Option<String>,
    /// Base64 raw key-change events needed to decrypt the original when it
    /// was encrypted under a different key version than this reply.
    pub reply_to_ckces: Option<Vec<String>>,
    /// User ID of the sender; resolves from the session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the message; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Raw 32-byte conversation key used to encrypt the message content;
    /// resolves from the key cache when unset (set together with
    /// `conversation_key_version`).
    pub conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key used for encryption; resolves from the
    /// key cache when unset (set together with `conversation_key`).
    pub conversation_key_version: Option<String>,
    /// The `sequence_id` of the message being replied to; derived from
    /// `reply_to_event` when unset.
    pub reply_to_sequence_id: Option<String>,
    /// The sender ID of the message being replied to (for preview); derived
    /// from `reply_to_event` when unset.
    pub reply_to_sender_id: Option<i64>,
    /// The text of the message being replied to (for preview); derived from
    /// `reply_to_event` when unset.
    pub reply_to_text: Option<String>,
    /// Optional rich-text entities (URLs, mentions, etc.) to embed in the outgoing message.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// Optional attachments (posts, URLs, media, etc.) to include in the outgoing message.
    pub attachments: Option<Vec<AttachmentDescriptor>>,
    /// Optional rich-text entities from the original message (for the reply
    /// preview); derived from `reply_to_event` when unset.
    pub reply_to_entities: Option<Vec<EntityDescriptor>>,
    /// Optional attachments from the original message (for the reply
    /// preview); derived from `reply_to_event` when unset.
    pub reply_to_attachments: Option<Vec<AttachmentDescriptor>>,
    /// Optional quick reply: a request offering selectable options, or a
    /// response selecting one.
    pub quick_reply: Option<QuickReply>,
    /// Whether to send a push notification. `None` defaults to `true`.
    pub should_notify: Option<bool>,
    /// Optional TTL in milliseconds for disappearing messages.
    pub ttl_msec: Option<i64>,
}

impl EncryptReplyParams {
    /// Create params with required fields; all optional fields default to
    /// `None`. `reply_to_event` is the base64 raw signed event being replied
    /// to; pass an empty string only when supplying the `reply_to_*` fields
    /// directly instead.
    pub fn new(
        conversation_id: impl Into<String>,
        text: impl Into<String>,
        reply_to_event: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            text: text.into(),
            reply_to_event: non_empty(reply_to_event),
            reply_to_edit_event: None,
            reply_to_ckces: None,
            sender_id: None,
            signing_key_version: None,
            conversation_key: None,
            conversation_key_version: None,
            reply_to_sequence_id: None,
            reply_to_sender_id: None,
            reply_to_text: None,
            entities: None,
            attachments: None,
            reply_to_entities: None,
            reply_to_attachments: None,
            quick_reply: None,
            should_notify: None,
            ttl_msec: None,
        }
    }

    /// Set the explicit conversation key and its version.
    ///
    /// The two travel together: the version names the key the recipients use
    /// to decrypt, so setting one without the other is rejected at encrypt
    /// time.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = Some(conversation_key_version.into());
        self
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for EncryptReplyParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptReplyParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptReplyParams")
            .field("conversation_id", &self.conversation_id)
            .field("text", &self.text)
            .field("reply_to_event", &self.reply_to_event)
            .field("reply_to_edit_event", &self.reply_to_edit_event)
            .field("reply_to_ckces", &self.reply_to_ckces)
            .field("sender_id", &self.sender_id)
            .field("signing_key_version", &self.signing_key_version)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .field("reply_to_sequence_id", &self.reply_to_sequence_id)
            .field("reply_to_sender_id", &self.reply_to_sender_id)
            .field("reply_to_text", &self.reply_to_text)
            .field("entities", &self.entities)
            .field("attachments", &self.attachments)
            .field("reply_to_entities", &self.reply_to_entities)
            .field("reply_to_attachments", &self.reply_to_attachments)
            .field("quick_reply", &self.quick_reply)
            .field("should_notify", &self.should_notify)
            .field("ttl_msec", &self.ttl_msec)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::encrypt_forward`].
///
/// A forward quotes an existing message in another conversation:
/// `forwarded_text` and `forwarded_entities` carry the original's full text
/// and rich-text entities, and the optional `text` is the sender's own comment
/// shown with it. Media is encrypted under its conversation's key, so the
/// original's attachments do not carry over: decrypt them, re-encrypt them
/// with this conversation's key, upload them, and pass the new descriptors in
/// `attachments`.
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output. No `PartialEq` is derived:
/// equality would byte-compare the key non-constant-time.
#[derive(Clone)]
pub struct EncryptForwardParams {
    /// ID of the conversation the forward is sent to.
    pub conversation_id: String,
    /// Full text of the message being forwarded.
    pub forwarded_text: String,
    /// Rich-text entities of the message being forwarded.
    pub forwarded_entities: Option<Vec<EntityDescriptor>>,
    /// Optional comment sent with the forward.
    pub text: Option<String>,
    /// Rich-text entities in `text`.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// The original's attachments, re-uploaded under this conversation.
    pub attachments: Option<Vec<AttachmentDescriptor>>,
    /// User ID of the sender; resolves from the session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the message; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Raw 32-byte conversation key used to encrypt the message content;
    /// resolves from the key cache when unset (set together with
    /// `conversation_key_version`).
    pub conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key used for encryption; resolves from the
    /// key cache when unset (set together with `conversation_key`).
    pub conversation_key_version: Option<String>,
    /// Whether to send a push notification. `None` defaults to `true`.
    pub should_notify: Option<bool>,
    /// Optional TTL in milliseconds for disappearing messages.
    pub ttl_msec: Option<i64>,
}

impl EncryptForwardParams {
    /// Create params with required fields; all optional fields default to
    /// `None`. `forwarded_text` is the original message's full text; pass an
    /// empty string only when forwarding a message that has attachments but
    /// no text.
    pub fn new(conversation_id: impl Into<String>, forwarded_text: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            forwarded_text: forwarded_text.into(),
            forwarded_entities: None,
            text: None,
            entities: None,
            attachments: None,
            sender_id: None,
            signing_key_version: None,
            conversation_key: None,
            conversation_key_version: None,
            should_notify: None,
            ttl_msec: None,
        }
    }

    /// Set the explicit conversation key and its version.
    ///
    /// The two travel together: the version names the key the recipients use
    /// to decrypt, so setting one without the other is rejected at encrypt
    /// time.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = Some(conversation_key_version.into());
        self
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for EncryptForwardParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptForwardParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptForwardParams")
            .field("conversation_id", &self.conversation_id)
            .field("forwarded_text", &self.forwarded_text)
            .field("forwarded_entities", &self.forwarded_entities)
            .field("text", &self.text)
            .field("entities", &self.entities)
            .field("attachments", &self.attachments)
            .field("sender_id", &self.sender_id)
            .field("signing_key_version", &self.signing_key_version)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .field("should_notify", &self.should_notify)
            .field("ttl_msec", &self.ttl_msec)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::encrypt_add_reaction`] and
/// [`crate::ChatCore::encrypt_remove_reaction`].
///
/// The preferred form passes `target_event` — the base64 raw event being
/// reacted to — and lets the SDK derive the conversation id and target
/// sequence id from it. The explicit field overrides remain for callers that
/// no longer hold the raw event. The same params value can be passed to both
/// methods to add and later remove the same reaction.
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output. No `PartialEq` is derived:
/// equality would byte-compare the key non-constant-time.
#[derive(Clone)]
pub struct EncryptReactionParams {
    /// Base64 of the raw event being reacted to. The conversation id and
    /// target sequence id are derived from it.
    pub target_event: Option<String>,
    /// The reaction emoji.
    pub emoji: String,
    /// ID of the conversation the reaction belongs to; derived from
    /// `target_event` when unset.
    pub conversation_id: Option<String>,
    /// The `sequence_id` of the message being reacted to; derived from
    /// `target_event` when unset.
    pub target_message_sequence_id: Option<String>,
    /// User ID of the sender; resolves from the session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the message; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Raw 32-byte conversation key used to encrypt the reaction content;
    /// resolves from the key cache when unset (set together with
    /// `conversation_key_version`).
    pub conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key used for encryption; resolves from the
    /// key cache when unset (set together with `conversation_key`).
    pub conversation_key_version: Option<String>,
}

impl EncryptReactionParams {
    /// Create params with required fields; all optional fields default to
    /// `None`. `target_event` is the base64 raw event being reacted to; pass
    /// an empty string only when supplying `conversation_id` and
    /// `target_message_sequence_id` directly instead.
    pub fn new(target_event: impl Into<String>, emoji: impl Into<String>) -> Self {
        Self {
            target_event: non_empty(target_event),
            emoji: emoji.into(),
            conversation_id: None,
            target_message_sequence_id: None,
            sender_id: None,
            signing_key_version: None,
            conversation_key: None,
            conversation_key_version: None,
        }
    }

    /// Set the explicit conversation key and its version.
    ///
    /// The two travel together: the version names the key the recipients use
    /// to decrypt, so setting one without the other is rejected at encrypt
    /// time.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = Some(conversation_key_version.into());
        self
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for EncryptReactionParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptReactionParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptReactionParams")
            .field("target_event", &self.target_event)
            .field("emoji", &self.emoji)
            .field("conversation_id", &self.conversation_id)
            .field(
                "target_message_sequence_id",
                &self.target_message_sequence_id,
            )
            .field("sender_id", &self.sender_id)
            .field("signing_key_version", &self.signing_key_version)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::encrypt_edit`].
///
/// The preferred form passes `target_event` — the base64 raw event of the
/// message being edited — and lets the SDK derive the conversation id and
/// target sequence id from it. The explicit field overrides remain for
/// callers that no longer hold the raw event.
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output. No `PartialEq` is derived:
/// equality would byte-compare the key non-constant-time.
#[derive(Clone)]
pub struct EncryptEditParams {
    /// Base64 of the raw event being edited. The conversation id and target
    /// sequence id are derived from it.
    pub target_event: Option<String>,
    /// The replacement message text.
    pub updated_text: String,
    /// Rich-text entities for the replacement text; `None` clears any
    /// entities the original carried.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// ID of the conversation the edit belongs to; derived from
    /// `target_event` when unset.
    pub conversation_id: Option<String>,
    /// The `sequence_id` of the message being edited; derived from
    /// `target_event` when unset.
    pub target_message_sequence_id: Option<String>,
    /// User ID of the sender; resolves from the session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the edit; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Raw 32-byte conversation key used to encrypt the edit content;
    /// resolves from the key cache when unset (set together with
    /// `conversation_key_version`).
    pub conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key used for encryption; resolves from the
    /// key cache when unset (set together with `conversation_key`).
    pub conversation_key_version: Option<String>,
}

impl EncryptEditParams {
    /// Create params with required fields; all optional fields default to
    /// `None`. `target_event` is the base64 raw event being edited; pass an
    /// empty string only when supplying `conversation_id` and
    /// `target_message_sequence_id` directly instead.
    pub fn new(target_event: impl Into<String>, updated_text: impl Into<String>) -> Self {
        Self {
            target_event: non_empty(target_event),
            updated_text: updated_text.into(),
            entities: None,
            conversation_id: None,
            target_message_sequence_id: None,
            sender_id: None,
            signing_key_version: None,
            conversation_key: None,
            conversation_key_version: None,
        }
    }

    /// Set the explicit conversation key and its version.
    ///
    /// The two travel together: the version names the key the recipients use
    /// to decrypt, so setting one without the other is rejected at encrypt
    /// time.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = Some(conversation_key_version.into());
        self
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for EncryptEditParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptEditParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptEditParams")
            .field("target_event", &self.target_event)
            .field("updated_text", &self.updated_text)
            .field("entities", &self.entities)
            .field("conversation_id", &self.conversation_id)
            .field(
                "target_message_sequence_id",
                &self.target_message_sequence_id,
            )
            .field("sender_id", &self.sender_id)
            .field("signing_key_version", &self.signing_key_version)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::prepare_message_delete`].
///
/// A delete is a signed plaintext event, not an encrypted message, so no
/// conversation key is involved: the result is an action signature the
/// caller submits alongside the delete request.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageDeleteParams {
    /// ID of the conversation the messages belong to.
    pub conversation_id: String,
    /// The `sequence_id`s of the messages to delete.
    pub sequence_ids: Vec<String>,
    /// Delete for every participant (`true`, own messages only) or only from
    /// the caller's view (`false`).
    pub delete_for_all: bool,
    /// User ID of the sender signing the delete; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the delete; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl MessageDeleteParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(
        conversation_id: impl Into<String>,
        sequence_ids: Vec<String>,
        delete_for_all: bool,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            sequence_ids,
            delete_for_all,
            sender_id: None,
            signing_key_version: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

/// A conversation setting to change with
/// [`crate::ChatCore::prepare_conversation_settings_change`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationSetting {
    /// Make new messages disappear `ttl_msec` milliseconds after they are
    /// sent. Must be positive.
    MessageDuration {
        /// Lifetime of each new message, in milliseconds.
        ttl_msec: i64,
    },
    /// Turn disappearing messages off.
    RemoveMessageDuration,
    /// Mute the conversation for the caller only.
    Mute,
    /// Unmute the conversation for the caller only.
    Unmute,
    /// Ask participants' clients to block screenshots and screen recording.
    EnableScreenCaptureBlocking,
    /// Stop asking participants' clients to block screen capture.
    DisableScreenCaptureBlocking,
}

impl ConversationSetting {
    /// Every name accepted by [`ConversationSetting::from_name`].
    pub const NAMES: [&'static str; 6] = [
        "message_duration",
        "remove_message_duration",
        "mute",
        "unmute",
        "enable_screen_capture_blocking",
        "disable_screen_capture_blocking",
    ];

    /// Parse the string form the language bindings take: one of
    /// [`ConversationSetting::NAMES`], with `ttl_msec` set for
    /// `"message_duration"` and only for it.
    pub fn from_name(setting: &str, ttl_msec: Option<i64>) -> Result<Self, SdkError> {
        let parsed = match setting {
            "message_duration" => {
                let Some(ttl_msec) = ttl_msec else {
                    return Err(SdkError::InvalidState(
                        "ttl_msec is required for setting \"message_duration\": pass the message \
                         lifetime in milliseconds"
                            .into(),
                    ));
                };
                return Ok(Self::MessageDuration { ttl_msec });
            }
            "remove_message_duration" => Self::RemoveMessageDuration,
            "mute" => Self::Mute,
            "unmute" => Self::Unmute,
            "enable_screen_capture_blocking" => Self::EnableScreenCaptureBlocking,
            "disable_screen_capture_blocking" => Self::DisableScreenCaptureBlocking,
            "" => {
                return Err(SdkError::InvalidState(format!(
                    "setting is empty: pass one of {}",
                    Self::NAMES.join(", ")
                )))
            }
            other => {
                return Err(SdkError::InvalidState(format!(
                    "unknown setting \"{other}\": pass one of {}",
                    Self::NAMES.join(", ")
                )))
            }
        };
        if ttl_msec.is_some() {
            return Err(SdkError::InvalidState(format!(
                "ttl_msec only applies to setting \"message_duration\": leave it unset for \
                 \"{setting}\""
            )));
        }
        Ok(parsed)
    }
}

/// Parameters for [`crate::ChatCore::prepare_conversation_settings_change`].
///
/// A settings change is a signed plaintext event, not an encrypted message,
/// so no conversation key is involved: the result is an action signature the
/// caller submits alongside the settings request.
#[derive(Clone, Debug, PartialEq)]
pub struct ConversationSettingsParams {
    /// ID of the conversation whose setting changes.
    pub conversation_id: String,
    /// The setting to change.
    pub setting: ConversationSetting,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl ConversationSettingsParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, setting: ConversationSetting) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            setting,
            sender_id: None,
            signing_key_version: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

/// A group admin action to sign with
/// [`crate::ChatCore::prepare_group_admin_change`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupAdminAction {
    /// Make existing members admins.
    AddAdmins {
        /// Members to promote.
        user_ids: Vec<String>,
    },
    /// Revoke admin rights; the users stay members.
    RemoveAdmins {
        /// Admins to demote.
        user_ids: Vec<String>,
    },
    /// Remove members from the group.
    RemoveMembers {
        /// Members to remove.
        user_ids: Vec<String>,
    },
    /// Decline pending requests to join through the invite link.
    RejectJoinRequests {
        /// Users whose join requests are declined.
        user_ids: Vec<String>,
    },
    /// Turn on joining through an invite link.
    EnableInviteLink {
        /// The invite link to publish.
        invite_url: String,
        /// When the link stops working, in milliseconds since the Unix
        /// epoch; `None` keeps it open until disabled.
        expires_at_msec: Option<i64>,
        /// Affiliate the link is attributed to, if any.
        affiliate_id: Option<String>,
    },
    /// Turn off the invite link. The event names the signing sender as the
    /// member who disabled it.
    DisableInviteLink,
}

impl GroupAdminAction {
    /// Every name accepted by [`GroupAdminAction::from_parts`].
    pub const NAMES: [&'static str; 6] = [
        "add_admins",
        "remove_admins",
        "remove_members",
        "reject_join_requests",
        "enable_invite_link",
        "disable_invite_link",
    ];

    /// Build an action from the flat form the language bindings take: an
    /// action name from [`GroupAdminAction::NAMES`] plus only the fields
    /// that action uses. `user_ids` belongs to the four roster actions;
    /// `invite_url`, `expires_at_msec`, and `affiliate_id` belong to
    /// `"enable_invite_link"`. Passing a field the action does not use is an
    /// error, so a mistyped action name cannot silently drop input.
    pub fn from_parts(
        action: &str,
        user_ids: Option<Vec<String>>,
        invite_url: Option<String>,
        expires_at_msec: Option<i64>,
        affiliate_id: Option<String>,
    ) -> Result<Self, SdkError> {
        let invite_fields_set =
            invite_url.is_some() || expires_at_msec.is_some() || affiliate_id.is_some();
        match action {
            "add_admins" | "remove_admins" | "remove_members" | "reject_join_requests" => {
                if invite_fields_set {
                    return Err(SdkError::InvalidState(format!(
                        "invite_url, expires_at_msec and affiliate_id only apply to action \
                         \"enable_invite_link\": leave them unset for \"{action}\""
                    )));
                }
                let Some(user_ids) = user_ids else {
                    return Err(SdkError::InvalidState(format!(
                        "user_ids is required for action \"{action}\": pass the users it \
                         applies to"
                    )));
                };
                Ok(match action {
                    "add_admins" => Self::AddAdmins { user_ids },
                    "remove_admins" => Self::RemoveAdmins { user_ids },
                    "remove_members" => Self::RemoveMembers { user_ids },
                    _ => Self::RejectJoinRequests { user_ids },
                })
            }
            "enable_invite_link" => {
                if user_ids.is_some() {
                    return Err(SdkError::InvalidState(
                        "user_ids does not apply to action \"enable_invite_link\": leave it unset"
                            .into(),
                    ));
                }
                let Some(invite_url) = invite_url else {
                    return Err(SdkError::InvalidState(
                        "invite_url is required for action \"enable_invite_link\": pass the \
                         invite link to publish"
                            .into(),
                    ));
                };
                Ok(Self::EnableInviteLink {
                    invite_url,
                    expires_at_msec,
                    affiliate_id,
                })
            }
            "disable_invite_link" => {
                if user_ids.is_some() || invite_fields_set {
                    return Err(SdkError::InvalidState(
                        "action \"disable_invite_link\" takes no other fields: leave user_ids, \
                         invite_url, expires_at_msec and affiliate_id unset"
                            .into(),
                    ));
                }
                Ok(Self::DisableInviteLink)
            }
            "" => Err(SdkError::InvalidState(format!(
                "action is empty: pass one of {}",
                Self::NAMES.join(", ")
            ))),
            other => Err(SdkError::InvalidState(format!(
                "unknown action \"{other}\": pass one of {}",
                Self::NAMES.join(", ")
            ))),
        }
    }
}

/// Parameters for [`crate::ChatCore::prepare_group_admin_change`].
///
/// Admin actions are signed plaintext events, not encrypted messages, so no
/// conversation key is involved: the result is an action signature the
/// caller submits alongside the group change request.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupAdminChangeParams {
    /// ID of the group (starts with `g`).
    pub conversation_id: String,
    /// The action to sign.
    pub action: GroupAdminAction,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupAdminChangeParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, action: GroupAdminAction) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            action,
            sender_id: None,
            signing_key_version: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

/// Parameters for [`crate::ChatCore::prepare_conversation_key_change`].
#[derive(Clone, Debug, PartialEq)]
pub struct ConversationKeyChangeParams {
    /// Identity public keys for every participant the new key is encrypted for.
    pub public_keys: Vec<PublicKeyInput>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// Conversation the change applies to. `None` — or an empty string —
    /// derives the canonical one-to-one id from the two participants; pass
    /// the existing id for a group key rotation.
    pub conversation_id: Option<String>,
}

impl ConversationKeyChangeParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(public_keys: Vec<PublicKeyInput>) -> Self {
        Self {
            public_keys,
            sender_id: None,
            signing_key_version: None,
            conversation_id: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

/// Parameters for [`crate::ChatCore::prepare_group_members_change`].
///
/// The `current_*` fields snapshot the group state the change is made
/// against. An empty string or negative TTL in an optional field is treated
/// as unset, and an unset value signs the null sentinel, so every binding
/// produces identical signed bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupMembersChangeParams {
    /// Identity public keys for every participant of the updated roster.
    pub public_keys: Vec<PublicKeyInput>,
    /// ID of the group conversation being changed.
    pub conversation_id: String,
    /// User IDs being added to the group.
    pub new_member_ids: Vec<String>,
    /// User IDs of the current members.
    pub current_member_ids: Vec<String>,
    /// User IDs of the current admins.
    pub current_admin_ids: Vec<String>,
    /// User IDs of members whose join is still pending.
    pub current_pending_member_ids: Vec<String>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// The group's current title, if set.
    pub current_title: Option<String>,
    /// The group's current avatar URL, if set.
    pub current_avatar_url: Option<String>,
    /// The group's current message TTL in milliseconds, if set.
    pub current_ttl_msec: Option<i64>,
    /// The group's current screen-capture-blocking state; `None` when unset.
    pub current_screen_capture_blocking_enabled: Option<bool>,
}

impl GroupMembersChangeParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(
        public_keys: Vec<PublicKeyInput>,
        conversation_id: impl Into<String>,
        new_member_ids: Vec<String>,
        current_member_ids: Vec<String>,
        current_admin_ids: Vec<String>,
        current_pending_member_ids: Vec<String>,
    ) -> Self {
        Self {
            public_keys,
            conversation_id: conversation_id.into(),
            new_member_ids,
            current_member_ids,
            current_admin_ids,
            current_pending_member_ids,
            sender_id: None,
            signing_key_version: None,
            current_title: None,
            current_avatar_url: None,
            current_ttl_msec: None,
            current_screen_capture_blocking_enabled: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

/// Parameters for [`crate::ChatCore::prepare_group_create`].
///
/// An empty string or negative TTL in an optional field is treated as unset,
/// and an unset value signs the null sentinel, so every binding produces
/// identical signed bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupCreateParams {
    /// Identity public keys for every participant of the new group.
    pub public_keys: Vec<PublicKeyInput>,
    /// ID of the new group conversation (the `g…` id minted by the
    /// initialize endpoint).
    pub conversation_id: String,
    /// User IDs of the group's members.
    pub member_ids: Vec<String>,
    /// User IDs of the group's admins.
    pub admin_ids: Vec<String>,
    /// User ID of the sender signing the create; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the create; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
    /// The group's title, if set.
    pub title: Option<String>,
    /// The group's avatar URL, if set.
    pub avatar_url: Option<String>,
    /// The group's message TTL in milliseconds, if set.
    pub ttl_msec: Option<i64>,
}

impl GroupCreateParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(
        public_keys: Vec<PublicKeyInput>,
        conversation_id: impl Into<String>,
        member_ids: Vec<String>,
        admin_ids: Vec<String>,
    ) -> Self {
        Self {
            public_keys,
            conversation_id: conversation_id.into(),
            member_ids,
            admin_ids,
            sender_id: None,
            signing_key_version: None,
            title: None,
            avatar_url: None,
            ttl_msec: None,
        }
    }

    /// Set the explicit sender identity, overriding the session identity.
    pub fn with_identity(
        mut self,
        sender_id: impl Into<String>,
        signing_key_version: impl Into<String>,
    ) -> Self {
        self.sender_id = non_empty(sender_id);
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChatCore;

    fn unlocked_core() -> ChatCore {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core
    }

    fn self_public_keys(core: &ChatCore) -> Vec<PublicKeyInput> {
        let pk = core.get_public_keys().unwrap();
        vec![PublicKeyInput {
            user_id: "me".to_string(),
            public_key: pk.identity,
            key_version: "1".to_string(),
        }]
    }

    // The encrypt-params structs deliberately derive no `PartialEq` (equality
    // would byte-compare the conversation key non-constant-time), so the
    // construction-equivalence tests compare field by field.
    fn assert_message_params_eq(a: &EncryptMessageParams, b: &EncryptMessageParams) {
        assert_eq!(a.conversation_id, b.conversation_id);
        assert_eq!(a.text, b.text);
        assert_eq!(a.sender_id, b.sender_id);
        assert_eq!(a.signing_key_version, b.signing_key_version);
        assert_eq!(a.conversation_key, b.conversation_key);
        assert_eq!(a.conversation_key_version, b.conversation_key_version);
        assert_eq!(a.entities, b.entities);
        assert_eq!(a.attachments, b.attachments);
        assert_eq!(a.quick_reply, b.quick_reply);
        assert_eq!(a.should_notify, b.should_notify);
        assert_eq!(a.ttl_msec, b.ttl_msec);
    }

    #[test]
    fn encrypt_message_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let ckey = crate::crypto::key_factory::KeyFactory::generate_conversation_key()
            .unwrap()
            .to_bytes();

        let mut via_new = EncryptMessageParams::new("conv-1", "hi")
            .with_identity("me", "2")
            .with_conversation_key(ckey.clone(), "1");
        via_new.should_notify = Some(false);
        via_new.ttl_msec = Some(30_000);

        let full = EncryptMessageParams {
            conversation_id: "conv-1".into(),
            text: "hi".into(),
            sender_id: Some("me".into()),
            signing_key_version: Some("2".into()),
            conversation_key: Some(ckey),
            conversation_key_version: Some("1".into()),
            entities: None,
            attachments: None,
            quick_reply: None,
            should_notify: Some(false),
            ttl_msec: Some(30_000),
        };
        assert_message_params_eq(&via_new, &full);

        let payload = core.encrypt_message(via_new).unwrap();
        assert!(!payload.should_notify);
        assert_eq!(payload.conversation_key_version, "1");
    }

    #[test]
    fn encrypt_reply_params_explicit_fields_encrypt() {
        let core = unlocked_core();
        let ckey = crate::crypto::key_factory::KeyFactory::generate_conversation_key()
            .unwrap()
            .to_bytes();

        let mut params = EncryptReplyParams::new("conv-1", "a reply", "")
            .with_identity("me", "2")
            .with_conversation_key(ckey, "1");
        params.reply_to_sequence_id = Some("seq-9".into());
        params.reply_to_sender_id = Some(42);
        params.reply_to_text = Some("original".into());

        let payload = core.encrypt_reply(params).unwrap();
        assert!(
            payload.should_notify,
            "unset should_notify defaults to true"
        );
    }

    #[test]
    fn encrypt_forward_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let ckey = crate::crypto::key_factory::KeyFactory::generate_conversation_key()
            .unwrap()
            .to_bytes();

        let mut via_new = EncryptForwardParams::new("conv-1", "original")
            .with_identity("me", "2")
            .with_conversation_key(ckey.clone(), "1");
        via_new.text = Some("fyi".into());
        via_new.should_notify = Some(false);

        let full = EncryptForwardParams {
            conversation_id: "conv-1".into(),
            forwarded_text: "original".into(),
            forwarded_entities: None,
            text: Some("fyi".into()),
            entities: None,
            attachments: None,
            sender_id: Some("me".into()),
            signing_key_version: Some("2".into()),
            conversation_key: Some(ckey),
            conversation_key_version: Some("1".into()),
            should_notify: Some(false),
            ttl_msec: None,
        };
        assert_eq!(via_new.conversation_id, full.conversation_id);
        assert_eq!(via_new.forwarded_text, full.forwarded_text);
        assert_eq!(via_new.forwarded_entities, full.forwarded_entities);
        assert_eq!(via_new.text, full.text);
        assert_eq!(via_new.entities, full.entities);
        assert_eq!(via_new.attachments, full.attachments);
        assert_eq!(via_new.sender_id, full.sender_id);
        assert_eq!(via_new.signing_key_version, full.signing_key_version);
        assert_eq!(via_new.conversation_key, full.conversation_key);
        assert_eq!(
            via_new.conversation_key_version,
            full.conversation_key_version
        );
        assert_eq!(via_new.should_notify, full.should_notify);
        assert_eq!(via_new.ttl_msec, full.ttl_msec);
        assert!(format!("{via_new:?}").contains("[REDACTED]"));

        let payload = core.encrypt_forward(via_new).unwrap();
        assert!(!payload.should_notify);
        assert_eq!(payload.conversation_key_version, "1");
    }

    #[test]
    fn encrypt_reaction_params_explicit_fields_encrypt_add_and_remove() {
        let core = unlocked_core();
        let ckey = crate::crypto::key_factory::KeyFactory::generate_conversation_key()
            .unwrap()
            .to_bytes();

        let mut params = EncryptReactionParams::new("", "👍")
            .with_identity("me", "2")
            .with_conversation_key(ckey, "1");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());

        // The same params value serves both the add and the remove.
        assert!(!core
            .encrypt_add_reaction(&params)
            .unwrap()
            .encrypted_content
            .is_empty());
        assert!(!core
            .encrypt_remove_reaction(&params)
            .unwrap()
            .encrypted_content
            .is_empty());
    }

    #[test]
    fn conversation_key_change_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let public_keys = self_public_keys(&core);

        let mut via_new = ConversationKeyChangeParams::new(public_keys.clone());
        via_new = via_new.with_identity("me", "1");
        via_new.conversation_id = Some("conv-1".into());

        let full = ConversationKeyChangeParams {
            public_keys,
            sender_id: Some("me".into()),
            signing_key_version: Some("1".into()),
            conversation_id: Some("conv-1".into()),
        };
        assert_eq!(via_new, full);

        let prepared = core.prepare_conversation_key_change(via_new).unwrap();
        assert_eq!(prepared.conversation_id, "conv-1");
        assert_eq!(prepared.action_signatures.len(), 1);
    }

    #[test]
    fn group_members_change_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let public_keys = self_public_keys(&core);

        let mut via_new = GroupMembersChangeParams::new(
            public_keys.clone(),
            "g123",
            vec!["new-1".into()],
            vec!["me".into()],
            vec!["me".into()],
            vec![],
        )
        .with_identity("me", "1");
        via_new.current_title = Some("Team".into());

        let full = GroupMembersChangeParams {
            public_keys,
            conversation_id: "g123".into(),
            new_member_ids: vec!["new-1".into()],
            current_member_ids: vec!["me".into()],
            current_admin_ids: vec!["me".into()],
            current_pending_member_ids: vec![],
            sender_id: Some("me".into()),
            signing_key_version: Some("1".into()),
            current_title: Some("Team".into()),
            current_avatar_url: None,
            current_ttl_msec: None,
            current_screen_capture_blocking_enabled: None,
        };
        assert_eq!(via_new, full);

        // Both constructions encode identical member-add event details for
        // the same conversation-key version (the detail is deterministic).
        let a = core
            .prepare_group_members_change_with_version(via_new, "42")
            .unwrap();
        let b = core
            .prepare_group_members_change_with_version(full, "42")
            .unwrap();
        assert_eq!(
            a.action_signatures[1].encoded_message_event_detail,
            b.action_signatures[1].encoded_message_event_detail,
        );
    }

    #[test]
    fn conversation_setting_from_name_parses_every_name() {
        use ConversationSetting as S;
        assert_eq!(
            S::from_name("message_duration", Some(1000)).unwrap(),
            S::MessageDuration { ttl_msec: 1000 }
        );
        let rest = [
            S::RemoveMessageDuration,
            S::Mute,
            S::Unmute,
            S::EnableScreenCaptureBlocking,
            S::DisableScreenCaptureBlocking,
        ];
        for (name, expected) in S::NAMES[1..].iter().zip(rest) {
            assert_eq!(S::from_name(name, None).unwrap(), expected);
        }
    }

    #[test]
    fn conversation_setting_from_name_rejects_bad_input() {
        let err = |s: &str, ttl: Option<i64>| {
            ConversationSetting::from_name(s, ttl)
                .unwrap_err()
                .to_string()
        };
        assert!(err("message_duration", None).contains("ttl_msec is required"));
        assert!(err("mute", Some(1)).contains("ttl_msec only applies"));
        assert!(err("", None).contains("setting is empty: pass one of message_duration"));
        assert!(err("Mute", None).contains("unknown setting \"Mute\": pass one of"));
    }

    #[test]
    fn group_admin_action_from_parts_maps_each_name() {
        use GroupAdminAction as A;
        let ids = || Some(vec!["222".to_string()]);
        assert_eq!(
            A::from_parts("add_admins", ids(), None, None, None).unwrap(),
            A::AddAdmins {
                user_ids: vec!["222".into()]
            }
        );
        assert_eq!(
            A::from_parts("remove_admins", ids(), None, None, None).unwrap(),
            A::RemoveAdmins {
                user_ids: vec!["222".into()]
            }
        );
        assert_eq!(
            A::from_parts("remove_members", ids(), None, None, None).unwrap(),
            A::RemoveMembers {
                user_ids: vec!["222".into()]
            }
        );
        assert_eq!(
            A::from_parts("reject_join_requests", ids(), None, None, None).unwrap(),
            A::RejectJoinRequests {
                user_ids: vec!["222".into()]
            }
        );
        assert_eq!(
            A::from_parts(
                "enable_invite_link",
                None,
                Some("https://example.com/i/a".into()),
                Some(5),
                Some("aff".into())
            )
            .unwrap(),
            A::EnableInviteLink {
                invite_url: "https://example.com/i/a".into(),
                expires_at_msec: Some(5),
                affiliate_id: Some("aff".into()),
            }
        );
        assert_eq!(
            A::from_parts("disable_invite_link", None, None, None, None).unwrap(),
            A::DisableInviteLink
        );
    }

    #[test]
    fn group_admin_action_from_parts_rejects_mismatched_fields() {
        let err =
            |action: &str, ids: Option<Vec<String>>, url: Option<&str>, expires: Option<i64>| {
                GroupAdminAction::from_parts(action, ids, url.map(str::to_string), expires, None)
                    .unwrap_err()
                    .to_string()
            };
        let ids = || Some(vec!["222".to_string()]);
        assert!(err("add_admins", None, None, None).contains("user_ids is required"));
        assert!(err("remove_members", ids(), Some("u"), None).contains("only apply to"));
        assert!(err("enable_invite_link", None, None, Some(5)).contains("invite_url is required"));
        assert!(err("enable_invite_link", ids(), Some("u"), None).contains("does not apply"));
        assert!(err("disable_invite_link", ids(), None, None).contains("takes no other fields"));
        assert!(err("", None, None, None).contains("action is empty"));
        assert!(err("promote", None, None, None).contains("unknown action \"promote\""));
    }

    #[test]
    fn group_admin_change_params_new_plus_identity_equals_full_construction() {
        let via_new = GroupAdminChangeParams::new("g1", GroupAdminAction::DisableInviteLink)
            .with_identity("me", "2");
        let full = GroupAdminChangeParams {
            conversation_id: "g1".into(),
            action: GroupAdminAction::DisableInviteLink,
            sender_id: Some("me".into()),
            signing_key_version: Some("2".into()),
        };
        assert_eq!(via_new, full);
    }

    #[test]
    fn conversation_settings_params_new_plus_identity_equals_full_construction() {
        let via_new = ConversationSettingsParams::new("g1", ConversationSetting::Mute)
            .with_identity("me", "2");
        let full = ConversationSettingsParams {
            conversation_id: "g1".into(),
            setting: ConversationSetting::Mute,
            sender_id: Some("me".into()),
            signing_key_version: Some("2".into()),
        };
        assert_eq!(via_new, full);
    }

    #[test]
    fn group_create_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let public_keys = self_public_keys(&core);

        let mut via_new = GroupCreateParams::new(
            public_keys.clone(),
            "g123",
            vec!["me".into(), "friend".into()],
            vec!["me".into()],
        )
        .with_identity("me", "1");
        via_new.title = Some("Team".into());

        let full = GroupCreateParams {
            public_keys,
            conversation_id: "g123".into(),
            member_ids: vec!["me".into(), "friend".into()],
            admin_ids: vec!["me".into()],
            sender_id: Some("me".into()),
            signing_key_version: Some("1".into()),
            title: Some("Team".into()),
            avatar_url: None,
            ttl_msec: None,
        };
        assert_eq!(via_new, full);

        // Both constructions encode identical group-create event details for
        // the same conversation-key version (the detail is deterministic).
        let a = core
            .prepare_group_create_with_version(via_new, "42")
            .unwrap();
        let b = core.prepare_group_create_with_version(full, "42").unwrap();
        assert_eq!(
            a.action_signatures[1].encoded_message_event_detail,
            b.action_signatures[1].encoded_message_event_detail,
        );
    }
}
