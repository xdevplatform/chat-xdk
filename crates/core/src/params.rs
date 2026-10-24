//! Parameter structs for the SDK methods that encrypt, decrypt, and sign.
//!
//! Each struct pairs a [`new()`] constructor taking only the required fields
//! with public fields for the optional ones, so call sites name every value
//! they set and new optional protocol fields can be added without breaking
//! existing callers:
//!
//! ```rust,ignore
//! chat.set_identity(&SetIdentityParams::new("1876543210", signing_key_version))?;
//! let mut params = EncryptMessageParams::new(conversation_id, "Hello");
//! params.ttl_msec = Some(86_400_000);
//! // The SDK generates the message id; read it back from the result.
//! let payload = chat.encrypt_message(&params)?;
//! let message_id = payload.message_id;
//! ```
//!
//! A message with files is built before its files are encrypted: each file's
//! attachment names the media hash key its upload started with, and each
//! file is then encrypted with [`EncryptFileParams`] or
//! [`FileEncryptorParams`] from the returned payload's `event_b64`. Upload
//! each file for one message only: reusing another message's uploads can give
//! this message that message's id.
//!
//! Identity fields (`sender_id`, `signing_key_version`) and key fields
//! (`conversation_key`, `conversation_key_version`) are optional overrides:
//! when unset they resolve from the session identity and the opt-in key
//! cache. An unset override and an explicit value produce byte-identical
//! signed output for the same logical inputs.

use std::collections::HashMap;

use zeroize::Zeroize;

use crate::crypto::keys::XChatConversationKey;
use crate::types::{
    AttachmentDescriptor, EntityDescriptor, PublicKeyInput, QuickReply, ScreenCaptureChange,
    SigningKeyEntry,
};

/// Convert an override string into storage form: an empty string means
/// "not set", so FFI layers that cannot express `Option` can pass `""`.
fn non_empty(s: impl Into<String>) -> Option<String> {
    let s = s.into();
    (!s.is_empty()).then_some(s)
}

/// Parameters for [`crate::ChatCore::set_identity`].
#[derive(Clone, Debug)]
pub struct SetIdentityParams {
    /// Your user id: the sender of everything this chat signs.
    pub user_id: String,
    /// The `public_key_version` the X API returned when your keys were
    /// registered.
    pub signing_key_version: String,
}

impl SetIdentityParams {
    /// Create params with both fields.
    pub fn new(user_id: impl Into<String>, signing_key_version: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            signing_key_version: signing_key_version.into(),
        }
    }
}

/// Parameters for [`crate::ChatCore::import_keys`].
///
/// The key bytes are zeroized when the params are dropped and are redacted
/// from `Debug` output.
#[derive(Clone)]
pub struct ImportKeysParams {
    /// The key blob from `export_keys`: 32 bytes (the identity key) or 64
    /// (the identity and signing keys).
    pub keys: Vec<u8>,
    /// The `public_key_version` the X API returned when the keys were
    /// registered. When set, it becomes the signing-key version, as with
    /// `set_identity`; when unset, the chat has no signing-key version until
    /// `set_identity` sets one.
    pub signing_key_version: Option<String>,
}

impl ImportKeysParams {
    /// Create params with the key blob; `signing_key_version` defaults to
    /// `None`.
    pub fn new(keys: impl Into<Vec<u8>>) -> Self {
        Self {
            keys: keys.into(),
            signing_key_version: None,
        }
    }

    /// Set the registered `public_key_version` of the keys.
    pub fn with_signing_key_version(mut self, signing_key_version: impl Into<String>) -> Self {
        self.signing_key_version = non_empty(signing_key_version);
        self
    }
}

impl Drop for ImportKeysParams {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

impl std::fmt::Debug for ImportKeysParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeysParams")
            .field("keys", &"[REDACTED]")
            .field("signing_key_version", &self.signing_key_version)
            .finish()
    }
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
    /// Optional attachments: posts, links, and files (media, and link-card
    /// images), each file named by the media hash key its upload started
    /// with.
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
    /// The user ID of the message's sender, as digits (for the preview);
    /// derived from `reply_to_event` when unset.
    pub reply_to_sender_id: Option<String>,
    /// The text of the message being replied to (for preview); derived from
    /// `reply_to_event` when unset.
    pub reply_to_text: Option<String>,
    /// Optional rich-text entities (URLs, mentions, etc.) to embed in the outgoing message.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// Optional attachments of the outgoing message: posts, links, and files
    /// (media, and link-card images), each file named by the media hash key
    /// its upload started with.
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

/// Parameters for [`crate::ChatCore::prepare_mark_conversation_read`].
///
/// A read receipt is a signed plaintext event, not an encrypted message, so
/// no conversation key is involved: the result is an action signature the
/// caller submits alongside the mark-read request.
#[derive(Clone, Debug, PartialEq)]
pub struct MarkConversationReadParams {
    /// ID of the conversation being marked read.
    pub conversation_id: String,
    /// The `sequence_id` of the newest event read.
    pub seen_until_sequence_id: String,
    /// When the conversation was read, in milliseconds since the Unix epoch;
    /// the current time when unset.
    pub seen_at_msec: Option<i64>,
    /// User ID of the sender signing the read receipt; resolves from the
    /// session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the read receipt; resolves
    /// from the session identity when unset.
    pub signing_key_version: Option<String>,
}

impl MarkConversationReadParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(
        conversation_id: impl Into<String>,
        seen_until_sequence_id: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            seen_until_sequence_id: seen_until_sequence_id.into(),
            seen_at_msec: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_members_remove`].
///
/// `public_keys` are the identity keys of the members who stay. When they
/// are set, the call rotates the conversation key for those members and
/// returns the new key alongside the signatures. When they are absent, the
/// call signs only the removal. An empty list is the same as absent.
///
/// `conversation_key_version` is the version bound into the removal
/// signature when the call does not rotate. An empty string is absent, and
/// an absent version signs the literal `null`. A rotation ignores this
/// field and binds the new version instead.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupMembersRemoveParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User IDs being removed.
    pub user_ids: Vec<String>,
    /// Identity public keys of the members who remain. Set to rotate the
    /// conversation key in this same call.
    pub public_keys: Option<Vec<PublicKeyInput>>,
    /// Conversation-key version bound into the removal when not rotating.
    pub conversation_key_version: Option<String>,
    /// User ID of the sender signing the removal; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the removal; resolves from
    /// the session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupMembersRemoveParams {
    /// Create params with required fields; all optional fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, user_ids: Vec<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            user_ids,
            public_keys: None,
            conversation_key_version: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_leave`].
///
/// Leaving is a removal of the sender that does not rotate the conversation
/// key. The result then signs a group-admin add when `promote_admin_id`
/// names the member who becomes an admin, and a conversation delete.
///
/// `conversation_key_version` is bound into the removal signature. An empty
/// string is absent, and an absent version signs the literal `null`.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupLeaveParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User ID promoted to admin with this leave, when the sender is the
    /// only admin. The caller chooses whom to promote.
    pub promote_admin_id: Option<String>,
    /// Conversation-key version bound into the removal signature.
    pub conversation_key_version: Option<String>,
    /// User ID of the member leaving; resolves from the session identity
    /// when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the leave; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupLeaveParams {
    /// Create params for leaving `conversation_id`.
    pub fn new(conversation_id: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            promote_admin_id: None,
            conversation_key_version: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_title_change`].
///
/// `custom_title` is the title ciphertext the request sends, not plaintext.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupTitleChangeParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// Conversation-key version the title is encrypted under.
    pub conversation_key_version: String,
    /// Encrypted title, the value the request sends as the group name.
    pub custom_title: String,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupTitleChangeParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(
        conversation_id: impl Into<String>,
        conversation_key_version: impl Into<String>,
        custom_title: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            conversation_key_version: conversation_key_version.into(),
            custom_title: custom_title.into(),
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

/// Parameters for [`crate::ChatCore::prepare_group_avatar_change`].
///
/// `custom_avatar_url` is the avatar value the request sends.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupAvatarChangeParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// Conversation-key version the avatar is associated with.
    pub conversation_key_version: String,
    /// Avatar URL the request sends.
    pub custom_avatar_url: String,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupAvatarChangeParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(
        conversation_id: impl Into<String>,
        conversation_key_version: impl Into<String>,
        custom_avatar_url: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            conversation_key_version: conversation_key_version.into(),
            custom_avatar_url: custom_avatar_url.into(),
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

/// Parameters for [`crate::ChatCore::prepare_group_description_change`].
///
/// `custom_description` is the description ciphertext the request sends.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupDescriptionChangeParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// Conversation-key version the description is encrypted under.
    pub conversation_key_version: String,
    /// Encrypted description the request sends.
    pub custom_description: String,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupDescriptionChangeParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(
        conversation_id: impl Into<String>,
        conversation_key_version: impl Into<String>,
        custom_description: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            conversation_key_version: conversation_key_version.into(),
            custom_description: custom_description.into(),
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

/// Parameters for [`crate::ChatCore::prepare_group_admins_add`].
#[derive(Clone, Debug, PartialEq)]
pub struct GroupAdminsAddParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User IDs gaining admin.
    pub user_ids: Vec<String>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupAdminsAddParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, user_ids: Vec<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            user_ids,
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

/// Parameters for [`crate::ChatCore::prepare_group_admins_remove`].
#[derive(Clone, Debug, PartialEq)]
pub struct GroupAdminsRemoveParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User IDs losing admin.
    pub user_ids: Vec<String>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupAdminsRemoveParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, user_ids: Vec<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            user_ids,
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

/// Parameters for [`crate::ChatCore::prepare_group_invite_enable`].
///
/// An empty `affiliate_id` and a negative `expires_at_msec` are treated as
/// unset, and an unset value signs the literal `null`.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupInviteEnableParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// Invite URL the request enables.
    pub invite_url: String,
    /// When the invite expires, in milliseconds since the Unix epoch.
    pub expires_at_msec: Option<i64>,
    /// Affiliate id carried with the invite.
    pub affiliate_id: Option<String>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupInviteEnableParams {
    /// Create params with required fields; optional fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, invite_url: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            invite_url: invite_url.into(),
            expires_at_msec: None,
            affiliate_id: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_invite_disable`].
///
/// `disabled_by` defaults to the sender when unset or empty.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupInviteDisableParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User ID of the member disabling the invite. The sender when unset.
    pub disabled_by: Option<String>,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupInviteDisableParams {
    /// Create params for disabling the invite on `conversation_id`.
    pub fn new(conversation_id: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            disabled_by: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_join_request`].
///
/// `requesting_user_id` defaults to the sender when unset or empty. The
/// invite token a request carries is not part of the signature.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupJoinRequestParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User ID asking to join. The sender when unset.
    pub requesting_user_id: Option<String>,
    /// User ID of the sender signing the request; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the request; resolves from
    /// the session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupJoinRequestParams {
    /// Create params for a join request on `conversation_id`.
    pub fn new(conversation_id: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            requesting_user_id: None,
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

/// Parameters for [`crate::ChatCore::prepare_group_join_reject`].
#[derive(Clone, Debug, PartialEq)]
pub struct GroupJoinRejectParams {
    /// ID of the group conversation.
    pub conversation_id: String,
    /// User IDs whose join request is rejected.
    pub user_ids: Vec<String>,
    /// User ID of the sender signing the rejection; resolves from the
    /// session identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the rejection; resolves from
    /// the session identity when unset.
    pub signing_key_version: Option<String>,
}

impl GroupJoinRejectParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, user_ids: Vec<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            user_ids,
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

/// Parameters for [`crate::ChatCore::prepare_message_ttl_change`].
///
/// The signature covers `ttl_msec` only.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageTtlChangeParams {
    /// ID of the conversation whose message TTL is changing.
    pub conversation_id: String,
    /// New message TTL, in milliseconds.
    pub ttl_msec: i64,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl MessageTtlChangeParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, ttl_msec: i64) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            ttl_msec,
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

/// Parameters for [`crate::ChatCore::prepare_message_ttl_remove`].
#[derive(Clone, Debug, PartialEq)]
pub struct MessageTtlRemoveParams {
    /// ID of the conversation whose message TTL is being cleared.
    pub conversation_id: String,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl MessageTtlRemoveParams {
    /// Create params for clearing the TTL on `conversation_id`.
    pub fn new(conversation_id: impl Into<String>) -> Self {
        Self {
            conversation_id: conversation_id.into(),
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

/// Parameters for [`crate::ChatCore::prepare_screen_capture`].
#[derive(Clone, Debug, PartialEq)]
pub struct ScreenCaptureParams {
    /// ID of the conversation whose screen-capture setting is changing.
    pub conversation_id: String,
    /// The setting being signed.
    pub change: ScreenCaptureChange,
    /// User ID of the sender signing the change; resolves from the session
    /// identity when unset.
    pub sender_id: Option<String>,
    /// Version of the signing key used to sign the change; resolves from the
    /// session identity when unset.
    pub signing_key_version: Option<String>,
}

impl ScreenCaptureParams {
    /// Create params with required fields; identity fields default to `None`.
    pub fn new(conversation_id: impl Into<String>, change: ScreenCaptureChange) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            change,
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

/// Parameters for [`crate::ChatCore::decrypt_event`].
///
/// The conversation keys zeroize when the params are dropped and are
/// redacted from `Debug` output.
#[derive(Clone, Debug)]
pub struct DecryptEventParams {
    /// The base64 event, as delivered.
    pub event_b64: String,
    /// The conversation's key map (`key version → key`), from
    /// `decrypt_events` or `extract_conversation_keys`. Leave it empty for
    /// events without message contents, or to take the keys from the opt-in
    /// key cache.
    pub conversation_keys: HashMap<String, XChatConversationKey>,
    /// Signing keys to verify the event with; the keys stored via
    /// `set_signing_keys` are used when unset or empty.
    pub signing_keys: Option<Vec<SigningKeyEntry>>,
}

impl DecryptEventParams {
    /// Create params with required fields; `signing_keys` defaults to `None`.
    pub fn new(
        event_b64: impl Into<String>,
        conversation_keys: HashMap<String, XChatConversationKey>,
    ) -> Self {
        Self {
            event_b64: event_b64.into(),
            conversation_keys,
            signing_keys: None,
        }
    }

    /// Set the signing keys to verify the event with.
    pub fn with_signing_keys(mut self, signing_keys: Vec<SigningKeyEntry>) -> Self {
        self.signing_keys = Some(signing_keys);
        self
    }
}

/// Parameters for [`crate::ChatCore::decrypt_events`].
#[derive(Clone, Debug)]
pub struct DecryptEventsParams {
    /// The base64 events, as delivered. Their key changes supply the
    /// conversation keys the messages among them are decrypted with.
    pub events: Vec<String>,
    /// Signing keys to verify the events with; the keys stored via
    /// `set_signing_keys` are used when unset or empty.
    pub signing_keys: Option<Vec<SigningKeyEntry>>,
}

impl DecryptEventsParams {
    /// Create params with required fields; `signing_keys` defaults to `None`.
    pub fn new(events: Vec<String>) -> Self {
        Self {
            events,
            signing_keys: None,
        }
    }

    /// Set the signing keys to verify the events with.
    pub fn with_signing_keys(mut self, signing_keys: Vec<SigningKeyEntry>) -> Self {
        self.signing_keys = Some(signing_keys);
        self
    }
}

/// Parameters for [`crate::ChatCore::encrypt_file`].
///
/// The conversation key, like the one [`EncryptMessageParams`] takes, is
/// optional: set it with its version, or leave both unset to resolve them
/// from the opt-in key cache. It is zeroized when the params are dropped and,
/// with the file, redacted from `Debug` output.
#[derive(Clone)]
pub struct EncryptFileParams {
    /// The file to encrypt.
    pub file: Vec<u8>,
    /// The `event_b64` of the payload that `encrypt_message` or
    /// `encrypt_reply` returned for the message carrying the file.
    pub event_b64: String,
    /// The media hash key the file's upload started with, as listed in the
    /// message's attachments.
    pub media_hash_key: String,
    /// The raw 32-byte conversation key the message was encrypted under;
    /// resolves from the key cache when unset, together with
    /// `conversation_key_version`.
    pub conversation_key: Option<Vec<u8>>,
    /// The version of `conversation_key`: the message's key version.
    pub conversation_key_version: Option<String>,
}

impl EncryptFileParams {
    /// Create params with the required fields; the conversation key pair
    /// defaults to the key cache.
    pub fn new(
        file: Vec<u8>,
        event_b64: impl Into<String>,
        media_hash_key: impl Into<String>,
    ) -> Self {
        Self {
            file,
            event_b64: event_b64.into(),
            media_hash_key: media_hash_key.into(),
            conversation_key: None,
            conversation_key_version: None,
        }
    }

    /// Set the conversation key the message was encrypted under, and its
    /// version.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = non_empty(conversation_key_version);
        self
    }
}

impl Drop for EncryptFileParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for EncryptFileParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptFileParams")
            .field("file", &format_args!("[{} bytes]", self.file.len()))
            .field("event_b64", &self.event_b64)
            .field("media_hash_key", &self.media_hash_key)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::decrypt_file`].
///
/// The conversation keys zeroize when the params are dropped and are
/// redacted from `Debug` output.
#[derive(Clone)]
pub struct DecryptFileParams {
    /// The encrypted file, as downloaded.
    pub encrypted: Vec<u8>,
    /// The base64 event of the message that carries the file, as passed to
    /// `decrypt_event`.
    pub event_b64: String,
    /// The conversation's key map (`key version → key`), as passed to
    /// `decrypt_event`.
    pub conversation_keys: HashMap<String, XChatConversationKey>,
    /// The file's media hash key from the decrypted message: a media
    /// attachment, a link card's banner or favicon, or media quoted in its
    /// reply preview.
    pub media_hash_key: String,
}

impl DecryptFileParams {
    /// Create params; every field is required.
    pub fn new(
        encrypted: Vec<u8>,
        event_b64: impl Into<String>,
        conversation_keys: HashMap<String, XChatConversationKey>,
        media_hash_key: impl Into<String>,
    ) -> Self {
        Self {
            encrypted,
            event_b64: event_b64.into(),
            conversation_keys,
            media_hash_key: media_hash_key.into(),
        }
    }
}

impl std::fmt::Debug for DecryptFileParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptFileParams")
            .field(
                "encrypted",
                &format_args!("[{} bytes]", self.encrypted.len()),
            )
            .field("event_b64", &self.event_b64)
            .field("conversation_keys", &self.conversation_keys)
            .field("media_hash_key", &self.media_hash_key)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::file_encryptor`]: those of
/// [`EncryptFileParams`] apart from the file, which is fed to the encryptor.
///
/// The conversation key is zeroized when the params are dropped and is
/// redacted from `Debug` output.
#[derive(Clone)]
pub struct FileEncryptorParams {
    /// The `event_b64` of the payload that `encrypt_message` or
    /// `encrypt_reply` returned for the message carrying the file.
    pub event_b64: String,
    /// The media hash key the file's upload started with, as listed in the
    /// message's attachments.
    pub media_hash_key: String,
    /// The raw 32-byte conversation key the message was encrypted under;
    /// resolves from the key cache when unset, together with
    /// `conversation_key_version`.
    pub conversation_key: Option<Vec<u8>>,
    /// The version of `conversation_key`: the message's key version.
    pub conversation_key_version: Option<String>,
}

impl FileEncryptorParams {
    /// Create params with the required fields; the conversation key pair
    /// defaults to the key cache.
    pub fn new(event_b64: impl Into<String>, media_hash_key: impl Into<String>) -> Self {
        Self {
            event_b64: event_b64.into(),
            media_hash_key: media_hash_key.into(),
            conversation_key: None,
            conversation_key_version: None,
        }
    }

    /// Set the conversation key the message was encrypted under, and its
    /// version.
    pub fn with_conversation_key(
        mut self,
        conversation_key: Vec<u8>,
        conversation_key_version: impl Into<String>,
    ) -> Self {
        self.conversation_key = Some(conversation_key);
        self.conversation_key_version = non_empty(conversation_key_version);
        self
    }
}

impl Drop for FileEncryptorParams {
    fn drop(&mut self) {
        self.conversation_key.zeroize();
    }
}

impl std::fmt::Debug for FileEncryptorParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEncryptorParams")
            .field("event_b64", &self.event_b64)
            .field("media_hash_key", &self.media_hash_key)
            .field(
                "conversation_key",
                &self.conversation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("conversation_key_version", &self.conversation_key_version)
            .finish()
    }
}

/// Parameters for [`crate::ChatCore::file_decryptor`]: those of
/// [`DecryptFileParams`] apart from the encrypted file, which is fed to the
/// decryptor.
///
/// The conversation keys zeroize when the params are dropped and are
/// redacted from `Debug` output.
#[derive(Clone, Debug)]
pub struct FileDecryptorParams {
    /// The base64 event of the message that carries the file, as passed to
    /// `decrypt_event`.
    pub event_b64: String,
    /// The conversation's key map (`key version → key`), as passed to
    /// `decrypt_event`.
    pub conversation_keys: HashMap<String, XChatConversationKey>,
    /// The file's media hash key from the decrypted message: a media
    /// attachment, a link card's banner or favicon, or media quoted in its
    /// reply preview.
    pub media_hash_key: String,
}

impl FileDecryptorParams {
    /// Create params; every field is required.
    pub fn new(
        event_b64: impl Into<String>,
        conversation_keys: HashMap<String, XChatConversationKey>,
        media_hash_key: impl Into<String>,
    ) -> Self {
        Self {
            event_b64: event_b64.into(),
            conversation_keys,
            media_hash_key: media_hash_key.into(),
        }
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
            user_id: "910002".to_string(),
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
            .with_identity("1000", "2")
            .with_conversation_key(ckey.clone(), "1");
        via_new.should_notify = Some(false);
        via_new.ttl_msec = Some(30_000);

        let full = EncryptMessageParams {
            conversation_id: "conv-1".into(),
            text: "hi".into(),
            sender_id: Some("1000".into()),
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

        let payload = core.encrypt_message(&via_new).unwrap();
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
            .with_identity("1000", "2")
            .with_conversation_key(ckey, "1");
        params.reply_to_sequence_id = Some("seq-9".into());
        params.reply_to_sender_id = Some("42".to_string());
        params.reply_to_text = Some("original".into());

        let payload = core.encrypt_reply(&params).unwrap();
        assert!(
            payload.should_notify,
            "unset should_notify defaults to true"
        );
    }

    #[test]
    fn encrypt_reaction_params_explicit_fields_encrypt_add_and_remove() {
        let core = unlocked_core();
        let ckey = crate::crypto::key_factory::KeyFactory::generate_conversation_key()
            .unwrap()
            .to_bytes();

        let mut params = EncryptReactionParams::new("", "👍")
            .with_identity("1000", "2")
            .with_conversation_key(ckey, "1");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());

        // The same params value serves both the add and the remove.
        assert!(!core
            .encrypt_add_reaction(&params)
            .unwrap()
            .encoded_message_create_event
            .is_empty());
        assert!(!core
            .encrypt_remove_reaction(&params)
            .unwrap()
            .encoded_message_create_event
            .is_empty());
    }

    #[test]
    fn conversation_key_change_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let public_keys = self_public_keys(&core);

        let mut via_new = ConversationKeyChangeParams::new(public_keys.clone());
        via_new = via_new.with_identity("910002", "1");
        via_new.conversation_id = Some("conv-1".into());

        let full = ConversationKeyChangeParams {
            public_keys,
            sender_id: Some("910002".into()),
            signing_key_version: Some("1".into()),
            conversation_id: Some("conv-1".into()),
        };
        assert_eq!(via_new, full);

        let prepared = core.prepare_conversation_key_change(&via_new).unwrap();
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
            vec!["910006".into()],
            vec!["910002".into()],
            vec!["910002".into()],
            vec![],
        )
        .with_identity("910002", "1");
        via_new.current_title = Some("Team".into());

        let full = GroupMembersChangeParams {
            public_keys,
            conversation_id: "g123".into(),
            new_member_ids: vec!["910006".into()],
            current_member_ids: vec!["910002".into()],
            current_admin_ids: vec!["910002".into()],
            current_pending_member_ids: vec![],
            sender_id: Some("910002".into()),
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
            .prepare_group_members_change_with_version(&via_new, "42")
            .unwrap();
        let b = core
            .prepare_group_members_change_with_version(&full, "42")
            .unwrap();
        assert_eq!(
            a.action_signatures[1].encoded_message_event_detail,
            b.action_signatures[1].encoded_message_event_detail,
        );
    }

    #[test]
    fn group_create_params_new_plus_field_set_equals_full_construction() {
        let core = unlocked_core();
        let public_keys = self_public_keys(&core);

        let mut via_new = GroupCreateParams::new(
            public_keys.clone(),
            "g123",
            vec!["910002".into(), "910005".into()],
            vec!["910002".into()],
        )
        .with_identity("910002", "1");
        via_new.title = Some("Team".into());

        let full = GroupCreateParams {
            public_keys,
            conversation_id: "g123".into(),
            member_ids: vec!["910002".into(), "910005".into()],
            admin_ids: vec!["910002".into()],
            sender_id: Some("910002".into()),
            signing_key_version: Some("1".into()),
            title: Some("Team".into()),
            avatar_url: None,
            ttl_msec: None,
        };
        assert_eq!(via_new, full);

        // Both constructions encode identical group-create event details for
        // the same conversation-key version (the detail is deterministic).
        let a = core
            .prepare_group_create_with_version(&via_new, "42")
            .unwrap();
        let b = core.prepare_group_create_with_version(&full, "42").unwrap();
        assert_eq!(
            a.action_signatures[1].encoded_message_event_detail,
            b.action_signatures[1].encoded_message_event_detail,
        );
    }
}
