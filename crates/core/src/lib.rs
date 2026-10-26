//! # X Chat SDK
//!
//! Encryption library for X Chat.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use chat_xdk_core::{
//!     Chat, DecryptEventParams, DecryptEventsParams, EncryptFileParams, EncryptMessageParams,
//!     Event,
//! };
//!
//! // Create client
//! let chat = Chat::new(juicebox_config);
//!
//! // On startup: unlock keys and set the session identity once.
//! chat.unlock(b"2580").await?;
//! chat.set_identity(&SetIdentityParams::new("1876543210", signing_key_version))?;
//! chat.set_cache_keys(true);
//! chat.set_signing_keys(signing_keys);
//!
//! // Handle webhook events (signatures verify with the stored signing keys).
//! let result = chat.decrypt_events(DecryptEventsParams::new(events));
//! let keys = result.conversation_keys.keys.clone();
//! let event = chat.decrypt_event(DecryptEventParams::new(event_b64, keys.clone()))?;
//! match event {
//!     Event::Message(msg) => println!("{}", msg.text().unwrap_or("")),
//!     Event::KeyChange(kc) => { /* key cached automatically */ }
//!     _ => {}
//! }
//!
//! // Send messages. The SDK generates the message id and returns it in the
//! // payload (payload.message_id); sender, signing-key version, and the
//! // conversation key resolve from the session and cache.
//! let payload = chat.encrypt_message(&EncryptMessageParams::new("conv-1", "Hello!"))?;
//! // POST payload to X API
//!
//! // A message with a file: start the upload to get its media hash key, list
//! // it in the attachments, then encrypt the file from the payload's event
//! // (its conversation key resolves from the cache, as for the message).
//! let encrypted = chat.encrypt_file(&EncryptFileParams::new(
//!     photo,
//!     payload.event_b64.clone(),
//!     media_hash_key,
//! ))?;
//! ```
//!
//! ## Core API
//!
//! Most developers only need these:
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Chat::generate_keypairs`] | One-time: generate registration payload |
//! | [`Chat::setup`] | Register existing keys in Juicebox |
//! | [`Chat::unlock`] | Load keys on startup |
//! | [`Chat::decrypt_event`] | Decrypt webhook events → [`Event`] |
//! | [`Chat::encrypt_message`] | Encrypt text → [`SendPayload`] |
//! | [`Chat::encrypt_file`] | Encrypt a file for an outgoing message |
//! | [`Chat::decrypt_file`] | Decrypt a file from the message that carries it |
//!
//! ## Event Types
//!
//! The [`Event`] enum covers all X Chat event types:
//!
//! | Variant | Description |
//! |---------|-------------|
//! | [`Event::Message`] | Text, reaction, edit, or other content |
//! | [`Event::KeyChange`] | Conversation key rotated |
//! | [`Event::GroupChange`] | Group membership/settings changed |
//! | [`Event::MessageDeleted`] | Messages deleted |
//! | [`Event::Typing`] | Someone is typing |
//! | [`Event::ReadReceipt`] | Conversation marked read |
//! | [`Event::Failure`] | Message delivery failed |
//!
//! ## Advanced Usage
//!
//! For more control, import from the submodules:
//!
//! ```rust,ignore
//! use chat_xdk_core::crypto::encryption::{encrypt_message, decrypt_message};
//! use chat_xdk_core::crypto::key_factory::KeyFactory;
//! use chat_xdk_core::keys::juicebox::JuiceboxConfig;
//! ```
//!
//! ## What This SDK Does
//!
//! - **Key Generation**: EC P-256 identity and signing keypairs
//! - **Key Storage**: PIN-protected storage via Juicebox SDK (requires `juicebox` feature)
//! - **Encryption**: XSalsa20-Poly1305 for messages,
//!   `crypto_secretstream_xchacha20poly1305` for files, ECIES for
//!   conversation-key exchange
//! - **Signing**: ECDSA signatures
//! - **Protocol**: Thrift message parsing/serialization
//!
//! ## Send format
//!
//! Encrypted sends from this crate are always v0, the format 0.5.x sends.
//! The language bindings move sends to v1 (per-message keys) when the X API's
//! `v1_send` feature switch turns on, but this crate never fetches the
//! switches. It reads v1 sends like every binding.
//!
//! ## What This SDK Does NOT Do
//!
//! - HTTP communication (you handle API calls)
//! - Webhook server hosting
//! - Message persistence
//! - OAuth token management
//!
//! ## Security Limitations
//!
//! The underlying protocol provides **no forward secrecy and no
//! post-compromise security**: conversation keys are long-lived symmetric
//! keys encrypted under long-term identity public keys, with no ratcheting.
//! Compromise of an identity private key exposes all conversation keys ever
//! encrypted to that public key — and therefore all past and future messages
//! in those conversations. Key rotation does not retroactively protect
//! messages encrypted under a previous key. See the "Known Limitations"
//! section of `docs/CRYPTO.md` for details.
//!
//! ## Feature Flags
//!
//! - `juicebox` (default): Enables `Chat` struct with PIN-protected key storage via Juicebox SDK.
//!   Disable this for WASM builds and use crypto primitives directly.

mod chat;
mod core;
mod features;
mod params;
mod types;
pub mod utils;

/// Version of this SDK, carried in every [`SendPayload`] as `xdk_version`.
pub(crate) const XDK_VERSION: &str = env!("CARGO_PKG_VERSION");

// Hidden support for the in-repo vector generator and fuzz targets.
// Not part of the public API — feature-gated so the default surface
// doesn't expose it; see the module docs.
#[cfg(feature = "internals")]
#[doc(hidden)]
pub mod internals;

// Hidden support for this repository's language bindings, which fetch the
// feature switches internally. Not part of the public API: the feature only
// compiles in this repository's builds (see build.rs), so no dependent crate
// can drive the switches.
#[cfg(all(feature = "bindings", not(chat_xdk_bindings)))]
compile_error!("the `bindings` feature is internal to the chat-xdk repository's language bindings");

#[cfg(feature = "bindings")]
#[doc(hidden)]
pub mod bindings;

// Internal modules — not part of the public API.
// Users interact with ChatCore / Chat, not these directly.
pub(crate) mod pipeline;
pub(crate) mod protocol;
pub(crate) mod thrift;

// Signatures module is public because ActionSignature is part of the public
// API, and the free functions are useful for testing / advanced users.
pub mod signatures;

// Public modules — crypto primitives and key types are useful standalone.
pub mod crypto;
pub mod error;
pub mod keys;

// Public re-exports — the user-facing API.
#[cfg(feature = "juicebox")]
pub use chat::Chat;
pub use core::ChatCore;
pub use crypto::encryption::{FileDecryptor, FileEncryptor};
pub use params::{
    ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams, DecryptFileParams,
    EncryptEditParams, EncryptFileParams, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, FileDecryptorParams, FileEncryptorParams, GroupAdminsAddParams,
    GroupAdminsRemoveParams, GroupAvatarChangeParams, GroupCreateParams,
    GroupDescriptionChangeParams, GroupInviteDisableParams, GroupInviteEnableParams,
    GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams, GroupMembersChangeParams,
    GroupMembersRemoveParams, GroupTitleChangeParams, ImportKeysParams, MarkConversationReadParams,
    MessageDeleteParams, MessageTtlChangeParams, MessageTtlRemoveParams, ScreenCaptureParams,
    SetIdentityParams,
};
pub use types::*;

// Re-export generated JS types when the js feature is enabled.
// These are camelCase wrappers for WASM builds.
// The derive macro JsCamelCase generates Js* types alongside each annotated type.
#[cfg(feature = "js")]
pub mod js {
    pub use crate::signatures::{JsActionSignature, JsMessageEventSignature};
    pub use crate::types::{
        JsAttachmentInfo,
        JsConversationDeletedEvent,
        JsConversationKeyResult,
        JsConversationParticipantKey,
        JsDecryptEventsResult,
        JsDecryptedMessage,
        // Event hierarchy
        JsEvent,
        // Supporting types
        JsEventMeta,
        JsFailureEvent,
        JsFailureType,
        JsGroupChange,
        JsGroupChangeEvent,
        JsKeyChangeEvent,
        JsMarkedUnreadEvent,
        JsMediaAttachmentInfo,
        JsMediaDimensionsInfo,
        JsMediaHashReference,
        JsMemberDeletedEvent,
        JsMessage,
        JsMessageContent,
        JsMessageDeletedEvent,
        JsMoneyAttachmentInfo,
        JsPostAttachmentInfo,
        JsPreparedAction,
        JsPreparedConversationChange,
        JsPublicKeyInput,
        JsPublicKeyRegistration,
        JsPublicKeyRegistrationPayload,
        JsQuickReply,
        JsRateLimitTier,
        JsReadReceiptEvent,
        JsReplyPreviewValidation,
        // Send/receive types
        JsScreenCaptureChange,
        JsSendPayload,
        JsSettingsChange,
        JsSettingsChangeEvent,
        JsSignatureInfo,
        JsSigningKeyEntry,
        JsTypingEvent,
        JsUnifiedCardAttachmentInfo,
        JsUnknownEvent,
        JsUrlAttachmentInfo,
    };
}

/// Convenient imports for power users.
///
/// ```rust,ignore
/// use chat_xdk_core::prelude::*;
/// ```
pub mod prelude {
    // Main API (requires juicebox feature)
    #[cfg(feature = "juicebox")]
    pub use crate::chat::Chat;

    pub use crate::params::{
        ConversationKeyChangeParams, EncryptEditParams, EncryptMessageParams,
        EncryptReactionParams, EncryptReplyParams, GroupAdminsAddParams, GroupAdminsRemoveParams,
        GroupAvatarChangeParams, GroupCreateParams, GroupDescriptionChangeParams,
        GroupInviteDisableParams, GroupInviteEnableParams, GroupJoinRejectParams,
        GroupJoinRequestParams, GroupLeaveParams, GroupMembersChangeParams,
        GroupMembersRemoveParams, GroupTitleChangeParams, ImportKeysParams,
        MarkConversationReadParams, MessageDeleteParams, MessageTtlChangeParams,
        MessageTtlRemoveParams, ScreenCaptureParams, SetIdentityParams,
    };

    // Types (always available)
    pub use crate::types::*;

    // Crypto primitives (always available)
    pub use crate::crypto::{
        encryption::{decrypt_message, encrypt_message},
        hash::{hkdf, sha256},
        key_factory::KeyFactory,
        keys::{
            KeypairPurpose, XChatConversationKey, XChatKeyPair, XChatPrivateKey, XChatPublicKey,
        },
    };

    // Errors
    pub use crate::error::{CryptoError, SdkError, SdkResult};

    // Juicebox types (always available for configuration)
    pub use crate::keys::juicebox::JuiceboxConfig;

    // Juicebox SDK types (requires juicebox feature)
    #[cfg(feature = "juicebox")]
    pub use crate::keys::juicebox::{JuiceboxApi, JuiceboxClient};
}
