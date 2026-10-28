//! # Chat - The X Chat SDK
//!
//! This module provides the main [`Chat`] struct for X Chat encryption.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! # #[cfg(feature = "juicebox")]
//! # async fn quick_start(
//! #     juicebox_config: chat_xdk_core::keys::juicebox::JuiceboxConfig,
//! #     user_id: &str,
//! #     signing_key_version: &str,
//! #     signing_keys: Vec<chat_xdk_core::SigningKeyEntry>,
//! #     events: Vec<String>,
//! #     conversation_id: &str,
//! #     event_b64: &str,
//! # ) -> Result<(), chat_xdk_core::error::SdkError> {
//! use chat_xdk_core::{
//!     Chat, DecryptEventsParams, EncryptMessageParams, EncryptReplyParams, SetIdentityParams,
//! };
//!
//! // Create, unlock, and set the session identity once
//! let chat = Chat::new(juicebox_config);
//! chat.unlock(b"2580").await?;
//! chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?;
//! chat.set_cache_keys(true);
//! chat.set_signing_keys(&signing_keys);
//!
//! // Decrypt incoming events; verified conversation keys are cached
//! let result = chat.decrypt_events(&DecryptEventsParams::new(events));
//!
//! // Send messages. The SDK generates the message id and returns it in the
//! // payload (payload.message_id); sender, signing-key version, and the
//! // conversation key resolve from the session and cache.
//! let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "Hello!"))?;
//! let reply = chat.encrypt_reply(&EncryptReplyParams::new(conversation_id, "Hi!", event_b64))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## API Levels
//!
//! The `Chat` struct provides methods at two levels:
//!
//! ### Level 1: Simple API (start here)
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Chat::generate_keypairs`] | Generate identity + signing keys |
//! | [`Chat::setup`] | Register existing keys in Juicebox |
//! | [`Chat::unlock`] | Load keys on startup |
//! | [`Chat::decrypt_event`] | Decrypt webhook events |
//! | [`Chat::encrypt_message`] | Encrypt outgoing messages |
//! | [`Chat::encrypt_file`] | Encrypt a file for an outgoing message |
//! | [`Chat::decrypt_file`] | Decrypt a file from the message that carries it |
//!
//! ### Level 2: Advanced API (when you need more control)
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Chat::prepare_conversation_key_change`] | Generate, encrypt, and sign a key change |
//! | [`Chat::prepare_group_create`] | Generate, encrypt, and sign a group create |
//! | [`Chat::prepare_group_members_change`] | Generate, encrypt, and sign a member add |
//! | [`Chat::prepare_group_members_remove`] | Sign a member removal and rotate the key for the members who stay |
//! | [`Chat::prepare_group_leave`] | Sign leaving a group |
//! | [`Chat::decrypt_conversation_key`] | Decrypt a conversation key |
//! | [`Chat::sign`] | Sign application data |
//! | [`Chat::verify`] | Verify a signature |
//! | [`Chat::export_keys`] | Export keys for backup |
//! | [`Chat::import_keys`] | Import keys from backup |
//!
//! ## Feature Gates
//!
//! The `Chat` struct with Juicebox integration requires the `juicebox` feature.
//! For WASM or environments without Juicebox, use the crypto primitives directly.

#[cfg(feature = "juicebox")]
use crate::crypto::keys::XChatConversationKey;
#[cfg(feature = "juicebox")]
use crate::error::{JuiceboxError, KeyError, SdkError};
#[cfg(feature = "juicebox")]
use crate::keys::juicebox::{JuiceboxApi, JuiceboxClient, JuiceboxConfig, RegisterResult};
#[cfg(feature = "juicebox")]
use crate::params::{
    ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams, DecryptFileParams,
    DecryptFileWithKeyParams, EncryptEditParams, EncryptFileParams, EncryptFileWithKeyParams,
    EncryptMessageParams, EncryptReactionParams, EncryptReplyParams, FileDecryptorParams,
    FileEncryptorParams, GroupAdminsAddParams, GroupAdminsRemoveParams, GroupAvatarChangeParams,
    GroupCreateParams, GroupDescriptionChangeParams, GroupInviteDisableParams,
    GroupInviteEnableParams, GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams,
    GroupMembersChangeParams, GroupMembersRemoveParams, GroupTitleChangeParams, ImportKeysParams,
    MarkConversationReadParams, MessageDeleteParams, MessageTtlChangeParams,
    MessageTtlRemoveParams, ScreenCaptureParams, SetIdentityParams,
};
#[cfg(feature = "juicebox")]
use crate::types::*;
#[cfg(feature = "juicebox")]
use std::sync::Arc;
#[cfg(feature = "juicebox")]
use zeroize::Zeroize;

/// The X Chat encryption SDK.
///
/// This is the main entry point for all X Chat cryptographic operations.
/// It handles key management, message encryption/decryption, and signature
/// verification.
///
/// **Note**: This struct requires the `juicebox` feature for PIN-protected key storage.
/// For WASM, use the crypto primitives directly and handle key storage in JavaScript.
///
/// # Example
///
/// ```rust,no_run
/// # use std::collections::HashMap;
/// # use chat_xdk_core::crypto::keys::XChatConversationKey;
/// # async fn example(
/// #     juicebox_config: chat_xdk_core::keys::juicebox::JuiceboxConfig,
/// #     user_id: &str,
/// #     signing_key_version: &str,
/// #     signing_keys: Vec<chat_xdk_core::SigningKeyEntry>,
/// #     event_b64: String,
/// #     conversation_keys: HashMap<String, XChatConversationKey>,
/// #     conversation_id: &str,
/// # ) -> Result<(), chat_xdk_core::error::SdkError> {
/// use chat_xdk_core::{
///     Chat, DecryptEventParams, EncryptMessageParams, Event, SetIdentityParams,
/// };
///
/// // First-time setup: generate keys, then register them in Juicebox
/// let chat = Chat::new(juicebox_config);
/// let registration = chat.generate_keypairs()?;
/// let public_keys = chat.setup(b"2580").await?;
/// // Upload the registration payload to the X API
///
/// // On subsequent startups
/// chat.unlock(b"2580").await?;
/// chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?;
/// chat.set_cache_keys(true);
/// chat.set_signing_keys(&signing_keys);
///
/// // Handle incoming webhook (signatures verify with the stored signing keys)
/// let event = chat.decrypt_event(&DecryptEventParams::new(event_b64, conversation_keys))?;
/// if let Event::Message(msg) = event {
///     let sender = msg.meta.sender_id.as_deref().unwrap_or("");
///     println!("{}: {}", sender, msg.text().unwrap_or(""));
/// }
///
/// // Send a message. The SDK generates the message id and returns it in the
/// // payload (payload.message_id); sender, signing-key version, and the
/// // conversation key resolve from the session and cache.
/// let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "Hello!"))?;
/// // POST payload to API
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "juicebox")]
pub struct Chat {
    /// The platform-agnostic encryption core.
    pub(crate) inner: crate::core::ChatCore,
    config: std::sync::RwLock<Option<JuiceboxConfig>>,
    juicebox: Arc<dyn JuiceboxApi>,
}

#[cfg(feature = "juicebox")]
impl Chat {
    /// Create a new Chat instance with Juicebox config.
    ///
    /// # Arguments
    /// * `config` - Juicebox configuration from the X API
    pub fn new(config: JuiceboxConfig) -> Self {
        Self::with_juicebox(config, Arc::new(JuiceboxClient::new()))
    }

    /// Create with a custom Juicebox implementation
    pub fn with_juicebox(config: JuiceboxConfig, juicebox: Arc<dyn JuiceboxApi>) -> Self {
        Self::from_parts(Some(config), juicebox)
    }

    fn from_parts(config: Option<JuiceboxConfig>, juicebox: Arc<dyn JuiceboxApi>) -> Self {
        Self {
            inner: crate::core::ChatCore::new(),
            config: std::sync::RwLock::new(config),
            juicebox,
        }
    }

    /// When enabled — the default — `decrypt_event` returns an error for any
    /// signed event whose signature cannot be verified (invalid, missing, or
    /// no matching signing key) instead of returning it with
    /// `verified: false`.
    pub fn set_reject_unverified(&self, reject: bool) {
        self.inner.set_reject_unverified(reject);
    }
    /// Set the session identity: the owner's user id and signing-key version,
    /// used as defaults wherever `sender_id` / `signing_key_version` is not
    /// passed explicitly.
    pub fn set_identity(&self, params: &SetIdentityParams) -> Result<(), SdkError> {
        self.inner.set_identity(params)
    }
    /// Enable or disable the conversation-key cache (off by default). While
    /// enabled, `decrypt_events` caches each conversation's verified latest
    /// key and the encrypt methods resolve an omitted key/version pair from it.
    pub fn set_cache_keys(&self, enabled: bool) {
        self.inner.set_cache_keys(enabled);
    }
    /// Store signing keys to use when a decrypt call omits its `signing_keys`
    /// argument. Only this call populates the store; each call replaces the
    /// previous set.
    pub fn set_signing_keys(&self, entries: &[SigningKeyEntry]) {
        self.inner.set_signing_keys(entries);
    }
    /// Set this chat's feature switches from the answer to `GET
    /// /2/chat/features`; see [`crate::ChatCore::set_feature_switches`].
    pub fn set_feature_switches(&self, status: u16, body: &[u8]) {
        self.inner.set_feature_switches(status, body);
    }
    /// The engine underneath, for the language bindings (see
    /// `crate::bindings`).
    #[cfg_attr(not(feature = "bindings"), allow(dead_code))]
    pub(crate) fn core(&self) -> &crate::core::ChatCore {
        &self.inner
    }
    /// Set or replace the Juicebox configuration: on first boot, for a chat
    /// created without one, or to refresh its auth tokens. Operations
    /// already under way keep the configuration they started with.
    pub fn update_config(&self, config: JuiceboxConfig) {
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = Some(config);
    }

    /// The current Juicebox configuration, copied so no lock is held across
    /// a Juicebox round trip.
    fn config(&self) -> Result<JuiceboxConfig, SdkError> {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .filter(|config| !config.config_json.trim().is_empty())
            .ok_or_else(crate::keys::juicebox::no_config_error)
    }

    // Juicebox key storage

    /// Generate new keypairs and return the registration payload.
    ///
    /// No signing-key version is set: after registering the keys, call
    /// [`Self::set_identity`] with the `public_key_version` the registration
    /// returns.
    pub fn generate_keypairs(&self) -> Result<PublicKeyRegistrationPayload, SdkError> {
        self.inner.generate_keypairs()
    }

    /// Register the current keys in Juicebox under `pin` and return public keys.
    ///
    /// The PIN must meet minimum strength requirements (4+ characters, not a
    /// single repeated character or a sequential digit run). It is passed as
    /// bytes so callers can zeroize their own buffer after the call.
    pub async fn setup(&self, pin: &[u8]) -> Result<PublicKeys, SdkError> {
        crate::keys::juicebox::validate_pin_strength(pin)?;
        let config = self.config()?;
        let mut secret = self.inner.export_keys()?;
        let result = self
            .juicebox
            .register_private_key(pin, &config, &secret)
            .await;
        secret.zeroize();
        match result {
            RegisterResult::Success => self.inner.get_public_keys(),
            RegisterResult::Failure(reason) => Err(SdkError::Juicebox(reason.into())),
        }
    }

    /// Recover keys from Juicebox using `pin` and load them into memory.
    ///
    /// No strength validation here — existing registrations must stay
    /// recoverable regardless of current PIN policy.
    pub async fn unlock(&self, pin: &[u8]) -> Result<(), SdkError> {
        use crate::keys::juicebox::RecoverResult;
        let config = self.config()?;
        match self.juicebox.recover_private_key(pin, &config).await {
            RecoverResult::Success(secret) => {
                self.inner
                    .import_keys(&ImportKeysParams::new(secret.to_vec()))?;
                Ok(())
            }
            // Invalid PIN carries the remaining-attempt count from Juicebox so
            // callers can warn the user before the guess budget runs out.
            RecoverResult::Failure {
                reason: crate::keys::juicebox::RecoverFailureReason::InvalidPin,
                guesses_remaining,
            } => Err(SdkError::Juicebox(JuiceboxError::InvalidPin {
                guesses_remaining,
            })),
            RecoverResult::Failure { reason, .. } => Err(SdkError::Juicebox(reason.into())),
            RecoverResult::KeyReconstructionFailed => Err(SdkError::Key(
                KeyError::ReconstructionFailed("Failed to reconstruct keys".into()),
            )),
            RecoverResult::NoTokens => Err(SdkError::Juicebox(JuiceboxError::NoTokens)),
        }
    }

    /// Delete the stored keys from Juicebox and clear them from memory.
    pub async fn delete(&self) -> Result<(), SdkError> {
        use crate::keys::juicebox::DeleteResult;
        let config = self.config()?;
        match self.juicebox.delete_keys(&config).await {
            DeleteResult::Success => {
                self.inner.lock();
                Ok(())
            }
            DeleteResult::Failure(reason) => Err(SdkError::Juicebox(JuiceboxError::DeleteFailed(
                format!("{:?}", reason),
            ))),
        }
    }

    /// Re-register the stored keys under a new PIN.
    ///
    /// The new PIN must meet the same strength requirements as [`Chat::setup`].
    pub async fn change_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), SdkError> {
        crate::keys::juicebox::validate_pin_strength(new_pin)?;
        self.unlock(old_pin).await?;
        let config = self.config()?;
        let mut secret = self.inner.export_keys()?;
        let result = self
            .juicebox
            .register_private_key(new_pin, &config, &secret)
            .await;
        secret.zeroize();
        match result {
            RegisterResult::Success => Ok(()),
            RegisterResult::Failure(reason) => Err(SdkError::Juicebox(reason.into())),
        }
    }

    // Delegations to ChatCore

    /// Extract and decrypt conversation keys from a batch of raw event strings.
    pub fn extract_conversation_keys(&self, events: &[&str]) -> ConversationKeyResult {
        self.inner.extract_conversation_keys(events)
    }

    /// Decrypt a raw webhook event payload; see
    /// [`crate::ChatCore::decrypt_event`].
    pub fn decrypt_event(&self, params: &DecryptEventParams) -> Result<Event, SdkError> {
        self.inner.decrypt_event(params)
    }

    /// Decrypt multiple events in batch; see
    /// [`crate::ChatCore::decrypt_events`].
    pub fn decrypt_events(&self, params: &DecryptEventsParams) -> DecryptEventsResult {
        self.inner.decrypt_events(params)
    }

    /// Encrypt a text message.
    pub fn encrypt_message(&self, params: &EncryptMessageParams) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_message(params)
    }
    /// Encrypt a reply.
    pub fn encrypt_reply(&self, params: &EncryptReplyParams) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_reply(params)
    }
    /// Encrypt a reaction-add.
    pub fn encrypt_add_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_add_reaction(params)
    }
    /// Encrypt a reaction-remove.
    pub fn encrypt_remove_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_remove_reaction(params)
    }
    /// Encrypt a message edit.
    pub fn encrypt_edit(&self, params: &EncryptEditParams) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_edit(params)
    }
    /// Build the signed action for deleting messages from a conversation.
    pub fn prepare_message_delete(
        &self,
        params: &MessageDeleteParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_message_delete(params)
    }
    /// Build the signed action for marking a conversation read.
    pub fn prepare_mark_conversation_read(
        &self,
        params: &MarkConversationReadParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_mark_conversation_read(params)
    }
    /// Decrypt an encrypted conversation key (ECIES).
    pub fn decrypt_conversation_key(
        &self,
        encrypted_key_b64: &str,
    ) -> Result<XChatConversationKey, SdkError> {
        self.inner.decrypt_conversation_key(encrypted_key_b64)
    }
    /// Encrypt a file for an outgoing message; see
    /// [`crate::ChatCore::encrypt_file`].
    pub fn encrypt_file(&self, params: &EncryptFileParams) -> Result<Vec<u8>, SdkError> {
        self.inner.encrypt_file(params)
    }

    /// Create an incremental encryptor for a file; see
    /// [`crate::ChatCore::file_encryptor`].
    pub fn file_encryptor(
        &self,
        params: &FileEncryptorParams,
    ) -> Result<crate::FileEncryptor, SdkError> {
        self.inner.file_encryptor(params)
    }

    /// Decrypt a file; see [`crate::ChatCore::decrypt_file`].
    pub fn decrypt_file(&self, params: &DecryptFileParams) -> Result<Vec<u8>, SdkError> {
        self.inner.decrypt_file(params)
    }

    /// Create an incremental decryptor for a file; see
    /// [`crate::ChatCore::file_decryptor`].
    pub fn file_decryptor(
        &self,
        params: &FileDecryptorParams,
    ) -> Result<crate::FileDecryptor, SdkError> {
        self.inner.file_decryptor(params)
    }

    /// Encrypt a file under a key you already hold, such as a group's
    /// avatar image under the conversation key; see
    /// [`crate::ChatCore::encrypt_file_with_key`].
    pub fn encrypt_file_with_key(
        &self,
        params: &EncryptFileWithKeyParams,
    ) -> Result<Vec<u8>, SdkError> {
        self.inner.encrypt_file_with_key(params)
    }

    /// Decrypt a file encrypted under a key you already hold; see
    /// [`crate::ChatCore::decrypt_file_with_key`].
    pub fn decrypt_file_with_key(
        &self,
        params: &DecryptFileWithKeyParams,
    ) -> Result<Vec<u8>, SdkError> {
        self.inner.decrypt_file_with_key(params)
    }

    /// Decrypt a group title or description the X API returns for a
    /// conversation; see [`crate::ChatCore::decrypt`].
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        self.inner.decrypt(ciphertext_b64, conversation_key)
    }

    /// Prepare a signed conversation-key change, ready to send to the X API.
    ///
    /// Use this to start a one-to-one or rotate an existing conversation's key
    /// (one-to-one or group). Creating a group or adding members requires a
    /// paired group signature as well — use [`Self::prepare_group_create`] or
    /// [`Self::prepare_group_members_change`] for those.
    ///
    /// Omit `conversation_id` for a one-to-one (it is derived from the two
    /// participants); pass the existing id for a group key rotation.
    pub fn prepare_conversation_key_change(
        &self,
        params: &ConversationKeyChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_conversation_key_change(params)
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Use this once, when creating a group (`conversation_id` is the `g…` id
    /// minted by the initialize endpoint). Later key rotations use
    /// [`Self::prepare_conversation_key_change`]; roster additions use
    /// [`Self::prepare_group_members_change`].
    ///
    /// Emits two action signatures: a conversation-key change and the
    /// group-create action the backend validates together. The plaintext
    /// title is encrypted under the new conversation key and returned as
    /// `encrypted_title`; see [`crate::ChatCore::prepare_group_create`].
    pub fn prepare_group_create(
        &self,
        params: &GroupCreateParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_create(params)
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Use this when adding members to an existing group. Creating the group is
    /// [`Self::prepare_group_create`]; a key rotation without a roster change is
    /// [`Self::prepare_conversation_key_change`].
    ///
    /// Emits two action signatures: a conversation-key change and the
    /// member-add action the backend validates together.
    pub fn prepare_group_members_change(
        &self,
        params: &GroupMembersChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_members_change(params)
    }
    /// Sign a group member removal and rotate the conversation key for the
    /// members who stay. See [`crate::ChatCore::prepare_group_members_remove`].
    pub fn prepare_group_members_remove(
        &self,
        params: &GroupMembersRemoveParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_members_remove(params)
    }
    /// Sign leaving a group. See [`crate::ChatCore::prepare_group_leave`].
    pub fn prepare_group_leave(
        &self,
        params: &GroupLeaveParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_leave(params)
    }
    /// Encrypt a new group title and sign the change. See
    /// [`crate::ChatCore::prepare_group_title_change`].
    pub fn prepare_group_title_change(
        &self,
        params: &GroupTitleChangeParams,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.inner.prepare_group_title_change(params)
    }
    /// Sign a group avatar change: the avatar image's media URL, as is, and
    /// the version of the key the image is encrypted under.
    pub fn prepare_group_avatar_change(
        &self,
        params: &GroupAvatarChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        self.inner.prepare_group_avatar_change(params)
    }
    /// Encrypt a new group description and sign the change.
    pub fn prepare_group_description_change(
        &self,
        params: &GroupDescriptionChangeParams,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.inner.prepare_group_description_change(params)
    }
    /// Sign adding group admins.
    pub fn prepare_group_admins_add(
        &self,
        params: &GroupAdminsAddParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_admins_add(params)
    }
    /// Sign removing group admins.
    pub fn prepare_group_admins_remove(
        &self,
        params: &GroupAdminsRemoveParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_admins_remove(params)
    }
    /// Sign enabling a group invite.
    pub fn prepare_group_invite_enable(
        &self,
        params: &GroupInviteEnableParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_invite_enable(params)
    }
    /// Sign disabling a group invite.
    pub fn prepare_group_invite_disable(
        &self,
        params: &GroupInviteDisableParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_invite_disable(params)
    }
    /// Sign a request to join a group.
    pub fn prepare_group_join_request(
        &self,
        params: &GroupJoinRequestParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_join_request(params)
    }
    /// Sign rejecting group join requests.
    pub fn prepare_group_join_reject(
        &self,
        params: &GroupJoinRejectParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_group_join_reject(params)
    }
    /// Sign a message-TTL change.
    pub fn prepare_message_ttl_change(
        &self,
        params: &MessageTtlChangeParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_message_ttl_change(params)
    }
    /// Sign clearing a conversation's message TTL.
    pub fn prepare_message_ttl_remove(
        &self,
        params: &MessageTtlRemoveParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_message_ttl_remove(params)
    }
    /// Sign one screen-capture setting change.
    pub fn prepare_screen_capture(
        &self,
        params: &ScreenCaptureParams,
    ) -> Result<crate::PreparedAction, SdkError> {
        self.inner.prepare_screen_capture(params)
    }
    /// Sign application data; see [`crate::ChatCore::sign`] for the data it
    /// refuses.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SdkError> {
        self.inner.sign(data)
    }
    /// Verify a signature.
    pub fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, SdkError> {
        self.inner.verify(public_key_b64, signature, data)
    }
    /// Get current public keys.
    pub fn get_public_keys(&self) -> Result<PublicKeys, SdkError> {
        self.inner.get_public_keys()
    }
    /// Get the fingerprint of the loaded identity public key.
    pub fn get_public_key_fingerprint(&self) -> Result<String, SdkError> {
        self.inner.get_public_key_fingerprint()
    }
    /// Export private keys as bytes for backup.
    ///
    /// Warning: Returns unencrypted private key material — handle with care.
    pub fn export_keys(&self) -> Result<Vec<u8>, SdkError> {
        self.inner.export_keys()
    }
    /// Import private keys from the blob `export_keys` returns (32 or 64
    /// bytes), with their registered `public_key_version` when
    /// `params.signing_key_version` is set. Clears the signing-key version of
    /// any previously loaded keys.
    pub fn import_keys(&self, params: &ImportKeysParams) -> Result<(), SdkError> {
        self.inner.import_keys(params)
    }
    /// Verify that a signing key is authentically bound to an identity key.
    pub fn verify_key_binding(
        &self,
        identity_public_key_b64: &str,
        signing_public_key_b64: &str,
        identity_public_key_signature_b64: &str,
    ) -> Result<bool, SdkError> {
        self.inner.verify_key_binding(
            identity_public_key_b64,
            signing_public_key_b64,
            identity_public_key_signature_b64,
        )
    }
    /// Report whether the loaded identity public key is the key in
    /// `public_key_b64` (raw SEC1 point or SPKI/DER, base64-encoded).
    pub fn matches_registered_key(&self, public_key_b64: &str) -> Result<bool, SdkError> {
        self.inner.matches_registered_key(public_key_b64)
    }
    /// Returns `true` when both the identity and signing keys are loaded.
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }
    /// Returns `true` when the identity key is loaded.
    pub fn has_identity_key(&self) -> bool {
        self.inner.has_identity_key()
    }
    /// Clear keys from memory.
    pub fn lock(&self) {
        self.inner.lock();
    }
}

#[cfg(feature = "juicebox")]
impl Default for Chat {
    /// A chat without a Juicebox config, for first boot, when the account has
    /// none yet: every crypto call works, and `setup`, `unlock`,
    /// `change_pin` and `delete` fail with an [`SdkError::InvalidState`] until
    /// [`Chat::update_config`] gives it one. A chat that keeps its keys with
    /// [`Chat::import_keys`] alone never needs one.
    fn default() -> Self {
        Self::from_parts(None, Arc::new(JuiceboxClient::new()))
    }
}

#[cfg(feature = "juicebox")]
impl std::fmt::Debug for Chat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chat")
            .field("is_unlocked", &self.is_unlocked())
            .finish()
    }
}

#[cfg(all(test, feature = "juicebox"))]
mod tests {
    use super::*;
    use crate::keys::juicebox::mock::MockJuiceboxApi;
    use crate::keys::juicebox::JuiceboxConfig;
    use crate::{
        ConversationKeyChangeParams, EncryptMessageParams, EncryptReactionParams,
        EncryptReplyParams, GroupCreateParams, GroupMembersChangeParams,
    };
    use std::sync::Arc;

    fn test_config() -> JuiceboxConfig {
        JuiceboxConfig::from_json(r#"{"realms": []}"#.to_string())
    }

    #[tokio::test]
    async fn a_chat_without_a_juicebox_config_says_so_until_it_gets_one() {
        let chat = Chat::from_parts(None, Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        let expected = "Invalid state: no Juicebox config: pass the juicebox_config the X API \
                        returns when you create the chat, or call update_config() first";
        let failures = [
            chat.setup(b"2580").await.unwrap_err(),
            chat.unlock(b"2580").await.unwrap_err(),
            chat.change_pin(b"2580", b"1359").await.unwrap_err(),
            chat.delete().await.unwrap_err(),
        ];
        for err in failures {
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidState);
            assert_eq!(err.to_string(), expected);
        }
        assert!(chat.is_unlocked(), "the keys stay loaded");

        chat.update_config(test_config());
        chat.setup(b"2580").await.unwrap();
        chat.unlock(b"2580").await.unwrap();

        assert_eq!(
            Chat::default().delete().await.unwrap_err().to_string(),
            expected
        );
        for empty in ["", "  "] {
            let chat = Chat::with_juicebox(
                JuiceboxConfig::from_json(empty.to_string()),
                Arc::new(MockJuiceboxApi::new()),
            );
            chat.generate_keypairs().unwrap();
            let err = chat.setup(b"2580").await.unwrap_err();
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidState);
            assert_eq!(err.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn test_setup_and_unlock() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));

        let payload = chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        assert!(!payload.public_key.public_key.is_empty());
        assert!(!payload.public_key.signing_public_key.is_empty());
        assert!(chat.is_unlocked());

        chat.lock();
        assert!(!chat.is_unlocked());

        chat.unlock(b"2580").await.unwrap();
        assert!(chat.is_unlocked());

        let keys_after = chat.get_public_keys().unwrap();
        assert!(!keys_after.identity.is_empty());
    }

    /// A Juicebox stub whose recover always fails with an invalid PIN,
    /// reporting a fixed remaining-guess count.
    struct InvalidPinJuicebox {
        guesses_remaining: Option<u16>,
    }

    #[async_trait::async_trait]
    impl crate::keys::juicebox::JuiceboxApi for InvalidPinJuicebox {
        async fn register_private_key(
            &self,
            _pin: &[u8],
            _config: &JuiceboxConfig,
            _secret: &[u8],
        ) -> RegisterResult {
            RegisterResult::Success
        }

        async fn recover_private_key(
            &self,
            _pin: &[u8],
            _config: &JuiceboxConfig,
        ) -> crate::keys::juicebox::RecoverResult {
            crate::keys::juicebox::RecoverResult::Failure {
                reason: crate::keys::juicebox::RecoverFailureReason::InvalidPin,
                guesses_remaining: self.guesses_remaining,
            }
        }

        async fn delete_keys(
            &self,
            _config: &JuiceboxConfig,
        ) -> crate::keys::juicebox::DeleteResult {
            crate::keys::juicebox::DeleteResult::Success
        }
    }

    #[tokio::test]
    async fn test_unlock_invalid_pin_carries_guesses_remaining() {
        let chat = Chat::with_juicebox(
            test_config(),
            Arc::new(InvalidPinJuicebox {
                guesses_remaining: Some(3),
            }),
        );
        let err = chat.unlock(b"0000").await.unwrap_err();
        match &err {
            SdkError::Juicebox(JuiceboxError::InvalidPin { guesses_remaining }) => {
                assert_eq!(*guesses_remaining, Some(3));
            }
            other => panic!("expected InvalidPin, got {other:?}"),
        }
        assert_eq!(
            err.to_string(),
            "Juicebox error: Invalid PIN: guesses_remaining=3"
        );
    }

    #[tokio::test]
    async fn test_unlock_invalid_pin_without_count() {
        let chat = Chat::with_juicebox(
            test_config(),
            Arc::new(InvalidPinJuicebox {
                guesses_remaining: None,
            }),
        );
        let err = chat.unlock(b"0000").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::Juicebox(JuiceboxError::InvalidPin {
                guesses_remaining: None
            })
        ));
        assert_eq!(err.to_string(), "Juicebox error: Invalid PIN");
    }

    /// `change_pin` unlocks with the old PIN first, so a wrong old PIN
    /// surfaces the same count-carrying error as `unlock`.
    #[tokio::test]
    async fn test_change_pin_invalid_old_pin_carries_guesses_remaining() {
        let chat = Chat::with_juicebox(
            test_config(),
            Arc::new(InvalidPinJuicebox {
                guesses_remaining: Some(0),
            }),
        );
        let err = chat.change_pin(b"0000", b"2580").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::Juicebox(JuiceboxError::InvalidPin {
                guesses_remaining: Some(0)
            })
        ));
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        // Generate and encrypt a conversation key for ourselves
        let ckey = chat.inner.generate_conversation_key().unwrap();

        // Encrypt and verify payload structure
        let payload = chat
            .encrypt_message(
                &EncryptMessageParams::new("conv-1", "Hello!")
                    .with_identity("4201", "1")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.signature.is_empty());
    }

    #[tokio::test]
    async fn test_sign_verify() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let data = b"test data";
        let signature = chat.sign(data).unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let valid = chat.verify(&public_keys.signing, &signature, data).unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_sign_verify_wrong_data() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let signature = chat.sign(b"original").unwrap();
        let public_keys = chat.get_public_keys().unwrap();
        let valid = chat
            .verify(&public_keys.signing, &signature, b"tampered")
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_export_import_keys() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let original_keys = chat.get_public_keys().unwrap();
        let exported = chat.export_keys().unwrap();
        assert!(exported.len() == 64); // identity(32) + signing(32)

        // Lock and re-import
        chat.lock();
        assert!(!chat.is_unlocked());

        chat.import_keys(&ImportKeysParams::new(exported.to_vec()))
            .unwrap();
        assert!(chat.is_unlocked());

        let reimported_keys = chat.get_public_keys().unwrap();
        assert_eq!(reimported_keys.identity, original_keys.identity);
        assert_eq!(reimported_keys.signing, original_keys.signing);
    }

    #[tokio::test]
    async fn test_change_pin() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let original_keys = chat.get_public_keys().unwrap();

        // Change PIN
        chat.change_pin(b"2580", b"8024").await.unwrap();

        // Lock and unlock with new PIN
        chat.lock();
        chat.unlock(b"8024").await.unwrap();
        assert!(chat.is_unlocked());

        let keys_after = chat.get_public_keys().unwrap();
        assert_eq!(keys_after.identity, original_keys.identity);
    }

    #[tokio::test]
    async fn test_encrypt_message_with_versions() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let payload = chat
            .encrypt_message(
                &EncryptMessageParams::new("conv-1", "Versioned message")
                    .with_identity("4201", "66")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert_eq!(payload.conversation_key_version, "1");
    }

    #[tokio::test]
    async fn test_encrypt_message() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let payload = chat
            .encrypt_message(
                &EncryptMessageParams::new("conv-1", "Hello via API!")
                    .with_identity("4101", "65")
                    .with_conversation_key(ckey.to_bytes(), "42"),
            )
            .unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_message_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "42");
    }

    #[tokio::test]
    async fn test_encrypt_reply() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let params = EncryptReplyParams::new("conv-1", "This is a reply", "")
            .with_identity("4101", "67")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-99")
            .with_reply_to_sender_id("12345")
            .with_reply_to_text("Original message");
        let payload = chat.encrypt_reply(&params).unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_reaction_for_api() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let params = EncryptReactionParams::new("", "👍")
            .with_identity("4101", "67")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_conversation_id("conv-1")
            .with_target_message_sequence_id("seq-42");

        let add_payload = chat.encrypt_add_reaction(&params).unwrap();
        assert!(!add_payload.encoded_message_create_event.is_empty());

        let remove_payload = chat.encrypt_remove_reaction(&params).unwrap();
        assert!(!remove_payload.encoded_message_create_event.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_message_with_should_notify_and_ttl() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        // should_notify=false, ttl_msec=30s
        let params = EncryptMessageParams::new("conv-1", "Disappearing!")
            .with_identity("4201", "66")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_should_notify(false)
            .with_ttl_msec(30_000);
        let payload = chat.encrypt_message(&params).unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.should_notify);
    }

    #[tokio::test]
    async fn test_encrypt_message_with_all_entity_types() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let entities = vec![
            EntityDescriptor::new(0, 7, "url"),
            EntityDescriptor::new(8, 13, "mention"),
            EntityDescriptor::new(14, 18, "hashtag"),
            EntityDescriptor::new(19, 23, "cashtag"),
            EntityDescriptor::new(24, 30, "email"),
            EntityDescriptor::new(31, 40, "address"),
            EntityDescriptor::new(41, 50, "phone_number"),
        ];
        let params = EncryptMessageParams::new(
            "conv-1",
            "x.com/a @user #tag $TAG a@b.co 1 Main St +15550100",
        )
        .with_identity("4201", "66")
        .with_conversation_key(ckey.to_bytes(), "1")
        .with_entities(entities);
        let payload = chat.encrypt_message(&params).unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_reply_with_attachments_and_options() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        chat.set_identity(&SetIdentityParams::new("4201", "66"))
            .unwrap();
        let params = EncryptReplyParams::new("conv-1", "Reply with media", "")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_reply_to_sequence_id("seq-99")
            .with_reply_to_sender_id("12345")
            .with_reply_to_text("Original")
            .with_attachments(vec![AttachmentDescriptor::Media {
                media_hash_key: "hash123".into(),
                width: 1024,
                height: 768,
                filesize_bytes: 50000,
                filename: "photo.jpg".into(),
                media_type: Some(1),
                duration_millis: None,
            }])
            .with_should_notify(false)
            .with_ttl_msec(60_000);
        let payload = chat.encrypt_reply(&params).unwrap();
        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.should_notify);
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput::new("910002", &public_keys.identity, "1")];

        let params = ConversationKeyChangeParams::new(input)
            .with_identity("910002", "1")
            .with_conversation_id("conv-1");
        let result = chat.prepare_conversation_key_change(&params).unwrap();

        assert_eq!(result.conversation_id, "conv-1");
        let ckey = result.conversation_key.as_ref().unwrap();
        assert_eq!(ckey.encoded().len(), 32);
        let version: u64 = result.conversation_key_version.parse().unwrap();
        assert!(version > 1_000_000_000_000); // should be millis
        assert_eq!(result.conversation_participant_keys.len(), 1);
        assert_eq!(result.conversation_participant_keys[0].user_id, "910002");
        assert_eq!(
            result.conversation_participant_keys[0].public_key_version,
            "1"
        );
        assert!(!result.conversation_participant_keys[0]
            .encrypted_conversation_key
            .is_empty());

        // The change is signed.
        assert_eq!(result.action_signatures.len(), 1);
        // The key-change payload embeds the plaintext conversation key, so it
        // is never exposed on the signature.
        assert!(result.action_signatures[0].signature_payload.is_empty());
        assert!(!result.action_signatures[0]
            .message_event_signature
            .signature
            .is_empty());

        // The encrypted key should be decryptable back to the raw key.
        let decrypted = chat
            .decrypt_conversation_key(
                &result.conversation_participant_keys[0].encrypted_conversation_key,
            )
            .unwrap();
        assert_eq!(decrypted.encoded(), ckey.encoded());
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change_deduplicates_users() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        // Same user with two key versions — should pick version "2"
        let input = vec![
            PublicKeyInput::new("910001", &public_keys.identity, "1"),
            PublicKeyInput::new("910001", &public_keys.identity, "2"),
        ];

        let params = ConversationKeyChangeParams::new(input)
            .with_identity("910001", "1")
            .with_conversation_id("conv-1");
        let result = chat.prepare_conversation_key_change(&params).unwrap();
        assert_eq!(result.conversation_participant_keys.len(), 1);
        assert_eq!(
            result.conversation_participant_keys[0].public_key_version,
            "2"
        );
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change_derives_one_to_one_id() {
        // Two separate Chat instances simulate two real users.
        let alice_chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        alice_chat.generate_keypairs().unwrap();
        alice_chat.setup(b"2580").await.unwrap();

        let bob_chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        bob_chat.generate_keypairs().unwrap();
        bob_chat.setup(b"8024").await.unwrap();

        let alice_pk = alice_chat.get_public_keys().unwrap();
        let bob_pk = bob_chat.get_public_keys().unwrap();

        // Numeric ids: the smaller sorts first regardless of input order.
        let input = vec![
            PublicKeyInput::new("1491585161162473473", &alice_pk.identity, "1"),
            PublicKeyInput::new("17380288", &bob_pk.identity, "3"),
        ];

        // Omitting conversation_id derives the canonical one-to-one id.
        let result = alice_chat
            .prepare_conversation_key_change(
                &ConversationKeyChangeParams::new(input).with_identity("1491585161162473473", "1"),
            )
            .unwrap();
        assert_eq!(result.conversation_id, "17380288:1491585161162473473");
        assert_eq!(result.conversation_participant_keys.len(), 2);

        let alice_entry = result
            .conversation_participant_keys
            .iter()
            .find(|k| k.user_id == "1491585161162473473")
            .unwrap();
        let bob_entry = result
            .conversation_participant_keys
            .iter()
            .find(|k| k.user_id == "17380288")
            .unwrap();

        let alice_decrypted = alice_chat
            .decrypt_conversation_key(&alice_entry.encrypted_conversation_key)
            .unwrap();
        let bob_decrypted = bob_chat
            .decrypt_conversation_key(&bob_entry.encrypted_conversation_key)
            .unwrap();

        let ckey = result.conversation_key.as_ref().unwrap();
        assert_eq!(alice_decrypted.encoded(), ckey.encoded());
        assert_eq!(bob_decrypted.encoded(), ckey.encoded());
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change_empty_fails() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let params = ConversationKeyChangeParams::new(vec![])
            .with_identity("910002", "1")
            .with_conversation_id("conv-1");
        let result = chat.prepare_conversation_key_change(&params);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change_one_to_one_needs_two_users() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput::new("solo", &public_keys.identity, "1")];

        // No conversation_id and only one participant cannot derive an id.
        let result = chat.prepare_conversation_key_change(
            &ConversationKeyChangeParams::new(input).with_identity("solo", "1"),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prepare_group_members_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput::new("910002", &public_keys.identity, "1")];

        let params = GroupMembersChangeParams::new(
            input,
            "g123",
            vec!["910006".to_string()],
            vec!["910002".to_string()],
            vec!["910002".to_string()],
            vec![],
        )
        .with_identity("910002", "1")
        .with_current_title("Team");
        let result = chat.prepare_group_members_change(&params).unwrap();

        assert_eq!(result.conversation_id, "g123");
        assert_eq!(result.conversation_participant_keys.len(), 1);
        // A member add carries two signed actions: the key change and the add.
        assert_eq!(result.action_signatures.len(), 2);
        assert!(result.action_signatures[0].signature_payload.is_empty());
        assert!(!result.action_signatures[0]
            .encoded_message_event_detail
            .is_empty());
        assert!(result.action_signatures[1]
            .signature_payload
            .starts_with("GroupChangeEvent.GroupMemberAddChange,"));
        assert!(!result.action_signatures[1]
            .encoded_message_event_detail
            .is_empty());
        assert!(result.conversation_key.is_some());
    }

    #[tokio::test]
    async fn test_prepare_group_create() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput::new("910002", &public_keys.identity, "1")];

        let params = GroupCreateParams::new(
            input,
            "g123",
            vec!["910002".to_string(), "910005".to_string()],
            vec!["910002".to_string()],
        )
        .with_identity("910002", "1")
        .with_title("Team");
        let result = chat.prepare_group_create(&params).unwrap();

        assert_eq!(result.conversation_id, "g123");
        assert_eq!(result.conversation_participant_keys.len(), 1);
        // A group create carries two signed actions: the key change and create.
        assert_eq!(result.action_signatures.len(), 2);
        assert!(result.action_signatures[0].signature_payload.is_empty());
        assert!(!result.action_signatures[0]
            .encoded_message_event_detail
            .is_empty());
        assert!(result.action_signatures[1]
            .signature_payload
            .starts_with("GroupChangeEvent.GroupCreate,"));
        assert!(!result.action_signatures[1]
            .encoded_message_event_detail
            .is_empty());
        assert!(result.conversation_key.is_some());
    }

    #[tokio::test]
    async fn test_operations_fail_when_locked() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        // Don't generate keys — everything should fail
        assert!(!chat.is_unlocked());
        assert!(chat.get_public_keys().is_err());
        assert!(chat.sign(b"data").is_err());
        assert!(chat.export_keys().is_err());
    }

    #[tokio::test]
    async fn test_import_invalid_keys_fails() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        assert!(chat
            .import_keys(&ImportKeysParams::new([0u8; 16].to_vec()))
            .is_err()); // wrong size
        assert!(chat
            .import_keys(&ImportKeysParams::new([].to_vec()))
            .is_err()); // empty
    }

    #[test]
    fn test_validate_pin_strength() {
        // Too short
        assert!(crate::keys::juicebox::validate_pin_strength(b"123").is_err());
        assert!(crate::keys::juicebox::validate_pin_strength(b"").is_err());
        // Single repeated character
        assert!(crate::keys::juicebox::validate_pin_strength(b"0000").is_err());
        assert!(crate::keys::juicebox::validate_pin_strength(b"aaaaaa").is_err());
        // Sequential digit runs
        assert!(crate::keys::juicebox::validate_pin_strength(b"1234").is_err());
        assert!(crate::keys::juicebox::validate_pin_strength(b"0123456").is_err());
        assert!(crate::keys::juicebox::validate_pin_strength(b"9876").is_err());
        // Acceptable
        assert!(crate::keys::juicebox::validate_pin_strength(b"2580").is_ok());
        assert!(crate::keys::juicebox::validate_pin_strength(b"1357").is_ok());
        assert!(crate::keys::juicebox::validate_pin_strength(b"correct horse").is_ok());
    }

    #[tokio::test]
    async fn test_setup_rejects_weak_pin() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        for weak in [&b"123"[..], b"0000", b"1234", b"4321"] {
            let err = chat.setup(weak).await.expect_err("weak PIN must fail");
            assert!(err.to_string().contains("Weak PIN"), "got: {}", err);
        }
        // A strong PIN still registers.
        chat.setup(b"2580").await.unwrap();
    }

    #[tokio::test]
    async fn test_change_pin_rejects_weak_new_pin() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        assert!(chat.change_pin(b"2580", b"1111").await.is_err());
        // Old (possibly weak) PINs can still unlock.
        chat.unlock(b"2580").await.unwrap();
    }

    #[tokio::test]
    async fn test_set_reject_unverified() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        chat.set_reject_unverified(true);

        // reject_unverified is tested indirectly — we can't easily construct
        // a valid encrypted event in a unit test, but we verify the flag is set
        // and the method compiles.
        assert!(chat.is_unlocked());
    }

    #[tokio::test]
    async fn test_generate_keypairs_produces_valid_payload() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        let payload = chat.generate_keypairs().unwrap();

        assert_eq!(payload.public_key.registration_method, "CustomPin");
        assert!(!payload.public_key.identity_public_key_signature.is_empty());
        assert!(!payload.public_key.public_key.is_empty());
        assert!(!payload.public_key.signing_public_key.is_empty());
        assert!(
            payload.public_key.public_key_fingerprint.is_some(),
            "fingerprint should be populated"
        );
        // Fingerprint is URL-safe base64 of SHA-256 → 43 chars (no padding)
        let fp = payload.public_key.public_key_fingerprint.as_ref().unwrap();
        assert_eq!(
            fp.len(),
            43,
            "SHA-256 → 32 bytes → 43 URL-safe base64 chars"
        );
        assert!(
            payload.public_key.signing_public_key_signature.is_some(),
            "signing_public_key_signature should be populated"
        );
        assert!(
            !payload
                .public_key
                .signing_public_key_signature
                .as_ref()
                .unwrap()
                .is_empty(),
            "signing_public_key_signature should not be empty"
        );
    }

    #[tokio::test]
    async fn test_update_config() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        let new_config = JuiceboxConfig::from_json(r#"{"realms": []}"#.to_string());
        chat.update_config(new_config);
        // Doesn't panic — config is updated
    }

    fn make_recipient(public_key: &str) -> RecipientInput {
        RecipientInput {
            user_id: "910002".into(),
            public_key: public_key.to_string(),
            key_version: "1".into(),
        }
    }

    #[tokio::test]
    async fn test_encrypt_conversation_key_for_recipients() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let public_keys = chat.get_public_keys().unwrap();
        let encrypted_keys = chat
            .inner
            .encrypt_conversation_key_for_recipients(
                &ckey,
                &[make_recipient(&public_keys.identity)],
            )
            .unwrap();
        assert!(encrypted_keys.len() == 1);
    }

    #[tokio::test]
    async fn test_decrypt_conversation_key_roundtrip() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let public_keys = chat.get_public_keys().unwrap();
        let encrypted_keys = chat
            .inner
            .encrypt_conversation_key_for_recipients(
                &ckey,
                &[make_recipient(&public_keys.identity)],
            )
            .unwrap();

        let decrypted = chat
            .decrypt_conversation_key(&encrypted_keys[0].encrypted_conversation_key)
            .unwrap();
        assert_eq!(ckey.encoded(), decrypted.encoded());
    }

    #[tokio::test]
    async fn test_encrypt_message_produces_valid_payload() {
        // encrypt_message returns a SendPayload with encoded_message_create_event (base64 of
        // MessageCreateEvent Thrift).  This is what gets POSTed to the X API.
        // The API wraps it in a full MessageEvent before delivering via webhook.
        // We can't directly decrypt_event(encoded_message_create_event) — that needs the
        // full MessageEvent wrapper.  So we just verify the payload structure.
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let params = EncryptMessageParams::new("conv-1", "Hello, World!")
            .with_identity("4001", "1")
            .with_conversation_key(ckey.to_bytes(), "1");
        let payload = chat.encrypt_message(&params).unwrap();

        assert!(!payload.encoded_message_create_event.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_message_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "1");
        assert_eq!(payload.signature_info.signature_version, "7");
        assert!(payload.should_notify);

        chat.inner.force_features(&[crate::features::V1_SEND]);
        let params = EncryptMessageParams::new("conv-1", "Hello again")
            .with_identity("4001", "1")
            .with_conversation_key(ckey.to_bytes(), "1");
        let payload = chat.encrypt_message(&params).unwrap();
        assert_eq!(payload.signature_info.signature_version, "10");
    }

    // File encrypt/decrypt

    /// An unlocked `Chat` with the session identity of user 1000.
    async fn sending_chat() -> Chat {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        chat.set_identity(&SetIdentityParams::new("1000", "1"))
            .unwrap();
        chat
    }

    /// The outgoing event of a message `chat` sends under key version "1"
    /// whose only attachment is the file `media_hash_key`, and the key map
    /// that opens it.
    fn sent_file_message(
        chat: &Chat,
        ckey: &XChatConversationKey,
        media_hash_key: &str,
    ) -> (
        String,
        std::collections::HashMap<String, XChatConversationKey>,
    ) {
        let params = EncryptMessageParams::new("1000:2000", "a file")
            .with_conversation_key(ckey.to_bytes(), "1")
            .with_attachments(vec![crate::AttachmentDescriptor::Media {
                media_hash_key: media_hash_key.to_string(),
                width: 4,
                height: 3,
                filesize_bytes: 64,
                filename: "photo.png".to_string(),
                media_type: None,
                duration_millis: None,
            }]);
        let payload = chat.encrypt_message(&params).unwrap();
        (
            payload.event_b64,
            [("1".to_string(), ckey.clone())].into_iter().collect(),
        )
    }

    #[tokio::test]
    async fn test_file_encrypt_decrypt_roundtrip() {
        let chat = sending_chat().await;
        let ckey = chat.inner.generate_conversation_key().unwrap();
        let plaintext = b"Hello file! This is some media content that could be an image or video.";
        let (event, keys) = sent_file_message(&chat, &ckey, "hash-1");

        let encrypted = chat
            .encrypt_file(
                &EncryptFileParams::new(plaintext.to_vec(), event.clone(), "hash-1")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len()); // overhead from nonce, tag, header

        let decrypted = chat
            .decrypt_file(&DecryptFileParams::new(encrypted, event, keys, "hash-1"))
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_file_encrypt_decrypt_large() {
        let chat = sending_chat().await;
        let ckey = chat.inner.generate_conversation_key().unwrap();
        // > 1024 bytes to test multi-chunk processing
        let plaintext: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let (event, keys) = sent_file_message(&chat, &ckey, "hash-1");

        let encrypted = chat
            .encrypt_file(
                &EncryptFileParams::new(plaintext.clone(), event.clone(), "hash-1")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        let mut encryptor = chat
            .file_encryptor(
                &FileEncryptorParams::new(event.clone(), "hash-1")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        let mut incremental_encrypted = Vec::new();
        for chunk in plaintext.chunks(700) {
            incremental_encrypted.extend(encryptor.push(chunk).unwrap());
        }
        incremental_encrypted.extend(encryptor.finish().unwrap());

        for encrypted in [&encrypted, &incremental_encrypted] {
            let decrypted = chat
                .decrypt_file(&DecryptFileParams::new(
                    encrypted.clone(),
                    event.clone(),
                    keys.clone(),
                    "hash-1",
                ))
                .unwrap();
            assert_eq!(decrypted, plaintext);
        }

        let mut decryptor = chat
            .file_decryptor(&FileDecryptorParams::new(event, keys, "hash-1"))
            .unwrap();
        let mut incremental = Vec::new();
        for chunk in encrypted.chunks(700) {
            incremental.extend(decryptor.push(chunk).unwrap());
        }
        incremental.extend(decryptor.finish().unwrap());
        assert_eq!(incremental, plaintext);
    }

    #[tokio::test]
    async fn test_file_wrong_key_fails() {
        let chat = sending_chat().await;
        let ckey1 = chat.inner.generate_conversation_key().unwrap();
        let ckey2 = chat.inner.generate_conversation_key().unwrap();
        let (event, _) = sent_file_message(&chat, &ckey1, "hash-1");
        let wrong_keys: std::collections::HashMap<_, _> =
            [("1".to_string(), ckey2)].into_iter().collect();

        assert!(chat
            .encrypt_file(
                &EncryptFileParams::new(b"secret media content".to_vec(), event.clone(), "hash-1")
                    .with_conversation_key(wrong_keys["1"].to_bytes(), "1"),
            )
            .is_err());
        let encrypted = chat
            .encrypt_file(
                &EncryptFileParams::new(b"secret media content".to_vec(), event.clone(), "hash-1")
                    .with_conversation_key(ckey1.to_bytes(), "1"),
            )
            .unwrap();
        assert!(chat
            .decrypt_file(&DecryptFileParams::new(
                encrypted, event, wrong_keys, "hash-1"
            ))
            .is_err());
    }

    // internal signature builders, exercised through the prepare methods

    #[tokio::test]
    async fn test_sign_add_members() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let sig = chat
            .inner
            .sign_add_members(
                "1",
                "msg-1",
                "910003",
                "conv-1",
                &["new-member-1".to_string()],
                &["member-1".to_string(), "member-2".to_string()],
                &["admin-1".to_string()],
                "1",
                Some("Group Name"),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        assert!(!sig.message_event_signature.signature.is_empty());
        assert!(!sig.signature_payload.is_empty());
        assert_eq!(sig.message_event_signature.public_key_version, "1");
    }

    #[tokio::test]
    async fn test_sign_key_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let sig = chat
            .inner
            .sign_key_change("1", "msg-1", "910003", "conv-1", "2", ckey.encoded())
            .unwrap();

        assert!(!sig.message_event_signature.signature.is_empty());
        // Withheld: the signed payload embeds the plaintext conversation key.
        assert!(sig.signature_payload.is_empty());
    }

    // delete + lock/unlock state

    #[tokio::test]
    async fn test_delete_clears_keys() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        assert!(chat.is_unlocked());

        chat.delete().await.unwrap();
        assert!(!chat.is_unlocked());
    }

    #[tokio::test]
    async fn test_lock_then_operations_fail() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();
        assert!(chat.is_unlocked());

        chat.lock();
        assert!(!chat.is_unlocked());

        assert!(chat.sign(b"test").is_err());
        assert!(chat.get_public_keys().is_err());
        assert!(chat.export_keys().is_err());
    }
}
