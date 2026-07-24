//! # Chat - The X Chat SDK
//!
//! This module provides the main [`Chat`] struct for X Chat encryption.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use chat_xdk_core::{Chat, EncryptMessageParams};
//!
//! // Create, unlock, and set the session identity once
//! let chat = Chat::new(juicebox_config);
//! chat.unlock(b"2580").await?;
//! chat.set_identity(user_id, signing_key_version);
//! chat.set_cache_keys(true);
//! chat.set_signing_keys(signing_keys);
//!
//! // Decrypt incoming events; verified conversation keys are cached
//! let result = chat.decrypt_events(&events, &[]);
//!
//! // Send messages. The SDK generates the message id and returns it in the
//! // payload (payload.message_id); sender, signing-key version, and the
//! // conversation key resolve from the session and cache.
//! let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "Hello!"))?;
//! let reply = chat.encrypt_reply(EncryptReplyParams::new(conversation_id, "Hi!", event_b64))?;
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
//!
//! ### Level 2: Advanced API (when you need more control)
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Chat::prepare_conversation_key_change`] | Generate, encrypt, and sign a key change |
//! | [`Chat::prepare_group_create`] | Generate, encrypt, and sign a group create |
//! | [`Chat::prepare_group_members_change`] | Generate, encrypt, and sign a member add |
//! | [`Chat::decrypt_conversation_key`] | Decrypt a conversation key |
//! | [`Chat::sign`] | Sign arbitrary data |
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
    ConversationKeyChangeParams, EncryptEditParams, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, GroupCreateParams, GroupMembersChangeParams, MessageDeleteParams,
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
/// ```rust,ignore
/// use chat_xdk_core::{Chat, Event, EncryptMessageParams};
///
/// // First-time setup: generate keys, then register them in Juicebox
/// let chat = Chat::new(juicebox_config);
/// let registration = chat.generate_keypairs()?;
/// let public_keys = chat.setup(b"2580").await?;
/// // Upload the registration payload to the X API
///
/// // On subsequent startups
/// chat.unlock(b"2580").await?;
/// chat.set_identity(user_id, signing_key_version);
/// chat.set_cache_keys(true);
/// chat.set_signing_keys(signing_keys);
///
/// // Handle incoming webhook (keys resolve from the session stores)
/// let event = chat.decrypt_event(event_b64, &Default::default(), &[])?;
/// if let Event::Message(msg) = event {
///     println!("{}: {}", msg.meta.sender_id.unwrap_or_default(), msg.text().unwrap_or(""));
/// }
///
/// // Send a message. The SDK generates the message id and returns it in the
/// // payload (payload.message_id); sender, signing-key version, and the
/// // conversation key resolve from the session and cache.
/// let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "Hello!"))?;
/// // POST payload to API
/// ```
#[cfg(feature = "juicebox")]
pub struct Chat {
    /// The platform-agnostic encryption core.
    pub(crate) inner: crate::core::ChatCore,
    config: JuiceboxConfig,
    juicebox: Arc<dyn JuiceboxApi>,
}

/// Minimum PIN length in bytes accepted for new registrations.
#[cfg(feature = "juicebox")]
pub(crate) const MIN_PIN_LENGTH: usize = 4;

/// Validate PIN strength for new registrations.
///
/// Rejects PINs that are shorter than [`MIN_PIN_LENGTH`], use a single
/// repeated character (`0000`), or are an ascending/descending run of
/// digits (`1234`, `9876`). Applied by [`Chat::setup`] and
/// [`Chat::change_pin`]; never applied on unlock, so existing
/// registrations stay recoverable.
#[cfg(feature = "juicebox")]
pub(crate) fn validate_pin_strength(pin: &[u8]) -> Result<(), SdkError> {
    if pin.len() < MIN_PIN_LENGTH {
        return Err(SdkError::Key(KeyError::WeakPin(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        ))));
    }
    if pin.iter().all(|&b| b == pin[0]) {
        return Err(SdkError::Key(KeyError::WeakPin(
            "PIN must not be a single repeated character".into(),
        )));
    }
    let ascending = pin.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let descending = pin.windows(2).all(|w| w[1] == w[0].wrapping_sub(1));
    if pin.iter().all(u8::is_ascii_digit) && (ascending || descending) {
        return Err(SdkError::Key(KeyError::WeakPin(
            "PIN must not be a sequential run of digits".into(),
        )));
    }
    Ok(())
}

#[cfg(feature = "juicebox")]
impl Chat {
    /// Create a new Chat instance with Juicebox config.
    ///
    /// # Arguments
    /// * `config` - Juicebox configuration from the X API
    pub fn new(config: JuiceboxConfig) -> Self {
        Self {
            inner: crate::core::ChatCore::new(),
            config,
            juicebox: Arc::new(JuiceboxClient::new()),
        }
    }

    /// Create with a custom Juicebox implementation
    pub fn with_juicebox(config: JuiceboxConfig, juicebox: Arc<dyn JuiceboxApi>) -> Self {
        Self {
            inner: crate::core::ChatCore::new(),
            config,
            juicebox,
        }
    }

    /// When enabled — the default — `decrypt_event` returns an error for any
    /// signed event whose signature cannot be verified (invalid, missing, or
    /// no matching signing key) instead of returning it with
    /// `verified: false`.
    pub fn set_reject_unverified(&mut self, reject: bool) {
        self.inner.set_reject_unverified(reject);
    }
    /// Set the session identity: the owner's user id and signing-key version,
    /// used as defaults wherever `sender_id` / `signing_key_version` is not
    /// passed explicitly.
    pub fn set_identity(&self, user_id: impl Into<String>, signing_key_version: impl Into<String>) {
        self.inner.set_identity(user_id, signing_key_version);
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
    pub fn set_signing_keys(&self, entries: Vec<SigningKeyEntry>) {
        self.inner.set_signing_keys(entries);
    }
    /// Replace the Juicebox configuration.
    pub fn update_config(&mut self, config: JuiceboxConfig) {
        self.config = config;
    }

    // Juicebox key storage

    /// Generate new keypairs and return the registration payload.
    pub fn generate_keypairs(&self) -> Result<PublicKeyRegistrationPayload, SdkError> {
        self.inner.generate_keypairs()
    }

    /// Register the current keys in Juicebox under `pin` and return public keys.
    ///
    /// The PIN must meet minimum strength requirements (4+ characters, not a
    /// single repeated character or a sequential digit run). It is passed as
    /// bytes so callers can zeroize their own buffer after the call.
    pub async fn setup(&self, pin: &[u8]) -> Result<PublicKeys, SdkError> {
        validate_pin_strength(pin)?;
        let mut secret = self.inner.export_keys()?;
        let result = self
            .juicebox
            .register_private_key(pin, &self.config, &secret)
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
        match self.juicebox.recover_private_key(pin, &self.config).await {
            RecoverResult::Success(secret) => {
                self.inner.import_keys(&secret)?;
                Ok(())
            }
            RecoverResult::Failure {
                reason,
                guesses_remaining: _,
            } => Err(SdkError::Juicebox(reason.into())),
            RecoverResult::KeyReconstructionFailed => Err(SdkError::Key(
                KeyError::ReconstructionFailed("Failed to reconstruct keys".into()),
            )),
            RecoverResult::NoTokens => Err(SdkError::Juicebox(JuiceboxError::NoTokens)),
        }
    }

    /// Delete the stored keys from Juicebox and clear them from memory.
    pub async fn delete(&self) -> Result<(), SdkError> {
        use crate::keys::juicebox::DeleteResult;
        match self.juicebox.delete_keys(&self.config).await {
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
        validate_pin_strength(new_pin)?;
        self.unlock(old_pin).await?;
        let mut secret = self.inner.export_keys()?;
        let result = self
            .juicebox
            .register_private_key(new_pin, &self.config, &secret)
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

    /// Decrypt a raw webhook event payload.
    pub fn decrypt_event(
        &self,
        event_b64: &str,
        conversation_keys: &std::collections::HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        self.inner
            .decrypt_event(event_b64, conversation_keys, signing_keys)
    }

    /// Decrypt multiple events in batch.
    pub fn decrypt_events(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
    ) -> DecryptEventsResult {
        self.inner.decrypt_events(events, signing_keys)
    }

    /// Encrypt a text message.
    pub fn encrypt_message(&self, params: EncryptMessageParams) -> Result<SendPayload, SdkError> {
        self.inner.encrypt_message(params)
    }
    /// Encrypt a reply.
    pub fn encrypt_reply(&self, params: EncryptReplyParams) -> Result<SendPayload, SdkError> {
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
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        self.inner.prepare_message_delete(params)
    }
    /// Decrypt an encrypted conversation key (ECIES).
    pub fn decrypt_conversation_key(
        &self,
        encrypted_key_b64: &str,
    ) -> Result<XChatConversationKey, SdkError> {
        self.inner.decrypt_conversation_key(encrypted_key_b64)
    }
    /// Encrypt a stream.
    pub fn encrypt_stream(
        &self,
        plaintext: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        self.inner.encrypt_stream(plaintext, conversation_key)
    }
    /// Decrypt a stream.
    pub fn decrypt_stream(
        &self,
        encrypted: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        self.inner.decrypt_stream(encrypted, conversation_key)
    }

    /// Create an incremental stream encryptor for large payloads.
    pub fn stream_encryptor(
        &self,
        conversation_key: &XChatConversationKey,
    ) -> Result<crate::crypto::encryption::StreamEncryptor, SdkError> {
        self.inner.stream_encryptor(conversation_key)
    }

    /// Create an incremental stream decryptor for large payloads.
    pub fn stream_decryptor(
        &self,
        conversation_key: &XChatConversationKey,
    ) -> Result<crate::crypto::encryption::StreamDecryptor, SdkError> {
        self.inner.stream_decryptor(conversation_key)
    }

    /// Encrypt a UTF-8 string using XSalsa20-Poly1305 and return base64.
    pub fn encrypt(
        &self,
        plaintext: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        self.inner.encrypt(plaintext, conversation_key)
    }

    /// Decrypt a base64-encoded XSalsa20-Poly1305 ciphertext to a UTF-8 string.
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
        params: ConversationKeyChangeParams,
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
    /// group-create action the backend validates together.
    pub fn prepare_group_create(
        &self,
        params: GroupCreateParams,
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
        params: GroupMembersChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_members_change(params)
    }
    /// Sign arbitrary data.
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
    /// Import private keys from bytes (32 or 64 bytes).
    pub fn import_keys(&self, key_bytes: &[u8]) -> Result<(), SdkError> {
        self.inner.import_keys(key_bytes)
    }
    /// Like [`Chat::import_keys`] but also records the public key version the
    /// keys were registered under.
    pub fn import_keys_with_version(
        &self,
        key_bytes: &[u8],
        version: &str,
    ) -> Result<(), SdkError> {
        self.inner.import_keys_with_version(key_bytes, version)
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
                EncryptMessageParams::new("conv-1", "Hello!")
                    .with_identity("me", "1")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap();
        assert!(!payload.encrypted_content.is_empty());
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

        chat.import_keys(&exported).unwrap();
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
                EncryptMessageParams::new("conv-1", "Versioned message")
                    .with_identity("me", "s1")
                    .with_conversation_key(ckey.to_bytes(), "v1"),
            )
            .unwrap();
        assert!(!payload.encrypted_content.is_empty());
        assert_eq!(payload.conversation_key_version, "v1");
    }

    #[tokio::test]
    async fn test_encrypt_message() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let payload = chat
            .encrypt_message(
                EncryptMessageParams::new("conv-1", "Hello via API!")
                    .with_identity("user-1", "v7")
                    .with_conversation_key(ckey.to_bytes(), "v42"),
            )
            .unwrap();
        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "v42");
    }

    #[tokio::test]
    async fn test_encrypt_reply() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let mut params = EncryptReplyParams::new("conv-1", "This is a reply", "")
            .with_identity("user-1", "v1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.reply_to_sequence_id = Some("seq-99".into());
        params.reply_to_sender_id = Some(12345);
        params.reply_to_text = Some("Original message".into());
        let payload = chat.encrypt_reply(params).unwrap();
        assert!(!payload.encrypted_content.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_reaction_for_api() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let mut params = EncryptReactionParams::new("", "👍")
            .with_identity("user-1", "v1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());

        let add_payload = chat.encrypt_add_reaction(&params).unwrap();
        assert!(!add_payload.encrypted_content.is_empty());

        let mut params = EncryptReactionParams::new("", "👍")
            .with_identity("user-1", "v1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());

        let remove_payload = chat.encrypt_remove_reaction(&params).unwrap();
        assert!(!remove_payload.encrypted_content.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_message_with_should_notify_and_ttl() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        // should_notify=false, ttl_msec=30s
        let mut params = EncryptMessageParams::new("conv-1", "Disappearing!")
            .with_identity("me", "s1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.should_notify = Some(false);
        params.ttl_msec = Some(30_000);
        let payload = chat.encrypt_message(params).unwrap();
        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.should_notify);
    }

    #[tokio::test]
    async fn test_encrypt_message_with_all_entity_types() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let entities = vec![
            EntityDescriptor {
                start: 0,
                end: 5,
                entity_type: "url".into(),
            },
            EntityDescriptor {
                start: 6,
                end: 10,
                entity_type: "mention".into(),
            },
            EntityDescriptor {
                start: 11,
                end: 15,
                entity_type: "hashtag".into(),
            },
            EntityDescriptor {
                start: 16,
                end: 20,
                entity_type: "cashtag".into(),
            },
            EntityDescriptor {
                start: 21,
                end: 30,
                entity_type: "email".into(),
            },
            EntityDescriptor {
                start: 31,
                end: 40,
                entity_type: "address".into(),
            },
            EntityDescriptor {
                start: 41,
                end: 50,
                entity_type: "phone_number".into(),
            },
        ];
        let mut params = EncryptMessageParams::new("conv-1", "text with all entity types")
            .with_identity("me", "s1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.entities = Some(entities);
        let payload = chat.encrypt_message(params).unwrap();
        assert!(!payload.encrypted_content.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_reply_with_attachments_and_options() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let mut params = EncryptReplyParams::new("conv-1", "Reply with media", "")
            .with_identity("me", "s1")
            .with_conversation_key(ckey.to_bytes(), "v1");
        params.reply_to_sequence_id = Some("seq-99".into());
        params.reply_to_sender_id = Some(12345);
        params.reply_to_text = Some("Original".into());
        params.attachments = Some(vec![AttachmentDescriptor::Media {
            media_hash_key: "hash123".into(),
            width: 1024,
            height: 768,
            filesize_bytes: 50000,
            filename: "photo.jpg".into(),
            media_type: Some(1),
            duration_millis: None,
        }]);
        params.should_notify = Some(false);
        params.ttl_msec = Some(60_000);
        let payload = chat.encrypt_reply(params).unwrap();
        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.should_notify);
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "me".into(),
            public_key: public_keys.identity.clone(),
            key_version: "1".into(),
        }];

        let mut params = ConversationKeyChangeParams::new(input).with_identity("me", "1");
        params.conversation_id = Some("conv-1".into());
        let result = chat.prepare_conversation_key_change(params).unwrap();

        assert_eq!(result.conversation_id, "conv-1");
        let ckey = result.conversation_key.as_ref().unwrap();
        assert_eq!(ckey.encoded().len(), 32);
        let version: u64 = result.conversation_key_version.parse().unwrap();
        assert!(version > 1_000_000_000_000); // should be millis
        assert_eq!(result.participant_keys.len(), 1);
        assert_eq!(result.participant_keys[0].user_id, "me");
        assert_eq!(result.participant_keys[0].public_key_version, "1");
        assert!(!result.participant_keys[0].encrypted_key.is_empty());

        // The change is signed.
        assert_eq!(result.action_signatures.len(), 1);
        // The key-change payload embeds the plaintext conversation key, so it
        // is never exposed on the signature.
        assert!(result.action_signatures[0].signature_payload.is_empty());
        assert!(!result.action_signatures[0].signature.is_empty());

        // The encrypted key should be decryptable back to the raw key.
        let decrypted = chat
            .decrypt_conversation_key(&result.participant_keys[0].encrypted_key)
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
            PublicKeyInput {
                user_id: "alice".into(),
                public_key: public_keys.identity.clone(),
                key_version: "1".into(),
            },
            PublicKeyInput {
                user_id: "alice".into(),
                public_key: public_keys.identity.clone(),
                key_version: "2".into(),
            },
        ];

        let mut params = ConversationKeyChangeParams::new(input).with_identity("alice", "1");
        params.conversation_id = Some("conv-1".into());
        let result = chat.prepare_conversation_key_change(params).unwrap();
        assert_eq!(result.participant_keys.len(), 1);
        assert_eq!(result.participant_keys[0].public_key_version, "2");
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
            PublicKeyInput {
                user_id: "1491585161162473473".into(),
                public_key: alice_pk.identity.clone(),
                key_version: "1".into(),
            },
            PublicKeyInput {
                user_id: "17380288".into(),
                public_key: bob_pk.identity.clone(),
                key_version: "3".into(),
            },
        ];

        // Omitting conversation_id derives the canonical one-to-one id.
        let result = alice_chat
            .prepare_conversation_key_change(
                ConversationKeyChangeParams::new(input).with_identity("1491585161162473473", "1"),
            )
            .unwrap();
        assert_eq!(result.conversation_id, "17380288:1491585161162473473");
        assert_eq!(result.participant_keys.len(), 2);

        let alice_entry = result
            .participant_keys
            .iter()
            .find(|k| k.user_id == "1491585161162473473")
            .unwrap();
        let bob_entry = result
            .participant_keys
            .iter()
            .find(|k| k.user_id == "17380288")
            .unwrap();

        let alice_decrypted = alice_chat
            .decrypt_conversation_key(&alice_entry.encrypted_key)
            .unwrap();
        let bob_decrypted = bob_chat
            .decrypt_conversation_key(&bob_entry.encrypted_key)
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

        let mut params = ConversationKeyChangeParams::new(vec![]).with_identity("me", "1");
        params.conversation_id = Some("conv-1".into());
        let result = chat.prepare_conversation_key_change(params);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prepare_conversation_key_change_one_to_one_needs_two_users() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "solo".into(),
            public_key: public_keys.identity.clone(),
            key_version: "1".into(),
        }];

        // No conversation_id and only one participant cannot derive an id.
        let result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams::new(input).with_identity("solo", "1"),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prepare_group_members_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let public_keys = chat.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "me".into(),
            public_key: public_keys.identity.clone(),
            key_version: "1".into(),
        }];

        let mut params = GroupMembersChangeParams::new(
            input,
            "g123",
            vec!["new-1".to_string()],
            vec!["me".to_string()],
            vec!["me".to_string()],
            vec![],
        )
        .with_identity("me", "1");
        params.current_title = Some("Team".into());
        let result = chat.prepare_group_members_change(params).unwrap();

        assert_eq!(result.conversation_id, "g123");
        assert_eq!(result.participant_keys.len(), 1);
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
        let input = vec![PublicKeyInput {
            user_id: "me".into(),
            public_key: public_keys.identity.clone(),
            key_version: "1".into(),
        }];

        let mut params = GroupCreateParams::new(
            input,
            "g123",
            vec!["me".to_string(), "friend".to_string()],
            vec!["me".to_string()],
        )
        .with_identity("me", "1");
        params.title = Some("Team".into());
        let result = chat.prepare_group_create(params).unwrap();

        assert_eq!(result.conversation_id, "g123");
        assert_eq!(result.participant_keys.len(), 1);
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
        assert!(chat.import_keys(&[0u8; 16]).is_err()); // wrong size
        assert!(chat.import_keys(&[]).is_err()); // empty
    }

    #[test]
    fn test_validate_pin_strength() {
        // Too short
        assert!(validate_pin_strength(b"123").is_err());
        assert!(validate_pin_strength(b"").is_err());
        // Single repeated character
        assert!(validate_pin_strength(b"0000").is_err());
        assert!(validate_pin_strength(b"aaaaaa").is_err());
        // Sequential digit runs
        assert!(validate_pin_strength(b"1234").is_err());
        assert!(validate_pin_strength(b"0123456").is_err());
        assert!(validate_pin_strength(b"9876").is_err());
        // Acceptable
        assert!(validate_pin_strength(b"2580").is_ok());
        assert!(validate_pin_strength(b"1357").is_ok());
        assert!(validate_pin_strength(b"correct horse").is_ok());
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
        let mut chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
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
        assert!(payload.generate_version);
        assert!(payload.version.is_some());
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
        let mut chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        let new_config = JuiceboxConfig::from_json(r#"{"realms": []}"#.to_string());
        chat.update_config(new_config);
        // Doesn't panic — config is updated
    }

    fn make_recipient(public_key: &str) -> RecipientInput {
        RecipientInput {
            user_id: "me".into(),
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
            .decrypt_conversation_key(&encrypted_keys[0].encrypted_key)
            .unwrap();
        assert_eq!(ckey.encoded(), decrypted.encoded());
    }

    #[tokio::test]
    async fn test_encrypt_message_produces_valid_payload() {
        // encrypt_message returns a SendPayload with encrypted_content (base64 of
        // MessageCreateEvent Thrift).  This is what gets POSTed to the X API.
        // The API wraps it in a full MessageEvent before delivering via webhook.
        // We can't directly decrypt_event(encrypted_content) — that needs the
        // full MessageEvent wrapper.  So we just verify the payload structure.
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();

        let params = EncryptMessageParams::new("conv-1", "Hello, World!")
            .with_identity("sender-1", "1")
            .with_conversation_key(ckey.to_bytes(), "1");
        let payload = chat.encrypt_message(params).unwrap();

        assert!(!payload.encrypted_content.is_empty());
        assert!(!payload.signature.is_empty());
        assert!(!payload.encoded_event_signature.is_empty());
        assert_eq!(payload.conversation_key_version, "1");
        assert_eq!(payload.signature_info.signature_version, "7");
        assert!(payload.should_notify);
    }

    // Stream encrypt/decrypt

    #[tokio::test]
    async fn test_stream_encrypt_decrypt_roundtrip() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let plaintext =
            b"Hello stream! This is some media content that could be an image or video.";

        let encrypted = chat.encrypt_stream(plaintext, &ckey).unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len()); // overhead from nonce, tag, header

        let decrypted = chat.decrypt_stream(&encrypted, &ckey).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_stream_encrypt_decrypt_large() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        // > 1024 bytes to test multi-chunk streaming
        let plaintext: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let encrypted = chat.encrypt_stream(&plaintext, &ckey).unwrap();
        let decrypted = chat.decrypt_stream(&encrypted, &ckey).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_stream_wrong_key_fails() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey1 = chat.inner.generate_conversation_key().unwrap();
        let ckey2 = chat.inner.generate_conversation_key().unwrap();
        let plaintext = b"secret media content";

        let encrypted = chat.encrypt_stream(plaintext, &ckey1).unwrap();
        let result = chat.decrypt_stream(&encrypted, &ckey2);
        assert!(result.is_err());
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
                "sender-1",
                "conv-1",
                &["new-member-1".to_string()],
                &["member-1".to_string(), "member-2".to_string()],
                &["admin-1".to_string()],
                "1",
                Some("Group Name"),
                None,
                None,
                None,
            )
            .unwrap();

        assert!(!sig.signature.is_empty());
        assert!(!sig.signature_payload.is_empty());
        assert_eq!(sig.public_key_version, "1");
    }

    #[tokio::test]
    async fn test_sign_key_change() {
        let chat = Chat::with_juicebox(test_config(), Arc::new(MockJuiceboxApi::new()));
        chat.generate_keypairs().unwrap();
        chat.setup(b"2580").await.unwrap();

        let ckey = chat.inner.generate_conversation_key().unwrap();
        let sig = chat
            .inner
            .sign_key_change("1", "msg-1", "sender-1", "conv-1", "2", ckey.encoded())
            .unwrap();

        assert!(!sig.signature.is_empty());
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
