//! Platform-agnostic encryption core.
//!
//! `ChatCore` provides all cryptographic operations (key management,
//! encrypt/decrypt, sign/verify) without any Juicebox dependency or
//! platform-specific concerns.  Both the native `Chat` (Juicebox
//! feature) and the WASM bindings wrap this struct.

use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{KeypairPurpose, XChatConversationKey, XChatKeyPair, XChatPrivateKey};
use crate::error::{CryptoError, SdkError};
use crate::keys::conversation_keys;
use crate::keys::keypair_manager::KeypairManager;
use crate::params::{
    ConversationKeyChangeParams, EncryptEditParams, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, GroupCreateParams, GroupMembersChangeParams, MessageDeleteParams,
};
use crate::protocol::serialization::{base64_decode, base64_encode};
use crate::thrift::event::{MessageEvent, MessageEventDetail};
use crate::thrift::product::{
    MediaType as ThriftMediaType, MessageAttachment as ThriftMessageAttachment,
    MessageEntryContents, MessageEntryHolder, UrlAttachmentImage as ThriftUrlAttachmentImage,
};
use crate::types::*;

use crate::protocol::safe_reader::BoundedProtocol;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use p256::pkcs8::EncodePublicKey;
use std::collections::HashMap;
use std::io::Cursor;
use thrift::protocol::{TBinaryInputProtocol, TSerializable};

/// Sequence number at or above which a conversation key change with an
/// invalid plaintext-key signature is dropped instead of adopted. Key changes
/// below it are always kept, so older conversations stay readable; at or above
/// it, key adoption is fail-closed.
///
/// `sequence_id` is unsigned backend metadata, so this is a compatibility
/// ramp, not a security boundary: a relay that strips or lowers the sequence
/// on a forged v6+ key change keeps that key adopted for *decryption* without
/// signature enforcement. The signed key version remains the ordering
/// authority — `apply_ckey_freshness` pins `latest_version` to the newest
/// *verified* key change, so the *encryption* path cannot be downgraded by
/// such an event. The gate exists only so stored history from before
/// plaintext-key signatures stays readable; it can be dropped (enforce
/// everywhere) once that history no longer needs to be decrypted.
const CKEY_SIG_V6_ENFORCE_AFTER_SEQ: i64 = 2070276095283454002;

/// Platform-agnostic encryption core.
///
/// Holds raw key state and exposes all crypto operations.  No Juicebox,
/// no async, no platform-specific code.  Both the native `Chat` and the
/// WASM `Chat` wrap this struct.
pub struct ChatCore {
    keypair_manager: KeypairManager,
    reject_unverified: bool,
    conversation_key_high_water: std::sync::RwLock<HashMap<String, u64>>,
    /// User id of this instance's owner, set by [`Self::set_identity`] and
    /// used as the default `sender_id` for signed actions.
    owner_user_id: std::sync::RwLock<Option<String>>,
    /// Whether the conversation-key cache is enabled (off by default).
    cache_keys: std::sync::atomic::AtomicBool,
    /// Per-conversation cache of the conversation key at the verified
    /// high-water version. Keys enter only through the signature-verified
    /// freshness pass, never from adopted-but-unverified key changes.
    conversation_key_cache: std::sync::RwLock<HashMap<String, CachedConversationKey>>,
    /// Caller-supplied signing keys used when a decrypt call omits them.
    /// Populated only by [`Self::set_signing_keys`] — never from event
    /// contents.
    signing_key_cache: std::sync::RwLock<Vec<SigningKeyEntry>>,
}

/// A cached conversation key pinned to its verified version.
///
/// The key zeroizes on drop via [`XChatConversationKey`]; `Debug` redacts it.
#[derive(Clone)]
struct CachedConversationKey {
    version: u64,
    key: XChatConversationKey,
}

impl std::fmt::Debug for CachedConversationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedConversationKey")
            .field("version", &self.version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ChatCore {
    /// Create a new `ChatCore` with no keys loaded.
    ///
    /// `reject_unverified` defaults to `true` — unverified events are
    /// rejected.  Call `set_reject_unverified(false)` to opt out.
    pub fn new() -> Self {
        Self {
            keypair_manager: KeypairManager::new(),
            reject_unverified: true,
            conversation_key_high_water: std::sync::RwLock::new(HashMap::new()),
            owner_user_id: std::sync::RwLock::new(None),
            cache_keys: std::sync::atomic::AtomicBool::new(false),
            conversation_key_cache: std::sync::RwLock::new(HashMap::new()),
            signing_key_cache: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// When enabled — the default — `decrypt_event` returns an error for any
    /// signed event type that cannot be positively verified: an invalid
    /// signature, a missing signature, no matching signing key (including an
    /// empty signing-key list), or an unencrypted message (which carries no
    /// verifiable signature). When disabled, such events are returned with
    /// `verified: false` instead. Event types that never carry a signature
    /// (typing, failure, member-account-delete) are unaffected either way.
    pub fn set_reject_unverified(&mut self, reject: bool) {
        self.reject_unverified = reject;
    }

    // Key Management

    /// Generate new keypairs and return the registration payload.
    ///
    /// The key version is a millisecond timestamp read from the system clock.
    /// On platforms without a clock (e.g. `wasm32-unknown-unknown`) call
    /// [`Self::generate_keypairs_with_version`] and supply the timestamp.
    pub fn generate_keypairs(&self) -> Result<PublicKeyRegistrationPayload, SdkError> {
        self.generate_keypairs_with_version(&now_millis())
    }

    /// Like [`Self::generate_keypairs`] but uses the caller-supplied key
    /// version string instead of the system clock. Pass a millisecond
    /// timestamp (e.g. from JavaScript `Date.now()` in a WASM host).
    pub fn generate_keypairs_with_version(
        &self,
        version: &str,
    ) -> Result<PublicKeyRegistrationPayload, SdkError> {
        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity)?;
        let signing = KeyFactory::generate_keypair(KeypairPurpose::Signing)?;

        let identity_spki = Self::public_key_spki_bytes(&identity.public)?;
        let signing_spki = Self::public_key_spki_bytes(&signing.public)?;

        // Signing key signs the identity key SPKI — raw r||s (64 bytes),
        // the wire format stored by the X API.
        let identity_signature = KeyFactory::sign(&signing.private, &identity_spki)?;
        // Identity key signs the signing key (bidirectional binding).
        let signing_key_signature = KeyFactory::sign(&identity.private, &signing_spki)?;

        self.keypair_manager
            .set_keypairs(identity.clone(), Some(signing.clone()));

        let fingerprint = Self::compute_public_key_fingerprint(&identity_spki);

        // Store the key version so extract_conversation_keys can filter
        // participant keys by version.
        self.keypair_manager.set_key_version(version.to_string());

        Ok(PublicKeyRegistrationPayload {
            public_key: PublicKeyRegistration {
                identity_public_key_signature: base64_encode(&identity_signature),
                public_key: base64_encode(&identity_spki),
                public_key_fingerprint: Some(fingerprint),
                registration_method: "CustomPin".to_string(),
                signing_public_key: base64_encode(&signing_spki),
                signing_public_key_signature: Some(base64_encode(&signing_key_signature)),
            },
            version: Some(version.to_string()),
            generate_version: true,
        })
    }

    /// Get current public keys.
    pub fn get_public_keys(&self) -> Result<PublicKeys, SdkError> {
        let identity = self.keypair_manager.get_identity_keypair()?;
        let signing = self.keypair_manager.get_signing_keypair()?;
        Ok(PublicKeys {
            identity: base64_encode(identity.public.encoded()),
            signing: base64_encode(signing.public.encoded()),
            version: String::new(),
        })
    }

    /// Get the fingerprint of the loaded identity public key.
    ///
    /// The fingerprint is URL-safe base64-encoded SHA-256 hash of the
    /// SPKI-encoded identity public key.  Users can compare fingerprints
    /// out-of-band (e.g. in person) to verify they are communicating
    /// with the intended party.
    pub fn get_public_key_fingerprint(&self) -> Result<String, SdkError> {
        let identity = self.keypair_manager.get_identity_keypair()?;
        let spki = Self::public_key_spki_bytes(&identity.public)?;
        Ok(Self::compute_public_key_fingerprint(&spki))
    }

    /// Export private keys as bytes for backup.
    ///
    /// # Security
    ///
    /// The returned bytes are **unencrypted private key material**. Anything
    /// with access to them (including, in browsers, any JavaScript running
    /// in the hosting page) permanently owns the identity.
    pub fn export_keys(&self) -> Result<Vec<u8>, SdkError> {
        let private_keys = self.keypair_manager.get_private_keys()?;
        Ok(private_keys.to_bytes())
    }

    /// Set the session identity: the owner's user id and the signing-key
    /// version, used as defaults wherever a method's `sender_id` /
    /// `signing_key_version` is not passed explicitly.
    ///
    /// The key version also lets `extract_conversation_keys` filter
    /// participant-key entries by version, avoiding decryption of keys
    /// intended for other key versions.
    ///
    /// A resolved default and an explicitly passed value produce
    /// byte-identical signed output for the same logical inputs.
    pub fn set_identity(&self, user_id: impl Into<String>, signing_key_version: impl Into<String>) {
        *self
            .owner_user_id
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(user_id.into());
        self.keypair_manager
            .set_key_version(signing_key_version.into());
    }

    /// Enable or disable the conversation-key cache (off by default).
    ///
    /// While enabled, `decrypt_events` caches, per conversation, the key
    /// whose key change carried a valid signature at the highest version
    /// seen, and the encrypt methods resolve an omitted
    /// `conversation_key`/`conversation_key_version` pair from it.
    /// Disabling clears the cache; the keys zeroize on drop.
    pub fn set_cache_keys(&self, enabled: bool) {
        self.cache_keys
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        if !enabled {
            self.conversation_key_cache
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
    }

    /// Store signing keys to use when a decrypt call omits its
    /// `signing_keys` argument.
    ///
    /// Only this explicit call populates the store — a key carried inside an
    /// event is never trusted for verification. Each call replaces the
    /// previous set.
    pub fn set_signing_keys(&self, entries: Vec<SigningKeyEntry>) {
        *self
            .signing_key_cache
            .write()
            .unwrap_or_else(|e| e.into_inner()) = entries;
    }

    /// Resolve the effective `sender_id`: the explicit override when present,
    /// otherwise the session identity.
    fn resolve_sender_id(&self, param: Option<&str>) -> Result<String, SdkError> {
        if let Some(v) = param.filter(|v| !v.is_empty()) {
            return Ok(v.to_string());
        }
        self.owner_user_id
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| {
                SdkError::InvalidState(
                    "sender_id is not set: pass it explicitly or call set_identity() first".into(),
                )
            })
    }

    /// Resolve the effective `signing_key_version`: the explicit override
    /// when present, otherwise the session identity.
    fn resolve_signing_key_version(&self, param: Option<&str>) -> Result<String, SdkError> {
        if let Some(v) = param.filter(|v| !v.is_empty()) {
            return Ok(v.to_string());
        }
        self.keypair_manager.get_key_version().ok_or_else(|| {
            SdkError::InvalidState(
                "signing_key_version is not set: pass it explicitly or call set_identity() first"
                    .into(),
            )
        })
    }

    /// Resolve the conversation key + version for an encrypt call: the
    /// explicit pair when present, otherwise the cached verified key for the
    /// conversation.
    fn resolve_conversation_key(
        &self,
        conversation_key: Option<&[u8]>,
        conversation_key_version: Option<&str>,
        conversation_id: &str,
        sender_id: &str,
    ) -> Result<(XChatConversationKey, String), SdkError> {
        let key = conversation_key.filter(|k| !k.is_empty());
        let version = conversation_key_version.filter(|v| !v.is_empty());
        match (key, version) {
            (Some(key), Some(version)) => {
                Ok((Self::conversation_key_from_bytes(key)?, version.to_string()))
            }
            (None, None) => {
                // The cache stores canonical conversation ids as carried by
                // events, so normalize the caller's form before the lookup.
                let canonical =
                    crate::pipeline::canonical_conversation_id(conversation_id, sender_id);
                let no_key = || {
                    SdkError::InvalidState(format!(
                        "no cached conversation key for '{}': pass conversation_key and \
                         conversation_key_version explicitly, or enable set_cache_keys(true) \
                         and decrypt the conversation's key-change events first",
                        canonical
                    ))
                };
                if !self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(no_key());
                }
                let cache = self
                    .conversation_key_cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let cached = cache.get(canonical.as_ref()).ok_or_else(no_key)?;
                Ok((cached.key.clone(), cached.version.to_string()))
            }
            _ => Err(SdkError::InvalidState(
                "conversation_key and conversation_key_version must be passed together \
                 (or both omitted to resolve from the key cache)"
                    .into(),
            )),
        }
    }

    /// Look up a cached conversation key for a specific conversation and key
    /// version. Used by the decrypt path when the caller omits its key map.
    fn cached_key_for(&self, conversation_id: &str, version: &str) -> Option<XChatConversationKey> {
        if !self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        let cache = self
            .conversation_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let cached = cache.get(conversation_id)?;
        (cached.version.to_string() == version).then(|| cached.key.clone())
    }

    /// Resolve the signing keys for a decrypt call: the explicit slice when
    /// non-empty, otherwise the keys stored via [`Self::set_signing_keys`].
    fn resolve_signing_keys(&self, param: &[SigningKeyEntry]) -> Vec<SigningKeyEntry> {
        if !param.is_empty() {
            return param.to_vec();
        }
        self.signing_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Import private keys from bytes (32 or 64 bytes).
    pub fn import_keys(&self, key_bytes: &[u8]) -> Result<(), SdkError> {
        use crate::crypto::keys::XChatPrivateKeys;
        let private_keys = XChatPrivateKeys::from_bytes(key_bytes).ok_or_else(|| {
            SdkError::Crypto(CryptoError::DecryptionFailed(
                "Invalid key format: expected 32 or 64 bytes".into(),
            ))
        })?;
        self.keypair_manager
            .load_from_private_keys(&private_keys)
            .map_err(SdkError::Crypto)
    }

    /// Like [`Self::import_keys`] but also records the public key version the
    /// keys were registered under, so participant-key filtering and the
    /// session `signing_key_version` are set in one call.
    pub fn import_keys_with_version(
        &self,
        key_bytes: &[u8],
        version: &str,
    ) -> Result<(), SdkError> {
        self.import_keys(key_bytes)?;
        self.keypair_manager.set_key_version(version.to_string());
        Ok(())
    }

    /// Returns `true` when both the identity and signing keys are loaded.
    ///
    /// Use this before calling any method that signs data (`encrypt_message`,
    /// `sign`, etc.). For decryption-only operations use `has_identity_key`.
    ///
    /// Both keys are checked under a single lock acquisition, so the answer
    /// reflects a consistent snapshot even under concurrent `lock()` /
    /// unlock.
    pub fn is_unlocked(&self) -> bool {
        self.keypair_manager.has_both_keypairs()
    }

    /// Returns `true` when the identity key is loaded.
    ///
    /// Sufficient for `decrypt_conversation_key` and `decrypt_event`.
    /// Signing operations also require the signing key — use `is_unlocked`.
    pub fn has_identity_key(&self) -> bool {
        self.keypair_manager.has_keypair()
    }

    /// Verify that a signing key is authentically bound to an identity key.
    ///
    /// During registration, `generate_keypairs()` has the signing key sign
    /// the identity key's SPKI encoding, producing `identity_public_key_signature`.
    /// This method verifies that signature with the signing key, proving the
    /// signing key holder endorsed this identity key.
    ///
    /// Call this when you receive another user's public keys from the X API
    /// to detect server-side key substitution.
    ///
    /// All inputs are base64-encoded. The signature is a raw r||s ECDSA signature.
    pub fn verify_key_binding(
        &self,
        identity_public_key_b64: &str,
        signing_public_key_b64: &str,
        identity_public_key_signature_b64: &str,
    ) -> Result<bool, SdkError> {
        let sig_bytes = base64_decode(identity_public_key_signature_b64)?;
        // The signing key signs the identity key's bytes exactly as they
        // appear on the wire (SPKI). Verify with the signing key over those
        // same bytes — the signature is raw r||s.
        let identity_bytes = base64_decode(identity_public_key_b64)?;
        self.verify(signing_public_key_b64, &sig_bytes, &identity_bytes)
    }

    /// Report whether the loaded identity public key is the key in
    /// `public_key_b64`.
    ///
    /// Use this to answer "is the key on this device one of the keys
    /// registered to this account?" — e.g. after a restore/import, to adopt
    /// the matching `public_key_version` for `set_identity`, or to check
    /// whether onboarding already happened. The X API returns the identity
    /// public key in the DER (SPKI) encoding that registration uploaded,
    /// while `get_public_keys` returns the raw SEC1 point, so naive string
    /// comparison of the two base64 values fails even for the same key.
    /// This method accepts either encoding.
    ///
    /// Errors when no identity keypair is loaded or the input is not valid
    /// base64. A structurally different key returns `Ok(false)`.
    pub fn matches_registered_key(&self, public_key_b64: &str) -> Result<bool, SdkError> {
        let identity = self.keypair_manager.get_identity_keypair()?;
        let candidate = base64_decode(public_key_b64)?;
        if candidate == identity.public.encoded() {
            return Ok(true);
        }
        let spki = Self::public_key_spki_bytes(&identity.public)?;
        Ok(candidate == spki)
    }

    /// Clear keys from memory.
    pub fn lock(&self) {
        self.keypair_manager.clear();
    }

    // Conversation Keys

    /// Decrypt an encrypted conversation key (ECIES).
    pub fn decrypt_conversation_key(
        &self,
        encrypted_key_b64: &str,
    ) -> Result<XChatConversationKey, SdkError> {
        let encrypted_bytes = base64_decode(encrypted_key_b64)?;
        let identity = self.keypair_manager.get_identity_keypair()?;
        let ckey =
            conversation_keys::decrypt_conversation_key(&encrypted_bytes, &identity.private)?;
        Ok(ckey)
    }

    /// Generate a new conversation key.
    pub(crate) fn generate_conversation_key(&self) -> Result<XChatConversationKey, SdkError> {
        Ok(KeyFactory::generate_conversation_key()?)
    }

    /// Encrypt a conversation key for one or more recipients.
    ///
    /// Public keys may be SEC1 uncompressed (65 bytes), SEC1 compressed (33 bytes),
    /// or SPKI/DER encoded (91 bytes). SPKI keys are automatically unwrapped.
    pub(crate) fn encrypt_conversation_key_for_recipients(
        &self,
        ckey: &XChatConversationKey,
        recipients: &[RecipientInput],
    ) -> Result<Vec<EncryptedKeyForRecipient>, SdkError> {
        let recipients_parsed: Vec<(String, crate::crypto::keys::XChatPublicKey, String)> =
            recipients
                .iter()
                .map(|r| {
                    let pk_bytes = base64_decode(&r.public_key)?;
                    // Strip 26-byte SPKI header if present (91-byte DER-encoded key)
                    let raw = if pk_bytes.len() == 91 {
                        &pk_bytes[26..]
                    } else {
                        &pk_bytes
                    };
                    let pk = KeyFactory::reconstruct_public_key(raw, KeypairPurpose::Identity)?;
                    Ok((r.user_id.clone(), pk, r.key_version.clone()))
                })
                .collect::<Result<Vec<_>, SdkError>>()?;

        let encrypted =
            conversation_keys::encrypt_conversation_key_for_recipients(ckey, &recipients_parsed)?;

        Ok(encrypted
            .into_iter()
            .map(|e| EncryptedKeyForRecipient {
                user_id: e.user_id,
                encrypted_key: base64_encode(&e.encrypted_key),
                public_key_version: e.public_key_version,
            })
            .collect())
    }

    /// Generate a conversation key and encrypt it for every participant.
    ///
    /// Groups `public_keys` by user, keeps the highest version per user, then
    /// returns the raw key (to store locally) and one encrypted copy per user.
    fn build_participant_keys(
        &self,
        public_keys: &[PublicKeyInput],
    ) -> Result<(XChatConversationKey, Vec<EncryptedKeyForRecipient>), SdkError> {
        if public_keys.is_empty() {
            return Err(SdkError::Parse("public_keys must not be empty".to_string()));
        }

        let mut best_by_user: HashMap<String, &PublicKeyInput> = HashMap::new();
        for pk in public_keys {
            let is_newer = match best_by_user.get(&pk.user_id) {
                None => true,
                Some(current) => match (
                    pk.key_version.parse::<u64>(),
                    current.key_version.parse::<u64>(),
                ) {
                    (Ok(new_ver), Ok(cur_ver)) => new_ver > cur_ver,
                    _ => pk.key_version > current.key_version,
                },
            };
            if is_newer {
                best_by_user.insert(pk.user_id.clone(), pk);
            }
        }

        let recipients: Vec<RecipientInput> = best_by_user
            .values()
            .map(|pk| RecipientInput {
                user_id: pk.user_id.clone(),
                public_key: pk.public_key.clone(),
                key_version: pk.key_version.clone(),
            })
            .collect();

        let ckey = self.generate_conversation_key()?;
        let participant_keys = self.encrypt_conversation_key_for_recipients(&ckey, &recipients)?;
        Ok((ckey, participant_keys))
    }

    /// Derive the canonical id for a one-to-one conversation.
    ///
    /// The id is the two distinct user ids ordered by
    /// [`crate::pipeline::join_sorted_pair`] — length then lexically, which
    /// equals numeric order for decimal ids — and joined with a colon.
    /// Signer and verifier derive the same string from the same pair, so the
    /// signed payload only matches when this exact form is used. Requires
    /// exactly two distinct users; a group must pass its id explicitly.
    fn derive_one_to_one_conversation_id(
        public_keys: &[PublicKeyInput],
    ) -> Result<String, SdkError> {
        let mut ids: Vec<&str> = Vec::new();
        for pk in public_keys {
            if !ids.contains(&pk.user_id.as_str()) {
                ids.push(pk.user_id.as_str());
            }
        }
        if ids.len() != 2 {
            return Err(SdkError::Parse(format!(
                "cannot derive a one-to-one conversation id from {} distinct user(s); \
                 pass conversation_id explicitly for group conversations",
                ids.len()
            )));
        }
        Ok(crate::pipeline::join_sorted_pair(ids[0], ids[1]))
    }

    /// Generate a random message id for a signed action.
    fn generate_message_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes)
            .into_uuid()
            .to_string()
    }

    /// Prepare a signed conversation-key change, ready to send to the X API.
    ///
    /// Use this to start a one-to-one or rotate an existing conversation's key
    /// (one-to-one or group). Creating a group or adding members requires a
    /// paired group signature as well — use [`Self::prepare_group_create`] or
    /// [`Self::prepare_group_members_change`] for those.
    ///
    /// Generates a fresh conversation key, encrypts it for every participant,
    /// and signs the change so recipients can verify it came from the sender.
    /// Omit `conversation_id` for a one-to-one and it is derived from the two
    /// participants; pass the existing id for a group key rotation.
    ///
    /// The returned `conversation_key` is the raw key to store locally for
    /// encrypting messages.
    pub fn prepare_conversation_key_change(
        &self,
        params: ConversationKeyChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_conversation_key_change_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_conversation_key_change`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_conversation_key_change_with_version(
        &self,
        params: ConversationKeyChangeParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        // An empty id means "derive": FFI layers cannot express Option and
        // send "" for "not set".
        let conversation_id = match params
            .conversation_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            // Canonicalize caller-supplied forms (hyphen pair, unsorted pair,
            // bare recipient id) so the signature covers the id the backend
            // fans out.
            Some(id) => crate::pipeline::canonical_conversation_id(id, &sender_id).into_owned(),
            None => Self::derive_one_to_one_conversation_id(&params.public_keys)?,
        };
        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;
        let message_id = Self::generate_message_id();
        let mut signature = self.sign_key_change(
            &signing_key_version,
            &message_id,
            &sender_id,
            &conversation_id,
            conversation_key_version,
            ckey.encoded(),
        )?;
        // The signed payload covers only the key bytes; the API also needs the
        // full event so it can persist and fan out the change.
        signature.encoded_message_event_detail =
            Self::encode_ckey_change_detail(conversation_key_version, &participant_keys)?;
        Ok(PreparedConversationChange {
            conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            participant_keys,
            action_signatures: vec![signature],
        })
    }

    /// Serialize the `ConversationKeyChangeEvent` the API persists and relays.
    ///
    /// Encoded as a base64 `MessageEventDetail` carrying the conversation-key
    /// version and the per-participant encrypted keys.
    fn encode_ckey_change_detail(
        conversation_key_version: &str,
        participant_keys: &[EncryptedKeyForRecipient],
    ) -> Result<String, SdkError> {
        let participant_keys = participant_keys
            .iter()
            .map(|pk| crate::thrift::event::ConversationParticipantKey {
                user_id: Some(pk.user_id.clone()),
                encrypted_conversation_key: Some(pk.encrypted_key.clone()),
                public_key_version: Some(pk.public_key_version.clone()),
            })
            .collect();
        let detail = crate::thrift::event::MessageEventDetail::ConversationKeyChangeEvent(
            crate::thrift::event::ConversationKeyChangeEvent {
                conversation_key_version: Some(conversation_key_version.to_string()),
                conversation_participant_keys: Some(participant_keys),
                ratchet_tree_change: None,
                for_key_rotation: Some(false),
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Serialize the `GroupCreate` event the API persists and relays.
    ///
    /// Encoded as a base64 `MessageEventDetail` carrying the full group roster,
    /// title, avatar, and conversation-key version. The backend matches on
    /// `member_ids`, `admin_ids`, `title`, `avatar_url`, and
    /// `conversation_key_version`, so all of them are populated.
    #[allow(clippy::too_many_arguments)]
    fn encode_group_create_detail(
        member_ids: &[String],
        admin_ids: &[String],
        title: Option<&str>,
        avatar_url: Option<&str>,
        conversation_key_version: &str,
        ttl_msec: Option<i64>,
        is_legacy_group_upgrade: Option<bool>,
    ) -> Result<String, SdkError> {
        let group_create = crate::thrift::event::GroupCreate {
            member_ids: Some(member_ids.to_vec()),
            admin_ids: Some(admin_ids.to_vec()),
            title: title.map(|s| s.to_string()),
            avatar_url: avatar_url.map(|s| s.to_string()),
            conversation_key_version: Some(conversation_key_version.to_string()),
            is_legacy_group_upgrade,
            ttl_msec,
        };
        let detail = crate::thrift::event::MessageEventDetail::GroupChangeEvent(
            crate::thrift::event::GroupChangeEvent {
                group_change: Some(crate::thrift::event::GroupChange::GroupCreate(group_create)),
                for_key_rotation: Some(false),
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Serialize the `GroupMemberAddChange` event the API persists and relays.
    ///
    /// Encoded as a base64 `MessageEventDetail` carrying the new members plus
    /// the current roster snapshot the backend matches against.
    #[allow(clippy::too_many_arguments)]
    fn encode_group_member_add_detail(
        new_member_ids: &[String],
        current_member_ids: &[String],
        current_admin_ids: &[String],
        current_pending_member_ids: &[String],
        current_title: Option<&str>,
        current_avatar_url: Option<&str>,
        current_ttl_msec: Option<i64>,
        current_screen_capture_blocking_enabled: Option<bool>,
        conversation_key_version: &str,
    ) -> Result<String, SdkError> {
        let change = crate::thrift::event::GroupMemberAddChange {
            member_ids: Some(new_member_ids.to_vec()),
            current_member_ids: Some(current_member_ids.to_vec()),
            current_admin_ids: Some(current_admin_ids.to_vec()),
            current_title: current_title.map(|s| s.to_string()),
            current_avatar_url: current_avatar_url.map(|s| s.to_string()),
            conversation_key_version: Some(conversation_key_version.to_string()),
            current_ttl_msec,
            current_pending_member_ids: Some(current_pending_member_ids.to_vec()),
            screen_capture_blocking_enabled: current_screen_capture_blocking_enabled,
            group_invite_enable: None,
            admin_settings: None,
        };
        let detail = crate::thrift::event::MessageEventDetail::GroupChangeEvent(
            crate::thrift::event::GroupChangeEvent {
                group_change: Some(crate::thrift::event::GroupChange::GroupMemberAdd(change)),
                for_key_rotation: Some(false),
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Use this once, when creating a group (`conversation_id` is the `g…` id
    /// minted by the initialize endpoint). Later key rotations use
    /// [`Self::prepare_conversation_key_change`]; roster additions use
    /// [`Self::prepare_group_members_change`].
    ///
    /// Generates a fresh conversation key for the new group, encrypts it for
    /// every participant, and emits the two action signatures the backend
    /// requires: a conversation-key change and the group-create itself. The
    /// returned `conversation_key` is the raw key to store locally.
    pub fn prepare_group_create(
        &self,
        params: GroupCreateParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_group_create_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_group_create`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_group_create_with_version(
        &self,
        params: GroupCreateParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        // Normalize absent-value encodings so every binding signs identical
        // bytes: FFI layers cannot express Option and pass "" / a negative
        // TTL for "not set".
        let title = params.title.as_deref().filter(|t| !t.is_empty());
        let avatar_url = params.avatar_url.as_deref().filter(|a| !a.is_empty());
        let ttl_msec = params.ttl_msec.filter(|t| *t >= 0);

        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;

        // A group create needs two signed actions: the conversation-key change
        // that seeds the group's key, and the group-create action itself.
        let ckce_message_id = Self::generate_message_id();
        let mut ckce_sig = self.sign_key_change(
            &signing_key_version,
            &ckce_message_id,
            &sender_id,
            &params.conversation_id,
            conversation_key_version,
            ckey.encoded(),
        )?;
        ckce_sig.encoded_message_event_detail =
            Self::encode_ckey_change_detail(conversation_key_version, &participant_keys)?;

        let create_message_id = Self::generate_message_id();
        let mut create_sig = self.sign_group_create(
            &signing_key_version,
            &create_message_id,
            &sender_id,
            &params.member_ids,
            title,
            avatar_url,
            conversation_key_version,
            None,
        )?;
        create_sig.encoded_message_event_detail = Self::encode_group_create_detail(
            &params.member_ids,
            &params.admin_ids,
            title,
            avatar_url,
            conversation_key_version,
            ttl_msec,
            None,
        )?;

        Ok(PreparedConversationChange {
            conversation_id: params.conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            participant_keys,
            action_signatures: vec![ckce_sig, create_sig],
        })
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Use this when adding members to an existing group. Creating the group is
    /// [`Self::prepare_group_create`]; a key rotation without a roster change is
    /// [`Self::prepare_conversation_key_change`].
    ///
    /// Generates a fresh conversation key for the updated roster, encrypts it
    /// for every participant in `public_keys`, and emits the two action
    /// signatures the backend requires: a conversation-key change and the
    /// member add itself. The returned `conversation_key` is the raw key to
    /// store locally.
    pub fn prepare_group_members_change(
        &self,
        params: GroupMembersChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_group_members_change_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_group_members_change`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_group_members_change_with_version(
        &self,
        params: GroupMembersChangeParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        // Normalize absent-value encodings so every binding signs identical
        // bytes: FFI layers cannot express Option and pass "" / a negative
        // TTL for "not set".
        let current_title = params.current_title.as_deref().filter(|t| !t.is_empty());
        let current_avatar_url = params
            .current_avatar_url
            .as_deref()
            .filter(|a| !a.is_empty());
        let current_ttl_msec = params.current_ttl_msec.filter(|t| *t >= 0);

        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;

        // A member add needs two signed actions: the conversation-key change
        // that rotates the group's key, and the member-add action itself.
        let ckce_message_id = Self::generate_message_id();
        let mut ckce_sig = self.sign_key_change(
            &signing_key_version,
            &ckce_message_id,
            &sender_id,
            &params.conversation_id,
            conversation_key_version,
            ckey.encoded(),
        )?;
        ckce_sig.encoded_message_event_detail =
            Self::encode_ckey_change_detail(conversation_key_version, &participant_keys)?;

        let add_message_id = Self::generate_message_id();
        let mut member_add_sig = self.sign_add_members(
            &signing_key_version,
            &add_message_id,
            &sender_id,
            &params.conversation_id,
            &params.new_member_ids,
            &params.current_member_ids,
            &params.current_admin_ids,
            conversation_key_version,
            current_title,
            current_avatar_url,
            current_ttl_msec,
            params.current_screen_capture_blocking_enabled,
        )?;
        member_add_sig.encoded_message_event_detail = Self::encode_group_member_add_detail(
            &params.new_member_ids,
            &params.current_member_ids,
            &params.current_admin_ids,
            &params.current_pending_member_ids,
            current_title,
            current_avatar_url,
            current_ttl_msec,
            params.current_screen_capture_blocking_enabled,
            conversation_key_version,
        )?;

        Ok(PreparedConversationChange {
            conversation_id: params.conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            participant_keys,
            action_signatures: vec![ckce_sig, member_add_sig],
        })
    }

    // Events

    /// Extract and decrypt conversation keys from a batch of raw event strings.
    ///
    /// Parses each event, attempts to decrypt participant keys using the loaded
    /// identity key, and returns a `ConversationKeyResult` with:
    /// - `keys`: Map of key version → conversation key
    /// - `latest_version`: The highest key version (for encryption)
    ///
    /// Events that are not `KeyChange` events, or whose keys can't be decrypted
    /// by this identity key, are silently skipped.
    ///
    /// Returns an empty result if no keys are loaded.
    ///
    /// # Security
    ///
    /// This call adopts every decryptable key without checking signatures and
    /// reports the batch's highest version. [`Self::decrypt_events`] hardens
    /// this: it pins `latest_version` to the newest key change with a valid
    /// signature and holds it monotonic, so a replayed older key cannot
    /// downgrade what callers encrypt with; per-message signatures are verified
    /// in [`Self::decrypt_event`].
    ///
    /// `latest_version` here is the highest version within this batch only.
    pub fn extract_conversation_keys(&self, events: &[&str]) -> ConversationKeyResult {
        if self.keypair_manager.get_identity_keypair().is_err() {
            return ConversationKeyResult {
                keys: HashMap::new(),
                latest_version: None,
            };
        }

        let mut result = HashMap::new();
        let mut latest_version: Option<String> = None;

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(ckey) = self.decrypt_key_change_ckey(kce) else {
                continue;
            };

            // Track the latest version (highest numeric value)
            let is_newer = match (&latest_version, version.parse::<u64>()) {
                (None, Ok(_)) => true,
                (Some(current), Ok(new_ver)) => {
                    current.parse::<u64>().map_or(true, |c| new_ver > c)
                }
                _ => latest_version.is_none(),
            };
            if is_newer {
                latest_version = Some(version.clone());
            }
            result.insert(version.clone(), ckey);
        }

        ConversationKeyResult {
            keys: result,
            latest_version,
        }
    }

    /// Drop adopted conversation keys whose key change fails signature
    /// enforcement.
    ///
    /// A key change is rejected only when its sequence number is at or above
    /// the configured threshold, its signature version carries a verifiable
    /// plaintext-key payload, and its signature does not verify. Below the
    /// threshold, or for earlier signature versions whose payload cannot be
    /// reproduced, the key is left adopted. Does nothing while `floor` is at
    /// the maximum.
    fn enforce_ckey_signatures(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        result: &mut ConversationKeyResult,
        floor: i64,
    ) {
        if floor == i64::MAX {
            return;
        }

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };

            let Some(seq) = parsed
                .sequence_id
                .as_deref()
                .and_then(|s| s.parse::<i64>().ok())
            else {
                continue;
            };
            if seq < floor {
                continue;
            }

            let sig_version = parsed
                .message_event_signature
                .as_ref()
                .and_then(|s| s.signature_version.as_deref())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);
            if sig_version < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION {
                continue;
            }

            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(adopted) = result.keys.get(&version) else {
                continue;
            };
            // Base64 of a live conversation key; wiped on drop like the
            // sign-path payloads.
            let ckey_b64 = zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(adopted.encoded()));
            let sender_keys: Vec<SigningKeyEntry> = match parsed.sender_id.as_deref() {
                Some(sid) => signing_keys
                    .iter()
                    .filter(|k| k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            let verified = matches!(
                self.verify_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64)),
                Ok(true)
            );
            if !verified {
                result.keys.remove(&version);
                if result.latest_version.as_deref() == Some(version.as_str()) {
                    result.latest_version = result
                        .keys
                        .keys()
                        .filter_map(|v| v.parse::<u64>().ok().map(|n| (n, v.clone())))
                        .max_by_key(|(n, _)| *n)
                        .map(|(_, v)| v);
                }
            }
        }
    }

    /// Pin the reported latest conversation-key version to the newest one whose
    /// key change is authentic, monotonically across this instance's lifetime.
    ///
    /// A malicious relay can replay an old, validly signed key change to make a
    /// caller encrypt under a stale key. Recording the highest *verified*
    /// version per conversation and never reporting a lower one defeats that
    /// downgrade, while every version stays adopted for decryption. Only
    /// signature versions carrying a reproducible plaintext-key payload can be
    /// authenticated; a conversation seen only through earlier versions keeps
    /// the value derived from the batch.
    fn apply_ckey_freshness(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        result: &mut ConversationKeyResult,
    ) {
        let mut batch_conversations: Vec<String> = Vec::new();
        let mut verified_max: HashMap<String, u64> = HashMap::new();

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            if let Some(conv_id) = parsed.conversation_id.as_deref() {
                if !batch_conversations.iter().any(|c| c == conv_id) {
                    batch_conversations.push(conv_id.to_string());
                }
            }
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };
            let Some(conv_id) = parsed.conversation_id.as_deref() else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Ok(version_num) = version.parse::<u64>() else {
                continue;
            };

            let sig_version = parsed
                .message_event_signature
                .as_ref()
                .and_then(|s| s.signature_version.as_deref())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);
            if sig_version < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION {
                continue;
            }

            let Some(adopted) = result.keys.get(&version) else {
                continue;
            };
            // Base64 of a live conversation key; wiped on drop like the
            // sign-path payloads.
            let ckey_b64 = zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(adopted.encoded()));
            let sender_keys: Vec<SigningKeyEntry> = match parsed.sender_id.as_deref() {
                Some(sid) => signing_keys
                    .iter()
                    .filter(|k| k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            if matches!(
                self.verify_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64)),
                Ok(true)
            ) {
                let entry = verified_max.entry(conv_id.to_string()).or_insert(0);
                *entry = (*entry).max(version_num);
            }
        }

        {
            let mut high_water = self
                .conversation_key_high_water
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for (conv_id, version_num) in &verified_max {
                let entry = high_water.entry(conv_id.clone()).or_insert(0);
                if version_num > entry {
                    *entry = *version_num;
                }
            }
        }

        if self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
            // Cache only keys whose key change verified above, at the
            // conversation's high-water version — never a merely adopted key,
            // and never over a newer cached one.
            let high_water = self
                .conversation_key_high_water
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let mut cache = self
                .conversation_key_cache
                .write()
                .unwrap_or_else(|e| e.into_inner());
            // Re-check under the write lock: a concurrent set_cache_keys(false)
            // clears the cache, and inserting after that clear would leave a
            // populated cache while the feature is off.
            if self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
                for (conv_id, version_num) in &verified_max {
                    if high_water.get(conv_id) != Some(version_num) {
                        continue;
                    }
                    let Some(key) = result.keys.get(&version_num.to_string()) else {
                        continue;
                    };
                    match cache.get(conv_id) {
                        Some(existing) if existing.version >= *version_num => {}
                        _ => {
                            cache.insert(
                                conv_id.clone(),
                                CachedConversationKey {
                                    version: *version_num,
                                    key: key.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        let high_water = self
            .conversation_key_high_water
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let pinned = batch_conversations
            .iter()
            .filter_map(|c| high_water.get(c).copied())
            .max();
        if let Some(version_num) = pinned {
            result.latest_version = Some(version_num.to_string());
        }
    }

    /// Decrypt the conversation key carried in a `ConversationKeyChange` event
    /// using the loaded identity key.
    ///
    /// Tries each participant entry (preferring the one matching our key
    /// version, if known) and returns the first that decrypts with our
    /// identity private key. Returns `None` if locked or none decrypt.
    fn decrypt_key_change_ckey(
        &self,
        kce: &crate::thrift::event::ConversationKeyChangeEvent,
    ) -> Option<XChatConversationKey> {
        let identity = self.keypair_manager.get_identity_keypair().ok()?;
        let participant_keys = kce.conversation_participant_keys.as_ref()?;
        let my_key_version = self.keypair_manager.get_key_version();

        for pk in participant_keys {
            // Skip entries targeting a different key version when ours is known.
            if let Some(ref my_ver) = my_key_version {
                if let Some(ref pk_ver) = pk.public_key_version {
                    if pk_ver != my_ver {
                        continue;
                    }
                }
            }
            let Some(encrypted_b64) = &pk.encrypted_conversation_key else {
                continue;
            };
            let Ok(encrypted_bytes) = base64_decode(encrypted_b64) else {
                continue;
            };
            if let Ok(ckey) =
                conversation_keys::decrypt_conversation_key(&encrypted_bytes, &identity.private)
            {
                return Some(ckey);
            }
        }
        None
    }

    /// Decrypt multiple events in batch.
    ///
    /// This is the recommended API for decrypting messages. It:
    /// 1. Extracts conversation keys from any KeyChange events
    /// 2. For each message, finds the correct signing key by matching sender_id + version
    /// 3. Decrypts the message using the appropriate conversation key
    ///
    /// # Arguments
    /// * `events` - Raw base64-encoded event strings from the webhook
    /// * `signing_keys` - All known signing keys for all participants (with user_id)
    ///
    /// # Returns
    /// A `DecryptEventsResult` containing:
    /// * `messages` - Successfully decrypted messages
    /// * `conversation_keys` - Extracted conversation keys (for caching)
    /// * `errors` - Map of event index → error message for failed decryptions
    pub fn decrypt_events(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
    ) -> DecryptEventsResult {
        // An empty slice falls back to the keys stored via set_signing_keys.
        let signing_keys = self.resolve_signing_keys(signing_keys);
        // Verify signing key bindings — filter out keys with invalid
        // cross-signatures so they can't be used for verification.
        let verified_signing_keys: Vec<SigningKeyEntry> = signing_keys
            .iter()
            .filter(|k| {
                self.verify_key_binding(
                    &k.identity_public_key,
                    &k.public_key,
                    &k.identity_public_key_signature,
                )
                .unwrap_or(false)
            })
            .cloned()
            .collect();

        // First pass: extract conversation keys, then drop any whose key
        // change fails signature enforcement (no-op while held at the max).
        let mut conv_keys_result = self.extract_conversation_keys(events);
        self.enforce_ckey_signatures(
            events,
            &verified_signing_keys,
            &mut conv_keys_result,
            CKEY_SIG_V6_ENFORCE_AFTER_SEQ,
        );
        // Pin the reported latest version to the newest authenticated key
        // change so a replayed older one cannot downgrade what callers encrypt
        // with.
        self.apply_ckey_freshness(events, &verified_signing_keys, &mut conv_keys_result);

        let mut messages = Vec::new();
        let mut errors = HashMap::new();

        // Second pass: decrypt each event
        for (idx, event_b64) in events.iter().enumerate() {
            let parsed = match Self::parse_event_b64(event_b64) {
                Ok(p) => p,
                Err(e) => {
                    errors.insert(idx, e.to_string());
                    continue;
                }
            };

            let sender_signing_keys: Vec<SigningKeyEntry> = match &parsed.sender_id {
                Some(sid) => verified_signing_keys
                    .iter()
                    .filter(|k| &k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };

            match self.decrypt_event_prefiltered(
                &parsed,
                &conv_keys_result.keys,
                &sender_signing_keys,
                &verified_signing_keys,
            ) {
                Ok(event) => {
                    messages.push(DecryptedMessage {
                        event,
                        original_b64: Some((*event_b64).to_string()),
                    });
                }
                Err(e) => {
                    errors.insert(idx, e.to_string());
                }
            }
        }

        DecryptEventsResult {
            messages,
            conversation_keys: conv_keys_result,
            errors,
        }
    }

    /// Decode and Thrift-parse a raw base64 event, so each event is parsed
    /// once and the result shared between sender-key filtering and decryption.
    fn parse_event_b64(event_b64: &str) -> Result<MessageEvent, SdkError> {
        let event_bytes = base64_decode(event_b64)?;
        parse_message_event(&event_bytes)
    }

    /// Decrypt a raw webhook event payload.
    ///
    /// `conversation_keys` is a map of `key_version → conversation_key` from
    /// `extract_conversation_keys()`. For non-message events the map is unused
    /// and may be empty.
    ///
    /// `signing_keys` may contain keys for any set of users (e.g. every
    /// conversation participant); before verification the SDK keeps only the
    /// entries whose identity binding checks out **and** whose `user_id`
    /// matches the event's sender, then picks the one matching the version
    /// embedded in the message signature — the same selection
    /// [`Self::decrypt_events`] applies. Under the default reject-unverified
    /// policy an empty slice makes every signed event fail; only after
    /// [`Self::set_reject_unverified`]`(false)` are such events returned with
    /// `verified: false`.
    pub fn decrypt_event(
        &self,
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        // Empty inputs fall back to the session stores: signing keys from
        // set_signing_keys, conversation keys from the opt-in key cache.
        let signing_keys = self.resolve_signing_keys(signing_keys);
        let parsed = Self::parse_event_b64(event_b64)?;
        let verified_signing_keys: Vec<SigningKeyEntry> = signing_keys
            .iter()
            .filter(|k| {
                self.verify_key_binding(
                    &k.identity_public_key,
                    &k.public_key,
                    &k.identity_public_key_signature,
                )
                .unwrap_or(false)
            })
            .cloned()
            .collect();
        let sender_signing_keys: Vec<SigningKeyEntry> = match &parsed.sender_id {
            Some(sid) => verified_signing_keys
                .iter()
                .filter(|k| &k.user_id == sid)
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        self.decrypt_event_prefiltered(
            &parsed,
            conversation_keys,
            &sender_signing_keys,
            &verified_signing_keys,
        )
    }

    /// [`Self::decrypt_event`] body for an already-parsed event and signing
    /// keys that are already binding-verified: `signing_keys` filtered to the
    /// event's sender, `all_signing_keys` unfiltered (reply-preview
    /// validation verifies raw events from other senders). The batch path
    /// does the binding verification once per batch instead of once per
    /// event.
    fn decrypt_event_prefiltered(
        &self,
        parsed: &MessageEvent,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
        all_signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        let meta = EventMeta {
            sequence_id: parsed.sequence_id.clone(),
            id: parsed.message_id.clone(),
            sender_id: parsed.sender_id.clone(),
            conversation_id: parsed.conversation_id.clone(),
            created_at_msec: parsed
                .created_at_msec
                .as_ref()
                .and_then(|s| s.parse::<i64>().ok()),
        };

        let detail = match &parsed.detail {
            Some(d) => d,
            None => {
                return Ok(Event::Unknown(UnknownEvent {
                    meta,
                    event_type_id: None,
                }))
            }
        };

        let event = match detail {
            MessageEventDetail::ConversationKeyChangeEvent(key_change) => {
                let participant_keys: Vec<ParticipantKey> = key_change
                    .conversation_participant_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|pk| {
                                Some(ParticipantKey {
                                    user_id: pk.user_id.clone()?,
                                    encrypted_key: pk.encrypted_conversation_key.clone()?,
                                    public_key_version: pk
                                        .public_key_version
                                        .clone()
                                        .unwrap_or_default(),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // CKCE v6+ signs the plaintext conversation key. Prefer the
                // caller-supplied key map; otherwise self-decrypt it from this
                // event's participant keys so a standalone KeyChange still
                // verifies without extra caller code. The base64 of the live
                // key is wiped on drop like the sign-path payloads.
                let ckey_version = key_change.conversation_key_version.as_deref().unwrap_or("");
                let ckey_b64 = conversation_keys
                    .get(ckey_version)
                    .map(|k| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(k.encoded())))
                    .or_else(|| {
                        self.decrypt_key_change_ckey(key_change)
                            .map(|k| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(k.encoded())))
                    });
                let sig_result = self.verify_event_signature(
                    parsed,
                    detail,
                    signing_keys,
                    ckey_b64.as_deref().map(String::as_str),
                );
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "KeyChange")?;
                Event::KeyChange(KeyChangeEvent {
                    meta,
                    key_version: key_change
                        .conversation_key_version
                        .clone()
                        .unwrap_or_default(),
                    verified,
                    participant_keys,
                })
            }
            MessageEventDetail::MessageTypingEvent(_) => Event::Typing(TypingEvent { meta }),
            MessageEventDetail::MarkConversationReadEvent(read_event) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "ReadReceipt")?;
                Event::ReadReceipt(ReadReceiptEvent {
                    meta,
                    verified,
                    seen_until_id: read_event.seen_until_sequence_id.clone(),
                    seen_at_msec: read_event.seen_at_millis,
                })
            }
            MessageEventDetail::MarkConversationUnreadEvent(unread_event) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "MarkedUnread")?;
                Event::MarkedUnread(MarkedUnreadEvent {
                    meta,
                    verified,
                    seen_until_id: unread_event.seen_until_sequence_id.clone(),
                })
            }
            MessageEventDetail::MessageDeleteEvent(del_event) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "MessageDelete")?;
                let delete_for_all = del_event
                    .delete_message_action
                    .as_ref()
                    .map(|a| a.0 == 2)
                    .unwrap_or(false);
                Event::MessageDeleted(MessageDeletedEvent {
                    meta,
                    verified,
                    message_ids: del_event.sequence_ids.clone().unwrap_or_default(),
                    delete_for_all,
                })
            }
            MessageEventDetail::ConversationDeleteEvent(conv_del) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "ConversationDelete")?;
                let clear_all = conv_del
                    .clear_conversation_options
                    .as_ref()
                    .and_then(|o| o.clear_all_messages)
                    .unwrap_or(false);
                Event::ConversationDeleted(ConversationDeletedEvent {
                    meta,
                    verified,
                    clear_all_messages: clear_all,
                })
            }
            MessageEventDetail::MessageFailureEvent(failure) => {
                let failure_type = convert_failure_type(failure.failure_type.as_ref());
                Event::Failure(FailureEvent {
                    meta,
                    failure: failure_type,
                    rate_limit_tier: convert_rate_limit_tier(failure.rate_limit_tier.as_ref()),
                })
            }
            MessageEventDetail::MemberAccountDeleteEvent(member_del) => {
                Event::MemberDeleted(MemberDeletedEvent {
                    meta,
                    member_id: member_del.member_id.clone().unwrap_or_default(),
                })
            }
            MessageEventDetail::GroupChangeEvent(group_change) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "GroupChange")?;
                let change = convert_group_change(group_change.group_change.as_ref());
                Event::GroupChange(GroupChangeEvent {
                    meta,
                    verified,
                    change,
                })
            }
            MessageEventDetail::ConversationMetadataChangeEvent(settings) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "SettingsChange")?;
                let change =
                    convert_settings_change(settings.conversation_metadata_change.as_ref());
                Event::SettingsChange(SettingsChangeEvent {
                    meta,
                    verified,
                    change,
                })
            }
            MessageEventDetail::MessageCreateEvent(mce) => {
                let contents = match &mce.contents {
                    Some(c) => c,
                    None => {
                        return Ok(Event::Unknown(UnknownEvent {
                            meta,
                            event_type_id: Some(1),
                        }))
                    }
                };

                // Unencrypted MCE: conversation_key_version is None — contents
                // are already plaintext Thrift bytes, no signature to verify.
                let is_unencrypted = mce.conversation_key_version.is_none();

                // Verify before decrypt so that an invalid signature never
                // results in plaintext being returned (when reject_unverified).
                // Unencrypted messages carry no signature, so they are treated
                // as unverifiable and rejected under reject_unverified too.
                let (verified, sig_result) = if is_unencrypted {
                    (false, Ok(false))
                } else {
                    let r = self.verify_event_signature(parsed, detail, signing_keys, None);
                    let v = matches!(r, Ok(true));
                    (v, r)
                };

                self.reject_if_unverified(&sig_result, "Message")?;

                let plaintext = if is_unencrypted {
                    contents.clone()
                } else {
                    let version = mce.conversation_key_version.as_deref().unwrap_or("");
                    // The caller-supplied map wins; the opt-in key cache
                    // covers callers that no longer hold the key map.
                    let cached;
                    let ckey = match conversation_keys.get(version) {
                        Some(k) => k,
                        None => {
                            cached = parsed
                                .conversation_id
                                .as_deref()
                                .and_then(|cid| self.cached_key_for(cid, version));
                            cached.as_ref().ok_or_else(|| {
                                let available = conversation_keys
                                    .keys()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                SdkError::Crypto(CryptoError::DecryptionFailed(format!(
                                    "Message encrypted with key version '{}' but no matching key \
                                     found. Available versions: [{}]. Include the conversation's \
                                     KeyChange events in the batch passed to decrypt_events(), \
                                     or pass the matching key map to decrypt_event().",
                                    version, available
                                )))
                            })?
                        }
                    };
                    decrypt_message_bytes(ckey, contents)?
                };

                let parsed_content = parse_message_content(&plaintext)?;

                // A preview that embeds its raw source event is always
                // validated; without one it passes through unvalidated.
                let reply_preview_validation = parsed_content
                    .raw_reply_preview
                    .as_ref()
                    .filter(|p| p.raw_event_message_create.is_some())
                    .map(|p| {
                        self.validate_reply_preview(parsed, p, conversation_keys, all_signing_keys)
                    });

                Event::Message(Box::new(Message {
                    meta,
                    content: parsed_content.content,
                    key_version: mce.conversation_key_version.clone(),
                    verified,
                    should_notify: mce.should_notify,
                    ttl_msec: mce.ttl_msec,
                    attachments: parsed_content.attachments,
                    media_hashes: parsed_content.media_hashes,
                    reply_preview_validation,
                }))
            }
            _ => Event::Unknown(UnknownEvent {
                meta,
                event_type_id: None,
            }),
        };

        Ok(event)
    }

    // Message Encryption

    /// Parse a raw conversation key supplied in a params struct.
    fn conversation_key_from_bytes(bytes: &[u8]) -> Result<XChatConversationKey, SdkError> {
        XChatConversationKey::from_bytes(bytes.to_vec())
            .ok_or_else(|| SdkError::Parse("Invalid conversation key (expected 32 bytes)".into()))
    }

    /// Encrypt a text message.
    pub fn encrypt_message(
        &self,
        mut params: EncryptMessageParams,
    ) -> Result<SendPayload, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &params.conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        // `take()` rather than a destructuring move: the params type zeroizes
        // its key on drop, which rules out moving fields.
        let thrift_entities = params
            .entities
            .take()
            .map(|e| crate::pipeline::build_thrift_entities(&e));
        if let Some(a) = params.attachments.as_deref() {
            crate::pipeline::validate_attachment_descriptors(a)?;
        }
        let thrift_attachments = params
            .attachments
            .take()
            .map(|a| crate::pipeline::build_thrift_attachments(&a));
        let content_bytes = crate::pipeline::build_message_content(
            &params.text,
            thrift_entities,
            thrift_attachments,
        )?;

        let message_id = Self::generate_message_id();
        let mut api_params = crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &params.conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        );
        api_params.should_notify = params.should_notify;
        api_params.ttl_msec = params.ttl_msec;
        crate::pipeline::encrypt_and_sign(api_params)
    }

    /// Encrypt a reply.
    ///
    /// When `reply_to_event` is set, the reply preview (sequence id, sender,
    /// text, entities, attachments) is derived from that raw signed event and
    /// the event itself is embedded so recipients can validate the preview.
    /// Explicit `reply_to_*` fields override the derived values.
    pub fn encrypt_reply(&self, mut params: EncryptReplyParams) -> Result<SendPayload, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &params.conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        // `take()` rather than a destructuring move: the params type zeroizes
        // its key on drop, which rules out moving fields.
        let thrift_entities = params
            .entities
            .take()
            .map(|e| crate::pipeline::build_thrift_entities(&e));
        if let Some(a) = params.attachments.as_deref() {
            crate::pipeline::validate_attachment_descriptors(a)?;
        }
        let thrift_attachments = params
            .attachments
            .take()
            .map(|a| crate::pipeline::build_thrift_attachments(&a));

        let preview = self.build_reply_preview(&mut params, &ckey, &conversation_key_version)?;

        let content_bytes = crate::pipeline::build_message_content_with_preview(
            &params.text,
            preview,
            thrift_entities,
            thrift_attachments,
        )?;

        let message_id = Self::generate_message_id();
        let mut api_params = crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &params.conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        );
        api_params.should_notify = params.should_notify;
        api_params.ttl_msec = params.ttl_msec;
        crate::pipeline::encrypt_and_sign(api_params)
    }

    /// Encrypt a reaction-add.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_add_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_reaction_target(params)?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let content_bytes =
            crate::pipeline::build_reaction_add_content(&target_sequence_id, &params.emoji)?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        ))
    }

    /// Encrypt a reaction-remove.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_remove_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_reaction_target(params)?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let content_bytes =
            crate::pipeline::build_reaction_remove_content(&target_sequence_id, &params.emoji)?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        ))
    }

    /// Encrypt a message edit.
    ///
    /// The edit replaces the target message's text (and entities) for every
    /// recipient; it is sent through the same message-create channel as a
    /// regular message and carries its own fresh message id.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_edit(&self, params: &EncryptEditParams) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_event_target(
            params.target_event.as_deref(),
            params.conversation_id.as_deref(),
            params.target_message_sequence_id.as_deref(),
        )?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let content_bytes = crate::pipeline::build_message_edit_content(
            &target_sequence_id,
            &params.updated_text,
            params.entities.as_deref(),
        )?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        ))
    }

    /// Build the signed action for deleting messages from a conversation.
    ///
    /// A delete is a plaintext `MessageDeleteEvent`, not an encrypted
    /// message: the result carries the encoded event detail and its
    /// signature, ready to submit alongside the delete request. The SDK
    /// generates the action's message id; read it back from the result.
    pub fn prepare_message_delete(
        &self,
        params: &MessageDeleteParams,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        if params.sequence_ids.is_empty() {
            return Err(SdkError::InvalidState(
                "sequence_ids is empty: pass at least one message to delete".into(),
            ));
        }
        if params.sequence_ids.iter().any(String::is_empty) {
            return Err(SdkError::InvalidState(
                "sequence_ids contains an empty id: every entry must name a message".into(),
            ));
        }
        if params.conversation_id.is_empty() {
            return Err(SdkError::InvalidState(
                "conversation_id is empty: pass the conversation the messages belong to".into(),
            ));
        }
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let conversation_id =
            crate::pipeline::canonical_conversation_id(&params.conversation_id, &sender_id);
        let signing_key = self.get_signing_private_key()?;

        let delete_action = if params.delete_for_all {
            crate::thrift::event::DeleteMessageAction::DELETE_FOR_ALL
        } else {
            crate::thrift::event::DeleteMessageAction::DELETE_FOR_SELF
        };
        let message_id = Self::generate_message_id();
        let mut signature = crate::signatures::build_message_delete_signature(
            &signing_key,
            &signing_key_version,
            &message_id,
            &sender_id,
            &conversation_id,
            &params.sequence_ids,
            delete_action.0,
        )?;
        signature.encoded_message_event_detail =
            Self::encode_message_delete_detail(&params.sequence_ids, delete_action)?;
        Ok(signature)
    }

    /// Serialize the `MessageDeleteEvent` the API validates and relays.
    ///
    /// Encoded as a base64 `MessageEventDetail` carrying the sequence ids and
    /// the delete action.
    fn encode_message_delete_detail(
        sequence_ids: &[String],
        delete_action: crate::thrift::event::DeleteMessageAction,
    ) -> Result<String, SdkError> {
        let detail = crate::thrift::event::MessageEventDetail::MessageDeleteEvent(
            crate::thrift::event::MessageDeleteEvent {
                sequence_ids: Some(sequence_ids.to_vec()),
                delete_message_action: Some(delete_action),
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Resolve a reaction's conversation id and target sequence id from the
    /// explicit fields or, when unset, from the parsed `target_event`.
    fn resolve_reaction_target(
        params: &EncryptReactionParams,
    ) -> Result<(String, String), SdkError> {
        Self::resolve_event_target(
            params.target_event.as_deref(),
            params.conversation_id.as_deref(),
            params.target_message_sequence_id.as_deref(),
        )
    }

    /// Resolve a target message's conversation id and sequence id from the
    /// explicit fields or, when unset, from the parsed `target_event`.
    fn resolve_event_target(
        target_event: Option<&str>,
        conversation_id: Option<&str>,
        target_message_sequence_id: Option<&str>,
    ) -> Result<(String, String), SdkError> {
        let explicit_conv = conversation_id.filter(|v| !v.is_empty());
        let explicit_seq = target_message_sequence_id.filter(|v| !v.is_empty());
        if let (Some(conv), Some(seq)) = (explicit_conv, explicit_seq) {
            return Ok((conv.to_string(), seq.to_string()));
        }

        let parsed = match target_event.filter(|v| !v.is_empty()) {
            Some(event_b64) => Some(Self::parse_event_b64(event_b64)?),
            None => None,
        };
        let conversation_id = match explicit_conv {
            Some(v) => v.to_string(),
            None => parsed
                .as_ref()
                .and_then(|p| p.conversation_id.clone())
                .ok_or_else(|| {
                    SdkError::InvalidState(
                        "conversation_id is not set: pass target_event or conversation_id".into(),
                    )
                })?,
        };
        let target_sequence_id = match explicit_seq {
            Some(v) => v.to_string(),
            None => parsed
                .as_ref()
                .and_then(|p| p.sequence_id.clone())
                .ok_or_else(|| {
                    SdkError::InvalidState(
                        "target_message_sequence_id is not set: pass target_event or \
                         target_message_sequence_id"
                            .into(),
                    )
                })?,
        };
        Ok((conversation_id, target_sequence_id))
    }

    /// Parse decrypted content bytes into the wire-level entry contents.
    fn parse_thrift_entry_contents(data: &[u8]) -> Result<MessageEntryContents, SdkError> {
        let cursor = Cursor::new(data);
        let mut raw = TBinaryInputProtocol::new(cursor, true);
        let mut protocol = BoundedProtocol::new(&mut raw);
        let holder = MessageEntryHolder::read_from_in_protocol(&mut protocol)
            .map_err(|e| SdkError::Parse(format!("Content parse error: {}", e)))?;
        holder
            .contents
            .map(|c| *c)
            .ok_or_else(|| SdkError::Parse("content carries no entry".into()))
    }

    /// Parse decrypted content bytes into the wire-level `MessageContents`.
    ///
    /// Errors when the content is not a text message (reactions, edits, and
    /// markers cannot anchor a reply preview).
    fn parse_thrift_message_contents(
        data: &[u8],
    ) -> Result<crate::thrift::product::MessageContents, SdkError> {
        match Self::parse_thrift_entry_contents(data)? {
            MessageEntryContents::Message(msg) => Ok(*msg),
            _ => Err(SdkError::Parse("reply target is not a text message".into())),
        }
    }

    /// Parse decrypted content bytes into the wire-level `MessageEdit`.
    fn parse_thrift_message_edit(
        data: &[u8],
    ) -> Result<crate::thrift::product::MessageEdit, SdkError> {
        match Self::parse_thrift_entry_contents(data)? {
            MessageEntryContents::MessageEdit(edit) => Ok(*edit),
            _ => Err(SdkError::Parse("edit event is not a message edit".into())),
        }
    }

    /// Decrypt the contents of a raw `MessageCreateEvent`, resolving the key
    /// from the reply's own key, the supplied key-change events, or the key
    /// cache.
    ///
    /// A wrong key cannot yield wrong plaintext — the cipher authenticates —
    /// so key-change events are usable here without their own verification.
    fn decrypt_raw_event_contents(
        &self,
        raw: &MessageEvent,
        outer_key: Option<&XChatConversationKey>,
        outer_version: Option<&str>,
        key_changes: &[MessageEvent],
        extra_keys: &HashMap<String, XChatConversationKey>,
    ) -> Result<Vec<u8>, SdkError> {
        let Some(MessageEventDetail::MessageCreateEvent(mce)) = &raw.detail else {
            return Err(SdkError::Parse(
                "raw event is not a MessageCreateEvent".into(),
            ));
        };
        let contents = mce
            .contents
            .as_ref()
            .ok_or_else(|| SdkError::Parse("raw event has no contents".into()))?;
        // No key version means the contents are already plaintext.
        let Some(version) = mce.conversation_key_version.as_deref() else {
            return Ok(contents.clone());
        };

        if let Some(key) = extra_keys.get(version) {
            return Ok(decrypt_message_bytes(key, contents)?);
        }
        if outer_version == Some(version) {
            if let Some(key) = outer_key {
                return Ok(decrypt_message_bytes(key, contents)?);
            }
        }
        if let Some(conv_id) = raw.conversation_id.as_deref() {
            if let Some(key) = self.cached_key_for(conv_id, version) {
                return Ok(decrypt_message_bytes(&key, contents)?);
            }
        }
        for kce_event in key_changes {
            let Some(MessageEventDetail::ConversationKeyChangeEvent(kce)) = &kce_event.detail
            else {
                continue;
            };
            if kce.conversation_key_version.as_deref() != Some(version) {
                continue;
            }
            if let Some(key) = self.decrypt_key_change_ckey(kce) {
                return Ok(decrypt_message_bytes(&key, contents)?);
            }
        }
        Err(SdkError::Crypto(CryptoError::DecryptionFailed(format!(
            "no conversation key for version '{}' of the replied-to message; \
             pass reply_to_ckces with its key-change event",
            version
        ))))
    }

    /// Build the wire `ReplyingToPreview` for an outgoing reply.
    ///
    /// When `reply_to_event` is set, the preview fields are derived from the
    /// decrypted original and the raw signed event is embedded so recipients
    /// can validate the preview; explicit `reply_to_*` fields override the
    /// derived values. Without it, the preview is built from the explicit
    /// fields alone.
    fn build_reply_preview(
        &self,
        params: &mut EncryptReplyParams,
        outer_key: &XChatConversationKey,
        outer_version: &str,
    ) -> Result<crate::thrift::product::ReplyingToPreview, SdkError> {
        let thrift_reply_entities = params
            .reply_to_entities
            .take()
            .map(|e| crate::pipeline::build_thrift_entities(&e))
            .map(|v| v.into_iter().map(|b| *b).collect::<Vec<_>>());
        // The attachment-combination guard deliberately does not apply here:
        // a reply preview mirrors an already-sent original (which receivers
        // validate against the embedded raw event), so rejecting it would
        // block replying to messages from clients that sent such lists.
        let thrift_reply_attachments = params
            .reply_to_attachments
            .take()
            .map(|a| crate::pipeline::build_thrift_attachments(&a));
        let explicit_sequence_id = params.reply_to_sequence_id.take().filter(|v| !v.is_empty());

        let Some(raw_b64) = params.reply_to_event.take().filter(|v| !v.is_empty()) else {
            let sequence_id = explicit_sequence_id.ok_or_else(|| {
                SdkError::InvalidState(
                    "reply target is not set: pass reply_to_event or reply_to_sequence_id".into(),
                )
            })?;
            return Ok(crate::thrift::product::ReplyingToPreview::new(
                params.reply_to_sender_id,
                params.reply_to_text.take(),
                thrift_reply_entities,
                thrift_reply_attachments,
                None::<String>,
                Some(sequence_id),
                None::<String>,
                None,
                None,
                None,
                None,
                None,
            ));
        };

        let raw = Self::parse_event_b64(&raw_b64)?;
        let edit_event = match params.reply_to_edit_event.take().filter(|v| !v.is_empty()) {
            Some(b64) => Some(Self::parse_event_b64(&b64)?),
            None => None,
        };
        let key_changes: Vec<MessageEvent> = params
            .reply_to_ckces
            .take()
            .unwrap_or_default()
            .iter()
            .filter(|b64| !b64.is_empty())
            .map(|b64| Self::parse_event_b64(b64))
            .collect::<Result<_, _>>()?;

        // Each override stands on its own: the original is decrypted whenever
        // any preview field is left unset, and skipped only when the
        // overrides cover every derived field.
        let need_original = params.reply_to_text.is_none()
            || thrift_reply_entities.is_none()
            || thrift_reply_attachments.is_none();
        let original = if need_original {
            let plaintext = self.decrypt_raw_event_contents(
                &raw,
                Some(outer_key),
                Some(outer_version),
                &key_changes,
                &HashMap::new(),
            )?;
            Some(Self::parse_thrift_message_contents(&plaintext)?)
        } else {
            None
        };

        // When the original was edited, the preview quotes what the message
        // says now, so text and entities derive from the edit's contents;
        // attachments stay with the original (edits do not carry them).
        let edited = match &edit_event {
            Some(edit) if params.reply_to_text.is_none() || thrift_reply_entities.is_none() => {
                let plaintext = self.decrypt_raw_event_contents(
                    edit,
                    Some(outer_key),
                    Some(outer_version),
                    &key_changes,
                    &HashMap::new(),
                )?;
                Some(Self::parse_thrift_message_edit(&plaintext)?)
            }
            _ => None,
        };

        let sequence_id = explicit_sequence_id
            .or_else(|| raw.sequence_id.clone())
            .ok_or_else(|| SdkError::Parse("reply_to_event carries no sequence_id".into()))?;
        let sender_id = params
            .reply_to_sender_id
            .or_else(|| raw.sender_id.as_deref().and_then(|s| s.parse::<i64>().ok()));
        let message_text = params.reply_to_text.take().or_else(|| match &edited {
            Some(edit) => edit.updated_text.clone(),
            None => original.as_ref().and_then(|m| m.message_text.clone()),
        });
        let entities = thrift_reply_entities.or_else(|| match &edited {
            Some(edit) => edit.entities.clone(),
            None => original
                .as_ref()
                .and_then(|m| m.entities.as_ref())
                .map(|e| e.iter().map(|b| (**b).clone()).collect()),
        });
        let attachments = thrift_reply_attachments
            .or_else(|| original.as_ref().and_then(|m| m.attachments.clone()));

        // A key-change event is only useful to a recipient when it carries a
        // key version this reply's own version does not already imply.
        let embedded_ckces: Vec<MessageEvent> = key_changes
            .into_iter()
            .filter(|e| match &e.detail {
                Some(MessageEventDetail::ConversationKeyChangeEvent(kce)) => {
                    kce.conversation_key_version.as_deref() != Some(outer_version)
                }
                _ => false,
            })
            .collect();

        Ok(crate::thrift::product::ReplyingToPreview::new(
            sender_id,
            message_text,
            entities,
            attachments,
            None::<String>,
            Some(sequence_id),
            raw.message_id.clone(),
            raw,
            edit_event,
            (!embedded_ckces.is_empty()).then_some(embedded_ckces),
            None,
            None,
        ))
    }

    /// Validate a received reply preview against the raw signed original
    /// event embedded in it: verify the raw event's signature, decrypt its
    /// contents, and check every claim the preview makes against the
    /// decrypted original.
    fn validate_reply_preview(
        &self,
        outer: &MessageEvent,
        preview: &crate::thrift::product::ReplyingToPreview,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        all_signing_keys: &[SigningKeyEntry],
    ) -> ReplyPreviewValidation {
        let Some(raw) = preview.raw_event_message_create.as_ref() else {
            return ReplyPreviewValidation::Invalid;
        };
        // The original must belong to the same conversation as the reply;
        // otherwise a participant could attribute words from elsewhere.
        if raw.conversation_id.is_none() || raw.conversation_id != outer.conversation_id {
            return ReplyPreviewValidation::Invalid;
        }
        let Some(raw_detail) = raw.detail.as_ref() else {
            return ReplyPreviewValidation::Invalid;
        };
        if !matches!(raw_detail, MessageEventDetail::MessageCreateEvent(_)) {
            return ReplyPreviewValidation::Invalid;
        }
        // Same key selection as top-level events: filter to the raw event's
        // sender, then match the version embedded in its signature.
        let sender_keys: Vec<SigningKeyEntry> = match raw.sender_id.as_deref() {
            Some(sid) => all_signing_keys
                .iter()
                .filter(|k| k.user_id == sid)
                .cloned()
                .collect(),
            None => return ReplyPreviewValidation::Invalid,
        };
        if !matches!(
            self.verify_event_signature(raw, raw_detail, &sender_keys, None),
            Ok(true)
        ) {
            return ReplyPreviewValidation::Invalid;
        }

        let embedded_ckces: Vec<MessageEvent> = preview.raw_event_ckces.clone().unwrap_or_default();
        let Ok(plaintext) =
            self.decrypt_raw_event_contents(raw, None, None, &embedded_ckces, conversation_keys)
        else {
            return ReplyPreviewValidation::Invalid;
        };
        let Ok(original) = Self::parse_thrift_message_contents(&plaintext) else {
            return ReplyPreviewValidation::Invalid;
        };

        if let Some(claimed_sender) = preview.sender_id {
            if raw.sender_id.as_deref() != Some(claimed_sender.to_string().as_str()) {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_seq) = preview.replying_to_message_sequence_id.as_deref() {
            if raw.sequence_id.as_deref() != Some(claimed_seq) {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_id) = preview.replying_to_message_id.as_deref() {
            if raw.message_id.as_deref() != Some(claimed_id) {
                return ReplyPreviewValidation::Invalid;
            }
        }

        // When an edit event is embedded, the preview quotes the edited
        // contents, so the text and entity claims are checked against the
        // edit; the edit itself must verify like the original and come from
        // the original's author. Attachment claims always check against the
        // original (edits do not carry attachments).
        let edited = match preview.raw_event_edit_message.as_ref() {
            None => None,
            Some(edit) => {
                if edit.conversation_id.is_none()
                    || edit.conversation_id != outer.conversation_id
                    || edit.sender_id.is_none()
                    || edit.sender_id != raw.sender_id
                {
                    return ReplyPreviewValidation::Invalid;
                }
                let Some(edit_detail) = edit.detail.as_ref() else {
                    return ReplyPreviewValidation::Invalid;
                };
                if !matches!(edit_detail, MessageEventDetail::MessageCreateEvent(_)) {
                    return ReplyPreviewValidation::Invalid;
                }
                if !matches!(
                    self.verify_event_signature(edit, edit_detail, &sender_keys, None),
                    Ok(true)
                ) {
                    return ReplyPreviewValidation::Invalid;
                }
                let Ok(edit_plaintext) = self.decrypt_raw_event_contents(
                    edit,
                    None,
                    None,
                    &embedded_ckces,
                    conversation_keys,
                ) else {
                    return ReplyPreviewValidation::Invalid;
                };
                let Ok(edit_contents) = Self::parse_thrift_message_edit(&edit_plaintext) else {
                    return ReplyPreviewValidation::Invalid;
                };
                Some(edit_contents)
            }
        };
        let quoted_text = match &edited {
            Some(edit) => edit.updated_text.as_deref(),
            None => original.message_text.as_deref(),
        };
        let quoted_entities: Vec<&crate::thrift::product::RichTextEntity> = match &edited {
            Some(edit) => edit.entities.iter().flatten().collect(),
            None => original
                .entities
                .iter()
                .flatten()
                .map(|b| b.as_ref())
                .collect(),
        };

        if let Some(claimed_text) = preview.message_text.as_deref() {
            let quoted_text = quoted_text.unwrap_or("");
            // Previews may be truncated on the wire, so a claim is valid when
            // it matches the quoted contents up to the preview's own length
            // (on a character boundary).
            if !quoted_text.is_char_boundary(claimed_text.len())
                || !quoted_text.starts_with(claimed_text)
            {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_entities) = preview.entities.as_ref() {
            for entity in claimed_entities {
                if !quoted_entities.contains(&entity) {
                    return ReplyPreviewValidation::Invalid;
                }
            }
        }
        if let Some(claimed_attachments) = preview.attachments.as_ref() {
            let original_attachments = original.attachments.as_deref().unwrap_or(&[]);
            for attachment in claimed_attachments {
                if !original_attachments.contains(attachment) {
                    return ReplyPreviewValidation::Invalid;
                }
            }
        }
        ReplyPreviewValidation::Valid
    }

    // Stream (Media)

    /// Encrypt a stream.
    pub fn encrypt_stream(
        &self,
        plaintext: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        let mut reader = Cursor::new(plaintext);
        let mut output: Vec<u8> = Vec::new();
        crate::crypto::encryption::encrypt_stream(conversation_key, &mut reader, &mut output)?;
        Ok(output)
    }

    /// Decrypt a stream.
    pub fn decrypt_stream(
        &self,
        encrypted: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        let mut reader = Cursor::new(encrypted);
        let mut output: Vec<u8> = Vec::new();
        crate::crypto::encryption::decrypt_stream(conversation_key, &mut reader, &mut output)?;
        Ok(output)
    }

    /// Create an incremental stream encryptor for large payloads.
    pub fn stream_encryptor(
        &self,
        conversation_key: &XChatConversationKey,
    ) -> Result<crate::crypto::encryption::StreamEncryptor, SdkError> {
        Ok(crate::crypto::encryption::StreamEncryptor::new(
            conversation_key,
        )?)
    }

    /// Create an incremental stream decryptor for large payloads.
    pub fn stream_decryptor(
        &self,
        conversation_key: &XChatConversationKey,
    ) -> Result<crate::crypto::encryption::StreamDecryptor, SdkError> {
        Ok(crate::crypto::encryption::StreamDecryptor::new(
            conversation_key,
        )?)
    }

    /// Encrypt a UTF-8 string using XSalsa20-Poly1305 and return base64.
    ///
    /// Use this for encrypting metadata fields like group names, descriptions,
    /// and avatar URLs before sending them to the API. The result is base64
    /// rather than raw bytes because it is an API-edge value sent verbatim.
    pub fn encrypt(
        &self,
        plaintext: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        let ciphertext =
            crate::crypto::encryption::encrypt_message(conversation_key, plaintext.as_bytes())?;
        Ok(crate::protocol::serialization::base64_encode(&ciphertext))
    }

    /// Decrypt a base64-encoded XSalsa20-Poly1305 ciphertext and return the
    /// UTF-8 plaintext string.
    ///
    /// Use this for decrypting metadata fields like group names, descriptions,
    /// and avatar URLs returned by the API. The input is base64 rather than raw
    /// bytes because it is an API-edge value consumed verbatim.
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        let ciphertext = crate::protocol::serialization::base64_decode(ciphertext_b64)?;
        let plaintext = crate::crypto::encryption::decrypt_message(conversation_key, &ciphertext)?;
        String::from_utf8(plaintext)
            .map_err(|e| SdkError::Parse(format!("Decrypted data is not valid UTF-8: {}", e)))
    }

    // Signing

    /// Sign arbitrary data.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SdkError> {
        let signing = self.keypair_manager.get_signing_keypair()?;
        let signature = KeyFactory::sign(&signing.private, data)?;
        Ok(signature)
    }

    /// Verify a signature.
    pub fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, SdkError> {
        let pk_bytes = base64_decode(public_key_b64)?;
        let raw_pk = if pk_bytes.len() == 91 {
            &pk_bytes[26..]
        } else {
            &pk_bytes
        };
        let public_key = KeyFactory::reconstruct_public_key(raw_pk, KeypairPurpose::Signing)?;
        Ok(KeyFactory::verify(&public_key, signature, data)?)
    }

    /// Build and sign a GroupMemberAdd action signature.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_add_members(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        conversation_id: &str,
        new_member_ids: &[String],
        current_member_ids: &[String],
        current_admin_ids: &[String],
        conversation_key_version: &str,
        current_title: Option<&str>,
        current_avatar_url: Option<&str>,
        current_ttl_msec: Option<i64>,
        current_screen_capture_blocking_enabled: Option<bool>,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::build_group_member_add_signature(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            conversation_id,
            new_member_ids,
            current_member_ids,
            current_admin_ids,
            current_title,
            current_avatar_url,
            current_ttl_msec,
            current_screen_capture_blocking_enabled,
            conversation_key_version,
        )
    }

    /// Build and sign a GroupCreate action signature.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_group_create(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        member_ids: &[String],
        title: Option<&str>,
        avatar_url: Option<&str>,
        conversation_key_version: &str,
        is_legacy_group_upgrade: Option<bool>,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::build_group_create_signature(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            member_ids,
            title,
            avatar_url,
            conversation_key_version,
            is_legacy_group_upgrade,
        )
    }

    /// Build and sign a ConversationKeyChange action signature (v7).
    ///
    /// `conversation_key` is the raw 32-byte conversation key.
    pub(crate) fn sign_key_change(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        conversation_id: &str,
        conversation_key_version: &str,
        conversation_key: &[u8],
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::build_ckey_change_signature(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            conversation_id,
            conversation_key_version,
            conversation_key,
        )
    }

    // Internal helpers

    fn get_signing_keypair_arc(&self) -> Result<std::sync::Arc<XChatKeyPair>, SdkError> {
        Ok(self.keypair_manager.get_signing_keypair()?)
    }

    fn get_signing_private_key(&self) -> Result<XChatPrivateKey, SdkError> {
        let signing = self.keypair_manager.get_signing_keypair()?;
        Ok(signing.private.clone())
    }

    /// Enforce `reject_unverified` policy on a signature result.
    ///
    /// When `reject_unverified` is enabled, both `Err(reason)` (signature
    /// present but cryptographically invalid) and `Ok(false)` (signature
    /// missing or no matching key) are rejected for event types that carry
    /// a signature.
    fn reject_if_unverified(
        &self,
        sig_result: &Result<bool, String>,
        event_label: &str,
    ) -> Result<(), SdkError> {
        if !self.reject_unverified {
            return Ok(());
        }
        match sig_result {
            Ok(true) => Ok(()),
            Ok(false) => Err(SdkError::Crypto(CryptoError::VerificationFailed(format!(
                "{} signature could not be verified: \
                 signature missing or no matching signing key",
                event_label
            )))),
            Err(reason) => Err(SdkError::Crypto(CryptoError::VerificationFailed(format!(
                "{} signature verification failed: {}",
                event_label, reason
            )))),
        }
    }

    /// Verify a message event signature against a set of signing keys.
    ///
    /// Selects the key whose `public_key_version` matches the version embedded
    /// in the event's `MessageEventSignature`. Returns `Ok(false)` when no
    /// matching key is available (not verifiable, but not invalid).
    ///
    /// `plaintext_ckey_b64` is needed for CKCE v6+ verification — pass the
    /// base64-no-padding of the decrypted conversation key, or None for other
    /// event types.
    fn verify_event_signature(
        &self,
        parsed: &crate::thrift::event::MessageEvent,
        detail: &crate::thrift::event::MessageEventDetail,
        signing_keys: &[SigningKeyEntry],
        plaintext_ckey_b64: Option<&str>,
    ) -> Result<bool, String> {
        let sig_data = match &parsed.message_event_signature {
            Some(sig) => sig,
            None => return Ok(false),
        };
        let signature_b64 = match &sig_data.signature {
            Some(s) => s,
            None => return Ok(false),
        };

        // Missing version is treated as current.
        let sig_version = sig_data
            .signature_version
            .as_deref()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);
        if sig_version < crate::signatures::MIN_SIGNATURE_VERSION {
            return Err(format!(
                "signature_version {} is no longer accepted (minimum: {})",
                sig_version,
                crate::signatures::MIN_SIGNATURE_VERSION
            ));
        }

        let key_version = sig_data.public_key_version.as_deref().unwrap_or("");
        let signing_key_b64 = match signing_keys
            .iter()
            .find(|e| e.public_key_version == key_version)
            .map(|e| e.public_key.as_str())
        {
            Some(k) => k,
            None => return Ok(false),
        };

        let payload = match build_event_signature_payload(parsed, detail, plaintext_ckey_b64) {
            Some(p) => p,
            None => return Ok(false),
        };

        let sig_bytes = base64_decode_or_empty(signature_b64);
        match self.verify(signing_key_b64, &sig_bytes, &payload) {
            Ok(true) => Ok(true),
            Ok(false) => Err(format!(
                "ECDSA mismatch: key_version={}, payload_len={}",
                key_version,
                payload.len()
            )),
            Err(e) => Err(format!("verify error: {}", e)),
        }
    }

    fn public_key_spki_bytes(
        public_key: &crate::crypto::keys::XChatPublicKey,
    ) -> Result<Vec<u8>, SdkError> {
        let pk = p256::PublicKey::from_sec1_bytes(public_key.encoded())
            .map_err(|e| SdkError::Parse(format!("Invalid public key: {}", e)))?;
        let spki = pk
            .to_public_key_der()
            .map_err(|e| SdkError::Parse(format!("SPKI encode error: {}", e)))?;
        Ok(spki.as_bytes().to_vec())
    }

    /// Compute a fingerprint from SPKI-encoded public key bytes.
    ///
    /// The fingerprint is `URL_SAFE_NO_PAD(SHA-256(spki_bytes))`.
    fn compute_public_key_fingerprint(spki_bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let hash = crate::crypto::hash::sha256(spki_bytes);
        URL_SAFE_NO_PAD.encode(hash)
    }
}

impl Default for ChatCore {
    fn default() -> Self {
        Self::new()
    }
}

fn base64_decode_or_empty(s: &str) -> Vec<u8> {
    base64_decode(s).unwrap_or_default()
}

/// Current time as a millisecond-timestamp string, used for key versions.
///
/// Reads the system clock, which panics on `wasm32-unknown-unknown`; WASM hosts
/// call the `*_with_version` variants and supply the timestamp from JavaScript.
fn now_millis() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}
pub(crate) fn parse_message_event(data: &[u8]) -> Result<MessageEvent, SdkError> {
    let cursor = Cursor::new(data);
    let mut raw = TBinaryInputProtocol::new(cursor, true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    MessageEvent::read_from_in_protocol(&mut protocol)
        .map_err(|e| SdkError::Parse(format!("Thrift parse error: {}", e)))
}

// Signature payload builders

/// Build the comma-separated signature payload for an event.
///
/// Returns `None` for event types that are not signed (typing, failure,
/// member account delete).
///
/// `plaintext_ckey_b64` is required for CKCE v6+ verification — pass the
/// base64-no-padding encoding of the decrypted conversation key bytes.
///
/// The result is zeroized on drop: a CKCE v6+ payload embeds the plaintext
/// conversation key, so the reconstruction gets the same hygiene as the
/// signing path.
pub fn build_event_signature_payload(
    event: &crate::thrift::event::MessageEvent,
    detail: &crate::thrift::event::MessageEventDetail,
    plaintext_ckey_b64: Option<&str>,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    use crate::thrift::event::{GroupChange as GenGC, MessageEventDetail};
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    let msg_id = event.message_id.as_deref()?;
    let sender_id = event.sender_id.as_deref()?;
    let conv_id = event.conversation_id.as_deref();

    let sig_version = event
        .message_event_signature
        .as_ref()
        .and_then(|s| s.signature_version.as_deref())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);

    match detail {
        MessageEventDetail::MessageCreateEvent(mce) => {
            // Versions below MIN_SIGNATURE_VERSION use an unverifiable payload
            // form, so reject them before reaching the verifier.
            if sig_version < crate::signatures::MIN_SIGNATURE_VERSION {
                return None;
            }
            let contents = mce.contents.as_ref()?;
            let contents_b64 = STANDARD_NO_PAD.encode(contents);
            let ckey_ver = mce.conversation_key_version.as_deref().unwrap_or("");
            build_component_payload(
                "MessageCreateEvent",
                msg_id,
                sender_id,
                conv_id,
                &[ckey_ver, &contents_b64],
            )
        }
        MessageEventDetail::ConversationKeyChangeEvent(ckce) => {
            let ckey_ver = ckce.conversation_key_version.as_deref()?;

            if sig_version >= crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION {
                // sign the plaintext conversation key bytes (base64 no-padding).
                let ckey_b64 = plaintext_ckey_b64?;
                build_component_payload(
                    "ConversationKeyChangeEvent",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[ckey_ver, ckey_b64],
                )
            } else {
                // pre-v6: sign the per-participant encrypted key triplets.
                let keys = ckce.conversation_participant_keys.as_ref()?;
                let mut extra: Vec<&str> = vec![ckey_ver];
                let parts: Vec<String> = keys
                    .iter()
                    .flat_map(|pk| {
                        vec![
                            pk.user_id.clone().unwrap_or_default(),
                            pk.encrypted_conversation_key.clone().unwrap_or_default(),
                            pk.public_key_version.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                let part_refs: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
                extra.extend(part_refs);
                build_component_payload(
                    "ConversationKeyChangeEvent",
                    msg_id,
                    sender_id,
                    conv_id,
                    &extra,
                )
            }
        }
        MessageEventDetail::MessageDeleteEvent(del) => {
            let action = del.delete_message_action.as_ref()?;
            let seq_ids = del.sequence_ids.as_ref()?;
            let mut extra = vec![action.0.to_string()];
            extra.extend(seq_ids.iter().cloned());
            let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
            build_component_payload(
                "MessageDeleteEvent",
                msg_id,
                sender_id,
                conv_id,
                &extra_refs,
            )
        }
        MessageEventDetail::ConversationDeleteEvent(conv_del) => {
            let opts = conv_del.clear_conversation_options.as_ref();
            let mut extra: Vec<String> = Vec::new();
            if let Some(o) = opts {
                if let Some(clear) = o.clear_all_messages {
                    extra.push(clear.to_string());
                }
                if let Some(sort) = o.sort_order_msec {
                    extra.push(sort.to_string());
                }
            }
            let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
            build_component_payload(
                "ConversationDeleteEvent",
                msg_id,
                sender_id,
                conv_id,
                &extra_refs,
            )
        }
        MessageEventDetail::MarkConversationReadEvent(read) => {
            let seen_until = read.seen_until_sequence_id.as_deref()?;
            let mut extra: Vec<String> = vec![seen_until.to_string()];
            if let Some(at) = read.seen_at_millis {
                extra.push(at.to_string());
            }
            let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
            build_component_payload(
                "MarkConversationReadEvent",
                msg_id,
                sender_id,
                conv_id,
                &extra_refs,
            )
        }
        MessageEventDetail::MarkConversationUnreadEvent(unread) => {
            let mut extra: Vec<&str> = Vec::new();
            if let Some(seen) = unread.seen_until_sequence_id.as_deref() {
                extra.push(seen);
            }
            build_component_payload(
                "MarkConversationUnreadEvent",
                msg_id,
                sender_id,
                conv_id,
                &extra,
            )
        }
        MessageEventDetail::GroupChangeEvent(gc_event) => {
            let gc = gc_event.group_change.as_ref()?;
            match gc {
                GenGC::GroupMemberAdd(c) => {
                    let member_ids = c.member_ids.as_ref()?;
                    let current_ids = c.current_member_ids.as_ref()?;
                    let admin_ids = c.current_admin_ids.as_ref()?;
                    let ckey_ver = c.conversation_key_version.as_deref()?;
                    let mut extra: Vec<String> = Vec::new();
                    extra.extend(member_ids.iter().cloned());
                    extra.extend(current_ids.iter().cloned());
                    extra.extend(admin_ids.iter().cloned());
                    // v3-v6: include pending member IDs. Removed at v7.
                    if (3..7).contains(&sig_version) {
                        for id in c.current_pending_member_ids.as_deref().unwrap_or(&[]) {
                            extra.push(id.clone());
                        }
                    }
                    extra.push(nullable_str(c.current_title.as_deref()));
                    extra.push(nullable_str(c.current_avatar_url.as_deref()));
                    extra.push(nullable_i64(c.current_ttl_msec));
                    extra.push(ckey_ver.to_string());
                    // v5+: screen_capture_blocking_enabled
                    if sig_version > 4 {
                        extra.push(nullable_bool(c.screen_capture_blocking_enabled));
                    }
                    // v7+: group_invite_enable fields (only if present)
                    if sig_version > 6 {
                        if let Some(ref invite) = c.group_invite_enable {
                            extra.push(nullable_str(invite.invite_url.as_deref()));
                            extra.push(nullable_str(invite.affiliate_id.as_deref()));
                            extra.push(nullable_i64(invite.expires_at_msec));
                        }
                    }
                    let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupMemberAddChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &extra_refs,
                    )
                }
                GenGC::GroupMemberRemove(c) => {
                    let ids = c.member_ids.as_ref()?;
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupMemberRemoveChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                GenGC::GroupAdminAdd(c) => {
                    let ids = c.admin_ids.as_ref()?;
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupAdminAddChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                GenGC::GroupAdminRemove(c) => {
                    let ids = c.admin_ids.as_ref()?;
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupAdminRemoveChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                GenGC::GroupTitleChange(c) => {
                    let ckey_ver = c.conversation_key_version.as_deref()?;
                    let title = c.custom_title.as_deref().unwrap_or("");
                    build_component_payload(
                        "GroupChangeEvent.GroupTitleChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[ckey_ver, title],
                    )
                }
                GenGC::GroupAvatarChange(c) => {
                    let ckey_ver = c.conversation_key_version.as_deref()?;
                    let avatar = c.custom_avatar_url.as_deref().unwrap_or("");
                    build_component_payload(
                        "GroupChangeEvent.GroupAvatarUrlChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[ckey_ver, avatar],
                    )
                }
                GenGC::GroupCreate(c) => {
                    let member_ids = c.member_ids.as_ref()?;
                    let ckey_ver = c.conversation_key_version.as_deref()?;
                    let mut extra: Vec<String> = vec![ckey_ver.to_string()];
                    extra.extend(member_ids.iter().cloned());
                    // v4+: legacy upgrade flag, title, avatar
                    if sig_version >= 4 {
                        extra.push(nullable_bool(c.is_legacy_group_upgrade));
                        extra.push(nullable_str(c.title.as_deref()));
                        extra.push(nullable_str(c.avatar_url.as_deref()));
                    }
                    let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupCreate",
                        msg_id,
                        sender_id,
                        None,
                        &extra_refs,
                    )
                }
                GenGC::GroupInviteEnable(c) => {
                    let url = c.invite_url.as_deref()?;
                    let expires = nullable_i64(c.expires_at_msec);
                    let affiliate = nullable_str(c.affiliate_id.as_deref());
                    build_component_payload(
                        "GroupChangeEvent.GroupInviteEnable",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[url, &expires, &affiliate],
                    )
                }
                GenGC::GroupInviteDisable(c) => {
                    let disabled_by = c.disabled_by_member_id.as_deref()?;
                    build_component_payload(
                        "GroupChangeEvent.GroupInviteDisable",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[disabled_by],
                    )
                }
                GenGC::GroupJoinRequest(c) => {
                    let user_id = c.requesting_user_id.as_deref()?;
                    build_component_payload(
                        "GroupChangeEvent.GroupJoinRequest",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[user_id],
                    )
                }
                GenGC::GroupJoinReject(c) => {
                    let ids = c.rejected_user_ids.as_ref()?;
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupJoinReject",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                // Not part of the signed payload.
                GenGC::GroupAdminSettingsChange(_) => None,
            }
        }
        MessageEventDetail::ConversationMetadataChangeEvent(meta_event) => {
            use crate::thrift::event::ConversationMetadataChange as CMC;
            let change = meta_event.conversation_metadata_change.as_ref()?;
            match change {
                CMC::MessageDurationChange(c) => {
                    let ttl = c.ttl_msec?;
                    let ttl_str = ttl.to_string();
                    build_component_payload(
                        "ConversationMetadataChangeEvent.MessageDurationChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[&ttl_str],
                    )
                }
                CMC::MessageDurationRemove(_) => build_component_payload(
                    "ConversationMetadataChangeEvent.MessageDurationRemove",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[],
                ),
                CMC::MuteConversation(c) => {
                    let ids = c.muted_conversation_ids.as_deref().unwrap_or(&[]);
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "ConversationMetadataChangeEvent.MuteConversation",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                CMC::UnmuteConversation(c) => {
                    let ids = c.unmuted_conversation_ids.as_deref().unwrap_or(&[]);
                    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "ConversationMetadataChangeEvent.UnmuteConversation",
                        msg_id,
                        sender_id,
                        conv_id,
                        &refs,
                    )
                }
                CMC::EnableScreenCaptureDetection(_) => build_component_payload(
                    "ConversationMetadataChangeEvent.EnableScreenCaptureDetection",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[],
                ),
                CMC::DisableScreenCaptureDetection(_) => build_component_payload(
                    "ConversationMetadataChangeEvent.DisableScreenCaptureDetection",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[],
                ),
                CMC::EnableScreenCaptureBlocking(_) => build_component_payload(
                    "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[],
                ),
                CMC::DisableScreenCaptureBlocking(_) => build_component_payload(
                    "ConversationMetadataChangeEvent.DisableScreenCaptureBlocking",
                    msg_id,
                    sender_id,
                    conv_id,
                    &[],
                ),
            }
        }
        // These event types are not signed
        MessageEventDetail::MessageTypingEvent(_)
        | MessageEventDetail::MessageFailureEvent(_)
        | MessageEventDetail::MemberAccountDeleteEvent(_) => None,
        _ => None,
    }
}

/// Render a nullable string into the signature payload: the value or `"null"`.
fn nullable_str(v: Option<&str>) -> String {
    v.map(|s| s.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Render a nullable i64 into the signature payload: digits or `"null"`.
fn nullable_i64(v: Option<i64>) -> String {
    v.map(|n| n.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Render a nullable bool into the signature payload: `"true"`, `"false"`, or `"null"`.
fn nullable_bool(v: Option<bool>) -> String {
    v.map(|b| b.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Build a comma-separated component payload: "eventName,msgId,senderId,convId,extras..."
fn build_component_payload(
    event_name: &str,
    message_id: &str,
    sender_id: &str,
    conv_id: Option<&str>,
    additional: &[&str],
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let mut parts: Vec<&str> = vec![event_name, message_id, sender_id];
    if let Some(cid) = conv_id {
        parts.push(cid);
    }
    parts.extend_from_slice(additional);
    if parts.iter().any(|p| p.contains(',')) {
        return None;
    }
    Some(zeroize::Zeroizing::new(parts.join(",").into_bytes()))
}

pub(crate) struct ParsedMessageContent {
    pub(crate) content: MessageContent,
    pub(crate) attachments: Vec<AttachmentInfo>,
    pub(crate) media_hashes: Vec<MediaHashReference>,
    /// The wire-level reply preview, kept alongside the mapped content so the
    /// decrypt path can validate it against its embedded raw source event.
    pub(crate) raw_reply_preview: Option<crate::thrift::product::ReplyingToPreview>,
}

fn media_type_name(media_type: &ThriftMediaType) -> Option<String> {
    match media_type.0 {
        1 => Some("image".to_string()),
        2 => Some("gif".to_string()),
        3 => Some("video".to_string()),
        4 => Some("audio".to_string()),
        5 => Some("file".to_string()),
        6 => Some("svg".to_string()),
        _ => None,
    }
}

fn url_image_media_hash(image: &Option<Box<ThriftUrlAttachmentImage>>) -> Option<String> {
    image.as_ref().and_then(|img| img.media_hash_key.clone())
}

fn push_media_hash(
    media_hashes: &mut Vec<MediaHashReference>,
    source: &str,
    hash: &Option<String>,
) {
    if let Some(value) = hash.clone() {
        media_hashes.push(MediaHashReference {
            source: source.to_string(),
            media_hash_key: value,
        });
    }
}

#[allow(clippy::vec_box)]
fn collect_attachments(
    attachments: Option<&Vec<Box<ThriftMessageAttachment>>>,
) -> (Vec<AttachmentInfo>, Vec<MediaHashReference>) {
    let mut parsed: Vec<AttachmentInfo> = Vec::new();
    let mut media_hashes: Vec<MediaHashReference> = Vec::new();

    let Some(attachments) = attachments else {
        return (parsed, media_hashes);
    };

    for attachment in attachments {
        match &**attachment {
            ThriftMessageAttachment::Media(media) => {
                push_media_hash(&mut media_hashes, "media", &media.media_hash_key);
                let dimensions = media.dimensions.as_ref().map(|d| MediaDimensionsInfo {
                    width: d.width,
                    height: d.height,
                });
                let info = MediaAttachmentInfo {
                    media_hash_key: media.media_hash_key.clone(),
                    dimensions,
                    media_type: media
                        .type_
                        .as_ref()
                        .and_then(|t| media_type_name(t.as_ref())),
                    duration_millis: media.duration_millis,
                    filesize_bytes: media.filesize_bytes,
                    filename: media.filename.clone(),
                    attachment_id: media.attachment_id.clone(),
                    legacy_media_url_https: media.legacy_media_url_https.clone(),
                    legacy_media_preview_url: media.legacy_media_preview_url.clone(),
                };
                parsed.push(AttachmentInfo::Media(info));
            }
            ThriftMessageAttachment::Url(url) => {
                let banner_hash = url_image_media_hash(&url.banner_image_media_hash_key);
                let favicon_hash = url_image_media_hash(&url.favicon_image_media_hash_key);
                push_media_hash(&mut media_hashes, "url_banner", &banner_hash);
                push_media_hash(&mut media_hashes, "url_favicon", &favicon_hash);
                let info = UrlAttachmentInfo {
                    url: url.url.clone(),
                    banner_image_media_hash_key: banner_hash,
                    favicon_image_media_hash_key: favicon_hash,
                    display_title: url.display_title.clone(),
                    attachment_id: url.attachment_id.clone(),
                };
                parsed.push(AttachmentInfo::Url(info));
            }
            ThriftMessageAttachment::Post(post) => {
                parsed.push(AttachmentInfo::Post(PostAttachmentInfo {
                    rest_id: post.rest_id.clone(),
                    post_url: post.post_url.clone(),
                    attachment_id: post.attachment_id.clone(),
                }));
            }
            ThriftMessageAttachment::UnifiedCard(card) => {
                parsed.push(AttachmentInfo::UnifiedCard(UnifiedCardAttachmentInfo {
                    url: card.url.clone(),
                    attachment_id: card.attachment_id.clone(),
                }));
            }
            ThriftMessageAttachment::Money(money) => {
                parsed.push(AttachmentInfo::Money(MoneyAttachmentInfo {
                    fallback_text: money.fallback_text.clone(),
                }));
            }
            ThriftMessageAttachment::Jetfuel(_) => {
                // This attachment variant is not yet supported; skip.
            }
        }
    }

    (parsed, media_hashes)
}

/// Parse decrypted message content using generated types from product.thrift.
pub(crate) fn parse_message_content(data: &[u8]) -> Result<ParsedMessageContent, SdkError> {
    let cursor = Cursor::new(data);
    let mut raw = TBinaryInputProtocol::new(cursor, true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    let holder = MessageEntryHolder::read_from_in_protocol(&mut protocol)
        .map_err(|e| SdkError::Parse(format!("Content parse error: {}", e)))?;

    let mut attachments: Vec<AttachmentInfo> = Vec::new();
    let mut media_hashes: Vec<MediaHashReference> = Vec::new();
    let mut raw_reply_preview: Option<crate::thrift::product::ReplyingToPreview> = None;

    let content = match holder.contents {
        Some(c) => match *c {
            MessageEntryContents::Message(msg) => {
                let (parsed_attachments, parsed_hashes) =
                    collect_attachments(msg.attachments.as_ref());
                attachments = parsed_attachments;
                media_hashes = parsed_hashes;
                raw_reply_preview = msg.replying_to_preview.as_deref().cloned();
                MessageContent::Text {
                    text: msg.message_text.clone().unwrap_or_default(),
                    entities: map_rich_text_entities_boxed(msg.entities.as_deref()),
                    attachments: map_message_attachments(msg.attachments.as_deref()),
                    replying_to_preview: msg
                        .replying_to_preview
                        .as_ref()
                        .map(|preview| map_replying_to_preview(preview)),
                    forwarded_message: msg
                        .forwarded_message
                        .as_ref()
                        .map(|forwarded| map_forwarded_message(forwarded)),
                    sent_from: msg
                        .sent_from
                        .as_ref()
                        .map(|sent_from| map_sent_from(sent_from)),
                    quick_reply: msg
                        .quick_reply
                        .as_ref()
                        .map(|quick_reply| map_quick_reply(quick_reply)),
                    ctas: map_ctas(msg.ctas.as_deref()),
                }
            }
            MessageEntryContents::ReactionAdd(r) => MessageContent::Reaction {
                emoji: r.emoji.unwrap_or_default(),
                target_message_id: r.message_sequence_id.unwrap_or_default(),
            },
            MessageEntryContents::ReactionRemove(r) => MessageContent::ReactionRemoved {
                emoji: r.emoji.unwrap_or_default(),
                target_message_id: r.message_sequence_id.unwrap_or_default(),
            },
            MessageEntryContents::MessageEdit(e) => MessageContent::Edit {
                target_message_id: e.message_sequence_id.unwrap_or_default(),
                new_text: e.updated_text.unwrap_or_default(),
                entities: map_rich_text_entities(e.entities.as_deref()),
            },
            MessageEntryContents::MarkConversationRead(_) => MessageContent::MarkRead,
            MessageEntryContents::MarkConversationUnread(_) => MessageContent::MarkUnread,
            _ => MessageContent::Unknown { type_id: None },
        },
        None => MessageContent::Unknown { type_id: None },
    };

    Ok(ParsedMessageContent {
        content,
        attachments,
        media_hashes,
        raw_reply_preview,
    })
}

fn map_rich_text_entities_boxed(
    entities: Option<&[Box<crate::thrift::product::RichTextEntity>]>,
) -> Option<Vec<RichTextEntity>> {
    entities.map(|items| {
        items
            .iter()
            .map(|entity| map_rich_text_entity(entity.as_ref()))
            .collect()
    })
}

fn map_rich_text_entities(
    entities: Option<&[crate::thrift::product::RichTextEntity]>,
) -> Option<Vec<RichTextEntity>> {
    entities.map(|items| items.iter().map(map_rich_text_entity).collect())
}

fn map_rich_text_entity(entity: &crate::thrift::product::RichTextEntity) -> RichTextEntity {
    RichTextEntity {
        start_index: entity.start_index,
        end_index: entity.end_index,
        content: entity
            .content
            .as_ref()
            .map(|content| map_rich_text_content(content)),
    }
}

fn map_rich_text_content(content: &crate::thrift::product::RichTextContent) -> RichTextContent {
    match content {
        crate::thrift::product::RichTextContent::Hashtag(_) => RichTextContent::Hashtag {
            hashtag: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::Cashtag(_) => RichTextContent::Cashtag {
            cashtag: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::Mention(_) => RichTextContent::Mention {
            mention: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::Url(_) => RichTextContent::Url {
            url: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::Email(_) => RichTextContent::Email {
            email: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::Address(_) => RichTextContent::Address {
            address: EmptyObject::default(),
        },
        crate::thrift::product::RichTextContent::PhoneNumber(_) => RichTextContent::PhoneNumber {
            phone_number: EmptyObject::default(),
        },
    }
}

fn map_message_attachments(
    attachments: Option<&[Box<crate::thrift::product::MessageAttachment>]>,
) -> Option<Vec<MessageAttachment>> {
    attachments.map(|items| {
        items
            .iter()
            .map(|attachment| map_message_attachment(attachment.as_ref()))
            .collect()
    })
}

fn map_message_attachment(
    attachment: &crate::thrift::product::MessageAttachment,
) -> MessageAttachment {
    match attachment {
        crate::thrift::product::MessageAttachment::Media(media) => MessageAttachment::Media {
            media: map_media_attachment(media),
        },
        crate::thrift::product::MessageAttachment::Post(post) => MessageAttachment::Post {
            post: map_post_attachment(post),
        },
        crate::thrift::product::MessageAttachment::Url(url) => MessageAttachment::Url {
            url: map_url_attachment(url),
        },
        crate::thrift::product::MessageAttachment::UnifiedCard(card) => {
            MessageAttachment::UnifiedCard {
                unified_card: map_unified_card_attachment(card),
            }
        }
        crate::thrift::product::MessageAttachment::Money(money) => MessageAttachment::Money {
            money: map_money_attachment(money),
        },
        crate::thrift::product::MessageAttachment::Jetfuel(_) => MessageAttachment::Money {
            money: MoneyAttachment {
                fallback_text: Some("Payment attachment".to_string()),
                payload: None,
            },
        },
    }
}

fn map_media_attachment(media: &crate::thrift::product::MediaAttachment) -> MediaAttachment {
    MediaAttachment {
        media_hash_key: media.media_hash_key.clone(),
        dimensions: media
            .dimensions
            .as_ref()
            .map(|dimensions| map_media_dimensions(dimensions)),
        media_type: media.type_.as_ref().map(|type_| map_media_type(type_)),
        duration_millis: media.duration_millis,
        filesize_bytes: media.filesize_bytes,
        filename: media.filename.clone(),
        attachment_id: media.attachment_id.clone(),
        legacy_media_url_https: media.legacy_media_url_https.clone(),
        legacy_media_preview_url: media.legacy_media_preview_url.clone(),
    }
}

fn map_media_dimensions(dimensions: &crate::thrift::product::MediaDimensions) -> MediaDimensions {
    MediaDimensions {
        width: dimensions.width,
        height: dimensions.height,
    }
}

fn map_media_type(media_type: &crate::thrift::product::MediaType) -> MediaType {
    match i32::from(media_type) {
        1 => MediaType::Known(MediaTypeKnown::Image),
        2 => MediaType::Known(MediaTypeKnown::Gif),
        3 => MediaType::Known(MediaTypeKnown::Video),
        4 => MediaType::Known(MediaTypeKnown::Audio),
        5 => MediaType::Known(MediaTypeKnown::File),
        6 => MediaType::Known(MediaTypeKnown::Svg),
        other => MediaType::Unknown(other),
    }
}

fn map_post_attachment(post: &crate::thrift::product::PostAttachment) -> PostAttachment {
    PostAttachment {
        rest_id: post.rest_id.clone(),
        post_url: post.post_url.clone(),
        attachment_id: post.attachment_id.clone(),
    }
}

fn map_url_attachment(url: &crate::thrift::product::UrlAttachment) -> UrlAttachment {
    UrlAttachment {
        url: url.url.clone(),
        banner_image_media_hash_key: url
            .banner_image_media_hash_key
            .as_ref()
            .map(|image| map_url_attachment_image(image)),
        favicon_image_media_hash_key: url
            .favicon_image_media_hash_key
            .as_ref()
            .map(|image| map_url_attachment_image(image)),
        display_title: url.display_title.clone(),
        attachment_id: url.attachment_id.clone(),
    }
}

fn map_url_attachment_image(
    image: &crate::thrift::product::UrlAttachmentImage,
) -> UrlAttachmentImage {
    UrlAttachmentImage {
        media_hash_key: image.media_hash_key.clone(),
        filesize_bytes: image.filesize_bytes,
        filename: image.filename.clone(),
        dimensions: image
            .dimensions
            .as_ref()
            .map(|dimensions| map_media_dimensions(dimensions)),
    }
}

fn map_unified_card_attachment(
    card: &crate::thrift::product::UnifiedCardAttachment,
) -> UnifiedCardAttachment {
    UnifiedCardAttachment {
        url: card.url.clone(),
        attachment_id: card.attachment_id.clone(),
    }
}

fn map_money_attachment(money: &crate::thrift::product::MoneyAttachment) -> MoneyAttachment {
    MoneyAttachment {
        fallback_text: money.fallback_text.clone(),
        payload: money
            .payload
            .as_ref()
            .map(|bytes| STANDARD_NO_PAD.encode(bytes)),
    }
}

fn map_replying_to_preview(
    preview: &crate::thrift::product::ReplyingToPreview,
) -> ReplyingToPreview {
    ReplyingToPreview {
        sender_id: preview.sender_id.map(|id| id.to_string()),
        message_text: preview.message_text.clone(),
        entities: map_rich_text_entities(preview.entities.as_deref()),
        attachments: map_message_attachments(preview.attachments.as_deref()),
        sender_display_name: preview.sender_display_name.clone(),
        replying_to_message_sequence_id: preview.replying_to_message_sequence_id.clone(),
        replying_to_message_id: preview.replying_to_message_id.clone(),
    }
}

fn map_forwarded_message(message: &crate::thrift::product::ForwardedMessage) -> ForwardedMessage {
    ForwardedMessage {
        message_text: message.message_text.clone(),
        entities: map_rich_text_entities(message.entities.as_deref()),
    }
}

fn map_sent_from(sent_from: &crate::thrift::product::SentFromSurface) -> SentFromSurface {
    match i32::from(sent_from) {
        1 => SentFromSurface::Known(SentFromSurfaceKnown::ConversationScreenComposer),
        2 => SentFromSurface::Known(SentFromSurfaceKnown::NotificationReply),
        3 => SentFromSurface::Known(SentFromSurfaceKnown::ShareSheet),
        4 => SentFromSurface::Known(SentFromSurfaceKnown::PaymentsSupportComposer),
        5 => SentFromSurface::Known(SentFromSurfaceKnown::MessageForwardSheet),
        other => SentFromSurface::Unknown(other),
    }
}

fn map_quick_reply(quick_reply: &crate::thrift::product::QuickReply) -> QuickReply {
    match quick_reply {
        crate::thrift::product::QuickReply::Request(request) => QuickReply::Request {
            request: map_quick_reply_request(request),
        },
        crate::thrift::product::QuickReply::Response(response) => QuickReply::Response {
            response: map_quick_reply_response(response),
        },
    }
}

fn map_quick_reply_request(
    request: &crate::thrift::product::QuickReplyRequest,
) -> QuickReplyRequest {
    match request {
        crate::thrift::product::QuickReplyRequest::Options(options) => QuickReplyRequest::Options {
            options: map_quick_reply_options_request(options),
        },
    }
}

fn map_quick_reply_response(
    response: &crate::thrift::product::QuickReplyResponse,
) -> QuickReplyResponse {
    match response {
        crate::thrift::product::QuickReplyResponse::Options(options) => {
            QuickReplyResponse::Options {
                options: map_quick_reply_options_response(options),
            }
        }
    }
}

fn map_quick_reply_options_request(
    options: &crate::thrift::product::QuickReplyOptionsRequest,
) -> QuickReplyOptionsRequest {
    QuickReplyOptionsRequest {
        id: options.id.clone(),
        options: options.options.as_ref().map(|items| {
            items
                .iter()
                .map(map_quick_reply_option)
                .collect::<Vec<QuickReplyOption>>()
        }),
    }
}

fn map_quick_reply_options_response(
    options: &crate::thrift::product::QuickReplyOptionsResponse,
) -> QuickReplyOptionsResponse {
    QuickReplyOptionsResponse {
        request_id: options.request_id.clone(),
        metadata: options.metadata.clone(),
        selected_option_id: options.selected_option_id.clone(),
    }
}

fn map_quick_reply_option(option: &crate::thrift::product::QuickReplyOption) -> QuickReplyOption {
    QuickReplyOption {
        id: option.id.clone(),
        label: option.label.clone(),
        metadata: option.metadata.clone(),
        description: option.description.clone(),
    }
}

fn map_ctas(
    ctas: Option<&[Box<crate::thrift::product::CallToAction>]>,
) -> Option<Vec<CallToAction>> {
    ctas.map(|items| {
        items
            .iter()
            .map(|cta| map_call_to_action(cta.as_ref()))
            .collect()
    })
}

fn map_call_to_action(cta: &crate::thrift::product::CallToAction) -> CallToAction {
    CallToAction {
        label: cta.label.clone(),
        url: cta.url.clone(),
    }
}

/// Convert generated FailureType to API FailureType.
pub(crate) fn convert_failure_type(ft: Option<&crate::thrift::event::FailureType>) -> FailureType {
    match ft {
        Some(t) => match t.0 {
            1 => FailureType::EmptyDetail,
            2 => FailureType::InternalError,
            3 => FailureType::ContentsTooLarge,
            4 => FailureType::TooManyMessages,
            5 => FailureType::InvalidSenderSignature,
            6 => FailureType::NonLatestKeyVersion,
            7 => FailureType::RecipientNotTrusted,
            8 => FailureType::RecipientKeyChanged,
            9 => FailureType::OnlyEncryptedMessagesAllowed,
            10 => FailureType::RequesterNotAdmin,
            11 => FailureType::FlaggedAsSpam,
            12 => FailureType::RateLimitUpsell,
            13 => FailureType::SignatureFailedToVerifyAgainstPublicKey,
            14 => FailureType::GenericError,
            15 => FailureType::SenderNotGroupMember,
            16 => FailureType::InvalidSignatureVersion,
            17 => FailureType::InvalidPinRequest,
            18 => FailureType::TooManyPins,
            _ => FailureType::Unknown,
        },
        None => FailureType::Unknown,
    }
}

/// Convert generated RateLimitTier to API RateLimitTier.
pub(crate) fn convert_rate_limit_tier(
    tier: Option<&crate::thrift::event::RateLimitTier>,
) -> Option<RateLimitTier> {
    tier.map(|t| match t.0 {
        1 => RateLimitTier::Free,
        2 => RateLimitTier::VerifiedPhone,
        3 => RateLimitTier::Premium,
        4 => RateLimitTier::PremiumPlus,
        5 => RateLimitTier::PremiumBusiness,
        _ => RateLimitTier::Unknown,
    })
}

/// Convert generated GroupChange to API GroupChange.
pub(crate) fn convert_group_change(gc: Option<&crate::thrift::event::GroupChange>) -> GroupChange {
    use crate::thrift::event::GroupChange as GenGC;
    match gc {
        Some(GenGC::GroupCreate(c)) => GroupChange::Created {
            member_ids: c.member_ids.clone().unwrap_or_default(),
            admin_ids: c.admin_ids.clone().unwrap_or_default(),
            title: c.title.clone(),
            avatar_url: c.avatar_url.clone(),
        },
        Some(GenGC::GroupTitleChange(c)) => GroupChange::TitleChanged {
            new_title: c.custom_title.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupAvatarChange(c)) => GroupChange::AvatarChanged {
            new_avatar_url: c.custom_avatar_url.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupAdminAdd(c)) => GroupChange::AdminsAdded {
            admin_ids: c.admin_ids.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupAdminRemove(c)) => GroupChange::AdminsRemoved {
            admin_ids: c.admin_ids.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupMemberAdd(c)) => GroupChange::MembersAdded {
            member_ids: c.member_ids.clone().unwrap_or_default(),
            current_member_ids: c.current_member_ids.clone().unwrap_or_default(),
            current_admin_ids: c.current_admin_ids.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupMemberRemove(c)) => GroupChange::MembersRemoved {
            member_ids: c.member_ids.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupInviteEnable(c)) => GroupChange::InviteEnabled {
            invite_url: c.invite_url.clone().unwrap_or_default(),
            expires_at_msec: c.expires_at_msec,
        },
        Some(GenGC::GroupInviteDisable(c)) => GroupChange::InviteDisabled {
            disabled_by: c.disabled_by_member_id.clone(),
        },
        Some(GenGC::GroupJoinRequest(c)) => GroupChange::JoinRequested {
            user_id: c.requesting_user_id.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupJoinReject(c)) => GroupChange::JoinRejected {
            user_ids: c.rejected_user_ids.clone().unwrap_or_default(),
        },
        Some(GenGC::GroupAdminSettingsChange(_)) => GroupChange::Unknown,
        None => GroupChange::Unknown,
    }
}

/// Convert generated ConversationMetadataChange to API SettingsChange.
pub(crate) fn convert_settings_change(
    c: Option<&crate::thrift::event::ConversationMetadataChange>,
) -> SettingsChange {
    use crate::thrift::event::ConversationMetadataChange as GenCMC;
    match c {
        Some(GenCMC::MessageDurationChange(d)) => SettingsChange::MessageDuration {
            ttl_msec: d.ttl_msec.unwrap_or(0),
            apply_to_all: d.apply_to_all_messages.unwrap_or(false),
        },
        Some(GenCMC::MessageDurationRemove(_)) => SettingsChange::MessageDurationRemoved,
        Some(GenCMC::MuteConversation(_)) => SettingsChange::Muted,
        Some(GenCMC::UnmuteConversation(_)) => SettingsChange::Unmuted,
        Some(GenCMC::EnableScreenCaptureDetection(_)) => {
            SettingsChange::ScreenCaptureDetectionEnabled
        }
        Some(GenCMC::DisableScreenCaptureDetection(_)) => {
            SettingsChange::ScreenCaptureDetectionDisabled
        }
        Some(GenCMC::EnableScreenCaptureBlocking(_)) => {
            SettingsChange::ScreenCaptureBlockingEnabled
        }
        Some(GenCMC::DisableScreenCaptureBlocking(_)) => {
            SettingsChange::ScreenCaptureBlockingDisabled
        }
        None => SettingsChange::Unknown,
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::serialize_thrift;
    use crate::protocol::serialization::base64_encode;
    use crate::thrift::event::{
        ClearConversationOptions, ConversationDeleteEvent as ThriftConvDel,
        ConversationKeyChangeEvent as ThriftCKCE, ConversationMetadataChange,
        ConversationMetadataChangeEvent as ThriftCMCE, ConversationParticipantKey,
        DeleteMessageAction, DisableScreenCaptureBlocking, DisableScreenCaptureDetection,
        EnableScreenCaptureBlocking, EnableScreenCaptureDetection,
        FailureType as ThriftFailureType, GrokSearchResponseEvent as ThriftGSRE,
        GroupAdminAddChange, GroupAdminRemoveChange, GroupAvatarUrlChange,
        GroupChangeEvent as ThriftGCE, GroupCreate, GroupInviteDisable, GroupInviteEnable,
        GroupJoinReject, GroupJoinRequest, GroupMemberAddChange, GroupMemberRemoveChange,
        GroupTitleChange, MarkConversationReadEvent as ThriftMCRE,
        MarkConversationUnreadEvent as ThriftMCUE, MemberAccountDeleteEvent as ThriftMADE,
        MessageCreateEvent as ThriftMCE, MessageDeleteEvent as ThriftMDE, MessageDurationChange,
        MessageDurationRemove, MessageEvent as ThriftMessageEvent,
        MessageEventDetail as ThriftDetail, MessageFailureEvent as ThriftMFE,
        MessageTypingEvent as ThriftMTE, MuteConversation, RateLimitTier as ThriftRateLimitTier,
        UnmuteConversation,
    };

    /// Build a base64-encoded MessageEvent wrapping a MessageCreateEvent.
    ///
    /// When `conversation_key_version` is `None` the MCE is unencrypted and
    /// `content_bytes` should be raw (plaintext) Thrift `MessageEntryHolder`.
    /// When it is `Some`, `content_bytes` should be ciphertext produced by
    /// `encrypt_message()`.
    fn build_test_message_event(
        content_bytes: &[u8],
        conversation_key_version: Option<&str>,
    ) -> String {
        let mce = ThriftMCE::new(
            Some(content_bytes.to_vec()),
            conversation_key_version.map(|s| s.to_string()),
            Some(true),   // should_notify
            None::<i64>,  // ttl_msec
            None::<i64>,  // delivered_at_msec
            None::<bool>, // is_pending_public_key
            None::<crate::thrift::event::EventQueuePriority>,
            None::<Vec<crate::thrift::event::AdditionalAction>>,
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),         // sequence_id
            Some("msg-1".to_string()),         // message_id
            Some("sender-1".to_string()),      // sender_id
            Some("conv-1".to_string()),        // conversation_id
            None::<String>,                    // conversation_token
            Some("1700000000000".to_string()), // created_at_msec
            Some(ThriftDetail::MessageCreateEvent(mce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            None::<crate::thrift::event::MessageEventSignature>,
            None::<String>, // previous_sequence_id
            None::<bool>,   // is_trusted
        );
        let bytes = serialize_thrift(&event).expect("serialize MessageEvent");
        base64_encode(&bytes)
    }

    /// Build plaintext Thrift content bytes for a simple text message.
    fn build_plaintext_content(text: &str) -> Vec<u8> {
        crate::pipeline::build_message_content(text, None, None).expect("build_message_content")
    }

    /// A message signed by encrypt_message must verify against the sender's
    /// signing key via decrypt_event. Catches send/verify payload or
    /// signature-version mismatches.
    #[test]
    fn encrypt_message_signature_verifies_on_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hello v7")
                    .with_identity("sender-1", "1733889755256")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();

        // The SendPayload.encrypted_content is the MCE; wrap it in a full
        // MessageEvent with the embedded signature, like the backend does.
        let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
        let mce = parse_message_event(&mce_bytes)
            .ok()
            .and_then(|e| e.detail)
            .or_else(|| {
                // encrypted_content is just the MCE struct, not a MessageEvent.
                let cursor = Cursor::new(mce_bytes.clone());
                let mut raw = TBinaryInputProtocol::new(cursor, true);
                let mut p = BoundedProtocol::new(&mut raw);
                crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                    .ok()
                    .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            })
            .expect("parse MCE");

        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some(payload.message_id.clone()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "1733889755256".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(msg.verified, "self-signed v7 message must verify");
                assert_eq!(msg.text(), Some("hello v7"));
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    /// An edit produced by `encrypt_edit` must decrypt and verify like any
    /// other message, surfacing the target sequence id, replacement text, and
    /// entities. Catches producer/consumer divergence on the edit wire shape.
    #[test]
    fn encrypt_edit_round_trips_through_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let mut params = crate::EncryptEditParams::new("", "read https://example.com")
            .with_identity("sender-1", "1733889755256")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-orig".into());
        params.entities = Some(vec![crate::types::EntityDescriptor {
            start: 5,
            end: 24,
            entity_type: "url".into(),
        }]);
        let payload = core.encrypt_edit(&params).unwrap();

        let event_b64 = wrap_signed_payload_with_seq(&payload, "sender-1", "conv-1", "seq-edit");
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "1733889755256".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(msg.verified, "self-signed edit must verify");
                match msg.content {
                    MessageContent::Edit {
                        target_message_id,
                        new_text,
                        entities,
                    } => {
                        assert_eq!(target_message_id, "seq-orig");
                        assert_eq!(new_text, "read https://example.com");
                        let entities = entities.expect("entities survive the round trip");
                        assert_eq!(entities.len(), 1);
                        assert_eq!(entities[0].start_index, Some(5));
                        assert_eq!(entities[0].end_index, Some(24));
                    }
                    other => panic!("expected Edit content, got {:?}", other),
                }
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    /// The SDK mints the message id: `encrypt_message` returns a fresh UUID in
    /// `SendPayload.message_id` on every call, and callers can no longer supply
    /// one. (That the returned id is the one actually signed is proven by the
    /// verify-on-decrypt tests, which embed `payload.message_id` in the event.)
    #[test]
    fn encrypt_message_generates_a_unique_uuid_message_id() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let encrypt = || {
            core.encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hello")
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap()
            .message_id
        };

        let first = encrypt();
        let second = encrypt();
        assert!(
            uuid::Uuid::parse_str(&first).is_ok(),
            "message id must be a UUID, got {first:?}"
        );
        assert_ne!(first, second, "each call must mint a distinct message id");
    }

    /// A URL card attachment with encrypted banner/favicon images survives an
    /// encrypt → decrypt round trip: the receive side must surface the image
    /// hashes both on the parsed attachment and in `media_hashes` (so callers
    /// can download and decrypt the blobs).
    #[test]
    fn url_card_with_banner_round_trips_through_encrypt_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let mut params = crate::EncryptMessageParams::new("conv-1", "Check this out")
            .with_identity("sender-1", "1733889755256")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.attachments = Some(vec![crate::AttachmentDescriptor::Url {
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
        let payload = core.encrypt_message(params).unwrap();

        let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
        let cursor = Cursor::new(mce_bytes);
        let mut raw = TBinaryInputProtocol::new(cursor, true);
        let mut p = BoundedProtocol::new(&mut raw);
        let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
            .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            .expect("parse MCE");

        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some(payload.message_id.clone()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "1733889755256".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        let Event::Message(msg) = event else {
            panic!("expected Message");
        };
        assert!(msg.verified);
        assert_eq!(msg.text(), Some("Check this out"));

        // The flattened attachment info carries both image hashes.
        let AttachmentInfo::Url(info) = &msg.attachments[0] else {
            panic!("expected Url attachment info, got {:?}", msg.attachments);
        };
        assert_eq!(info.url.as_deref(), Some("https://example.com/product"));
        assert_eq!(info.display_title.as_deref(), Some("Example Product"));
        assert_eq!(
            info.banner_image_media_hash_key.as_deref(),
            Some("banner-hash")
        );
        assert_eq!(
            info.favicon_image_media_hash_key.as_deref(),
            Some("favicon-hash")
        );

        // media_hashes lists both blobs for download + decrypt_stream.
        let hashes: Vec<(&str, &str)> = msg
            .media_hashes
            .iter()
            .map(|h| (h.source.as_str(), h.media_hash_key.as_str()))
            .collect();
        assert!(hashes.contains(&("url_banner", "banner-hash")));
        assert!(hashes.contains(&("url_favicon", "favicon-hash")));

        // The full-fidelity content attachment keeps the image metadata.
        let MessageContent::Text { attachments, .. } = &msg.content else {
            panic!("expected Text content");
        };
        let Some(MessageAttachment::Url { url }) = attachments.as_deref().map(|a| &a[0]) else {
            panic!("expected Url attachment in content");
        };
        let banner = url.banner_image_media_hash_key.as_ref().expect("banner");
        assert_eq!(banner.media_hash_key.as_deref(), Some("banner-hash"));
        assert_eq!(banner.filesize_bytes, Some(24_000));
        assert_eq!(banner.filename.as_deref(), Some("banner.jpg"));
        let dims = banner.dimensions.as_ref().expect("dimensions");
        assert_eq!(dims.width, Some(1200));
        assert_eq!(dims.height, Some(630));
    }

    /// A signing key must only verify events from its own user. Passing every
    /// participant's keys to `decrypt_event` (as callers commonly do) must not
    /// let one participant's valid key verify an event claiming another
    /// participant as sender.
    #[test]
    fn decrypt_event_rejects_signature_from_wrong_participant() {
        let attacker = ChatCore::new();
        let attacker_reg = attacker.generate_keypairs().unwrap();
        let victim = ChatCore::new();
        let victim_reg = victim.generate_keypairs().unwrap();

        // Attacker signs a message that claims the victim as sender.
        let ckey = attacker.generate_conversation_key().unwrap();
        let payload = attacker
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "forged")
                    .with_identity("victim-id", "attacker-pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();

        let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
        let cursor = Cursor::new(mce_bytes);
        let mut raw = TBinaryInputProtocol::new(cursor, true);
        let mut p = BoundedProtocol::new(&mut raw);
        let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
            .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            .expect("parse MCE");

        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-forged".to_string()),
            Some("victim-id".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();

        // Batch-style key list: one entry per participant. The attacker's own
        // entry carries the version the forged signature names, so selecting
        // by version alone would wrongly verify this event.
        let signing_keys = [
            SigningKeyEntry {
                user_id: "victim-id".to_string(),
                public_key_version: "victim-pkv".to_string(),
                public_key: victim_reg.public_key.signing_public_key.clone(),
                identity_public_key: victim_reg.public_key.public_key.clone(),
                identity_public_key_signature: victim_reg
                    .public_key
                    .identity_public_key_signature
                    .clone(),
            },
            SigningKeyEntry {
                user_id: "attacker-id".to_string(),
                public_key_version: "attacker-pkv".to_string(),
                public_key: attacker_reg.public_key.signing_public_key.clone(),
                identity_public_key: attacker_reg.public_key.public_key.clone(),
                identity_public_key_signature: attacker_reg
                    .public_key
                    .identity_public_key_signature
                    .clone(),
            },
        ];

        let err = attacker
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .expect_err("forged sender must not verify");
        assert!(
            err.to_string().contains("could not be verified"),
            "expected unverifiable-signature rejection, got: {}",
            err
        );

        // Relaxed policy still must not report the forgery as verified.
        let mut lenient = ChatCore::new();
        lenient.set_reject_unverified(false);
        match lenient
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap()
        {
            Event::Message(msg) => assert!(!msg.verified, "forged sender must not verify"),
            other => panic!("expected Message, got {:?}", other),
        }
    }

    /// Whatever conversation-id form the caller signs with — bare recipient
    /// id, hyphen pair in either order, or the colon form — the signature must
    /// verify against the canonical id the backend embeds in fanned-out events.
    #[test]
    fn encrypt_message_verifies_from_any_conversation_id_form() {
        let sender = "1843439638876491776";
        let recipient = "1215441834412953600";
        let canonical = "1215441834412953600:1843439638876491776";
        let input_forms = [
            recipient,
            "1215441834412953600-1843439638876491776",
            "1843439638876491776-1215441834412953600",
            canonical,
        ];

        for form in input_forms {
            let core = ChatCore::new();
            let reg = core.generate_keypairs().unwrap();
            let ckey = core.generate_conversation_key().unwrap();
            let payload = core
                .encrypt_message(
                    crate::EncryptMessageParams::new(form, "any form")
                        .with_identity(sender, "1733889755256")
                        .with_conversation_key(ckey.to_bytes(), "9001"),
                )
                .unwrap();

            let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
            let cursor = Cursor::new(mce_bytes);
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            let mce = crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
                .expect("parse MCE");

            let sig_struct = crate::thrift::event::MessageEventSignature::new(
                Some(payload.signature.clone()),
                Some(payload.signature_info.public_key_version.clone()),
                Some(payload.signature_info.signature_version.clone()),
                None,
                None,
            );
            let event = ThriftMessageEvent::new(
                Some("seq-1".to_string()),
                Some(payload.message_id.clone()),
                Some(sender.to_string()),
                Some(canonical.to_string()),
                None::<String>,
                Some("1700000000000".to_string()),
                Some(mce),
                None::<crate::thrift::event::MessageEventRelaySource>,
                Some(sig_struct),
                None::<String>,
                None::<bool>,
            );
            let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

            let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
            let signing_keys = [SigningKeyEntry {
                user_id: sender.to_string(),
                public_key_version: "1733889755256".to_string(),
                public_key: reg.public_key.signing_public_key.clone(),
                identity_public_key: reg.public_key.public_key.clone(),
                identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
            }];

            let event = core
                .decrypt_event(&event_b64, &conv_keys, &signing_keys)
                .unwrap();
            match event {
                Event::Message(msg) => {
                    assert!(
                        msg.verified,
                        "form {form:?} must verify against {canonical}"
                    );
                }
                other => panic!("expected Message for form {form:?}, got {other:?}"),
            }
        }
    }

    /// An explicit conversation id passed to prepare_conversation_key_change
    /// canonicalizes the same way: the returned id is the colon form and the
    /// signature round-trips against it.
    #[test]
    fn prepare_conversation_key_change_canonicalizes_explicit_id() {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "111".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        for form in ["222", "222-111", "111:222"] {
            let mut params =
                crate::ConversationKeyChangeParams::new(input.clone()).with_identity("111", "1");
            params.conversation_id = Some(form.to_string());
            let prepared = core.prepare_conversation_key_change(params).unwrap();
            assert_eq!(prepared.conversation_id, "111:222", "form {form:?}");
            let ckey_b64 =
                STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
            assert_action_signature_round_trips(
                &core,
                &prepared.action_signatures[0],
                "111",
                "111:222",
                Some(&ckey_b64),
            );
        }
    }

    // Unencrypted MCE tests

    #[test]
    fn decrypt_event_unencrypted_mce_with_none_key_returns_message() {
        let mut core = ChatCore::new();
        // generate_keypairs loads keys into the manager so verify works
        core.generate_keypairs().unwrap();
        // Unencrypted messages have no signature; allow them through.
        core.set_reject_unverified(false);

        let content = build_plaintext_content("Hello unencrypted!");
        let event_b64 = build_test_message_event(&content, None);

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();

        match event {
            Event::Message(msg) => {
                assert_eq!(msg.text(), Some("Hello unencrypted!"));
                assert!(msg.key_version.is_none(), "key_version should be None");
                assert!(!msg.verified, "verified should be false");
                assert_eq!(msg.should_notify, Some(true));
                assert_eq!(msg.meta.sender_id.as_deref(), Some("sender-1"));
                assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
                assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
            }
            other => panic!("Expected Event::Message, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_unencrypted_mce_with_key_still_works() {
        // Even if the caller passes a conversation key, the SDK should
        // recognise the MCE is unencrypted and skip decryption.
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(false);

        let content = build_plaintext_content("Plaintext with key present");
        let event_b64 = build_test_message_event(&content, None);

        // Unencrypted MCE — key map is unused, any map works
        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();

        match event {
            Event::Message(msg) => {
                assert_eq!(msg.text(), Some("Plaintext with key present"));
                assert!(msg.key_version.is_none());
                assert!(!msg.verified);
            }
            other => panic!("Expected Event::Message, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_unencrypted_mce_reject_unverified_errors() {
        // Unencrypted MCEs carry no signature, so under reject_unverified
        // (the default) they are unverifiable and must be rejected.
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let content = build_plaintext_content("No sig");
        let event_b64 = build_test_message_event(&content, None);

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(
            result.is_err(),
            "unencrypted message must be rejected under reject_unverified"
        );
    }

    #[test]
    fn decrypt_event_encrypted_mce_without_key_errors() {
        // An encrypted MCE with no signing keys and reject_unverified=true
        // (default) should be rejected at the signature check before
        // reaching the missing-key error.
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let content = build_plaintext_content("will be 'encrypted'");
        let event_b64 = build_test_message_event(&content, Some("3"));

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result.is_err());

        // With reject_unverified=false, the signature check passes and
        // we get the missing conversation key error instead.
        let mut core2 = ChatCore::new();
        core2.generate_keypairs().unwrap();
        core2.set_reject_unverified(false);

        let result2 = core2.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result2.is_err());
        let err_msg = format!("{}", result2.unwrap_err());
        assert!(
            err_msg.contains("no matching key found"),
            "Error should mention missing key, got: {}",
            err_msg
        );
    }

    #[test]
    fn decrypt_event_unencrypted_mce_empty_content_returns_unknown() {
        // An MCE with no contents at all (None) should return Unknown,
        // regardless of encryption status.
        let mce = ThriftMCE::new(
            None::<Vec<u8>>, // no contents
            None::<String>,  // no key version
            Some(true),
            None::<i64>,
            None::<i64>,
            None::<bool>,
            None::<crate::thrift::event::EventQueuePriority>,
            None::<Vec<crate::thrift::event::AdditionalAction>>,
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-1".to_string()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::MessageCreateEvent(mce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            None::<crate::thrift::event::MessageEventSignature>,
            None::<String>,
            None::<bool>,
        );
        let bytes = serialize_thrift(&event).unwrap();
        let event_b64 = base64_encode(&bytes);

        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let result = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        assert!(
            matches!(result, Event::Unknown(_)),
            "MCE with no contents should return Unknown"
        );
    }

    #[test]
    fn decrypt_event_unencrypted_mce_preserves_metadata() {
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(false);

        let content = build_plaintext_content("metadata check");
        let event_b64 = build_test_message_event(&content, None);

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert_eq!(msg.meta.sequence_id.as_deref(), Some("seq-1"));
                assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
                assert_eq!(msg.meta.sender_id.as_deref(), Some("sender-1"));
                assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
                assert_eq!(msg.meta.created_at_msec, Some(1700000000000));
            }
            other => panic!("Expected Event::Message, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_encrypted_mce_roundtrip() {
        // Verify the normal encrypted path still works end-to-end.
        // Disable reject_unverified since we don't supply signing keys.
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let plaintext = build_plaintext_content("Encrypted roundtrip");

        // Encrypt the content the same way the pipeline does.
        let encrypted = crate::crypto::encryption::encrypt_message(&ckey, &plaintext).unwrap();
        let event_b64 = build_test_message_event(&encrypted, Some("42"));

        let event = core
            .decrypt_event(
                &event_b64,
                &[("42".to_string(), ckey.clone())].into_iter().collect(),
                &[],
            )
            .unwrap();

        match event {
            Event::Message(msg) => {
                assert_eq!(msg.text(), Some("Encrypted roundtrip"));
                assert_eq!(msg.key_version.as_deref(), Some("42"));
                // No trusted signing key provided → verified is false
                assert!(!msg.verified);
            }
            other => panic!("Expected Event::Message, got {:?}", other),
        }
    }

    // Signature passthrough tests — events with missing fields should not
    // be blocked by reject_unverified

    /// Build a base64-encoded MessageEvent wrapping an arbitrary detail.
    fn build_test_event(detail: ThriftDetail) -> String {
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-1".to_string()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(detail),
            None::<crate::thrift::event::MessageEventRelaySource>,
            None::<crate::thrift::event::MessageEventSignature>,
            None::<String>,
            None::<bool>,
        );
        let bytes = serialize_thrift(&event).expect("serialize");
        base64_encode(&bytes)
    }

    #[test]
    fn reject_unverified_rejects_group_title_change_without_signing_keys() {
        // GroupTitleChange with no signing keys — reject_unverified=true
        // must reject it (not silently pass it through).
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(true);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupTitleChange(
                GroupTitleChange::new(Some("New Title".to_string()), None::<String>),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result.is_err(), "Should reject unsigned GroupChange");

        // With reject_unverified=false it passes through with verified=false.
        core.set_reject_unverified(false);
        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => {
                assert!(!gc.verified);
                assert!(matches!(gc.change, GroupChange::TitleChanged { .. }));
            }
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn reject_unverified_rejects_group_member_add_without_signing_keys() {
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(true);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupMemberAdd(
                GroupMemberAddChange::new(
                    Some(vec!["new-member".to_string()]),
                    Some(vec!["member-1".to_string()]),
                    Some(vec!["admin-1".to_string()]),
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<i64>,
                    None::<Vec<String>>,
                    None,
                    None,
                    None,
                ),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result.is_err(), "Should reject unsigned GroupChange");
    }

    #[test]
    fn reject_unverified_rejects_message_delete_without_signing_keys() {
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(true);

        let del = ThriftMDE::new(
            Some(vec!["seq-99".to_string()]),
            None::<DeleteMessageAction>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result.is_err(), "Should reject unsigned MessageDelete");
    }

    #[test]
    fn reject_unverified_rejects_group_change_with_no_inner_change() {
        let mut core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_reject_unverified(true);

        let gc = ThriftGCE::new(None::<crate::thrift::event::GroupChange>, None);
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(result.is_err(), "Should reject unsigned GroupChange");
    }

    /// `generate_keypairs` produces a bidirectional cross-signature.
    ///
    /// - `identity_public_key_signature`: signing key signs identity SPKI
    /// - `signing_public_key_signature`:  identity key signs signing SPKI
    ///
    /// Both signatures must verify against the corresponding public key.
    #[test]
    fn generate_keypairs_produces_bidirectional_cross_signatures() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;
        use p256::PublicKey;

        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();
        let reg = &payload.public_key;

        // Decode public keys
        let identity_spki_bytes =
            crate::protocol::serialization::base64_decode(&reg.public_key).unwrap();
        let signing_spki_bytes =
            crate::protocol::serialization::base64_decode(&reg.signing_public_key).unwrap();

        let identity_pk = PublicKey::from_public_key_der(&identity_spki_bytes)
            .expect("identity SPKI should parse");
        let signing_pk =
            PublicKey::from_public_key_der(&signing_spki_bytes).expect("signing SPKI should parse");

        let identity_vk = VerifyingKey::from(identity_pk);
        let signing_vk = VerifyingKey::from(signing_pk);

        // 1. Verify identity_public_key_signature: signing key signed identity SPKI
        let id_sig_bytes =
            crate::protocol::serialization::base64_decode(&reg.identity_public_key_signature)
                .unwrap();
        let id_sig = Signature::from_slice(&id_sig_bytes)
            .expect("identity_public_key_signature should be valid raw r||s");
        signing_vk
            .verify(&identity_spki_bytes, &id_sig)
            .expect("signing key should verify identity SPKI signature");

        // 2. Verify signing_public_key_signature: identity key signed signing SPKI
        let spk_sig_b64 = reg
            .signing_public_key_signature
            .as_ref()
            .expect("signing_public_key_signature should be Some");
        let spk_sig_bytes = crate::protocol::serialization::base64_decode(spk_sig_b64).unwrap();
        let spk_sig = Signature::from_slice(&spk_sig_bytes)
            .expect("signing_public_key_signature should be valid raw r||s");
        identity_vk
            .verify(&signing_spki_bytes, &spk_sig)
            .expect("identity key should verify signing SPKI signature");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let core = ChatCore::new();
        let key = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();

        let plaintext = "My Group Chat";
        let ciphertext_b64 = core.encrypt(plaintext, &key).unwrap();
        let decrypted = core.decrypt(&ciphertext_b64, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_string() {
        let core = ChatCore::new();
        let key = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();

        let ciphertext_b64 = core.encrypt("", &key).unwrap();
        let decrypted = core.decrypt(&ciphertext_b64, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let core = ChatCore::new();
        let key1 = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let key2 = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x43u8; 32]).unwrap();

        let ciphertext_b64 = core.encrypt("secret", &key1).unwrap();
        assert!(core.decrypt(&ciphertext_b64, &key2).is_err());
    }

    #[test]
    fn encrypt_decrypt_unicode() {
        let core = ChatCore::new();
        let key = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();

        let plaintext = "Group Chat Name";
        let ciphertext_b64 = core.encrypt(plaintext, &key).unwrap();
        let decrypted = core.decrypt(&ciphertext_b64, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // decrypt_event branch coverage: all MessageEventDetail variants

    #[test]
    fn decrypt_event_typing_event() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let typing = ThriftMTE::new(Some("conv-1".to_string()));
        let event_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Typing(t) => {
                assert_eq!(t.meta.sender_id.as_deref(), Some("sender-1"));
                assert_eq!(t.meta.conversation_id.as_deref(), Some("conv-1"));
                assert_eq!(t.meta.sequence_id.as_deref(), Some("seq-1"));
            }
            other => panic!("Expected Event::Typing, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_mark_conversation_read() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let read = ThriftMCRE::new(Some("seq-50".to_string()), Some(1700000050000i64));
        let event_b64 = build_test_event(ThriftDetail::MarkConversationReadEvent(read));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::ReadReceipt(r) => {
                assert_eq!(r.seen_until_id.as_deref(), Some("seq-50"));
                assert_eq!(r.seen_at_msec, Some(1700000050000));
                assert!(!r.verified);
                assert_eq!(r.meta.sender_id.as_deref(), Some("sender-1"));
            }
            other => panic!("Expected Event::ReadReceipt, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_mark_conversation_unread() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let unread = ThriftMCUE::new(Some("seq-42".to_string()));
        let event_b64 = build_test_event(ThriftDetail::MarkConversationUnreadEvent(unread));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::MarkedUnread(u) => {
                assert_eq!(u.seen_until_id.as_deref(), Some("seq-42"));
                assert!(!u.verified);
            }
            other => panic!("Expected Event::MarkedUnread, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_message_delete_for_self() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let del = ThriftMDE::new(
            Some(vec!["seq-10".to_string(), "seq-11".to_string()]),
            Some(DeleteMessageAction::DELETE_FOR_SELF),
        );
        let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::MessageDeleted(md) => {
                assert_eq!(md.message_ids, vec!["seq-10", "seq-11"]);
                assert!(!md.delete_for_all);
                assert!(!md.verified);
            }
            other => panic!("Expected Event::MessageDeleted, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_message_delete_for_all() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let del = ThriftMDE::new(
            Some(vec!["seq-20".to_string()]),
            Some(DeleteMessageAction::DELETE_FOR_ALL),
        );
        let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::MessageDeleted(md) => {
                assert_eq!(md.message_ids, vec!["seq-20"]);
                assert!(md.delete_for_all);
            }
            other => panic!("Expected Event::MessageDeleted, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_conversation_delete_with_clear_all() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let conv_del = ThriftConvDel::new(
            Some("conv-99".to_string()),
            Some(ClearConversationOptions::new(
                Some(true),
                Some(1700000000000i64),
            )),
        );
        let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::ConversationDeleted(cd) => {
                assert!(cd.clear_all_messages);
                assert!(!cd.verified);
            }
            other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_conversation_delete_without_clear_all() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let conv_del = ThriftConvDel::new(
            Some("conv-100".to_string()),
            None::<ClearConversationOptions>,
        );
        let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::ConversationDeleted(cd) => {
                assert!(!cd.clear_all_messages);
            }
            other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_internal_error() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::INTERNAL_ERROR),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => {
                assert_eq!(f.failure, FailureType::InternalError);
                assert_eq!(f.rate_limit_tier, None);
                assert_eq!(f.meta.sender_id.as_deref(), Some("sender-1"));
            }
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_rate_limit_tier() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::RATE_LIMIT_UPSELL),
            Some(ThriftRateLimitTier::PREMIUM),
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => {
                assert_eq!(f.failure, FailureType::RateLimitUpsell);
                assert_eq!(f.rate_limit_tier, Some(RateLimitTier::Premium));
            }
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_contents_too_large() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::CONTENTS_TOO_LARGE),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => {
                assert_eq!(f.failure, FailureType::ContentsTooLarge);
            }
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_too_many_messages() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::TOO_MANY_MESSAGES),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::TooManyMessages),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_invalid_sender_signature() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::INVALID_SENDER_SIGNATURE),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::InvalidSenderSignature),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_non_latest_ckey_version() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::NON_LATEST_CKEY_VERSION),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::NonLatestKeyVersion),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_recipient_not_trusted() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientNotTrusted),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_recipient_key_changed() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::RECIPIENT_KEY_HAS_CHANGED),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientKeyChanged),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_empty_detail() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::EMPTY_DETAIL),
            None::<ThriftRateLimitTier>,
        );
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::EmptyDetail),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_failure_none_type_returns_unknown() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let failure = ThriftMFE::new(None::<ThriftFailureType>, None::<ThriftRateLimitTier>);
        let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Failure(f) => assert_eq!(f.failure, FailureType::Unknown),
            other => panic!("Expected Event::Failure, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_member_account_delete() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let member_del = ThriftMADE::new(Some("deleted-user-42".to_string()));
        let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::MemberDeleted(md) => {
                assert_eq!(md.member_id, "deleted-user-42");
                assert_eq!(md.meta.sender_id.as_deref(), Some("sender-1"));
            }
            other => panic!("Expected Event::MemberDeleted, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_member_account_delete_no_member_id() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let member_del = ThriftMADE::new(None::<String>);
        let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::MemberDeleted(md) => {
                assert_eq!(md.member_id, ""); // defaults to empty
            }
            other => panic!("Expected Event::MemberDeleted, got {:?}", other),
        }
    }

    // GroupChange sub-variants

    #[test]
    fn decrypt_event_group_change_group_create() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupCreate(
                GroupCreate::new(
                    Some(vec!["m1".to_string(), "m2".to_string()]),
                    Some(vec!["a1".to_string()]),
                    Some("Test Group".to_string()),
                    Some("https://avatar.url".to_string()),
                    Some("v1".to_string()),
                    None::<bool>,
                    None::<i64>,
                ),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::Created {
                    ref member_ids,
                    ref admin_ids,
                    ref title,
                    ref avatar_url,
                } => {
                    assert_eq!(member_ids, &["m1", "m2"]);
                    assert_eq!(admin_ids, &["a1"]);
                    assert_eq!(title.as_deref(), Some("Test Group"));
                    assert_eq!(avatar_url.as_deref(), Some("https://avatar.url"));
                }
                other => panic!("Expected GroupChange::Created, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_avatar_changed() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupAvatarChange(
                GroupAvatarUrlChange::new(
                    Some("https://new-avatar.png".to_string()),
                    Some("v2".to_string()),
                ),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::AvatarChanged { ref new_avatar_url } => {
                    assert_eq!(new_avatar_url, "https://new-avatar.png");
                }
                other => panic!("Expected AvatarChanged, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_admins_added() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupAdminAdd(
                GroupAdminAddChange::new(Some(vec!["admin-new".to_string()])),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::AdminsAdded { ref admin_ids } => {
                    assert_eq!(admin_ids, &["admin-new"]);
                }
                other => panic!("Expected AdminsAdded, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_admins_removed() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupAdminRemove(
                GroupAdminRemoveChange::new(Some(vec!["admin-old".to_string()])),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::AdminsRemoved { ref admin_ids } => {
                    assert_eq!(admin_ids, &["admin-old"]);
                }
                other => panic!("Expected AdminsRemoved, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_members_added() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupMemberAdd(
                GroupMemberAddChange::new(
                    Some(vec!["new-member".to_string()]),
                    Some(vec!["m1".to_string(), "m2".to_string()]),
                    Some(vec!["a1".to_string()]),
                    Some("Title".to_string()),
                    Some("avatar".to_string()),
                    Some("v3".to_string()),
                    Some(30000i64),
                    None::<Vec<String>>,
                    None,
                    None,
                    None,
                ),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::MembersAdded {
                    ref member_ids,
                    ref current_member_ids,
                    ref current_admin_ids,
                } => {
                    assert_eq!(member_ids, &["new-member"]);
                    assert_eq!(current_member_ids, &["m1", "m2"]);
                    assert_eq!(current_admin_ids, &["a1"]);
                }
                other => panic!("Expected MembersAdded, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_members_removed() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupMemberRemove(
                GroupMemberRemoveChange::new(Some(vec!["removed-user".to_string()])),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::MembersRemoved { ref member_ids } => {
                    assert_eq!(member_ids, &["removed-user"]);
                }
                other => panic!("Expected MembersRemoved, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_invite_enabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupInviteEnable(
                GroupInviteEnable::new(
                    Some(1700000100000i64),
                    Some("https://invite.link".to_string()),
                    None::<String>,
                ),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::InviteEnabled {
                    ref invite_url,
                    expires_at_msec,
                } => {
                    assert_eq!(invite_url, "https://invite.link");
                    assert_eq!(expires_at_msec, Some(1700000100000));
                }
                other => panic!("Expected InviteEnabled, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_invite_disabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupInviteDisable(
                GroupInviteDisable::new(Some("admin-1".to_string())),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::InviteDisabled { ref disabled_by } => {
                    assert_eq!(disabled_by.as_deref(), Some("admin-1"));
                }
                other => panic!("Expected InviteDisabled, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_join_requested() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupJoinRequest(
                GroupJoinRequest::new(Some("requester-1".to_string())),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::JoinRequested { ref user_id } => {
                    assert_eq!(user_id, "requester-1");
                }
                other => panic!("Expected JoinRequested, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_group_change_join_rejected() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let gc = ThriftGCE::new(
            Some(crate::thrift::event::GroupChange::GroupJoinReject(
                GroupJoinReject::new(Some(vec![
                    "rejected-1".to_string(),
                    "rejected-2".to_string(),
                ])),
            )),
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::GroupChange(gc) => match gc.change {
                GroupChange::JoinRejected { ref user_ids } => {
                    assert_eq!(user_ids, &["rejected-1", "rejected-2"]);
                }
                other => panic!("Expected JoinRejected, got {:?}", other),
            },
            other => panic!("Expected Event::GroupChange, got {:?}", other),
        }
    }

    // ConversationMetadataChangeEvent (SettingsChange) sub-variants

    #[test]
    fn decrypt_event_settings_change_message_duration() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::MessageDurationChange(MessageDurationChange::new(
            Some(60000i64),
            Some(true),
        ));
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => match sc.change {
                SettingsChange::MessageDuration {
                    ttl_msec,
                    apply_to_all,
                } => {
                    assert_eq!(ttl_msec, 60000);
                    assert!(apply_to_all);
                }
                other => panic!("Expected MessageDuration, got {:?}", other),
            },
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_message_duration_removed() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::MessageDurationRemove(MessageDurationRemove::new(
            Some(30000i64),
        ));
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(sc.change, SettingsChange::MessageDurationRemoved));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_muted() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change =
            ConversationMetadataChange::MuteConversation(MuteConversation::new(Some(vec![
                "conv-1".to_string(),
            ])));
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(sc.change, SettingsChange::Muted));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_unmuted() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change =
            ConversationMetadataChange::UnmuteConversation(UnmuteConversation::new(Some(vec![
                "conv-1".to_string(),
            ])));
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(sc.change, SettingsChange::Unmuted));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_screen_capture_detection_enabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::EnableScreenCaptureDetection(
            EnableScreenCaptureDetection::new(None::<String>),
        );
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(
                    sc.change,
                    SettingsChange::ScreenCaptureDetectionEnabled
                ));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_screen_capture_detection_disabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::DisableScreenCaptureDetection(
            DisableScreenCaptureDetection::new(None::<String>),
        );
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(
                    sc.change,
                    SettingsChange::ScreenCaptureDetectionDisabled
                ));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_screen_capture_blocking_enabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::EnableScreenCaptureBlocking(
            EnableScreenCaptureBlocking::new(None::<String>),
        );
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(
                    sc.change,
                    SettingsChange::ScreenCaptureBlockingEnabled
                ));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_screen_capture_blocking_disabled() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let change = ConversationMetadataChange::DisableScreenCaptureBlocking(
            DisableScreenCaptureBlocking::new(None::<String>),
        );
        let cmce = ThriftCMCE::new(Some(change));
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(
                    sc.change,
                    SettingsChange::ScreenCaptureBlockingDisabled
                ));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_settings_change_none_returns_unknown() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let cmce = ThriftCMCE::new(None::<ConversationMetadataChange>);
        let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::SettingsChange(sc) => {
                assert!(matches!(sc.change, SettingsChange::Unknown));
            }
            other => panic!("Expected Event::SettingsChange, got {:?}", other),
        }
    }

    // Unknown/missing detail → Event::Unknown

    #[test]
    fn decrypt_event_no_detail_returns_unknown() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        // Build event with no detail (detail = None)
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-1".to_string()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            None::<ThriftDetail>, // no detail
            None::<crate::thrift::event::MessageEventRelaySource>,
            None::<crate::thrift::event::MessageEventSignature>,
            None::<String>,
            None::<bool>,
        );
        let bytes = serialize_thrift(&event).expect("serialize");
        let event_b64 = base64_encode(&bytes);

        let result = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match result {
            Event::Unknown(u) => {
                assert!(u.event_type_id.is_none());
                assert_eq!(u.meta.sender_id.as_deref(), Some("sender-1"));
            }
            other => panic!("Expected Event::Unknown, got {:?}", other),
        }
    }

    #[test]
    fn decrypt_event_grok_search_response_returns_unknown() {
        // GrokSearchResponseEvent is handled by the catch-all `_` branch
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let grok = ThriftGSRE::new(Some("search-1".to_string()));
        let event_b64 = build_test_event(ThriftDetail::GrokSearchResponseEvent(grok));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::Unknown(u) => {
                assert!(u.event_type_id.is_none());
            }
            other => panic!(
                "Expected Event::Unknown for GrokSearchResponse, got {:?}",
                other
            ),
        }
    }

    // KeyChange event via decrypt_event

    #[test]
    fn decrypt_event_key_change() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let kce = ThriftCKCE::new(
            Some("v42".to_string()),
            Some(vec![
                ConversationParticipantKey::new(
                    Some("user-1".to_string()),
                    Some("encrypted-key-1".to_string()),
                    Some("pkv-1".to_string()),
                ),
                ConversationParticipantKey::new(
                    Some("user-2".to_string()),
                    Some("encrypted-key-2".to_string()),
                    Some("pkv-2".to_string()),
                ),
            ]),
            None,
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

        let event = core
            .decrypt_event(&event_b64, &Default::default(), &[])
            .unwrap();
        match event {
            Event::KeyChange(kc) => {
                assert_eq!(kc.key_version, "v42");
                assert_eq!(kc.participant_keys.len(), 2);
                assert_eq!(kc.participant_keys[0].user_id, "user-1");
                assert_eq!(kc.participant_keys[0].encrypted_key, "encrypted-key-1");
                assert_eq!(kc.participant_keys[1].user_id, "user-2");
                assert!(!kc.verified);
            }
            other => panic!("Expected Event::KeyChange, got {:?}", other),
        }
    }

    /// A KeyChange whose signature was produced by `sign_key_change` must
    /// verify on `decrypt_event` — even with an empty conversation-key map,
    /// because the SDK self-decrypts the plaintext key from the event's own
    /// participant entry (encrypted to our identity key). Guards the v7
    /// plaintext-ckey verification path end to end (default reject_unverified).
    #[test]
    fn decrypt_event_key_change_verifies_signature() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let pubkeys = core.get_public_keys().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let ckey_version = "1733889755256";

        // Encrypt the conversation key for ourselves so the SDK can
        // self-decrypt it from the event to rebuild the signed payload.
        let recipients = [RecipientInput {
            user_id: "sender-1".to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "pkv-self".to_string(),
        }];
        let encrypted = core
            .encrypt_conversation_key_for_recipients(&ckey, &recipients)
            .unwrap();

        // Sign the key change (v7 signs the plaintext conversation key).
        let sig = core
            .sign_key_change(
                "pkv-self",
                "msg-1",
                "sender-1",
                "conv-1",
                ckey_version,
                ckey.encoded(),
            )
            .unwrap();

        let kce = ThriftCKCE::new(
            Some(ckey_version.to_string()),
            Some(vec![ConversationParticipantKey::new(
                Some("sender-1".to_string()),
                Some(encrypted[0].encrypted_key.clone()),
                // Must match our identity key version so the self-decrypt
                // path selects this entry.
                reg.version.clone(),
            )]),
            None,
            None,
        );
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(sig.signature.clone()),
            Some(sig.public_key_version.clone()),
            Some(sig.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-1".to_string()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "pkv-self".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        // Empty key map forces the self-decrypt path.
        let decrypted = core
            .decrypt_event(&event_b64, &Default::default(), &signing_keys)
            .unwrap();
        match decrypted {
            Event::KeyChange(kc) => {
                assert!(kc.verified, "CKCE signature must verify via self-decrypt");
                assert_eq!(kc.key_version, ckey_version);
            }
            other => panic!("Expected Event::KeyChange, got {:?}", other),
        }
    }

    // decrypt_events (batch) tests

    #[test]
    fn decrypt_events_mixed_event_types() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        core.generate_keypairs().unwrap();

        let typing = ThriftMTE::new(None::<String>);
        let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::INTERNAL_ERROR),
            None::<ThriftRateLimitTier>,
        );
        let failure_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let member_del = ThriftMADE::new(Some("user-99".to_string()));
        let member_del_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

        let events: Vec<&str> = vec![&typing_b64, &failure_b64, &member_del_b64];
        let result = core.decrypt_events(&events, &[]);

        assert_eq!(result.messages.len(), 3);
        assert!(result.errors.is_empty());

        assert!(matches!(result.messages[0].event, Event::Typing(_)));
        assert!(matches!(result.messages[1].event, Event::Failure(_)));
        assert!(matches!(result.messages[2].event, Event::MemberDeleted(_)));
    }

    #[test]
    fn decrypt_events_with_errors_for_invalid_b64() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let typing = ThriftMTE::new(None::<String>);
        let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

        let events: Vec<&str> = vec![&typing_b64, "!!!invalid-base64!!!"];
        let result = core.decrypt_events(&events, &[]);

        assert_eq!(result.messages.len(), 1);
        assert!(result.errors.contains_key(&1));
    }

    #[test]
    fn decrypt_events_preserves_original_b64() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);

        let typing = ThriftMTE::new(None::<String>);
        let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

        let events: Vec<&str> = vec![&typing_b64];
        let result = core.decrypt_events(&events, &[]);

        assert_eq!(result.messages.len(), 1);
        assert_eq!(
            result.messages[0].original_b64.as_deref(),
            Some(typing_b64.as_str()),
        );
    }

    // extract_conversation_keys tests

    #[test]
    fn extract_conversation_keys_empty_events() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let result = core.extract_conversation_keys(&[]);
        assert!(result.is_empty());
        assert!(result.latest_version.is_none());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn extract_conversation_keys_no_keys_loaded() {
        let core = ChatCore::new();
        // Don't generate keys — no identity key loaded

        let typing = ThriftMTE::new(None::<String>);
        let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));
        let result = core.extract_conversation_keys(&[&typing_b64]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_conversation_keys_skips_non_key_events() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let typing = ThriftMTE::new(None::<String>);
        let typing_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

        let failure = ThriftMFE::new(
            Some(ThriftFailureType::INTERNAL_ERROR),
            None::<ThriftRateLimitTier>,
        );
        let failure_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

        let result = core.extract_conversation_keys(&[&typing_b64, &failure_b64]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_conversation_keys_skips_malformed_b64() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let result = core.extract_conversation_keys(&["not-valid-base64!!!"]);
        assert!(result.is_empty());
    }

    #[test]
    fn registered_key_version_selects_matching_participant_entry_and_skips_others() {
        // With a registered key version, participant-key entries targeting a
        // different version are skipped instead of trial-decrypted: an entry
        // matching the version is used even when an earlier decryptable entry
        // exists, and an event with only mismatched entries yields no key.
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "V");

        let pubkeys = core.get_public_keys().unwrap();
        let encrypt_for_self = |ckey: &XChatConversationKey| {
            let recipients = [RecipientInput {
                user_id: "sender-1".to_string(),
                public_key: pubkeys.identity.clone(),
                key_version: "unused".to_string(),
            }];
            core.encrypt_conversation_key_for_recipients(ckey, &recipients)
                .unwrap()[0]
                .encrypted_key
                .clone()
        };

        // Both entries decrypt with our identity key but carry different
        // conversation keys, so the extracted key reveals which entry was used.
        let ckey_mismatch = core.generate_conversation_key().unwrap();
        let ckey_match = core.generate_conversation_key().unwrap();

        let entry = |ckey_b64: String, version: &str| {
            ConversationParticipantKey::new(
                Some("sender-1".to_string()),
                Some(ckey_b64),
                Some(version.to_string()),
            )
        };

        let kce = ThriftCKCE::new(
            Some("42".to_string()),
            Some(vec![
                entry(encrypt_for_self(&ckey_mismatch), "not-V"),
                entry(encrypt_for_self(&ckey_match), "V"),
            ]),
            None,
            None,
        );
        let event_b64 = build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce));

        let result = core.extract_conversation_keys(&[&event_b64]);
        let extracted = result.get("42").expect("matching-version entry adopted");
        assert_eq!(extracted.encoded(), ckey_match.encoded());

        // Mismatched-only event: the key must not be adopted.
        let kce_mismatch_only = ThriftCKCE::new(
            Some("43".to_string()),
            Some(vec![entry(encrypt_for_self(&ckey_mismatch), "not-V")]),
            None,
            None,
        );
        let event_b64 =
            build_test_event(ThriftDetail::ConversationKeyChangeEvent(kce_mismatch_only));
        let result = core.extract_conversation_keys(&[&event_b64]);
        assert!(result.is_empty());
    }

    // export_keys / import_keys tests

    #[test]
    fn export_import_keys_roundtrip() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        // Export keys
        let exported = core.export_keys().unwrap();
        assert!(!exported.is_empty());

        // Get public keys before lock
        let public_keys_before = core.get_public_keys().unwrap();

        // Lock (clear keys)
        core.lock();
        assert!(!core.has_identity_key());
        assert!(!core.is_unlocked());

        // Import keys
        core.import_keys(&exported).unwrap();
        assert!(core.has_identity_key());
        assert!(core.is_unlocked());

        // Verify keys match
        let public_keys_after = core.get_public_keys().unwrap();
        assert_eq!(public_keys_before.identity, public_keys_after.identity);
        assert_eq!(public_keys_before.signing, public_keys_after.signing);
    }

    #[test]
    fn import_keys_invalid_format_errors() {
        let core = ChatCore::new();

        // Wrong size: not 32 or 64 bytes
        let result = core.import_keys(&[0u8; 16]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid key format"));
    }

    #[test]
    fn export_keys_without_keys_errors() {
        let core = ChatCore::new();

        let result = core.export_keys();
        assert!(result.is_err());
    }

    // Key management state tests

    #[test]
    fn is_unlocked_and_has_identity_key() {
        let core = ChatCore::new();

        // No keys loaded
        assert!(!core.is_unlocked());
        assert!(!core.has_identity_key());

        // Generate keys
        core.generate_keypairs().unwrap();
        assert!(core.is_unlocked());
        assert!(core.has_identity_key());

        // Lock
        core.lock();
        assert!(!core.is_unlocked());
        assert!(!core.has_identity_key());
    }

    #[test]
    fn get_public_keys_without_keys_errors() {
        let core = ChatCore::new();
        assert!(core.get_public_keys().is_err());
    }

    #[test]
    fn get_public_key_fingerprint_works() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let fingerprint = core.get_public_key_fingerprint().unwrap();
        assert!(!fingerprint.is_empty());
        // URL-safe base64 of SHA-256 (32 bytes → 43 chars without padding)
        assert_eq!(fingerprint.len(), 43);
    }

    #[test]
    fn get_public_key_fingerprint_without_keys_errors() {
        let core = ChatCore::new();
        assert!(core.get_public_key_fingerprint().is_err());
    }

    #[test]
    fn verify_key_binding_roundtrip() {
        // identity_public_key_signature = signing key signing the
        // SPKI-encoded identity key (raw r||s). The registration payload
        // carries the SPKI-encoded keys — the same format the X API
        // returns on the public keys endpoint.
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        let identity_spki = payload.public_key.public_key.clone();
        let signing_spki = payload.public_key.signing_public_key.clone();
        let sig = payload.public_key.identity_public_key_signature.clone();

        // Valid binding verifies.
        let ok = core
            .verify_key_binding(&identity_spki, &signing_spki, &sig)
            .unwrap();
        assert!(ok, "valid key binding should verify");

        // Wrong identity key fails.
        let other = ChatCore::new();
        let other_payload = other.generate_keypairs().unwrap();
        let bad = core
            .verify_key_binding(&other_payload.public_key.public_key, &signing_spki, &sig)
            .unwrap();
        assert!(!bad, "binding with wrong identity key must fail");
    }

    #[test]
    fn matches_registered_key_accepts_both_encodings() {
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        // SPKI/DER form — what the X API returns for a registered key.
        let spki = payload.public_key.public_key;
        assert!(core.matches_registered_key(&spki).unwrap());

        // Raw SEC1 point — what get_public_keys returns.
        let raw = core.get_public_keys().unwrap().identity;
        assert!(core.matches_registered_key(&raw).unwrap());
    }

    #[test]
    fn matches_registered_key_rejects_other_key() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let other = ChatCore::new();
        let other_payload = other.generate_keypairs().unwrap();
        assert!(!core
            .matches_registered_key(&other_payload.public_key.public_key)
            .unwrap());
    }

    #[test]
    fn matches_registered_key_without_keys_errors() {
        let core = ChatCore::new();
        assert!(core.matches_registered_key("AAAA").is_err());
    }

    #[test]
    fn matches_registered_key_invalid_base64_errors() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        assert!(core.matches_registered_key("not base64!!").is_err());
    }

    #[test]
    fn matches_registered_key_garbage_bytes_is_false() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        // Valid base64 of bytes that are not a public key in either encoding.
        let garbage = base64_encode(&[0u8; 65]);
        assert!(!core.matches_registered_key(&garbage).unwrap());
    }

    #[test]
    fn generate_keypairs_returns_registration_payload() {
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        assert!(!payload.public_key.public_key.is_empty());
        assert!(!payload.public_key.signing_public_key.is_empty());
        assert!(!payload.public_key.identity_public_key_signature.is_empty());
        assert_eq!(payload.public_key.registration_method, "CustomPin");
        assert!(payload.generate_version);
        assert!(payload.version.is_some());
        assert!(payload.public_key.public_key_fingerprint.is_some());
        assert!(payload.public_key.signing_public_key_signature.is_some());
    }

    // Conversation key encryption/decryption roundtrip

    #[test]
    fn generate_and_decrypt_conversation_key() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let public_keys = core.get_public_keys().unwrap();

        let recipients = vec![RecipientInput {
            user_id: "self".to_string(),
            public_key: public_keys.identity.clone(),
            key_version: "v1".to_string(),
        }];

        let encrypted = core
            .encrypt_conversation_key_for_recipients(&ckey, &recipients)
            .unwrap();
        assert_eq!(encrypted.len(), 1);
        assert_eq!(encrypted[0].user_id, "self");

        let decrypted = core
            .decrypt_conversation_key(&encrypted[0].encrypted_key)
            .unwrap();
        assert_eq!(decrypted.encoded(), ckey.encoded());
    }

    // prepare_conversation_key_change tests

    #[test]
    fn prepare_conversation_key_change_empty_input_errors() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let mut params = crate::ConversationKeyChangeParams::new(vec![]).with_identity("me", "1");
        params.conversation_id = Some("conv-1".into());
        let result = core.prepare_conversation_key_change(params);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("must not be empty"));
    }

    #[test]
    fn prepare_conversation_key_change_picks_latest_version() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let public_keys = core.get_public_keys().unwrap();
        let input = vec![
            PublicKeyInput {
                user_id: "user-1".to_string(),
                public_key: public_keys.identity.clone(),
                key_version: "100".to_string(),
            },
            PublicKeyInput {
                user_id: "user-1".to_string(),
                public_key: public_keys.identity.clone(),
                key_version: "200".to_string(),
            },
        ];

        let mut params =
            crate::ConversationKeyChangeParams::new(input).with_identity("user-1", "1");
        params.conversation_id = Some("conv-1".into());
        let result = core.prepare_conversation_key_change(params).unwrap();
        assert_eq!(result.participant_keys.len(), 1);
        assert_eq!(result.participant_keys[0].public_key_version, "200");
        assert!(result.conversation_key.is_some());
        assert!(!result.conversation_key_version.is_empty());
        assert_eq!(result.action_signatures.len(), 1);
    }

    #[test]
    fn derive_one_to_one_conversation_id_sorts_numerically() {
        // Numeric ordering: the shorter id is numerically smaller and sorts
        // first, even though it would sort last lexically.
        let input = vec![
            PublicKeyInput {
                user_id: "1491585161162473473".to_string(),
                public_key: "x".to_string(),
                key_version: "1".to_string(),
            },
            PublicKeyInput {
                user_id: "17380288".to_string(),
                public_key: "y".to_string(),
                key_version: "1".to_string(),
            },
        ];
        let id = ChatCore::derive_one_to_one_conversation_id(&input).unwrap();
        assert_eq!(id, "17380288:1491585161162473473");
    }

    #[test]
    fn derive_one_to_one_conversation_id_requires_two_users() {
        let one = vec![PublicKeyInput {
            user_id: "solo".to_string(),
            public_key: "x".to_string(),
            key_version: "1".to_string(),
        }];
        assert!(ChatCore::derive_one_to_one_conversation_id(&one).is_err());
    }

    #[test]
    fn prepare_conversation_key_change_encodes_event_detail() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];
        let mut params =
            crate::ConversationKeyChangeParams::new(input).with_identity("user-1", "1");
        params.conversation_id = Some("conv-1".into());
        let result = core.prepare_conversation_key_change(params).unwrap();
        let sig = &result.action_signatures[0];
        assert!(!sig.encoded_message_event_detail.is_empty());

        // The encoded detail must decode as a ConversationKeyChangeEvent carrying
        // the same key version and one participant key.
        let bytes = base64_decode(&sig.encoded_message_event_detail).unwrap();
        let mut cursor = Cursor::new(bytes);
        let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
        let mut proto = BoundedProtocol::new(&mut raw);
        let detail = MessageEventDetail::read_from_in_protocol(&mut proto).unwrap();
        match detail {
            MessageEventDetail::ConversationKeyChangeEvent(kce) => {
                assert_eq!(
                    kce.conversation_key_version.as_deref(),
                    Some(result.conversation_key_version.as_str())
                );
                assert_eq!(kce.conversation_participant_keys.unwrap().len(), 1);
            }
            _ => panic!("expected ConversationKeyChangeEvent"),
        }
    }

    fn decode_detail(b64: &str) -> MessageEventDetail {
        let bytes = base64_decode(b64).unwrap();
        let mut cursor = Cursor::new(bytes);
        let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
        let mut proto = BoundedProtocol::new(&mut raw);
        MessageEventDetail::read_from_in_protocol(&mut proto).unwrap()
    }

    #[test]
    fn prepare_group_create_emits_two_signatures_with_details() {
        use crate::thrift::event::GroupChange as GenGC;
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        let mut params = crate::GroupCreateParams::new(
            input,
            "g999",
            vec!["user-1".to_string(), "user-2".to_string()],
            vec!["user-1".to_string()],
        )
        .with_identity("user-1", "1");
        params.title = Some("Squad".into());
        params.avatar_url = Some("https://img/a.png".into());
        params.ttl_msec = Some(86400000);
        let result = core.prepare_group_create(params).unwrap();

        assert_eq!(result.conversation_id, "g999");
        assert_eq!(result.action_signatures.len(), 2);

        let ckce = &result.action_signatures[0];
        // Withheld: the key-change payload embeds the plaintext conversation key.
        assert!(ckce.signature_payload.is_empty());
        assert!(matches!(
            decode_detail(&ckce.encoded_message_event_detail),
            MessageEventDetail::ConversationKeyChangeEvent(_)
        ));

        let create = &result.action_signatures[1];
        assert!(create
            .signature_payload
            .starts_with("GroupChangeEvent.GroupCreate,"));
        // conversation id is not part of the signed create payload.
        assert!(!create.signature_payload.contains("g999"));
        match decode_detail(&create.encoded_message_event_detail) {
            MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
                GenGC::GroupCreate(gc) => {
                    assert_eq!(
                        gc.member_ids.as_deref(),
                        Some(["user-1".to_string(), "user-2".to_string()].as_slice())
                    );
                    assert_eq!(
                        gc.admin_ids.as_deref(),
                        Some(["user-1".to_string()].as_slice())
                    );
                    assert_eq!(gc.title.as_deref(), Some("Squad"));
                    assert_eq!(gc.avatar_url.as_deref(), Some("https://img/a.png"));
                    assert_eq!(
                        gc.conversation_key_version.as_deref(),
                        Some(result.conversation_key_version.as_str())
                    );
                    assert_eq!(gc.ttl_msec, Some(86400000));
                }
                other => panic!("expected GroupCreate, got {:?}", other),
            },
            _ => panic!("expected GroupChangeEvent"),
        }
    }

    #[test]
    fn prepare_group_members_change_emits_two_signatures_with_details() {
        use crate::thrift::event::GroupChange as GenGC;
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        let mut params = crate::GroupMembersChangeParams::new(
            input,
            "g555",
            vec!["new-1".to_string()],
            vec!["user-1".to_string()],
            vec!["user-1".to_string()],
            vec![],
        )
        .with_identity("user-1", "1");
        params.current_title = Some("Team".into());
        let result = core.prepare_group_members_change(params).unwrap();

        assert_eq!(result.action_signatures.len(), 2);

        let ckce = &result.action_signatures[0];
        // Withheld: the key-change payload embeds the plaintext conversation key.
        assert!(ckce.signature_payload.is_empty());
        assert!(matches!(
            decode_detail(&ckce.encoded_message_event_detail),
            MessageEventDetail::ConversationKeyChangeEvent(_)
        ));

        let add = &result.action_signatures[1];
        assert!(add
            .signature_payload
            .starts_with("GroupChangeEvent.GroupMemberAddChange,"));
        match decode_detail(&add.encoded_message_event_detail) {
            MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
                GenGC::GroupMemberAdd(c) => {
                    assert_eq!(
                        c.member_ids.as_deref(),
                        Some(["new-1".to_string()].as_slice())
                    );
                    assert_eq!(
                        c.current_member_ids.as_deref(),
                        Some(["user-1".to_string()].as_slice())
                    );
                    assert_eq!(c.current_title.as_deref(), Some("Team"));
                    assert_eq!(c.screen_capture_blocking_enabled, None);
                    assert_eq!(
                        c.conversation_key_version.as_deref(),
                        Some(result.conversation_key_version.as_str())
                    );
                }
                other => panic!("expected GroupMemberAdd, got {:?}", other),
            },
            _ => panic!("expected GroupChangeEvent"),
        }
    }

    /// Reconstruct the canonical signed payload for an emitted action signature
    /// through the exact code `decrypt_events` uses to verify, assert it equals
    /// the bytes the signer signed, and verify the signature with the signer's
    /// public key. This pins sign↔verify self-consistency for group actions.
    fn assert_action_signature_round_trips(
        core: &ChatCore,
        sig: &crate::signatures::ActionSignature,
        sender_id: &str,
        conversation_id: &str,
        plaintext_ckey_b64: Option<&str>,
    ) {
        let detail = decode_detail(&sig.encoded_message_event_detail);
        let event_sig = crate::thrift::event::MessageEventSignature::new(
            Some(sig.signature.clone()),
            Some(sig.public_key_version.clone()),
            Some(sig.signature_version.clone()),
            None::<String>,
            None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
        );
        let event = crate::thrift::event::MessageEvent::new(
            Some("seq-1".to_string()),
            Some(sig.message_id.clone()),
            Some(sender_id.to_string()),
            Some(conversation_id.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(detail.clone()),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(event_sig),
            None::<String>,
            None::<bool>,
        );

        let reconstructed = build_event_signature_payload(&event, &detail, plaintext_ckey_b64)
            .expect("verifier could not reconstruct the signed payload");
        // Key-change signatures withhold their payload (it embeds the
        // plaintext conversation key); for those the ECDSA check below is
        // the sign↔verify pin. Group actions keep the payload — compare it.
        if !sig.signature_payload.is_empty() {
            assert_eq!(
                reconstructed.as_slice(),
                sig.signature_payload.as_bytes(),
                "signer payload and verifier reconstruction diverge"
            );
        }

        let signing_pubkey = core.get_public_keys().unwrap().signing;
        let sig_bytes = base64_decode(&sig.signature).unwrap();
        assert!(
            core.verify(&signing_pubkey, &sig_bytes, &reconstructed)
                .unwrap(),
            "signature did not verify against the reconstructed payload"
        );
    }

    #[test]
    fn group_signatures_verify_against_own_reconstruction() {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        // GroupCreate: CKCE + GroupCreate signatures both round-trip.
        let mut create_params = crate::GroupCreateParams::new(
            input.clone(),
            "g999",
            vec!["user-1".to_string(), "user-2".to_string()],
            vec!["user-1".to_string()],
        )
        .with_identity("user-1", "1");
        create_params.title = Some("Squad".into());
        create_params.avatar_url = Some("https://img/a.png".into());
        create_params.ttl_msec = Some(86400000);
        let created = core.prepare_group_create(create_params).unwrap();
        let created_ckey_b64 =
            STANDARD_NO_PAD.encode(created.conversation_key.as_ref().unwrap().encoded());
        assert_action_signature_round_trips(
            &core,
            &created.action_signatures[0],
            "user-1",
            "g999",
            Some(&created_ckey_b64),
        );
        assert_action_signature_round_trips(
            &core,
            &created.action_signatures[1],
            "user-1",
            "g999",
            None,
        );

        // GroupMemberAdd: CKCE + GroupMemberAdd signatures both round-trip.
        let mut add_params = crate::GroupMembersChangeParams::new(
            input.clone(),
            "g555",
            vec!["new-1".to_string()],
            vec!["user-1".to_string()],
            vec!["user-1".to_string()],
            vec!["pending-1".to_string()],
        )
        .with_identity("user-1", "1");
        add_params.current_title = Some("Team".into());
        add_params.current_avatar_url = Some("https://img/b.png".into());
        add_params.current_ttl_msec = Some(3600000);
        let added = core.prepare_group_members_change(add_params).unwrap();
        let added_ckey_b64 =
            STANDARD_NO_PAD.encode(added.conversation_key.as_ref().unwrap().encoded());
        assert_action_signature_round_trips(
            &core,
            &added.action_signatures[0],
            "user-1",
            "g555",
            Some(&added_ckey_b64),
        );
        assert_action_signature_round_trips(
            &core,
            &added.action_signatures[1],
            "user-1",
            "g555",
            None,
        );

        // GroupMemberAdd with screen-capture blocking enabled: the flag lands
        // in the encoded detail, is signed, and the signature round-trips.
        let mut blocked_params = crate::GroupMembersChangeParams::new(
            input,
            "g555",
            vec!["new-1".to_string()],
            vec!["user-1".to_string()],
            vec!["user-1".to_string()],
            vec![],
        )
        .with_identity("user-1", "1");
        blocked_params.current_screen_capture_blocking_enabled = Some(true);
        let blocked = core.prepare_group_members_change(blocked_params).unwrap();
        let blocked_add = &blocked.action_signatures[1];
        assert!(blocked_add.signature_payload.ends_with(",true"));
        match decode_detail(&blocked_add.encoded_message_event_detail) {
            MessageEventDetail::GroupChangeEvent(gce) => match gce.group_change.unwrap() {
                crate::thrift::event::GroupChange::GroupMemberAdd(c) => {
                    assert_eq!(c.screen_capture_blocking_enabled, Some(true));
                }
                other => panic!("expected GroupMemberAdd, got {:?}", other),
            },
            _ => panic!("expected GroupChangeEvent"),
        }
        assert_action_signature_round_trips(&core, blocked_add, "user-1", "g555", None);
    }

    #[test]
    fn message_delete_signature_verifies_against_own_reconstruction() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let params = crate::MessageDeleteParams::new(
            "222-111",
            vec!["seq-10".to_string(), "seq-11".to_string()],
            true,
        )
        .with_identity("111", "1");
        let sig = core.prepare_message_delete(&params).unwrap();

        // The 1:1 conversation id is signed in canonical colon form even when
        // the params carry the hyphen form.
        assert_eq!(
            sig.signature_payload,
            format!(
                "MessageDeleteEvent,{},111,111:222,2,seq-10,seq-11",
                sig.message_id
            )
        );

        match decode_detail(&sig.encoded_message_event_detail) {
            MessageEventDetail::MessageDeleteEvent(del) => {
                assert_eq!(
                    del.sequence_ids,
                    Some(vec!["seq-10".to_string(), "seq-11".to_string()])
                );
                assert_eq!(
                    del.delete_message_action,
                    Some(crate::thrift::event::DeleteMessageAction::DELETE_FOR_ALL)
                );
            }
            other => panic!("expected MessageDeleteEvent, got {:?}", other),
        }

        assert_action_signature_round_trips(&core, &sig, "111", "111:222", None);
    }

    #[test]
    fn message_delete_for_self_signs_action_one() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let params = crate::MessageDeleteParams::new("g999", vec!["seq-1".to_string()], false)
            .with_identity("111", "1");
        let sig = core.prepare_message_delete(&params).unwrap();

        assert_eq!(
            sig.signature_payload,
            format!("MessageDeleteEvent,{},111,g999,1,seq-1", sig.message_id)
        );
        assert_action_signature_round_trips(&core, &sig, "111", "g999", None);
    }

    #[test]
    fn prepare_message_delete_rejects_empty_sequence_ids() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let params =
            crate::MessageDeleteParams::new("g999", vec![], true).with_identity("111", "1");
        assert!(core.prepare_message_delete(&params).is_err());
    }

    /// Empty id components would sign a degenerate payload with empty
    /// comma-separated slots (e.g. `...,111,,2,,seq-2`) that only fails
    /// server-side; reject them up front instead.
    #[test]
    fn prepare_message_delete_rejects_empty_id_components() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let empty_conversation =
            crate::MessageDeleteParams::new("", vec!["seq-1".to_string()], true)
                .with_identity("111", "1");
        let err = core
            .prepare_message_delete(&empty_conversation)
            .unwrap_err();
        assert!(
            err.to_string().contains("conversation_id is empty"),
            "unexpected error: {err}"
        );

        let empty_member = crate::MessageDeleteParams::new(
            "g999",
            vec!["".to_string(), "seq-2".to_string()],
            true,
        )
        .with_identity("111", "1");
        let err = core.prepare_message_delete(&empty_member).unwrap_err();
        assert!(
            err.to_string().contains("empty id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prepare_group_create_rejects_comma_in_title() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        let mut params = crate::GroupCreateParams::new(
            input,
            "g999",
            vec!["user-1".to_string()],
            vec!["user-1".to_string()],
        )
        .with_identity("user-1", "1");
        params.title = Some("Team, the sequel".into());
        let result = core.prepare_group_create(params);
        assert!(matches!(result, Err(SdkError::Parse(_))));
    }

    #[test]
    fn prepare_group_create_normalizes_absent_value_encodings() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];
        let members = vec!["user-1".to_string()];
        let admins = vec!["user-1".to_string()];

        // Empty strings and a negative TTL are the FFI encodings of "not
        // set"; they must produce the same signed bytes as None.
        let mut ffi_params =
            crate::GroupCreateParams::new(input.clone(), "g999", members.clone(), admins.clone())
                .with_identity("user-1", "1");
        ffi_params.title = Some("".into());
        ffi_params.avatar_url = Some("".into());
        ffi_params.ttl_msec = Some(-1);
        let ffi_form = core
            .prepare_group_create_with_version(ffi_params, "42")
            .unwrap();
        let none_form = core
            .prepare_group_create_with_version(
                crate::GroupCreateParams::new(input, "g999", members, admins)
                    .with_identity("user-1", "1"),
                "42",
            )
            .unwrap();
        assert_eq!(
            ffi_form.action_signatures[1].encoded_message_event_detail,
            none_form.action_signatures[1].encoded_message_event_detail,
            "empty-string/negative inputs must encode identically to None"
        );
        assert!(
            ffi_form.action_signatures[1]
                .signature_payload
                .ends_with(",null,null,null"),
            "normalized title/avatar must sign as the null sentinel"
        );
    }

    #[test]
    fn prepare_group_members_change_rejects_comma_in_title() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];

        let mut params = crate::GroupMembersChangeParams::new(
            input,
            "g999",
            vec!["new-1".to_string()],
            vec!["user-1".to_string()],
            vec!["user-1".to_string()],
            vec![],
        )
        .with_identity("user-1", "1");
        params.current_title = Some("Team, the sequel".into());
        let result = core.prepare_group_members_change(params);
        assert!(matches!(result, Err(SdkError::Parse(_))));
    }

    #[test]
    fn prepare_group_members_change_normalizes_absent_value_encodings() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let pk = core.get_public_keys().unwrap();
        let input = vec![PublicKeyInput {
            user_id: "user-1".to_string(),
            public_key: pk.identity.clone(),
            key_version: "1".to_string(),
        }];
        let new_members = vec!["new-1".to_string()];
        let members = vec!["user-1".to_string()];
        let admins = vec!["user-1".to_string()];

        // Empty strings and a negative TTL are the FFI encodings of "not
        // set"; unlike group create, title/avatar/TTL all enter the signed
        // member-add payload, so both the detail and the signed bytes must
        // match the None form.
        let mut ffi_params = crate::GroupMembersChangeParams::new(
            input.clone(),
            "g999",
            new_members.clone(),
            members.clone(),
            admins.clone(),
            vec![],
        )
        .with_identity("user-1", "1");
        ffi_params.current_title = Some("".into());
        ffi_params.current_avatar_url = Some("".into());
        ffi_params.current_ttl_msec = Some(-1);
        let ffi_form = core
            .prepare_group_members_change_with_version(ffi_params, "42")
            .unwrap();
        let none_form = core
            .prepare_group_members_change_with_version(
                crate::GroupMembersChangeParams::new(
                    input,
                    "g999",
                    new_members,
                    members,
                    admins,
                    vec![],
                )
                .with_identity("user-1", "1"),
                "42",
            )
            .unwrap();
        let ffi_add = &ffi_form.action_signatures[1];
        let none_add = &none_form.action_signatures[1];
        // The message id (second component) is random per call; every other
        // signed component must match.
        let strip_msg_id = |payload: &str| {
            let mut parts: Vec<&str> = payload.split(',').collect();
            parts.remove(1);
            parts.join(",")
        };
        assert_eq!(
            strip_msg_id(&ffi_add.signature_payload),
            strip_msg_id(&none_add.signature_payload),
            "empty-string/negative inputs must sign identically to None"
        );
        assert_eq!(
            ffi_add.encoded_message_event_detail, none_add.encoded_message_event_detail,
            "empty-string/negative inputs must encode identically to None"
        );
        assert!(
            ffi_add
                .signature_payload
                .ends_with(",null,null,null,42,null"),
            "normalized title/avatar/ttl must sign as the null sentinel"
        );
    }

    // sign / verify tests

    #[test]
    fn sign_and_verify_roundtrip() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let data = b"Hello, world!";
        let signature = core.sign(data).unwrap();
        assert!(!signature.is_empty());

        let public_keys = core.get_public_keys().unwrap();
        let verified = core.verify(&public_keys.signing, &signature, data).unwrap();
        assert!(verified);

        // Wrong data should not verify
        let bad_verified = core
            .verify(&public_keys.signing, &signature, b"wrong data")
            .unwrap();
        assert!(!bad_verified);
    }

    #[test]
    fn sign_without_keys_errors() {
        let core = ChatCore::new();
        assert!(core.sign(b"data").is_err());
    }

    // Stream encryption tests

    #[test]
    fn encrypt_decrypt_stream_roundtrip() {
        let core = ChatCore::new();
        let ckey = core.generate_conversation_key().unwrap();

        let plaintext = b"stream data for media encryption test";
        let encrypted = core.encrypt_stream(plaintext, &ckey).unwrap();
        assert_ne!(&encrypted[..], plaintext);

        let decrypted = core.decrypt_stream(&encrypted, &ckey).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn encrypt_decrypt_stream_empty() {
        let core = ChatCore::new();
        let ckey = core.generate_conversation_key().unwrap();

        let encrypted = core.encrypt_stream(b"", &ckey).unwrap();
        let decrypted = core.decrypt_stream(&encrypted, &ckey).unwrap();
        assert!(decrypted.is_empty());
    }

    // ChatCore::default() test

    #[test]
    fn chatcore_default_is_new() {
        let core = ChatCore::default();
        assert!(!core.is_unlocked());
        assert!(!core.has_identity_key());
    }

    // decrypt_event with invalid base64 errors

    #[test]
    fn decrypt_event_invalid_base64_errors() {
        let core = ChatCore::new();
        let result = core.decrypt_event("not_valid_base64!!!", &Default::default(), &[]);
        assert!(result.is_err());
    }

    // convert_failure_type coverage

    #[test]
    fn convert_failure_type_all_variants() {
        use crate::thrift::event::FailureType as TFT;
        for (thrift, expected) in [
            (TFT::EMPTY_DETAIL, FailureType::EmptyDetail),
            (TFT::INTERNAL_ERROR, FailureType::InternalError),
            (TFT::CONTENTS_TOO_LARGE, FailureType::ContentsTooLarge),
            (TFT::TOO_MANY_MESSAGES, FailureType::TooManyMessages),
            (
                TFT::INVALID_SENDER_SIGNATURE,
                FailureType::InvalidSenderSignature,
            ),
            (
                TFT::NON_LATEST_CKEY_VERSION,
                FailureType::NonLatestKeyVersion,
            ),
            (
                TFT::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION,
                FailureType::RecipientNotTrusted,
            ),
            (
                TFT::RECIPIENT_KEY_HAS_CHANGED,
                FailureType::RecipientKeyChanged,
            ),
            (
                TFT::ONLY_ENCRYPTED_MESSAGES_ALLOWED,
                FailureType::OnlyEncryptedMessagesAllowed,
            ),
            (TFT::REQUESTER_NOT_ADMIN, FailureType::RequesterNotAdmin),
            (TFT::FLAGGED_AS_SPAM, FailureType::FlaggedAsSpam),
            (TFT::RATE_LIMIT_UPSELL, FailureType::RateLimitUpsell),
            (
                TFT::SIGNATURE_FAILED_TO_VERIFY_AGAINST_PUBLIC_KEY,
                FailureType::SignatureFailedToVerifyAgainstPublicKey,
            ),
            (TFT::GENERIC_ERROR, FailureType::GenericError),
            (
                TFT::SENDER_NOT_GROUP_MEMBER,
                FailureType::SenderNotGroupMember,
            ),
            (
                TFT::INVALID_SIGNATURE_VERSION,
                FailureType::InvalidSignatureVersion,
            ),
            (TFT::INVALID_PIN_REQUEST, FailureType::InvalidPinRequest),
            (TFT::TOO_MANY_PINS, FailureType::TooManyPins),
        ] {
            assert_eq!(convert_failure_type(Some(&thrift)), expected);
        }
        assert_eq!(convert_failure_type(Some(&TFT(99))), FailureType::Unknown);
        assert_eq!(convert_failure_type(None), FailureType::Unknown);
    }

    #[test]
    fn convert_rate_limit_tier_all_variants() {
        use crate::thrift::event::RateLimitTier as TRT;
        for (thrift, expected) in [
            (TRT::FREE, RateLimitTier::Free),
            (TRT::VERIFIED_PHONE, RateLimitTier::VerifiedPhone),
            (TRT::PREMIUM, RateLimitTier::Premium),
            (TRT::PREMIUM_PLUS, RateLimitTier::PremiumPlus),
            (TRT::PREMIUM_BUSINESS, RateLimitTier::PremiumBusiness),
        ] {
            assert_eq!(convert_rate_limit_tier(Some(&thrift)), Some(expected));
        }
        assert_eq!(
            convert_rate_limit_tier(Some(&TRT(99))),
            Some(RateLimitTier::Unknown)
        );
        assert_eq!(convert_rate_limit_tier(None), None);
    }

    // convert_group_change coverage

    #[test]
    fn convert_group_change_none_returns_unknown() {
        let change = convert_group_change(None);
        assert!(matches!(change, GroupChange::Unknown));
    }

    // convert_settings_change coverage

    #[test]
    fn convert_settings_change_none_returns_unknown() {
        let change = convert_settings_change(None);
        assert!(matches!(change, SettingsChange::Unknown));
    }

    // ConversationKeyResult accessors

    #[test]
    fn conversation_key_result_accessors() {
        let ckey = crate::crypto::keys::XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), ckey.clone());

        let result = ConversationKeyResult {
            keys,
            latest_version: Some("v1".to_string()),
        };

        assert!(!result.is_empty());
        assert_eq!(result.len(), 1);
        assert!(result.get("v1").is_some());
        assert!(result.get("v2").is_none());
        assert!(result.latest_key().is_some());
    }

    #[test]
    fn conversation_key_result_latest_key_none() {
        let result = ConversationKeyResult {
            keys: HashMap::new(),
            latest_version: None,
        };

        assert!(result.is_empty());
        assert!(result.latest_key().is_none());
    }

    // decrypt_conversation_key without keys errors

    #[test]
    fn decrypt_conversation_key_without_identity_errors() {
        let core = ChatCore::new();
        let result = core.decrypt_conversation_key("AAAA");
        assert!(result.is_err());
    }

    // verify_key_binding negative cases

    /// A tampered `identity_public_key_signature` must not verify.
    #[test]
    fn verify_key_binding_tampered_signature_fails() {
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        let identity_spki = payload.public_key.public_key.clone();
        let signing_spki = payload.public_key.signing_public_key.clone();

        // Flip a byte in the raw signature bytes and re-encode.
        let mut sig_bytes =
            base64_decode(&payload.public_key.identity_public_key_signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        let tampered_sig = base64_encode(&sig_bytes);

        let ok = core
            .verify_key_binding(&identity_spki, &signing_spki, &tampered_sig)
            .unwrap();
        assert!(!ok, "tampered signature must not verify");
    }

    /// A valid signature verified against the wrong *signing* key must fail.
    #[test]
    fn verify_key_binding_mismatched_signing_key_fails() {
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        let identity_spki = payload.public_key.public_key.clone();
        let sig = payload.public_key.identity_public_key_signature.clone();

        // A different keypair's signing key did not produce this signature.
        let other = ChatCore::new();
        let other_payload = other.generate_keypairs().unwrap();
        let wrong_signing_spki = other_payload.public_key.signing_public_key.clone();

        let bad = core
            .verify_key_binding(&identity_spki, &wrong_signing_spki, &sig)
            .unwrap();
        assert!(!bad, "binding with wrong signing key must fail");
    }

    /// Sanity: the binding produced by `generate_keypairs` verifies.
    #[test]
    fn verify_key_binding_valid_passes() {
        let core = ChatCore::new();
        let payload = core.generate_keypairs().unwrap();

        let ok = core
            .verify_key_binding(
                &payload.public_key.public_key,
                &payload.public_key.signing_public_key,
                &payload.public_key.identity_public_key_signature,
            )
            .unwrap();
        assert!(ok, "valid binding from generate_keypairs should verify");
    }

    // Helpers for signed-message roundtrips

    /// Wrap a `SendPayload` (the MCE + signature produced by an `encrypt_*`
    /// call) into a full base64 `MessageEvent` with the embedded signature,
    /// mirroring what the backend delivers. `message_id`/`sender_id`/
    /// `conversation_id` must match the values passed to the `encrypt_*`
    /// call so the signature payload reconstructs identically.
    fn wrap_signed_payload(
        payload: &SendPayload,
        message_id: &str,
        sender_id: &str,
        conversation_id: &str,
    ) -> String {
        let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
        let mce = parse_message_event(&mce_bytes)
            .ok()
            .and_then(|e| e.detail)
            .or_else(|| {
                let cursor = Cursor::new(mce_bytes.clone());
                let mut raw = TBinaryInputProtocol::new(cursor, true);
                let mut p = BoundedProtocol::new(&mut raw);
                crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                    .ok()
                    .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            })
            .expect("parse MCE");

        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some(message_id.to_string()),
            Some(sender_id.to_string()),
            Some(conversation_id.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        base64_encode(&serialize_thrift(&event).unwrap())
    }

    /// Build a `ConversationKeyChangeEvent` (base64) that carries `ckey`
    /// self-encrypted to the loaded identity key, so that
    /// `extract_conversation_keys` can recover it. `reg_version` must be the
    /// loaded identity key version (`reg.version`).
    fn build_self_keychange_event(
        core: &ChatCore,
        ckey: &XChatConversationKey,
        ckey_version: &str,
        sender_id: &str,
        reg_version: Option<String>,
    ) -> String {
        let pubkeys = core.get_public_keys().unwrap();
        let recipients = [RecipientInput {
            user_id: sender_id.to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "pkv-self".to_string(),
        }];
        let encrypted = core
            .encrypt_conversation_key_for_recipients(ckey, &recipients)
            .unwrap();

        let kce = ThriftCKCE::new(
            Some(ckey_version.to_string()),
            Some(vec![ConversationParticipantKey::new(
                Some(sender_id.to_string()),
                Some(encrypted[0].encrypted_key.clone()),
                reg_version,
            )]),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-kc".to_string()),
            Some("msg-kc".to_string()),
            Some(sender_id.to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            None::<crate::thrift::event::MessageEventSignature>,
            None::<String>,
            None::<bool>,
        );
        base64_encode(&serialize_thrift(&event).unwrap())
    }

    // decrypt_events drops signing keys whose identity binding is invalid

    #[test]
    fn decrypt_events_drops_key_with_invalid_binding() {
        let mut core = ChatCore::new();
        // We supply unsigned KeyChange events; allow unverified through so
        // the conversation key is still extracted and the message decodes.
        core.set_reject_unverified(false);
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let ckey_version = "ckv-1";

        // KeyChange event seeds the conversation key for the batch.
        let kc_b64 =
            build_self_keychange_event(&core, &ckey, ckey_version, "sender-1", reg.version.clone());

        // A signed message encrypted with that conversation key.
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "binding check")
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), ckey_version),
            )
            .unwrap();
        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let good_key = SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "pkv".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        };

        // A bad-binding variant: corrupt the identity binding signature.
        let mut bad_sig_bytes =
            base64_decode(&reg.public_key.identity_public_key_signature).unwrap();
        bad_sig_bytes[0] ^= 0xFF;
        let mut bad_key = good_key.clone();
        bad_key.identity_public_key_signature = base64_encode(&bad_sig_bytes);

        let events: Vec<&str> = vec![&kc_b64, &msg_b64];

        // With only the bad-binding key, it is dropped → message unverified.
        let result_bad = core.decrypt_events(&events, std::slice::from_ref(&bad_key));
        let msg_bad = result_bad
            .messages
            .iter()
            .find_map(|m| match &m.event {
                Event::Message(b) => Some(b),
                _ => None,
            })
            .expect("expected a decrypted Message");
        assert_eq!(msg_bad.text(), Some("binding check"));
        assert!(
            !msg_bad.verified,
            "key with invalid binding must be dropped → unverified"
        );

        // With the correct key, the same message verifies.
        let result_good = core.decrypt_events(&events, std::slice::from_ref(&good_key));
        let msg_good = result_good
            .messages
            .iter()
            .find_map(|m| match &m.event {
                Event::Message(b) => Some(b),
                _ => None,
            })
            .expect("expected a decrypted Message");
        assert!(msg_good.verified, "valid binding → verified");
    }

    // decrypt_events only adopts keys from verified KeyChange events

    /// Like `build_self_keychange_event`, but embeds a v7
    /// `MessageEventSignature` produced by `sign_key_change`, mirroring
    /// what a legitimate client publishes.
    fn build_signed_self_keychange_event(
        core: &ChatCore,
        ckey: &XChatConversationKey,
        ckey_version: &str,
        sender_id: &str,
        signing_key_version: &str,
        reg_version: Option<String>,
    ) -> String {
        let pubkeys = core.get_public_keys().unwrap();
        let recipients = [RecipientInput {
            user_id: sender_id.to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "pkv-self".to_string(),
        }];
        let encrypted = core
            .encrypt_conversation_key_for_recipients(ckey, &recipients)
            .unwrap();

        let action_sig = core
            .sign_key_change(
                signing_key_version,
                "msg-kc",
                sender_id,
                "conv-1",
                ckey_version,
                ckey.encoded(),
            )
            .unwrap();

        let kce = ThriftCKCE::new(
            Some(ckey_version.to_string()),
            Some(vec![ConversationParticipantKey::new(
                Some(sender_id.to_string()),
                Some(encrypted[0].encrypted_key.clone()),
                reg_version,
            )]),
            None,
            None,
        );
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(action_sig.signature.clone()),
            Some(action_sig.public_key_version.clone()),
            Some(action_sig.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-kc".to_string()),
            Some("msg-kc".to_string()),
            Some(sender_id.to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        base64_encode(&serialize_thrift(&event).unwrap())
    }

    fn signing_key_entry_for(reg: &PublicKeyRegistrationPayload, user_id: &str) -> SigningKeyEntry {
        SigningKeyEntry {
            user_id: user_id.to_string(),
            public_key_version: "pkv".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }
    }

    #[test]
    fn decrypt_events_adopts_key_from_keychange_the_sdk_cannot_verify() {
        // Some KeyChange events are signed with a payload the SDK does not
        // reproduce, so the signature does not verify here. The key is still
        // adopted so messages decrypt (the KeyChange event is reported as an
        // error under the default reject_unverified policy).
        let core = ChatCore::new(); // default reject_unverified = true
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let ckey_version = "1001";

        let kc_b64 =
            build_self_keychange_event(&core, &ckey, ckey_version, "sender-1", reg.version.clone());

        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hello")
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), ckey_version),
            )
            .unwrap();
        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        let events: Vec<&str> = vec![&kc_b64, &msg_b64];
        let result = core.decrypt_events(&events, &signing_keys);

        // Key adopted despite the unverifiable KeyChange signature.
        assert!(result.conversation_keys.keys.contains_key(ckey_version));
        assert_eq!(
            result.conversation_keys.latest_version,
            Some(ckey_version.to_string())
        );
        // The message under it decrypts (its own signature verifies).
        let msg = result
            .messages
            .iter()
            .find_map(|m| match &m.event {
                Event::Message(b) => Some(b),
                _ => None,
            })
            .expect("message under adopted key must decrypt");
        assert_eq!(msg.text(), Some("hello"));
        // The KeyChange event itself is still reported unverified.
        assert!(result.errors.contains_key(&0));
    }

    #[test]
    fn decrypt_events_adopts_key_from_signed_keychange() {
        // The legitimate path: a v7-signed KeyChange is adopted and the
        // message encrypted under it decrypts and verifies.
        let core = ChatCore::new(); // default reject_unverified = true
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let ckey_version = "1001";

        let kc_b64 = build_signed_self_keychange_event(
            &core,
            &ckey,
            ckey_version,
            "sender-1",
            "pkv",
            reg.version.clone(),
        );

        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hello verified")
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), ckey_version),
            )
            .unwrap();
        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        let events: Vec<&str> = vec![&kc_b64, &msg_b64];
        let result = core.decrypt_events(&events, &signing_keys);

        assert!(
            result.conversation_keys.keys.contains_key(ckey_version),
            "key from signed KeyChange must be adopted; errors: {:?}",
            result.errors
        );
        assert_eq!(
            result.conversation_keys.latest_version,
            Some(ckey_version.to_string())
        );
        let msg = result
            .messages
            .iter()
            .find_map(|m| match &m.event {
                Event::Message(b) => Some(b),
                _ => None,
            })
            .expect("message under adopted key must decrypt");
        assert_eq!(msg.text(), Some("hello verified"));
        assert!(msg.verified);
    }

    #[test]
    fn ckey_sig_v6_enforcement_gates_adoption_by_sequence_number() {
        // Build a v7-signed CKCE at a numeric sequence number, optionally
        // corrupting its signature, and confirm the sequence-number threshold
        // gates key adoption.
        let build = |core: &ChatCore, seq: &str, corrupt: bool| -> String {
            let ckey = core.generate_conversation_key().unwrap();
            let pubkeys = core.get_public_keys().unwrap();
            let recipients = [RecipientInput {
                user_id: "sender-1".to_string(),
                public_key: pubkeys.identity.clone(),
                key_version: "pkv-self".to_string(),
            }];
            let encrypted = core
                .encrypt_conversation_key_for_recipients(&ckey, &recipients)
                .unwrap();
            let action_sig = core
                .sign_key_change(
                    "pkv",
                    "msg-kc",
                    "sender-1",
                    "conv-1",
                    "1001",
                    ckey.encoded(),
                )
                .unwrap();
            let signature = if corrupt {
                let mut raw = base64_decode(&action_sig.signature).unwrap();
                raw[5] ^= 0xff;
                STANDARD_NO_PAD.encode(raw)
            } else {
                action_sig.signature.clone()
            };
            let kce = ThriftCKCE::new(
                Some("1001".to_string()),
                Some(vec![ConversationParticipantKey::new(
                    Some("sender-1".to_string()),
                    Some(encrypted[0].encrypted_key.clone()),
                    None,
                )]),
                None,
                None,
            );
            let sig_struct = crate::thrift::event::MessageEventSignature::new(
                Some(signature),
                Some(action_sig.public_key_version.clone()),
                Some(action_sig.signature_version.clone()),
                None,
                None,
            );
            let event = ThriftMessageEvent::new(
                Some(seq.to_string()),
                Some("msg-kc".to_string()),
                Some("sender-1".to_string()),
                Some("conv-1".to_string()),
                None::<String>,
                None::<String>,
                Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
                None::<crate::thrift::event::MessageEventRelaySource>,
                Some(sig_struct),
                None::<String>,
                None::<bool>,
            );
            base64_encode(&serialize_thrift(&event).unwrap())
        };

        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        // The shipped decrypt path holds enforcement off, so a bad signature
        // is still adopted (and surfaced as an error).
        let bad = build(&core, "100", true);
        let result = core.decrypt_events(&[&bad], &signing_keys);
        assert!(result.conversation_keys.keys.contains_key("1001"));

        // Enforce from sequence 0: a valid signature is kept.
        let good = build(&core, "100", false);
        let mut kr = core.extract_conversation_keys(&[&good]);
        core.enforce_ckey_signatures(&[&good], &signing_keys, &mut kr, 0);
        assert!(kr.keys.contains_key("1001"));

        // Enforce from sequence 0: a bad signature is dropped, not adopted.
        let bad = build(&core, "100", true);
        let mut kr = core.extract_conversation_keys(&[&bad]);
        core.enforce_ckey_signatures(&[&bad], &signing_keys, &mut kr, 0);
        assert!(!kr.keys.contains_key("1001"));
        assert_eq!(kr.latest_version, None);

        // Threshold above the event sequence: the bad signature is kept.
        let bad = build(&core, "100", true);
        let mut kr = core.extract_conversation_keys(&[&bad]);
        core.enforce_ckey_signatures(&[&bad], &signing_keys, &mut kr, 200);
        assert!(kr.keys.contains_key("1001"));
    }

    #[test]
    fn decrypt_events_opt_out_preserves_unsigned_keychange_adoption() {
        // With reject_unverified disabled, any decryptable key is adopted.
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        let reg = core.generate_keypairs().unwrap();

        let ckey = core.generate_conversation_key().unwrap();
        let ckey_version = "1001";

        let kc_b64 =
            build_self_keychange_event(&core, &ckey, ckey_version, "sender-1", reg.version.clone());

        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        let result = core.decrypt_events(&[&kc_b64], &signing_keys);

        assert!(
            result.conversation_keys.keys.contains_key(ckey_version),
            "opt-out mode must still adopt any decryptable key"
        );
    }

    // Conversation-key freshness (monotonic latest version)

    /// Build a v7-signed CKCE for `conv_id` at `version`, optionally corrupting
    /// the signature so it fails verification.
    fn build_freshness_keychange(
        core: &ChatCore,
        conv_id: &str,
        version: &str,
        corrupt: bool,
    ) -> String {
        let ckey = core.generate_conversation_key().unwrap();
        let pubkeys = core.get_public_keys().unwrap();
        let recipients = [RecipientInput {
            user_id: "sender-1".to_string(),
            public_key: pubkeys.identity.clone(),
            key_version: "pkv-self".to_string(),
        }];
        let encrypted = core
            .encrypt_conversation_key_for_recipients(&ckey, &recipients)
            .unwrap();
        let action_sig = core
            .sign_key_change(
                "pkv",
                "msg-kc",
                "sender-1",
                conv_id,
                version,
                ckey.encoded(),
            )
            .unwrap();
        let signature = if corrupt {
            let mut raw = base64_decode(&action_sig.signature).unwrap();
            raw[5] ^= 0xff;
            STANDARD_NO_PAD.encode(raw)
        } else {
            action_sig.signature.clone()
        };
        let kce = ThriftCKCE::new(
            Some(version.to_string()),
            Some(vec![ConversationParticipantKey::new(
                Some("sender-1".to_string()),
                Some(encrypted[0].encrypted_key.clone()),
                None,
            )]),
            None,
            None,
        );
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(signature),
            Some(action_sig.public_key_version.clone()),
            Some(action_sig.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-kc".to_string()),
            Some("msg-kc".to_string()),
            Some("sender-1".to_string()),
            Some(conv_id.to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        base64_encode(&serialize_thrift(&event).unwrap())
    }

    #[test]
    fn latest_version_holds_at_newest_verified_keychange() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        // A verified key change at version 200 is reported as latest.
        let kc200 = build_freshness_keychange(&core, "conv-1", "200", false);
        let result = core.decrypt_events(&[&kc200], &signing_keys);
        assert_eq!(
            result.conversation_keys.latest_version.as_deref(),
            Some("200")
        );

        // A later replay of an OLDER verified key change does not downgrade the
        // reported latest, but its key is still adopted for decryption.
        let kc100 = build_freshness_keychange(&core, "conv-1", "100", false);
        let result = core.decrypt_events(&[&kc100], &signing_keys);
        assert_eq!(
            result.conversation_keys.latest_version.as_deref(),
            Some("200")
        );
        assert!(result.conversation_keys.keys.contains_key("100"));
    }

    #[test]
    fn latest_version_ignores_unverified_higher_keychange() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        // Establish a verified high-water at 100.
        let kc100 = build_freshness_keychange(&core, "conv-1", "100", false);
        let result = core.decrypt_events(&[&kc100], &signing_keys);
        assert_eq!(
            result.conversation_keys.latest_version.as_deref(),
            Some("100")
        );

        // A higher version 200 with a bad signature must not become latest.
        let kc200_bad = build_freshness_keychange(&core, "conv-1", "200", true);
        let result = core.decrypt_events(&[&kc200_bad], &signing_keys);
        assert_eq!(
            result.conversation_keys.latest_version.as_deref(),
            Some("100")
        );
    }

    #[test]
    fn freshness_high_water_is_per_conversation() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        // High-water for conv-1 at 500.
        let kc_a = build_freshness_keychange(&core, "conv-1", "500", false);
        let _ = core.decrypt_events(&[&kc_a], &signing_keys);

        // conv-2 is independent: its own verified version 100 is latest.
        let kc_b = build_freshness_keychange(&core, "conv-2", "100", false);
        let result = core.decrypt_events(&[&kc_b], &signing_keys);
        assert_eq!(
            result.conversation_keys.latest_version.as_deref(),
            Some("100")
        );
    }

    // Signature versions below the floor are rejected

    /// Build a signed message event but overwrite the embedded
    /// signature_version with `version`.
    fn build_message_event_with_sig_version(core: &ChatCore, version: &str) -> (String, String) {
        let ckey = core.generate_conversation_key().unwrap();
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "downgrade probe")
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();
        let mut event_b64 =
            wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        // Re-parse and rewrite the signature_version field.
        let bytes = base64_decode(&event_b64).unwrap();
        let mut event = parse_message_event(&bytes).unwrap();
        if let Some(sig) = event.message_event_signature.as_mut() {
            sig.signature_version = Some(version.to_string());
        }
        event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        let ckey_b64 = STANDARD_NO_PAD.encode(ckey.encoded());
        (event_b64, ckey_b64)
    }

    #[test]
    fn signature_version_below_floor_is_rejected() {
        let core = ChatCore::new(); // default reject_unverified = true
        let reg = core.generate_keypairs().unwrap();
        let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "1");

        let ckey =
            XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        let result = core.decrypt_event(&event_b64, &conv_keys, &signing_keys);
        let err = result.expect_err("v1 signature must be rejected");
        assert!(
            err.to_string().contains("no longer accepted"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn signature_version_below_floor_never_verifies_in_permissive_mode() {
        let mut core = ChatCore::new();
        core.set_reject_unverified(false);
        let reg = core.generate_keypairs().unwrap();
        let (event_b64, ckey_b64) = build_message_event_with_sig_version(&core, "0");

        let ckey =
            XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        match core.decrypt_event(&event_b64, &conv_keys, &signing_keys) {
            Ok(Event::Message(msg)) => {
                assert!(!msg.verified, "below-floor version must never verify")
            }
            Ok(other) => panic!("expected Message, got {:?}", other),
            Err(e) => panic!("permissive mode should pass through unverified: {}", e),
        }
    }

    #[test]
    fn signature_version_at_floor_is_processed() {
        // At/above the floor the message payload format is identical, so
        // the signature still verifies.
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let (event_b64, ckey_b64) = build_message_event_with_sig_version(
            &core,
            &crate::signatures::MIN_SIGNATURE_VERSION.to_string(),
        );

        let ckey =
            XChatConversationKey::from_bytes(STANDARD_NO_PAD.decode(&ckey_b64).unwrap()).unwrap();
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        match core.decrypt_event(&event_b64, &conv_keys, &signing_keys) {
            Ok(Event::Message(msg)) => assert!(msg.verified),
            other => panic!("expected verified Message, got {:?}", other),
        }
    }

    // Default reject_unverified=true rejects unverifiable events

    #[test]
    fn reject_unverified_rejects_keychange_without_matching_signing_key() {
        // Default reject_unverified=true. A signed KeyChange with no
        // matching signing key cannot be verified and must be rejected.
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let kce = ThriftCKCE::new(
            Some("ckv-1".to_string()),
            None::<Vec<ConversationParticipantKey>>,
            None,
            None,
        );
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some("AAAA".to_string()),
            Some("pkv".to_string()),
            Some("7".to_string()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some("seq-1".to_string()),
            Some("msg-1".to_string()),
            Some("sender-1".to_string()),
            Some("conv-1".to_string()),
            None::<String>,
            None::<String>,
            Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        let event_b64 = base64_encode(&serialize_thrift(&event).unwrap());

        // No matching signing key supplied → rejected.
        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(
            result.is_err(),
            "KeyChange with no matching signing key must be rejected"
        );
    }

    #[test]
    fn reject_unverified_rejects_unencrypted_message_by_default() {
        // An unencrypted message (no conversation_key_version) carries no
        // signature, so under the default reject_unverified it is rejected.
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();

        let content = build_plaintext_content("plaintext");
        let event_b64 = build_test_message_event(&content, None);

        let result = core.decrypt_event(&event_b64, &Default::default(), &[]);
        assert!(
            result.is_err(),
            "unencrypted message must be rejected under default reject_unverified"
        );
    }

    // ChatCore-level roundtrips: reply / add-reaction / remove-reaction

    #[test]
    fn encrypt_reply_signature_verifies_on_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let mut reply_params = crate::EncryptReplyParams::new("conv-1", "a reply", "")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        reply_params.reply_to_sequence_id = Some("seq-99".into());
        let payload = core.encrypt_reply(reply_params).unwrap();
        let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "pkv".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(msg.verified, "self-signed reply must verify");
                assert_eq!(msg.text(), Some("a reply"));
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn encrypt_add_reaction_signature_verifies_on_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let mut params = crate::EncryptReactionParams::new("", "thumbs")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());
        let payload = core.encrypt_add_reaction(&params).unwrap();
        let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "pkv".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(msg.verified, "self-signed reaction must verify");
                match &msg.content {
                    MessageContent::Reaction {
                        emoji,
                        target_message_id,
                    } => {
                        assert_eq!(emoji, "thumbs");
                        assert_eq!(target_message_id, "seq-42");
                    }
                    other => panic!("expected Reaction, got {:?}", other),
                }
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn encrypt_remove_reaction_signature_verifies_on_decrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let mut params = crate::EncryptReactionParams::new("", "thumbs")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.conversation_id = Some("conv-1".into());
        params.target_message_sequence_id = Some("seq-42".into());
        let payload = core.encrypt_remove_reaction(&params).unwrap();
        let event_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");

        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [SigningKeyEntry {
            user_id: "sender-1".to_string(),
            public_key_version: "pkv".to_string(),
            public_key: reg.public_key.signing_public_key.clone(),
            identity_public_key: reg.public_key.public_key.clone(),
            identity_public_key_signature: reg.public_key.identity_public_key_signature.clone(),
        }];

        let event = core
            .decrypt_event(&event_b64, &conv_keys, &signing_keys)
            .unwrap();
        match event {
            Event::Message(msg) => {
                assert!(msg.verified, "self-signed reaction-remove must verify");
                match &msg.content {
                    MessageContent::ReactionRemoved {
                        emoji,
                        target_message_id,
                    } => {
                        assert_eq!(emoji, "thumbs");
                        assert_eq!(target_message_id, "seq-42");
                    }
                    other => panic!("expected ReactionRemoved, got {:?}", other),
                }
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    // Session identity

    /// Like `wrap_signed_payload` but with an explicit sequence id, for tests
    /// that reference a message by sequence (replies, reactions).
    fn wrap_signed_payload_with_seq(
        payload: &SendPayload,
        sender_id: &str,
        conversation_id: &str,
        sequence_id: &str,
    ) -> String {
        let mce_bytes = base64_decode(&payload.encrypted_content).unwrap();
        let mce = parse_message_event(&mce_bytes)
            .ok()
            .and_then(|e| e.detail)
            .or_else(|| {
                let cursor = Cursor::new(mce_bytes.clone());
                let mut raw = TBinaryInputProtocol::new(cursor, true);
                let mut p = BoundedProtocol::new(&mut raw);
                crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                    .ok()
                    .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
            })
            .expect("parse MCE");
        let sig_struct = crate::thrift::event::MessageEventSignature::new(
            Some(payload.signature.clone()),
            Some(payload.signature_info.public_key_version.clone()),
            Some(payload.signature_info.signature_version.clone()),
            None,
            None,
        );
        let event = ThriftMessageEvent::new(
            Some(sequence_id.to_string()),
            Some(payload.message_id.clone()),
            Some(sender_id.to_string()),
            Some(conversation_id.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(mce),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(sig_struct),
            None::<String>,
            None::<bool>,
        );
        base64_encode(&serialize_thrift(&event).unwrap())
    }

    #[test]
    fn session_identity_signs_the_same_values_as_explicit_params() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");
        let ckey = core.generate_conversation_key().unwrap();

        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hi")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();
        assert_eq!(payload.signature_info.public_key_version, "pkv");

        // Verifying against the session sender_id and signing_key_version
        // proves the signature covers exactly the values an explicit call
        // would have signed.
        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        match core
            .decrypt_event(&msg_b64, &conv_keys, &signing_keys)
            .unwrap()
        {
            Event::Message(msg) => {
                assert!(msg.verified);
                assert_eq!(msg.text(), Some("hi"));
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn encrypt_message_without_sender_id_errors() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();
        let err = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hi")
                    .with_conversation_key(ckey.to_bytes(), "1"),
            )
            .unwrap_err();
        assert!(err.to_string().contains("sender_id"), "got: {err}");
    }

    /// Encrypt must fail loudly on attachment combinations first-party
    /// clients cannot render (temporary client-compat guard) and must not
    /// produce ciphertext for them, while multi image/gif/video stays allowed.
    #[test]
    fn encrypt_message_rejects_disallowed_attachment_combos() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let media = |mt: Option<i32>| crate::AttachmentDescriptor::Media {
            media_hash_key: "hash".into(),
            width: 100,
            height: 100,
            filesize_bytes: 1000,
            filename: "file".into(),
            media_type: mt,
            duration_millis: None,
        };
        let url = || crate::AttachmentDescriptor::Url {
            url: "https://example.com".into(),
            display_title: None,
            banner_image: None,
            favicon_image: None,
        };
        let params_with = |attachments: Vec<crate::AttachmentDescriptor>| {
            let mut p = crate::EncryptMessageParams::new("conv-1", "hi")
                .with_identity("sender-1", "pkv")
                .with_conversation_key(ckey.to_bytes(), "1");
            p.attachments = Some(attachments);
            p
        };

        // Mixed media + URL card is rejected before any ciphertext exists.
        let err = core
            .encrypt_message(params_with(vec![media(Some(1)), url()]))
            .unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
        assert!(err.to_string().contains("attachment combination"));

        // Two URL cards are rejected.
        let err = core
            .encrypt_message(params_with(vec![url(), url()]))
            .unwrap_err();
        assert!(err.to_string().contains("attachment combination"));

        // Multiple image/gif/video media stay allowed.
        core.encrypt_message(params_with(vec![
            media(Some(1)),
            media(Some(2)),
            media(Some(3)),
        ]))
        .unwrap();

        // A lone non-multi attachment (file media) stays allowed.
        core.encrypt_message(params_with(vec![media(Some(5))]))
            .unwrap();
    }

    #[test]
    fn encrypt_reply_rejects_disallowed_attachment_combos() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();

        let mut params = crate::EncryptReplyParams::new("conv-1", "hi", "")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "1");
        params.reply_to_sequence_id = Some("seq-1".into());
        params.attachments = Some(vec![
            crate::AttachmentDescriptor::Post {
                rest_id: Some("1".into()),
                post_url: None,
            },
            crate::AttachmentDescriptor::Media {
                media_hash_key: "hash".into(),
                width: 100,
                height: 100,
                filesize_bytes: 1000,
                filename: "pic.jpg".into(),
                media_type: Some(1),
                duration_millis: None,
            },
        ]);
        let err = core.encrypt_reply(params).unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
        assert!(err.to_string().contains("attachment combination"));
    }

    #[test]
    fn encrypt_message_without_signing_key_version_errors() {
        let source = ChatCore::new();
        source.generate_keypairs().unwrap();
        let exported = source.export_keys().unwrap();

        // A raw import carries no key version, so nothing can resolve it.
        let core = ChatCore::new();
        core.import_keys(&exported).unwrap();
        let ckey = core.generate_conversation_key().unwrap();
        let mut params = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1");
        params.sender_id = Some("sender-1".into());
        let err = core.encrypt_message(params).unwrap_err();
        assert!(
            err.to_string().contains("signing_key_version"),
            "got: {err}"
        );
    }

    #[test]
    fn import_keys_with_version_completes_the_identity() {
        let source = ChatCore::new();
        source.generate_keypairs().unwrap();
        let exported = source.export_keys().unwrap();

        let core = ChatCore::new();
        core.import_keys_with_version(&exported, "pkv-2").unwrap();
        let ckey = core.generate_conversation_key().unwrap();
        let mut params = crate::EncryptMessageParams::new("conv-1", "hi")
            .with_conversation_key(ckey.to_bytes(), "1");
        params.sender_id = Some("sender-1".into());
        let payload = core.encrypt_message(params).unwrap();
        assert_eq!(payload.signature_info.public_key_version, "pkv-2");
    }

    #[test]
    fn prepare_conversation_key_change_uses_session_identity() {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core.set_identity("me", "1");
        let pubkeys = core.get_public_keys().unwrap();
        let mut params = crate::ConversationKeyChangeParams::new(vec![PublicKeyInput {
            user_id: "me".into(),
            public_key: pubkeys.identity,
            key_version: "1".into(),
        }]);
        params.conversation_id = Some("conv-1".into());
        let prepared = core.prepare_conversation_key_change(params).unwrap();
        assert_eq!(prepared.action_signatures[0].public_key_version, "1");
    }

    // Conversation-key and signing-key caches

    #[test]
    fn cache_resolves_verified_latest_key_for_encrypt() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");
        core.set_cache_keys(true);

        let ckey = core.generate_conversation_key().unwrap();
        let kc_b64 = build_signed_self_keychange_event(
            &core,
            &ckey,
            "1001",
            "sender-1",
            "pkv",
            Some("pkv".to_string()),
        );
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        core.decrypt_events(&[kc_b64.as_str()], &signing_keys);

        // No key passed: it resolves from the cache at the verified version.
        let payload = core
            .encrypt_message(crate::EncryptMessageParams::new("conv-1", "cached"))
            .unwrap();
        assert_eq!(payload.conversation_key_version, "1001");

        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");
        let conv_keys = [("1001".to_string(), ckey)].into_iter().collect();
        match core
            .decrypt_event(&msg_b64, &conv_keys, &signing_keys)
            .unwrap()
        {
            Event::Message(msg) => assert_eq!(msg.text(), Some("cached")),
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn cache_is_off_by_default() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");

        let ckey = core.generate_conversation_key().unwrap();
        let kc_b64 = build_signed_self_keychange_event(
            &core,
            &ckey,
            "1001",
            "sender-1",
            "pkv",
            Some("pkv".to_string()),
        );
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        core.decrypt_events(&[kc_b64.as_str()], &signing_keys);

        let err = core
            .encrypt_message(crate::EncryptMessageParams::new("conv-1", "no cache"))
            .unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
    }

    #[test]
    fn unverified_key_change_never_becomes_an_encryption_key() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");
        core.set_cache_keys(true);

        // Adopted-for-decryption key change with an unverifiable signature.
        let ckey = core.generate_conversation_key().unwrap();
        let kc_b64 =
            build_self_keychange_event(&core, &ckey, "2002", "sender-1", Some("pkv".to_string()));
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];
        let result = core.decrypt_events(&[kc_b64.as_str()], &signing_keys);
        assert!(result.conversation_keys.keys.contains_key("2002"));

        let err = core
            .encrypt_message(crate::EncryptMessageParams::new("conv-1", "must fail"))
            .unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err}");
    }

    #[test]
    fn cache_never_moves_below_the_verified_high_water() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");
        core.set_cache_keys(true);
        let signing_keys = [signing_key_entry_for(&reg, "sender-1")];

        let newer = core.generate_conversation_key().unwrap();
        let kc_newer = build_signed_self_keychange_event(
            &core,
            &newer,
            "2000",
            "sender-1",
            "pkv",
            Some("pkv".to_string()),
        );
        core.decrypt_events(&[kc_newer.as_str()], &signing_keys);

        // A validly signed but older key change replayed later must not
        // displace the newer cached key.
        let older = core.generate_conversation_key().unwrap();
        let kc_older = build_signed_self_keychange_event(
            &core,
            &older,
            "1000",
            "sender-1",
            "pkv",
            Some("pkv".to_string()),
        );
        core.decrypt_events(&[kc_older.as_str()], &signing_keys);

        let payload = core
            .encrypt_message(crate::EncryptMessageParams::new("conv-1", "fresh"))
            .unwrap();
        assert_eq!(payload.conversation_key_version, "2000");
    }

    #[test]
    fn signing_key_store_is_used_when_the_argument_is_omitted() {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        core.set_identity("sender-1", "pkv");
        let ckey = core.generate_conversation_key().unwrap();
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "hello")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();
        let msg_b64 = wrap_signed_payload(&payload, &payload.message_id, "sender-1", "conv-1");
        let conv_keys: HashMap<String, XChatConversationKey> =
            [("9001".to_string(), ckey)].into_iter().collect();

        // Without stored keys an empty slice still fails verification.
        assert!(core.decrypt_event(&msg_b64, &conv_keys, &[]).is_err());

        core.set_signing_keys(vec![signing_key_entry_for(&reg, "sender-1")]);
        match core.decrypt_event(&msg_b64, &conv_keys, &[]).unwrap() {
            Event::Message(msg) => {
                assert!(msg.verified);
                assert_eq!(msg.text(), Some("hello"));
            }
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn cached_key_debug_output_is_redacted() {
        let key = KeyFactory::generate_conversation_key().unwrap();
        let cached = CachedConversationKey { version: 1, key };
        let debug = format!("{:?}", cached);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("bytes"));
    }

    // Event-based replies and reactions + reply-preview validation

    /// Two-party setup: returns (receiver core, sender identities) where both
    /// senders' signing keys are known to the receiver.
    fn reply_test_setup() -> (ChatCore, XChatConversationKey, Vec<SigningKeyEntry>) {
        let core = ChatCore::new();
        let reg = core.generate_keypairs().unwrap();
        let ckey = core.generate_conversation_key().unwrap();
        // Both participants sign with the same test keypair; only the
        // user ids differ, which is what key selection filters on.
        let signing_keys = vec![
            signing_key_entry_for(&reg, "sender-1"),
            signing_key_entry_for(&reg, "sender-2"),
        ];
        (core, ckey, signing_keys)
    }

    fn original_event_b64(core: &ChatCore, ckey: &XChatConversationKey, text: &str) -> String {
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", text)
                    .with_identity("sender-2", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();
        wrap_signed_payload_with_seq(&payload, "sender-2", "conv-1", "seq-orig")
    }

    fn decrypt_reply(
        core: &ChatCore,
        ckey: &XChatConversationKey,
        reply_payload: &SendPayload,
        signing_keys: &[SigningKeyEntry],
    ) -> Message {
        let reply_b64 =
            wrap_signed_payload_with_seq(reply_payload, "sender-1", "conv-1", "seq-reply");
        let conv_keys = [("9001".to_string(), ckey.clone())].into_iter().collect();
        match core
            .decrypt_event(&reply_b64, &conv_keys, signing_keys)
            .unwrap()
        {
            Event::Message(msg) => *msg,
            other => panic!("expected Message, got {:?}", other),
        }
    }

    #[test]
    fn encrypt_reply_derives_preview_from_raw_event_and_validates() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "original words");

        let reply_payload = core
            .encrypt_reply(
                crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(msg.text(), Some("the reply"));
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Valid)
        );
        match &msg.content {
            MessageContent::Text {
                replying_to_preview: Some(preview),
                ..
            } => {
                assert_eq!(preview.message_text.as_deref(), Some("original words"));
                assert_eq!(
                    preview.replying_to_message_sequence_id.as_deref(),
                    Some("seq-orig")
                );
            }
            other => panic!("expected Text with preview, got {:?}", other),
        }
    }

    #[test]
    fn forged_preview_text_is_marked_invalid() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "what was actually said");

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_text = Some("words never sent".into());
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Invalid)
        );
    }

    #[test]
    fn forged_preview_sender_is_marked_invalid() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "hello");

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_sender_id = Some(424242);
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Invalid)
        );
    }

    #[test]
    fn tampered_raw_event_signature_is_marked_invalid() {
        let (core, ckey, signing_keys) = reply_test_setup();

        // Corrupt the original's signature before embedding it: the sender
        // path never verifies it, the receiver must.
        let payload = core
            .encrypt_message(
                crate::EncryptMessageParams::new("conv-1", "genuine text")
                    .with_identity("sender-2", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();
        let mut tampered = payload.clone();
        let mut sig = base64_decode_or_empty(&tampered.signature);
        sig[0] ^= 0x01;
        tampered.signature = STANDARD_NO_PAD.encode(&sig);
        let orig_b64 = wrap_signed_payload_with_seq(&tampered, "sender-2", "conv-1", "seq-orig");

        let reply_payload = core
            .encrypt_reply(
                crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
                    .with_identity("sender-1", "pkv")
                    .with_conversation_key(ckey.to_bytes(), "9001"),
            )
            .unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Invalid)
        );
    }

    #[test]
    fn truncated_preview_text_is_valid() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "a long original message body");

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_text = Some("a long original".into());
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Valid)
        );
    }

    #[test]
    fn text_override_still_derives_entities_from_the_original() {
        let (core, ckey, signing_keys) = reply_test_setup();

        let mut orig_params = crate::EncryptMessageParams::new("conv-1", "#topic original")
            .with_identity("sender-2", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        orig_params.entities = Some(vec![crate::EntityDescriptor {
            start: 0,
            end: 6,
            entity_type: "hashtag".into(),
        }]);
        let orig_payload = core.encrypt_message(orig_params).unwrap();
        let orig_b64 =
            wrap_signed_payload_with_seq(&orig_payload, "sender-2", "conv-1", "seq-orig");

        // A prefix text override must not suppress deriving the remaining
        // preview fields from the decrypted original.
        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_text = Some("#topic".into());
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Valid)
        );
        match &msg.content {
            MessageContent::Text {
                replying_to_preview: Some(preview),
                ..
            } => {
                assert_eq!(preview.message_text.as_deref(), Some("#topic"));
                let entities = preview.entities.as_ref().expect("derived entities");
                assert_eq!(entities.len(), 1);
            }
            other => panic!("expected Text with preview, got {:?}", other),
        }
    }

    #[test]
    fn preview_without_raw_event_passes_through_unvalidated() {
        let (core, ckey, signing_keys) = reply_test_setup();

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", "")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_sequence_id = Some("seq-orig".into());
        params.reply_to_text = Some("whatever".into());
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(msg.reply_preview_validation, None);
    }

    /// Build a signed, encrypted edit event for `original_seq`, framed as the
    /// backend delivers it.
    fn edit_event_b64(
        core: &ChatCore,
        ckey: &XChatConversationKey,
        sender: &str,
        original_seq: &str,
        updated_text: &str,
        edit_seq: &str,
    ) -> String {
        let edit = crate::thrift::product::MessageEdit::new(
            Some(original_seq.to_string()),
            Some(updated_text.to_string()),
            None,
        );
        let holder = crate::thrift::product::MessageEntryHolder::new(Some(Box::new(
            crate::thrift::product::MessageEntryContents::MessageEdit(Box::new(edit)),
        )));
        let content_bytes = serialize_thrift(&holder).unwrap();
        let signing = core.get_signing_keypair_arc().unwrap();
        let message_id = ChatCore::generate_message_id();
        let payload =
            crate::pipeline::encrypt_and_sign(crate::pipeline::EncryptAndSignParams::new(
                ckey,
                &signing.private,
                &message_id,
                sender,
                "conv-1",
                &content_bytes,
                "9001",
                "pkv",
            ))
            .unwrap();
        wrap_signed_payload_with_seq(&payload, sender, "conv-1", edit_seq)
    }

    #[test]
    fn reply_to_edited_original_derives_and_validates_the_edited_text() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
        let edit_b64 = edit_event_b64(
            &core,
            &ckey,
            "sender-2",
            "seq-orig",
            "the new wording",
            "seq-edit",
        );

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_edit_event = Some(edit_b64);
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Valid)
        );
        match &msg.content {
            MessageContent::Text {
                replying_to_preview: Some(preview),
                ..
            } => {
                // The preview quotes what the message says after the edit.
                assert_eq!(preview.message_text.as_deref(), Some("the new wording"));
            }
            other => panic!("expected Text with preview, got {:?}", other),
        }
    }

    #[test]
    fn preview_claiming_pre_edit_text_is_marked_invalid() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
        let edit_b64 = edit_event_b64(
            &core,
            &ckey,
            "sender-2",
            "seq-orig",
            "the new wording",
            "seq-edit",
        );

        // A preview that embeds the edit but quotes the pre-edit text is
        // misattributing the message's current contents.
        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_edit_event = Some(edit_b64);
        params.reply_to_text = Some("the first wording".into());
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Invalid)
        );
    }

    #[test]
    fn edit_by_a_different_sender_is_marked_invalid() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "the first wording");
        // Same signing key, different claimed author than the original.
        let edit_b64 = edit_event_b64(
            &core,
            &ckey,
            "sender-1",
            "seq-orig",
            "the new wording",
            "seq-edit",
        );

        let mut params = crate::EncryptReplyParams::new("conv-1", "the reply", orig_b64)
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        params.reply_to_edit_event = Some(edit_b64);
        let reply_payload = core.encrypt_reply(params).unwrap();

        let msg = decrypt_reply(&core, &ckey, &reply_payload, &signing_keys);
        assert_eq!(
            msg.reply_preview_validation,
            Some(ReplyPreviewValidation::Invalid)
        );
    }

    #[test]
    fn encrypt_reaction_derives_target_from_event() {
        let (core, ckey, signing_keys) = reply_test_setup();
        let orig_b64 = original_event_b64(&core, &ckey, "react to me");

        let params = crate::EncryptReactionParams::new(orig_b64, "👍")
            .with_identity("sender-1", "pkv")
            .with_conversation_key(ckey.to_bytes(), "9001");
        let payload = core.encrypt_add_reaction(&params).unwrap();

        let react_b64 = wrap_signed_payload_with_seq(&payload, "sender-1", "conv-1", "seq-react");
        let conv_keys = [("9001".to_string(), ckey)].into_iter().collect();
        match core
            .decrypt_event(&react_b64, &conv_keys, &signing_keys)
            .unwrap()
        {
            Event::Message(msg) => match &msg.content {
                MessageContent::Reaction {
                    emoji,
                    target_message_id,
                } => {
                    assert_eq!(emoji, "👍");
                    assert_eq!(target_message_id, "seq-orig");
                }
                other => panic!("expected Reaction, got {:?}", other),
            },
            other => panic!("expected Message, got {:?}", other),
        }
    }
}
