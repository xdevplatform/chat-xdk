//! Platform-agnostic encryption core.
//!
//! `ChatCore` provides all cryptographic operations (key management,
//! encrypt/decrypt, sign/verify) without any Juicebox dependency or
//! platform-specific concerns.  Both the native `Chat` (Juicebox
//! feature) and the WASM bindings wrap this struct.

use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::crypto::encryption::{FileDecryptor, FileEncryptor};
use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{KeypairPurpose, XChatConversationKey, XChatKeyPair, XChatPrivateKey};
use crate::crypto::message_keys;
use crate::error::{CryptoError, SdkError};
use crate::keys::conversation_keys;
use crate::keys::keypair_manager::KeypairManager;
use crate::params::{
    ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams, DecryptFileParams,
    EncryptEditParams, EncryptFileParams, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, FileDecryptorParams, FileEncryptorParams, GroupCreateParams,
    GroupMembersChangeParams, ImportKeysParams, MarkConversationReadParams, MessageDeleteParams,
    SetIdentityParams,
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
    reject_unverified: std::sync::atomic::AtomicBool,
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
    /// This instance's feature switches from `GET /2/chat/features`; all off
    /// until an answer turns them on.
    features: std::sync::Mutex<crate::features::ChatFeatures>,
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
            reject_unverified: std::sync::atomic::AtomicBool::new(true),
            conversation_key_high_water: std::sync::RwLock::new(HashMap::new()),
            owner_user_id: std::sync::RwLock::new(None),
            cache_keys: std::sync::atomic::AtomicBool::new(false),
            conversation_key_cache: std::sync::RwLock::new(HashMap::new()),
            signing_key_cache: std::sync::RwLock::new(Vec::new()),
            features: std::sync::Mutex::new(Default::default()),
        }
    }

    /// When enabled — the default — `decrypt_event` returns an error for any
    /// signed event type that cannot be positively verified: an invalid
    /// signature, a missing signature, no matching signing key (including an
    /// empty signing-key list), or an unencrypted message (which carries no
    /// verifiable signature). When disabled, such events are returned with
    /// `verified: false` instead. Event types that never carry a signature
    /// (typing, failure, member-account-delete) are unaffected either way.
    pub fn set_reject_unverified(&self, reject: bool) {
        self.reject_unverified
            .store(reject, std::sync::atomic::Ordering::Relaxed);
    }

    // Key Management

    /// Generate new keypairs and return the registration payload.
    ///
    /// No signing-key version is set: after registering the keys, call
    /// [`Self::set_identity`] with the `public_key_version` the registration
    /// returns.
    pub fn generate_keypairs(&self) -> Result<PublicKeyRegistrationPayload, SdkError> {
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

        Ok(PublicKeyRegistrationPayload {
            public_key: PublicKeyRegistration {
                identity_public_key_signature: base64_encode(&identity_signature),
                public_key: base64_encode(&identity_spki),
                public_key_fingerprint: Some(fingerprint),
                registration_method: "CustomPin".to_string(),
                signing_public_key: base64_encode(&signing_spki),
                signing_public_key_signature: Some(base64_encode(&signing_key_signature)),
            },
        })
    }

    /// Get current public keys.
    pub fn get_public_keys(&self) -> Result<PublicKeys, SdkError> {
        let identity = self.keypair_manager.get_identity_keypair()?;
        let signing = self.keypair_manager.get_signing_keypair()?;
        Ok(PublicKeys {
            identity: base64_encode(identity.public.encoded()),
            signing: base64_encode(signing.public.encoded()),
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
    /// The signing-key version is the `public_key_version` returned when the
    /// loaded keys were registered. It also lets `extract_conversation_keys`
    /// filter participant-key entries by version, avoiding decryption of keys
    /// intended for other key versions.
    ///
    /// A resolved default and an explicitly passed value produce
    /// byte-identical signed output for the same logical inputs.
    pub fn set_identity(&self, params: &SetIdentityParams) -> Result<(), SdkError> {
        crate::pipeline::validate_user_id("user_id", &params.user_id)?;
        crate::pipeline::validate_key_version("signing_key_version", &params.signing_key_version)?;
        *self
            .owner_user_id
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(params.user_id.clone());
        self.keypair_manager
            .set_key_version(params.signing_key_version.clone());
        Ok(())
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
    pub fn set_signing_keys(&self, entries: &[SigningKeyEntry]) {
        *self
            .signing_key_cache
            .write()
            .unwrap_or_else(|e| e.into_inner()) = entries.to_vec();
    }

    /// Resolve the effective `sender_id`: the explicit override when present,
    /// otherwise the session identity.
    fn resolve_sender_id(&self, param: Option<&str>) -> Result<String, SdkError> {
        let sender_id = match param.filter(|v| !v.is_empty()) {
            Some(v) => v.to_string(),
            None => self
                .owner_user_id
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| {
                    SdkError::InvalidState(
                        "sender_id is not set: pass it explicitly or call set_identity() first"
                            .into(),
                    )
                })?,
        };
        crate::pipeline::validate_user_id("sender_id", &sender_id)?;
        Ok(sender_id)
    }

    /// Resolve the effective `signing_key_version`: the explicit override
    /// when present, otherwise the session identity.
    fn resolve_signing_key_version(&self, param: Option<&str>) -> Result<String, SdkError> {
        let version = match param.filter(|v| !v.is_empty()) {
            Some(v) => v.to_string(),
            None => self.keypair_manager.get_key_version().ok_or_else(|| {
                SdkError::InvalidState(
                    "signing_key_version is not set: pass it explicitly or call set_identity() \
                     first"
                        .into(),
                )
            })?,
        };
        crate::pipeline::validate_key_version("signing_key_version", &version)?;
        Ok(version)
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
            _ => Err(SdkError::InvalidInput(
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

    /// Import private keys from the blob `export_keys` returns (32 or 64
    /// bytes).
    ///
    /// Clears the signing-key version of any previously loaded keys. When
    /// `params.signing_key_version` is set, it becomes the imported keys'
    /// version, so participant-key filtering and the session signing-key
    /// version are set in one call.
    pub fn import_keys(&self, params: &ImportKeysParams) -> Result<(), SdkError> {
        use crate::crypto::keys::XChatPrivateKeys;
        if let Some(version) = params.signing_key_version.as_deref() {
            crate::pipeline::validate_key_version("signing_key_version", version)?;
        }
        let private_keys = XChatPrivateKeys::from_bytes(&params.keys).ok_or_else(|| {
            SdkError::InvalidInput("Invalid key format: expected 32 or 64 bytes".into())
        })?;
        self.keypair_manager
            .load_from_private_keys(&private_keys)
            .map_err(SdkError::Crypto)?;
        if let Some(version) = params.signing_key_version.as_deref() {
            self.keypair_manager.set_key_version(version.to_string());
        }
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
        let sig_bytes = decode_input(
            "identity_public_key_signature",
            identity_public_key_signature_b64,
        )?;
        // The signing key signs the identity key's bytes exactly as they
        // appear on the wire (SPKI). Verify with the signing key over those
        // same bytes — the signature is raw r||s.
        let identity_bytes = decode_input("identity_public_key", identity_public_key_b64)?;
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
        let candidate = decode_input("public key", public_key_b64)?;
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

    // Feature switches (see `crate::features`).

    /// Set this instance's feature switches from the answer to `GET
    /// /2/chat/features` ([`crate::FEATURES_ENDPOINT`]): the response's HTTP
    /// status and body. The SDK never makes the request: GET it yourself
    /// once, when you create the instance, without credentials or query
    /// parameters, within [`crate::FEATURES_TIMEOUT_MS`], reading at most
    /// [`crate::FEATURES_MAX_BODY`] plus one byte of the body.
    ///
    /// Sends are v0 (the format 0.5.x sends) until the answer turns
    /// `v1_send` on, then v1 (per-message keys). Every switch stays off when
    /// the status is not 200 or the body is longer than
    /// [`crate::FEATURES_MAX_BODY`] or is not a `{"features": {...}}` object;
    /// a switch whose value is not `true` reads off. An instance takes one
    /// answer for its lifetime: later calls change nothing.
    pub fn set_feature_switches(&self, status: u16, body: &[u8]) {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .answer(status, body);
    }

    /// Whether the feature switch `name` is on for this instance.
    pub(crate) fn feature_enabled(&self, name: &str) -> bool {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enabled(name)
    }

    /// Read this instance's feature switches from `endpoint`, within
    /// `timeout_ms`, when its read starts.
    #[cfg_attr(not(feature = "bindings"), allow(dead_code))]
    pub(crate) fn configure_features(&self, endpoint: &str, timeout_ms: u64) {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .configure(endpoint, timeout_ms);
    }

    /// Start this instance's one read of the feature switches: the GET to
    /// perform, or `None` when it shares a GET in flight or has started its
    /// read already.
    #[cfg_attr(not(feature = "bindings"), allow(dead_code))]
    pub(crate) fn start_features(&self) -> Option<crate::features::Fetch> {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .start()
    }

    /// Read exactly `on` as on from now on, without any fetch.
    #[cfg(test)]
    pub(crate) fn force_features(&self, on: &[&str]) {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .force(on);
    }

    /// The wire format sends use: v1 while `v1_send` is on, else v0.
    fn send_version(&self) -> crate::pipeline::SendVersion {
        if self.feature_enabled(crate::features::V1_SEND) {
            crate::pipeline::SendVersion::V1
        } else {
            crate::pipeline::SendVersion::V0
        }
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
        if !self
            .reject_unverified
            .load(std::sync::atomic::Ordering::Relaxed)
        {
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
        if sig_version > crate::signatures::MAX_SIGNATURE_VERSION {
            return Err(format!(
                "signature_version {} is not supported (maximum: {})",
                sig_version,
                crate::signatures::MAX_SIGNATURE_VERSION
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

/// Decode a caller's base64 argument, naming it in the error.
fn decode_input(name: &str, b64: &str) -> Result<Vec<u8>, SdkError> {
    base64_decode(b64).map_err(|e| SdkError::InvalidInput(format!("Invalid {name}: {e}")))
}

/// Current time as a millisecond-timestamp string, used for key versions.
///
/// Reads the system clock, which panics on `wasm32-unknown-unknown`; WASM hosts
/// call the `*_with_version` variants and supply the timestamp from JavaScript.
fn now_millis() -> String {
    now_msec().to_string()
}

/// Current time in milliseconds since the Unix epoch.
///
/// Reads the system clock, which panics on `wasm32-unknown-unknown`; WASM hosts
/// supply the time from JavaScript instead.
fn now_msec() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
pub(crate) fn parse_message_event(data: &[u8]) -> Result<MessageEvent, SdkError> {
    let cursor = Cursor::new(data);
    let mut raw = TBinaryInputProtocol::new(cursor, true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    MessageEvent::read_from_in_protocol(&mut protocol)
        .map_err(|e| SdkError::Parse(format!("Thrift parse error: {}", e)))
}

// Signature payload builders

/// Build the comma-separated signature payload for an event, in the layout
/// of the signature version the event carries.
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

    let mut payload = match detail {
        MessageEventDetail::MessageCreateEvent(mce) => {
            // Versions below MIN_SIGNATURE_VERSION use an unverifiable payload
            // form, so reject them before reaching the verifier.
            if sig_version < crate::signatures::MIN_SIGNATURE_VERSION {
                return None;
            }
            let contents = mce.contents.as_ref()?;
            let contents_b64 = STANDARD_NO_PAD.encode(contents);
            // v8+ signs the key version as a canonical integer, "null" when
            // absent or not an integer. Earlier versions sign it as carried,
            // empty when absent.
            let ckey_ver = if sig_version >= 8 {
                nullable_i64(
                    mce.conversation_key_version
                        .as_deref()
                        .and_then(|v| v.parse::<i64>().ok()),
                )
            } else {
                mce.conversation_key_version.clone().unwrap_or_default()
            };
            let mut extra = vec![ckey_ver, contents_b64];
            // v10+: contents_encryption_version
            if sig_version >= 10 {
                extra.push(nullable_i64(mce.contents_encryption_version.map(i64::from)));
            }
            let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
            build_component_payload(
                "MessageCreateEvent",
                msg_id,
                sender_id,
                conv_id,
                &extra_refs,
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
                    // v8+: current_description
                    if sig_version > 7 {
                        extra.push(nullable_str(c.current_description.as_deref()));
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
                    let mut extra: Vec<String> = ids.clone();
                    // v11+: conversation_key_version
                    if sig_version >= 11 {
                        extra.push(nullable_str(c.conversation_key_version.as_deref()));
                    }
                    let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
                    build_component_payload(
                        "GroupChangeEvent.GroupMemberRemoveChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &extra_refs,
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
                    // v9+: group_type, as its number
                    if sig_version >= 9 {
                        extra.push(nullable_i64(c.group_type.map(|t| i64::from(t.0))));
                    }
                    // v10+: ttl_msec
                    if sig_version >= 10 {
                        extra.push(nullable_i64(c.ttl_msec));
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
                // Key version, then the description. An absent description
                // signs as empty, the same way a title change signs its title.
                GenGC::GroupDescriptionChange(c) => {
                    let ckey_ver = c.conversation_key_version.as_deref()?;
                    let description = c.custom_description.as_deref().unwrap_or("");
                    build_component_payload(
                        "GroupChangeEvent.GroupDescriptionChange",
                        msg_id,
                        sender_id,
                        conv_id,
                        &[ckey_ver, description],
                    )
                }
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
                // Not surfaced by the SDK, so left unverifiable.
                CMC::EnableGrok(_)
                | CMC::DisableGrok(_)
                | CMC::ArchiveConversation(_)
                | CMC::UnarchiveConversation(_) => None,
            }
        }
        // These event types are not signed
        MessageEventDetail::MessageTypingEvent(_)
        | MessageEventDetail::MessageFailureEvent(_)
        | MessageEventDetail::MemberAccountDeleteEvent(_) => None,
        _ => None,
    }?;

    // v9+ binds the signature version into every component payload.
    if sig_version >= 9 {
        payload.extend_from_slice(format!(",signature_version={}", sig_version).as_bytes());
    }
    Some(payload)
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

/// Whether the SDK surfaces this attachment kind. Payment-receipt and
/// bot-message attachments have no public model, so they are left out
/// wherever attachments are mapped or compared.
fn is_modeled_attachment(attachment: &ThriftMessageAttachment) -> bool {
    !matches!(
        attachment,
        ThriftMessageAttachment::PaymentReceipt(_) | ThriftMessageAttachment::BotMessage(_)
    )
}

/// An attachment in the form a reply preview's claims are compared in:
/// kinds the SDK does not surface are left out, and a media attachment's
/// `plaintext_sha256` is ignored, as it does not change which media is
/// quoted.
fn claim_comparable(attachment: &ThriftMessageAttachment) -> Option<ThriftMessageAttachment> {
    if !is_modeled_attachment(attachment) {
        return None;
    }
    let mut comparable = attachment.clone();
    if let ThriftMessageAttachment::Media(media) = &mut comparable {
        media.plaintext_sha256 = None;
    }
    Some(comparable)
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
                // The SDK doesn't support this attachment variant; skip it.
            }
            ThriftMessageAttachment::PaymentReceipt(_) | ThriftMessageAttachment::BotMessage(_) => {
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
                target_message_sequence_id: r.message_sequence_id.unwrap_or_default(),
            },
            MessageEntryContents::ReactionRemove(r) => MessageContent::ReactionRemoved {
                emoji: r.emoji.unwrap_or_default(),
                target_message_sequence_id: r.message_sequence_id.unwrap_or_default(),
            },
            MessageEntryContents::MessageEdit(e) => MessageContent::Edit {
                target_message_sequence_id: e.message_sequence_id.unwrap_or_default(),
                target_message_id: e.message_id,
                updated_text: e.updated_text.unwrap_or_default(),
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
            .filter_map(|attachment| map_message_attachment(attachment.as_ref()))
            .collect()
    })
}

fn map_message_attachment(
    attachment: &crate::thrift::product::MessageAttachment,
) -> Option<MessageAttachment> {
    Some(match attachment {
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
        crate::thrift::product::MessageAttachment::PaymentReceipt(_)
        | crate::thrift::product::MessageAttachment::BotMessage(_) => return None,
    })
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
        Some(
            GenCMC::EnableGrok(_)
            | GenCMC::DisableGrok(_)
            | GenCMC::ArchiveConversation(_)
            | GenCMC::UnarchiveConversation(_),
        ) => SettingsChange::Unknown,
        None => SettingsChange::Unknown,
    }
}

mod conversation;
mod decrypt;
mod encrypt;
mod files;
mod group_actions;
mod media;
mod signing;

// Tests

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod signature_version_tests;

#[cfg(test)]
mod message_key_tests;

#[cfg(test)]
mod media_tests;

#[cfg(test)]
mod send_tests;

#[cfg(test)]
mod send_version_tests;

#[cfg(test)]
mod compat_v05_tests;

#[cfg(test)]
mod tests;
