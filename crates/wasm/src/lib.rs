//! # X Chat SDK - WebAssembly Bindings
//!
//! Pure cryptographic engine for JavaScript/TypeScript.  The Rust WASM layer
//! handles **only** crypto operations — Juicebox key-storage lifecycle
//! (setup/unlock/delete/changePin) is orchestrated entirely in the JS wrapper
//! (`index.js`) to avoid `globalThis` bridges and singleton state.
//!
//! ## Usage
//!
//! ```javascript
//! import { createChat } from 'chat-xdk';
//!
//! const chat = await createChat({
//!   juiceboxConfig: configFromXApi,
//!   getAuthToken: async (realmId) => await backend.getToken(realmId),
//! });
//! await chat.unlock("2580");
//!
//! // Batch decrypt — handles key extraction + signing key matching
//! const result = chat.decryptEvents({ events: rawEvents, signingKeys });
//! for (const dm of result.messages) {
//!   console.log(dm.event.type, dm.event.content?.text);
//! }
//!
//! // Single event with cached keys
//! const conversationKeys = result.conversationKeys.keys;
//! const event = chat.decryptEvent({ eventB64: newEventB64, conversationKeys, signingKeys });
//! ```

use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use chat_xdk_core::bindings::{self, FeatureSwitches};
use chat_xdk_core::crypto::keys::XChatConversationKey;

// Import generated camelCase JS types from core
use chat_xdk_core::js::{
    JsEvent, JsPreparedAction, JsPreparedConversationChange, JsPublicKeyInput,
    JsPublicKeyRegistrationPayload, JsSendPayload, JsSigningKeyEntry,
};

// Utility Functions (free functions, not methods)

/// Return the exact size of a file once encrypted: the size its upload
/// declares before the file is encrypted.
#[wasm_bindgen(js_name = encryptedFileSize)]
pub fn encrypted_file_size(plaintext_size: f64) -> Result<f64, JsError> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

    if !plaintext_size.is_finite()
        || plaintext_size < 0.0
        || plaintext_size.fract() != 0.0
        || plaintext_size > MAX_SAFE_INTEGER
    {
        return Err(JsError::new(
            "Plaintext size must be a non-negative safe integer",
        ));
    }

    let encrypted_size = chat_xdk_core::utils::encrypted_file_size(plaintext_size as u64)
        .ok_or_else(|| JsError::new("Encrypted file size overflow"))?;
    if encrypted_size > MAX_SAFE_INTEGER as u64 {
        return Err(JsError::new(
            "Encrypted file size exceeds Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(encrypted_size as f64)
}

/// Encode bytes to base64 string.
#[wasm_bindgen(js_name = bytesToBase64)]
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    chat_xdk_core::utils::bytes_to_base64(bytes)
}

/// Decode base64 string to bytes.
///
/// Returns null if the input is not valid base64.
#[wasm_bindgen(js_name = base64ToBytes)]
pub fn base64_to_bytes(b64: &str) -> Option<Vec<u8>> {
    chat_xdk_core::utils::base64_to_bytes(b64)
}

/// Encode bytes to lowercase hex string.
#[wasm_bindgen(js_name = bytesToHex)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    chat_xdk_core::utils::bytes_to_hex(bytes)
}

/// Decode hex string to bytes.
///
/// Returns null if the input is not valid hex.
#[wasm_bindgen(js_name = hexToBytes)]
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    chat_xdk_core::utils::hex_to_bytes(hex)
}

/// Detect MIME type from file bytes using magic numbers.
///
/// Returns the MIME type string (e.g., "image/png", "video/mp4") or null.
#[wasm_bindgen(js_name = detectMimeType)]
pub fn detect_mime_type(bytes: &[u8]) -> Option<String> {
    chat_xdk_core::utils::detect_mime_type(bytes).map(|s| s.to_string())
}

/// Detect image dimensions from file bytes.
///
/// Supports PNG, JPEG, GIF, WebP, and BMP.
/// Returns `{ width, height }` or null.
#[wasm_bindgen(js_name = detectImageDimensions)]
pub fn detect_image_dimensions(bytes: &[u8]) -> JsValue {
    match chat_xdk_core::utils::detect_image_dimensions(bytes) {
        Some(dims) => {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(&obj, &"width".into(), &(dims.width as f64).into()).ok();
            js_sys::Reflect::set(&obj, &"height".into(), &(dims.height as f64).into()).ok();
            obj.into()
        }
        None => JsValue::NULL,
    }
}

// Feature switches (GET /2/chat/features). The core decides when to fetch and
// what an answer means; the JS wrapper only steps a driver when the core wakes
// it and performs each GET it is handed. None of this is API, and all of it is
// left out of the TypeScript declarations.

thread_local! {
    static FEATURE_WAKER: std::cell::RefCell<Option<js_sys::Function>> =
        const { std::cell::RefCell::new(None) };
}

fn wake_feature_driver() {
    let waker = FEATURE_WAKER.with(|waker| waker.borrow().clone());
    if let Some(waker) = waker {
        let _ = waker.call0(&JsValue::NULL);
    }
}

/// Milliseconds from `performance.now()`, or `Date.now()` without it.
fn feature_clock() -> u64 {
    let performance = js_sys::Reflect::get(&js_sys::global(), &"performance".into()).ok();
    let now = performance.and_then(|performance| {
        let now: js_sys::Function = js_sys::Reflect::get(&performance, &"now".into())
            .ok()?
            .dyn_into()
            .ok()?;
        now.call0(&performance).ok()?.as_f64()
    });
    now.unwrap_or_else(js_sys::Date::now) as u64
}

/// Register the function the core calls to start the feature driver, or to
/// have it poll again, whenever its plan changes.
#[wasm_bindgen(js_name = __featureSetWaker, skip_typescript)]
pub fn feature_set_waker(waker: js_sys::Function) {
    FEATURE_WAKER.with(|slot| *slot.borrow_mut() = Some(waker));
    bindings::set_clock(feature_clock);
    bindings::set_polling_waker(wake_feature_driver);
}

/// The driver's next step: `{ id, url, timeoutMs, maxBytes }` to perform a
/// GET, `{ waitMs }` to poll again after that long (or when woken), or
/// `undefined` when no chat needs the switches.
#[wasm_bindgen(js_name = __featurePoll, skip_typescript)]
pub fn feature_poll() -> JsValue {
    let step = js_sys::Object::new();
    let set = |name: &str, value: JsValue| {
        js_sys::Reflect::set(&step, &name.into(), &value).ok();
    };
    match bindings::poll_fetch() {
        bindings::Poll::Fetch(fetch) => {
            set("id", (fetch.id as f64).into());
            set("url", fetch.url.into());
            set("timeoutMs", (fetch.timeout_ms as f64).into());
            set("maxBytes", (fetch.max_bytes as f64).into());
        }
        bindings::Poll::Wait(ms) => set("waitMs", (ms as f64).into()),
        bindings::Poll::Idle => return JsValue::UNDEFINED,
    }
    step.into()
}

/// Report the result of the GET `id`: its HTTP status, 0 when no complete
/// response arrived, and its body.
#[wasm_bindgen(js_name = __featureComplete, skip_typescript)]
pub fn feature_complete(id: f64, status: u16, body: &[u8]) {
    bindings::complete_fetch(id as u64, status, body);
}

/// For this repository's tests: the endpoint of every chat that does not set
/// its own, or the X API's when absent.
#[wasm_bindgen(js_name = __featureSetDefaultEndpoint, skip_typescript)]
pub fn feature_set_default_endpoint(endpoint: Option<String>) {
    bindings::set_default_endpoint(endpoint.as_deref());
}

/// Initialize panic hook for better error messages in console.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "panic_hook")]
    console_error_panic_hook::set_once();
}

/// The X Chat encryption SDK for JavaScript (crypto-only WASM layer).
///
/// Provides all cryptographic operations: key generation, encrypt/decrypt,
/// sign/verify. Juicebox key-storage lifecycle (setup/unlock/delete/changePin)
/// is handled by the JS wrapper in `index.js`, which calls `exportKeys()` /
/// `importKeys()` to shuttle raw key bytes across the boundary.
#[wasm_bindgen]
pub struct Chat {
    /// Platform-agnostic encryption core (single source of truth).
    inner: chat_xdk_core::ChatCore,
}

impl Default for Chat {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Chat {
    /// Create a new Chat instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Chat {
        Chat {
            inner: chat_xdk_core::ChatCore::new(),
        }
    }

    /// When enabled — the default — `decryptEvent` throws for any signed
    /// event whose signature cannot be verified (invalid, missing, or no
    /// matching signing key) instead of returning it with `verified: false`.
    #[wasm_bindgen(js_name = setRejectUnverified)]
    pub fn set_reject_unverified(&mut self, reject: bool) {
        self.inner.set_reject_unverified(reject);
    }

    /// Generate new keypairs and return the registration payload.
    #[wasm_bindgen(js_name = generateKeypairs)]
    pub fn generate_keypairs_impl(&mut self) -> Result<JsValue, JsError> {
        let payload = self
            .inner
            .generate_keypairs()
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsPublicKeyRegistrationPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Export private keys as raw bytes (`Uint8Array`).
    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .export_keys()
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Import private keys: `{ keys, signingKeyVersion? }`, where `keys` is
    /// the `Uint8Array` `exportKeys` returned. The SDK's copy of the bytes is
    /// zeroized after import. When `signingKeyVersion` is given it also
    /// records the public key version the keys were registered under
    /// (participant-key filtering plus the session `signingKeyVersion`).
    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(&mut self, params: JsValue) -> Result<(), JsError> {
        let mut p: JsImportKeysParams = from_js_params("importKeys", params)?;
        let mut core_params = chat_xdk_core::ImportKeysParams::new(std::mem::take(&mut p.keys));
        core_params.signing_key_version = p.signing_key_version.take().filter(|v| !v.is_empty());
        self.inner
            .import_keys(&core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Set the session identity: `{ userId, signingKeyVersion }`, used as
    /// defaults wherever a params object omits `senderId` /
    /// `signingKeyVersion`.
    #[wasm_bindgen(js_name = setIdentity)]
    pub fn set_identity(&self, params: JsValue) -> Result<(), JsError> {
        let p: JsSetIdentityParams = from_js_params("setIdentity", params)?;
        self.inner
            .set_identity(&chat_xdk_core::SetIdentityParams::new(
                p.user_id,
                p.signing_key_version,
            ))
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Enable or disable the conversation-key cache (off by default).
    ///
    /// While enabled, `decryptEvents` caches, per conversation, the key whose
    /// key change carried a valid signature at the highest version seen, and
    /// the encrypt methods resolve an omitted `conversationKey` /
    /// `conversationKeyVersion` pair from it. Disabling clears the cache.
    #[wasm_bindgen(js_name = setCacheKeys)]
    pub fn set_cache_keys(&self, enabled: bool) {
        self.inner.set_cache_keys(enabled);
    }

    /// For this repository's tests: fetch this chat's feature switches from
    /// `endpoint`, with these timings in milliseconds. Not API.
    #[wasm_bindgen(js_name = __configureFeatures, skip_typescript)]
    pub fn configure_features(
        &self,
        endpoint: &str,
        timeout_ms: f64,
        recheck_ms: f64,
        first_retry_ms: f64,
    ) {
        self.inner.configure_features(
            endpoint,
            timeout_ms as u64,
            recheck_ms as u64,
            first_retry_ms as u64,
        );
    }

    /// Store signing keys to use when a decrypt call omits its `signingKeys`
    /// argument (same array shape as `decryptEvents`). Only this explicit
    /// call populates the store — a key carried inside an event is never
    /// trusted for verification. Each call replaces the previous set.
    #[wasm_bindgen(js_name = setSigningKeys)]
    pub fn set_signing_keys(&self, signing_keys: JsValue) -> Result<(), JsError> {
        self.inner
            .set_signing_keys(js_to_signing_keys(signing_keys)?);
        Ok(())
    }

    /// Get current public keys.
    #[wasm_bindgen(js_name = getPublicKeys)]
    pub fn get_public_keys(&self) -> Result<JsValue, JsError> {
        let keys = self
            .inner
            .get_public_keys()
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        to_js_value(&keys)
    }

    /// Get the fingerprint of the loaded identity public key.
    ///
    /// Returns a URL-safe base64 string that users can compare
    /// out-of-band (e.g. in person or over a trusted channel) to
    /// verify key authenticity.
    #[wasm_bindgen(js_name = getPublicKeyFingerprint)]
    pub fn get_public_key_fingerprint(&self) -> Result<String, JsError> {
        self.inner
            .get_public_key_fingerprint()
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Returns `true` when both identity and signing keys are loaded.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Returns `true` when the identity key is loaded (sufficient for decryption).
    #[wasm_bindgen(js_name = hasIdentityKey)]
    pub fn has_identity_key(&self) -> bool {
        self.inner.has_identity_key()
    }

    /// Clear keys from memory.
    pub fn lock(&mut self) {
        self.inner.lock();
    }
}

#[wasm_bindgen]
impl Chat {
    /// Decrypt an encrypted conversation key (ECIES).
    #[wasm_bindgen(js_name = decryptConversationKey)]
    pub fn decrypt_conversation_key(&self, encrypted_key_b64: &str) -> Result<Vec<u8>, JsError> {
        let ckey = self
            .inner
            .decrypt_conversation_key(encrypted_key_b64)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(ckey.encoded().to_vec())
    }

    /// Extract and decrypt conversation keys from raw KeyChange event strings.
    ///
    /// Returns a `ConversationKeyResult` with:
    /// - `keys`: Object mapping key version strings to `Uint8Array` conversation keys
    /// - `latestVersion`: The highest key version (use for encrypting new messages)
    #[wasm_bindgen(js_name = extractConversationKeys)]
    pub fn extract_conversation_keys(&self, events: Vec<String>) -> Result<JsValue, JsError> {
        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let result = self.inner.extract_conversation_keys(&refs);

        // Build JS object with keys map and latestVersion
        let obj = js_sys::Object::new();

        // Build the keys map
        let keys_obj = js_sys::Object::new();
        for (version, key) in &result.keys {
            let arr = js_sys::Uint8Array::from(key.encoded());
            js_sys::Reflect::set(&keys_obj, &JsValue::from_str(version), &arr.into())
                .map_err(|_| JsError::new("Failed to build conversation key map"))?;
        }

        js_sys::Reflect::set(&obj, &"keys".into(), &keys_obj.into())
            .map_err(|_| JsError::new("Failed to set keys"))?;

        js_sys::Reflect::set(
            &obj,
            &"latestVersion".into(),
            &result
                .latest_version
                .map(|v| JsValue::from_str(&v))
                .unwrap_or(JsValue::NULL),
        )
        .map_err(|_| JsError::new("Failed to set latestVersion"))?;

        Ok(obj.into())
    }

    /// Decrypt multiple events in batch.
    ///
    /// This is the recommended API for decrypting messages. It:
    /// 1. Extracts conversation keys from any KeyChange events
    /// 2. For each message, finds the correct signing key by matching userId + version
    /// 3. Decrypts the message using the appropriate conversation key
    ///
    /// Takes a single params object: `events`, the raw base64 events, and
    /// optional `signingKeys`, an array of `{ userId, publicKeyVersion,
    /// publicKey, identityPublicKey, identityPublicKeySignature }` objects for
    /// ALL participants in the conversation (pass the X API response
    /// through). Omitting `signingKeys` falls back to the keys stored via
    /// `setSigningKeys`.
    ///
    /// Returns `{ messages, conversationKeys, errors }`.
    #[wasm_bindgen(js_name = decryptEvents)]
    pub fn decrypt_events(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsDecryptEventsParams = from_js_params("decryptEvents", params)?;
        let mut core_params = chat_xdk_core::DecryptEventsParams::new(p.events);
        core_params.signing_keys = p
            .signing_keys
            .map(|keys| keys.into_iter().map(Into::into).collect());

        let result = self.inner.decrypt_events(core_params);

        // Build JS result object
        let obj = js_sys::Object::new();

        // Convert messages
        let messages_arr = js_sys::Array::new();
        for dm in result.messages {
            let msg_obj = js_sys::Object::new();
            let js_event: JsEvent = dm.event.into();
            let event_val = to_js_value(&js_event)?;
            js_sys::Reflect::set(&msg_obj, &"event".into(), &event_val)
                .map_err(|_| JsError::new("Failed to set event"))?;
            if let Some(b64) = dm.original_b64 {
                js_sys::Reflect::set(&msg_obj, &"originalB64".into(), &JsValue::from_str(&b64))
                    .map_err(|_| JsError::new("Failed to set originalB64"))?;
            }
            messages_arr.push(&msg_obj);
        }
        js_sys::Reflect::set(&obj, &"messages".into(), &messages_arr.into())
            .map_err(|_| JsError::new("Failed to set messages"))?;

        // Convert conversation keys
        let conv_keys_obj = js_sys::Object::new();
        let keys_obj = js_sys::Object::new();
        for (version, key) in &result.conversation_keys.keys {
            let arr = js_sys::Uint8Array::from(key.encoded());
            js_sys::Reflect::set(&keys_obj, &JsValue::from_str(version), &arr.into())
                .map_err(|_| JsError::new("Failed to build conversation key map"))?;
        }
        js_sys::Reflect::set(&conv_keys_obj, &"keys".into(), &keys_obj.into())
            .map_err(|_| JsError::new("Failed to set keys"))?;
        js_sys::Reflect::set(
            &conv_keys_obj,
            &"latestVersion".into(),
            &result
                .conversation_keys
                .latest_version
                .map(|v| JsValue::from_str(&v))
                .unwrap_or(JsValue::NULL),
        )
        .map_err(|_| JsError::new("Failed to set latestVersion"))?;
        js_sys::Reflect::set(&obj, &"conversationKeys".into(), &conv_keys_obj.into())
            .map_err(|_| JsError::new("Failed to set conversationKeys"))?;

        // Convert errors
        let errors_obj = js_sys::Object::new();
        for (idx, err) in result.errors {
            js_sys::Reflect::set(
                &errors_obj,
                &JsValue::from_f64(idx as f64),
                &JsValue::from_str(&err),
            )
            .map_err(|_| JsError::new("Failed to set error"))?;
        }
        js_sys::Reflect::set(&obj, &"errors".into(), &errors_obj.into())
            .map_err(|_| JsError::new("Failed to set errors"))?;

        Ok(obj.into())
    }

    /// Decrypt a raw webhook event payload.
    ///
    /// Takes a single params object: `eventB64`, the base64 event;
    /// `conversationKeys`, a plain `version → key bytes` map — the `.keys`
    /// property of the object returned by `decryptEvents` or
    /// `extractConversationKeys`, or `{}` for events without message
    /// contents (an empty map also falls back to the opt-in key cache); and
    /// optional `signingKeys`, an array of `{ userId, publicKeyVersion,
    /// publicKey, identityPublicKey, identityPublicKeySignature }` objects.
    /// Signing keys are filtered to the event's sender and the SDK picks the
    /// matching version automatically; omitting them falls back to the keys
    /// stored via `setSigningKeys`. Under the default reject-unverified
    /// policy no signing keys from either source makes every signed event
    /// throw; only after `setRejectUnverified(false)` are such events
    /// returned with `verified: false`.
    #[wasm_bindgen(js_name = decryptEvent)]
    pub fn decrypt_event(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsDecryptEventParams = from_js_params("decryptEvent", params)?;
        let conversation_keys =
            if p.conversation_keys.is_undefined() || p.conversation_keys.is_null() {
                HashMap::new()
            } else {
                js_to_conv_keys("decryptEvent", p.conversation_keys)?
            };
        let mut core_params =
            chat_xdk_core::DecryptEventParams::new(p.event_b64, conversation_keys);
        core_params.signing_keys = p
            .signing_keys
            .map(|keys| keys.into_iter().map(Into::into).collect());

        let event = self
            .inner
            .decrypt_event(core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))?;

        // Convert to camelCase JS type
        let js_event: JsEvent = event.into();
        to_js_value(&js_event)
    }

    /// Sign data. Returns raw signature bytes (`Uint8Array`).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .sign(data)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    // API Message Encryption

    /// Encrypt a text message for the X API.
    ///
    /// Takes a single params object with camelCase keys: required
    /// `conversationId` and `text`, plus optional `senderId` /
    /// `signingKeyVersion` (resolved from the session identity set via
    /// `setIdentity` when omitted), `conversationKey` (Uint8Array) /
    /// `conversationKeyVersion` (resolved from the opt-in key cache when
    /// omitted), `entities` (array of `[start, end, "type"]` tuples),
    /// `attachments` (array of attachment objects), `quickReply` (the same
    /// shape decrypted text content carries), `shouldNotify`, and `ttlMsec`.
    ///
    /// The message id comes back as `messageId` on the result. A v1 message
    /// with files takes an id derived from its files, so building it again
    /// gives the same id; other messages take a random id. Encrypt each file
    /// afterwards with `encryptFile` or `fileEncryptor` and the result's
    /// `eventB64`.
    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsEncryptMessageParams = from_js_params("encryptMessage", params)?;
        let mut core_params = chat_xdk_core::EncryptMessageParams::new(p.conversation_id, p.text);
        core_params.sender_id = p.sender_id;
        core_params.signing_key_version = p.signing_key_version;
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        core_params.entities = p.entities.map(entity_tuples_to_descs);
        core_params.attachments = p.attachments;
        core_params.quick_reply = p.quick_reply.map(Into::into);
        core_params.should_notify = p.should_notify;
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);
        let payload = self
            .inner
            .encrypt_message(&core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Encrypt a reply message for the X API.
    ///
    /// Takes a single params object: the same fields as `encryptMessage` plus
    /// `replyToEvent` — the base64 raw signed event being replied to, from
    /// which the reply preview (sequence id, sender, text, entities,
    /// attachments) is derived — with optional `replyToEditEvent`,
    /// `replyToCkces` (base64 raw key-change events needed to decrypt the
    /// original), and explicit `replyToSequenceId`, `replyToSenderId`,
    /// `replyToText`, `replyToEntities`, `replyToAttachments` overrides for
    /// callers that no longer hold the raw event. The reply's id and files
    /// work as in `encryptMessage`.
    #[wasm_bindgen(js_name = encryptReply)]
    pub fn encrypt_reply(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsEncryptReplyParams = from_js_params("encryptReply", params)?;
        let mut core_params = chat_xdk_core::EncryptReplyParams::new(
            p.conversation_id,
            p.text,
            p.reply_to_event.unwrap_or_default(),
        );
        core_params.reply_to_edit_event = p.reply_to_edit_event;
        core_params.reply_to_ckces = p.reply_to_ckces;
        core_params.sender_id = p.sender_id;
        core_params.signing_key_version = p.signing_key_version;
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        core_params.reply_to_sequence_id = p.reply_to_sequence_id;
        core_params.reply_to_sender_id = p.reply_to_sender_id;
        core_params.reply_to_text = p.reply_to_text;
        core_params.entities = p.entities.map(entity_tuples_to_descs);
        core_params.attachments = p.attachments;
        core_params.reply_to_entities = p.reply_to_entities.map(entity_tuples_to_descs);
        core_params.reply_to_attachments = p.reply_to_attachments;
        core_params.quick_reply = p.quick_reply.map(Into::into);
        core_params.should_notify = p.should_notify;
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);
        let payload = self
            .inner
            .encrypt_reply(&core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Encrypt a reaction-add.
    ///
    /// Takes a single params object with camelCase keys: required `emoji`,
    /// plus `targetEvent` — the base64 raw event being reacted to, from which
    /// the conversation id and target sequence id are derived — or explicit
    /// `conversationId` / `targetMessageSequenceId` overrides. `senderId`,
    /// `signingKeyVersion`, `conversationKey` (Uint8Array), and
    /// `conversationKeyVersion` resolve from the session identity and key
    /// cache when omitted. The same shape works for `encryptRemoveReaction`.
    /// The SDK generates the message id and returns it as `messageId` on the
    /// result.
    #[wasm_bindgen(js_name = encryptAddReaction)]
    pub fn encrypt_add_reaction(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsEncryptReactionParams = from_js_params("encryptAddReaction", params)?;
        let payload = self
            .inner
            .encrypt_add_reaction(&p.into_core())
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Encrypt a reaction-remove.
    ///
    /// Takes the same params object shape as `encryptAddReaction`.
    #[wasm_bindgen(js_name = encryptRemoveReaction)]
    pub fn encrypt_remove_reaction(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsEncryptReactionParams = from_js_params("encryptRemoveReaction", params)?;
        let payload = self
            .inner
            .encrypt_remove_reaction(&p.into_core())
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Encrypt a message edit.
    ///
    /// Takes a single params object with camelCase keys: `updatedText`,
    /// plus `targetEvent` — the base64 raw event being edited, from which the
    /// conversation id and target sequence id are derived — or explicit
    /// `conversationId` / `targetMessageSequenceId` overrides. `entities`
    /// (array of `[start, end, "type"]` tuples) describes the replacement
    /// text; `senderId`, `signingKeyVersion`, `conversationKey` (Uint8Array),
    /// and `conversationKeyVersion` resolve from the session identity and key
    /// cache when omitted. The SDK generates the message id and returns it as
    /// `messageId` on the result.
    #[wasm_bindgen(js_name = encryptEdit)]
    pub fn encrypt_edit(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsEncryptEditParams = from_js_params("encryptEdit", params)?;
        let payload = self
            .inner
            .encrypt_edit(&p.into_core())
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Build the signed action for deleting messages from a conversation.
    ///
    /// Takes a single params object with camelCase keys: `conversationId`,
    /// `sequenceIds` (array of message sequence ids), `deleteForAll`
    /// (boolean: every participant vs only the caller's view), plus optional
    /// `senderId` / `signingKeyVersion` (resolved from the session identity
    /// when omitted). Returns the request's `actionSignatures`, one entry
    /// with its signature nested under `messageEventSignature`; the SDK
    /// generates the action's message id (`messageId` on the entry).
    #[wasm_bindgen(js_name = prepareMessageDelete)]
    pub fn prepare_message_delete(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsMessageDeleteParams = from_js_params("prepareMessageDelete", params)?;
        let prepared = self
            .inner
            .prepare_message_delete(&p.into_core())
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_prepared: JsPreparedAction = prepared.into();
        to_js_value(&js_prepared)
    }

    /// Build the signed action for marking a conversation read.
    ///
    /// Takes a single params object with camelCase keys: `conversationId`,
    /// `seenUntilSequenceId` (the sequence id of the newest event read), plus
    /// optional `seenAtMsec` (when it was read, in milliseconds since the
    /// Unix epoch; the current time when omitted) and `senderId` /
    /// `signingKeyVersion` (resolved from the session identity when omitted).
    /// Returns the mark-read request's `actionSignatures`, shaped as
    /// `prepareMessageDelete` returns them. The SDK generates the action's
    /// message id (`messageId` on the entry).
    #[wasm_bindgen(js_name = prepareMarkConversationRead)]
    pub fn prepare_mark_conversation_read(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsMarkConversationReadParams =
            from_js_params("prepareMarkConversationRead", params)?;
        let prepared = self
            .inner
            .prepare_mark_conversation_read(&p.into_core())
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        let js_prepared: JsPreparedAction = prepared.into();
        to_js_value(&js_prepared)
    }

    /// Encrypt a file of an outgoing message, after the message is built.
    ///
    /// Takes a single params object: `file` (Uint8Array); `eventB64`, the
    /// `eventB64` of the payload `encryptMessage` or `encryptReply` returned
    /// for the message carrying the file; `mediaHashKey`, the media hash key
    /// the file's upload started with, as listed in the message's
    /// attachments; and optionally `conversationKey` with
    /// `conversationKeyVersion`, the key the message was encrypted under,
    /// resolved from the key cache when both are omitted. The SDK finds that
    /// attachment and encrypts the file under its key. Upload the result
    /// under the same media hash key; its size is
    /// `encryptedFileSize(file.length)`. Errors say what to pass instead.
    #[wasm_bindgen(js_name = encryptFile)]
    pub fn encrypt_file(&self, params: JsValue) -> Result<Vec<u8>, JsError> {
        let p: JsEncryptFileParams = from_js_params("encryptFile", params)?;
        let mut core_params = chat_xdk_core::EncryptFileParams::new(
            js_to_bytes("encryptFile", "file", &p.file)?,
            p.event_b64,
            p.media_hash_key,
        );
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        self.inner
            .encrypt_file(&core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Create an incremental encryptor for a file too large to hold in
    /// memory. Takes the params of `encryptFile` apart from `file`, which is
    /// fed to the encryptor.
    #[wasm_bindgen(js_name = fileEncryptor)]
    pub fn file_encryptor(&self, params: JsValue) -> Result<FileEncryptor, JsError> {
        let p: JsFileEncryptorParams = from_js_params("fileEncryptor", params)?;
        let mut core_params =
            chat_xdk_core::FileEncryptorParams::new(p.event_b64, p.media_hash_key);
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        let inner = self
            .inner
            .file_encryptor(&core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(FileEncryptor { inner })
    }

    /// Decrypt an encrypted file, as downloaded.
    ///
    /// Takes a single params object: `encrypted` (Uint8Array); `eventB64`,
    /// the event of the message that carries the file, and
    /// `conversationKeys`, the conversation's key map, as passed to
    /// `decryptEvent` (the map must hold the key for the message's version);
    /// and `mediaHashKey`, the file's media hash key from the decrypted
    /// message: a media attachment, a link card's banner or favicon, or media
    /// quoted in its reply preview. Errors say what to pass instead.
    #[wasm_bindgen(js_name = decryptFile)]
    pub fn decrypt_file(&self, params: JsValue) -> Result<Vec<u8>, JsError> {
        let p: JsDecryptFileParams = from_js_params("decryptFile", params)?;
        let core_params = chat_xdk_core::DecryptFileParams::new(
            js_to_bytes("decryptFile", "encrypted", &p.encrypted)?,
            p.event_b64,
            js_to_conv_keys("decryptFile", p.conversation_keys)?,
            p.media_hash_key,
        );
        self.inner
            .decrypt_file(core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Create an incremental decryptor for an encrypted file too large to
    /// hold in memory. Takes the params of `decryptFile` apart from
    /// `encrypted`, which is fed to the decryptor.
    #[wasm_bindgen(js_name = fileDecryptor)]
    pub fn file_decryptor(&self, params: JsValue) -> Result<FileDecryptor, JsError> {
        let p: JsFileParams = from_js_params("fileDecryptor", params)?;
        let core_params = chat_xdk_core::FileDecryptorParams::new(
            p.event_b64,
            js_to_conv_keys("fileDecryptor", p.conversation_keys)?,
            p.media_hash_key,
        );
        let inner = self
            .inner
            .file_decryptor(core_params)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(FileDecryptor { inner })
    }

    /// Encrypt a UTF-8 string and return base64 ciphertext.
    ///
    /// Use for metadata fields like group names before sending to the API.
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, plaintext: &str, conversation_key: Vec<u8>) -> Result<String, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        self.inner
            .encrypt(plaintext, &ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Decrypt a base64-encoded ciphertext and return the UTF-8 plaintext.
    ///
    /// Use for metadata fields like group names returned by the API.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: Vec<u8>,
    ) -> Result<String, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        self.inner
            .decrypt(ciphertext_b64, &ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Prepare a signed conversation-key change, ready to send to the X API.
    ///
    /// Takes a single params object with camelCase keys: `publicKeys` (the
    /// flat array of public keys — self plus recipients — from the X API),
    /// plus optional `senderId` / `signingKeyVersion` (resolved from the
    /// session identity when omitted) and `conversationId`. Omit
    /// `conversationId` for a one-to-one and it is derived from the two
    /// participants; pass the existing id for a group key rotation.
    ///
    /// Returns `{ conversationId, conversationKey, conversationKeyVersion,
    /// participantKeys, actionSignatures }`.
    #[wasm_bindgen(js_name = prepareConversationKeyChange)]
    pub fn prepare_conversation_key_change(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsConversationKeyChangeParams =
            from_js_params("prepareConversationKeyChange", params)?;
        let mut core_params = chat_xdk_core::ConversationKeyChangeParams::new(
            p.public_keys.into_iter().map(Into::into).collect(),
        );
        core_params.sender_id = p.sender_id;
        core_params.signing_key_version = p.signing_key_version;
        core_params.conversation_id = p.conversation_id;

        let result = self
            .inner
            .prepare_conversation_key_change_with_version(&core_params, &now_millis())
            .map_err(|e| JsError::new(&format!("{}", e)))?;

        prepared_change_to_js(result)
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Takes a single params object with camelCase keys: `publicKeys` (for
    /// the updated roster), `conversationId`, `newMemberIds`,
    /// `currentMemberIds`, `currentAdminIds`, `currentPendingMemberIds`,
    /// plus optional `senderId` / `signingKeyVersion` (resolved from the
    /// session identity when omitted), `currentTitle`, `currentAvatarUrl`,
    /// `currentTtlMsec`, and `currentScreenCaptureBlockingEnabled`. Returns
    /// the same shape as [`Chat::prepare_conversation_key_change`].
    #[wasm_bindgen(js_name = prepareGroupMembersChange)]
    pub fn prepare_group_members_change(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsGroupMembersChangeParams = from_js_params("prepareGroupMembersChange", params)?;
        let mut core_params = chat_xdk_core::GroupMembersChangeParams::new(
            p.public_keys.into_iter().map(Into::into).collect(),
            p.conversation_id,
            p.new_member_ids,
            p.current_member_ids,
            p.current_admin_ids,
            p.current_pending_member_ids,
        );
        core_params.sender_id = p.sender_id;
        core_params.signing_key_version = p.signing_key_version;
        core_params.current_title = p.current_title;
        core_params.current_avatar_url = p.current_avatar_url;
        core_params.current_ttl_msec = p.current_ttl_msec.map(|t| t as i64);
        core_params.current_screen_capture_blocking_enabled =
            p.current_screen_capture_blocking_enabled;

        let result = self
            .inner
            .prepare_group_members_change_with_version(&core_params, &now_millis())
            .map_err(|e| JsError::new(&format!("{}", e)))?;

        prepared_change_to_js(result)
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Takes a single params object with camelCase keys: `publicKeys` (for
    /// the new roster), `conversationId`, `memberIds`, `adminIds`, plus
    /// optional `senderId` / `signingKeyVersion` (resolved from the session
    /// identity when omitted), `title`, `avatarUrl`, and `ttlMsec`. Emits
    /// two action signatures (a conversation-key change and the group
    /// create). Returns the same shape as
    /// [`Chat::prepare_conversation_key_change`].
    #[wasm_bindgen(js_name = prepareGroupCreate)]
    pub fn prepare_group_create(&self, params: JsValue) -> Result<JsValue, JsError> {
        let p: JsGroupCreateParams = from_js_params("prepareGroupCreate", params)?;
        let mut core_params = chat_xdk_core::GroupCreateParams::new(
            p.public_keys.into_iter().map(Into::into).collect(),
            p.conversation_id,
            p.member_ids,
            p.admin_ids,
        );
        core_params.sender_id = p.sender_id;
        core_params.signing_key_version = p.signing_key_version;
        core_params.title = p.title;
        core_params.avatar_url = p.avatar_url;
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);

        let result = self
            .inner
            .prepare_group_create_with_version(&core_params, &now_millis())
            .map_err(|e| JsError::new(&format!("{}", e)))?;

        prepared_change_to_js(result)
    }

    // Signing

    /// Verify a signature.
    pub fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, JsError> {
        self.inner
            .verify(public_key_b64, signature, data)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Verify that a signing key is authentically bound to an identity key.
    ///
    /// Call this when you receive another user's public keys from the X API
    /// to detect server-side key substitution. All inputs are base64.
    #[wasm_bindgen(js_name = verifyKeyBinding)]
    pub fn verify_key_binding(
        &self,
        identity_public_key_b64: &str,
        signing_public_key_b64: &str,
        identity_public_key_signature_b64: &str,
    ) -> Result<bool, JsError> {
        self.inner
            .verify_key_binding(
                identity_public_key_b64,
                signing_public_key_b64,
                identity_public_key_signature_b64,
            )
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Report whether the loaded identity public key is the key in
    /// `publicKeyB64`.
    ///
    /// The X API returns the identity public key in SPKI/DER encoding while
    /// `getPublicKeys` returns the raw SEC1 point; this accepts either
    /// encoding, so use it to check whether the keys on this device belong
    /// to a key registered to the account.
    #[wasm_bindgen(js_name = matchesRegisteredKey)]
    pub fn matches_registered_key(&self, public_key_b64: &str) -> Result<bool, JsError> {
        self.inner
            .matches_registered_key(public_key_b64)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }
}

/// Build the JS result object for a prepared key change, exposing
/// `conversationKey` as a `Uint8Array` and the rest as camelCase fields.
fn prepared_change_to_js(
    result: chat_xdk_core::PreparedConversationChange,
) -> Result<JsValue, JsError> {
    use serde::Serialize;

    let obj = js_sys::Object::new();

    if let Some(ckey) = &result.conversation_key {
        let arr = js_sys::Uint8Array::from(ckey.encoded());
        js_sys::Reflect::set(&obj, &"conversationKey".into(), &arr.into())
            .map_err(|_| JsError::new("Failed to set conversationKey"))?;
    }
    js_sys::Reflect::set(
        &obj,
        &"conversationId".into(),
        &JsValue::from_str(&result.conversation_id),
    )
    .map_err(|_| JsError::new("Failed to set conversationId"))?;
    js_sys::Reflect::set(
        &obj,
        &"conversationKeyVersion".into(),
        &JsValue::from_str(&result.conversation_key_version),
    )
    .map_err(|_| JsError::new("Failed to set conversationKeyVersion"))?;

    let js_prepared: JsPreparedConversationChange = result.into();
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    let participant_keys_val = js_prepared
        .participant_keys
        .serialize(&serializer)
        .map_err(|e| JsError::new(&format!("Serialization failed: {:?}", e)))?;
    js_sys::Reflect::set(&obj, &"participantKeys".into(), &participant_keys_val)
        .map_err(|_| JsError::new("Failed to set participantKeys"))?;
    let action_signatures_val = js_prepared
        .action_signatures
        .serialize(&serializer)
        .map_err(|e| JsError::new(&format!("Serialization failed: {:?}", e)))?;
    js_sys::Reflect::set(&obj, &"actionSignatures".into(), &action_signatures_val)
        .map_err(|_| JsError::new("Failed to set actionSignatures"))?;

    Ok(obj.into())
}

/// Incremental encryptor for one file of an outgoing message.
///
/// Feed the file with `push`; call `finish` once to emit the final frame.
#[wasm_bindgen]
pub struct FileEncryptor {
    inner: chat_xdk_core::FileEncryptor,
}

#[wasm_bindgen]
impl FileEncryptor {
    /// Encrypt a chunk of the file, returning the encrypted bytes available
    /// so far.
    #[wasm_bindgen]
    pub fn push(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, JsError> {
        self.inner
            .push(&plaintext)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Emit the final frame and consume the encryptor.
    #[wasm_bindgen]
    pub fn finish(self) -> Result<Vec<u8>, JsError> {
        self.inner
            .finish()
            .map_err(|e| JsError::new(&format!("{}", e)))
    }
}

/// Incremental decryptor for one encrypted file.
///
/// Feed the encrypted bytes with `push`; call `finish` once at end of input.
/// `finish` throws if the file ended before its final frame (truncation), so
/// callers must not treat the bytes as complete until `finish` succeeds.
#[wasm_bindgen]
pub struct FileDecryptor {
    inner: chat_xdk_core::FileDecryptor,
}

#[wasm_bindgen]
impl FileDecryptor {
    /// Decrypt a chunk of the encrypted file, returning the bytes available
    /// so far.
    #[wasm_bindgen]
    pub fn push(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsError> {
        self.inner
            .push(&ciphertext)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Decrypt the final frame and consume the decryptor.
    #[wasm_bindgen]
    pub fn finish(self) -> Result<Vec<u8>, JsError> {
        self.inner
            .finish()
            .map_err(|e| JsError::new(&format!("{}", e)))
    }
}

// WASM helpers (serialization, base64, key maps)

/// Current time as a millisecond-timestamp string, read from the JS clock.
///
/// The `wasm32-unknown-unknown` target has no system clock, so conversation key
/// versions come from JavaScript's `Date.now()` instead.
fn now_millis() -> String {
    (js_sys::Date::now() as u64).to_string()
}

/// Parse a params object's `conversationKeys`, a plain object mapping key
/// version to the raw 32-byte key (`Uint8Array`). Anything else, including a
/// missing map or an entry that is not a 32-byte `Uint8Array`, is an error.
fn js_to_conv_keys(
    method: &str,
    js: JsValue,
) -> Result<HashMap<String, XChatConversationKey>, JsError> {
    if !js.is_object() || js_sys::Array::is_array(&js) {
        return Err(JsError::new(&format!(
            "Invalid {method} params: conversationKeys must be an object mapping key version to \
             key bytes (the `keys` map of decryptEvents or extractConversationKeys)"
        )));
    }
    let mut result = HashMap::new();
    let entries = js_sys::Object::entries(&js_sys::Object::from(js));
    for i in 0..entries.length() {
        let pair = js_sys::Array::from(&entries.get(i));
        let version = pair.get(0).as_string().unwrap_or_default();
        let value = pair.get(1);
        let key = value
            .dyn_ref::<js_sys::Uint8Array>()
            .and_then(|bytes| XChatConversationKey::from_bytes(bytes.to_vec()))
            .ok_or_else(|| {
                JsError::new(&format!(
                    "the key for version '{}' in the conversation key map is not 32 bytes: pass \
                     the raw 32-byte conversation keys (the `keys` map of decryptEvents or \
                     extractConversationKeys)",
                    version
                ))
            })?;
        result.insert(version, key);
    }
    Ok(result)
}

/// Copy a params object's `Uint8Array` field in one step.
fn js_to_bytes(method: &str, field: &str, js: &JsValue) -> Result<Vec<u8>, JsError> {
    js.dyn_ref::<js_sys::Uint8Array>()
        .map(js_sys::Uint8Array::to_vec)
        .ok_or_else(|| {
            JsError::new(&format!(
                "Invalid {method} params: {field} must be a Uint8Array"
            ))
        })
}

/// Parse a JS `signingKeys` array into core entries. Absent/null yields an
/// empty list (the core falls back to the `setSigningKeys` store); a
/// malformed array is a caller error and is surfaced rather than silently
/// ignored.
fn js_to_signing_keys(js: JsValue) -> Result<Vec<chat_xdk_core::SigningKeyEntry>, JsError> {
    if js.is_null() || js.is_undefined() {
        return Ok(Vec::new());
    }
    let entries: Vec<JsSigningKeyEntry> = serde_wasm_bindgen::from_value(js)
        .map_err(|e| JsError::new(&format!("Invalid signingKeys: {}", e)))?;
    Ok(entries.into_iter().map(Into::into).collect())
}

/// Deserialize a JS params object into its camelCase mirror struct.
///
/// A missing required field surfaces as `Invalid <method> params: missing
/// field `<name>``, naming both the method and the field.
fn from_js_params<T: serde::de::DeserializeOwned>(
    method: &str,
    value: JsValue,
) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsError::new(&format!("Invalid {} params: {}", method, e)))
}

/// `replyToSenderId`: a user id, as a digits-only string. A number is
/// rejected by name, since JS may already have rounded an id past 2^53.
fn reply_to_sender_id_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Str(String),
        Num(#[allow(dead_code)] f64),
    }
    match <Option<Raw> as serde::Deserialize>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Raw::Str(id)) => Ok(Some(id)),
        Some(Raw::Num(_)) => Err(serde::de::Error::custom(
            "replyToSenderId must be the user id as a string of digits, not a number",
        )),
    }
}

/// Convert entity tuples `[start, end, "type"]` into core descriptors.
fn entity_tuples_to_descs(tuples: Vec<(i32, i32, String)>) -> Vec<chat_xdk_core::EntityDescriptor> {
    tuples
        .into_iter()
        .map(
            |(start, end, entity_type)| chat_xdk_core::EntityDescriptor {
                start,
                end,
                entity_type,
            },
        )
        .collect()
}

// JS params mirrors — camelCase keys, deserialized from a single JS object.
// Attachment objects keep the snake_case keys of the wire format (see
// `AttachmentDescriptor` in the core).

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSetIdentityParams {
    user_id: String,
    signing_key_version: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsImportKeysParams {
    keys: Vec<u8>,
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEncryptMessageParams {
    conversation_id: String,
    text: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
    quick_reply: Option<chat_xdk_core::js::JsQuickReply>,
    should_notify: Option<bool>,
    ttl_msec: Option<f64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEncryptReplyParams {
    conversation_id: String,
    text: String,
    reply_to_event: Option<String>,
    reply_to_edit_event: Option<String>,
    reply_to_ckces: Option<Vec<String>>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
    reply_to_sequence_id: Option<String>,
    #[serde(default, deserialize_with = "reply_to_sender_id_string")]
    reply_to_sender_id: Option<String>,
    reply_to_text: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
    reply_to_entities: Option<Vec<(i32, i32, String)>>,
    reply_to_attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
    quick_reply: Option<chat_xdk_core::js::JsQuickReply>,
    should_notify: Option<bool>,
    ttl_msec: Option<f64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEncryptReactionParams {
    emoji: String,
    target_event: Option<String>,
    conversation_id: Option<String>,
    target_message_sequence_id: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

impl JsEncryptReactionParams {
    fn into_core(self) -> chat_xdk_core::EncryptReactionParams {
        let mut params = chat_xdk_core::EncryptReactionParams::new(
            self.target_event.unwrap_or_default(),
            self.emoji,
        );
        params.conversation_id = self.conversation_id;
        params.target_message_sequence_id = self.target_message_sequence_id;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params.conversation_key = self.conversation_key;
        params.conversation_key_version = self.conversation_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEncryptEditParams {
    updated_text: String,
    target_event: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    conversation_id: Option<String>,
    target_message_sequence_id: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

impl JsEncryptEditParams {
    fn into_core(self) -> chat_xdk_core::EncryptEditParams {
        let mut params = chat_xdk_core::EncryptEditParams::new(
            self.target_event.unwrap_or_default(),
            self.updated_text,
        );
        params.entities = self.entities.map(entity_tuples_to_descs);
        params.conversation_id = self.conversation_id;
        params.target_message_sequence_id = self.target_message_sequence_id;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params.conversation_key = self.conversation_key;
        params.conversation_key_version = self.conversation_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMessageDeleteParams {
    conversation_id: String,
    sequence_ids: Vec<String>,
    delete_for_all: bool,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsMessageDeleteParams {
    fn into_core(self) -> chat_xdk_core::MessageDeleteParams {
        let mut params = chat_xdk_core::MessageDeleteParams::new(
            self.conversation_id,
            self.sequence_ids,
            self.delete_for_all,
        );
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMarkConversationReadParams {
    conversation_id: String,
    seen_until_sequence_id: String,
    seen_at_msec: Option<f64>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsMarkConversationReadParams {
    /// An omitted `seenAtMsec` takes the JavaScript clock, so the core never
    /// falls back to the system clock `wasm32-unknown-unknown` lacks.
    fn into_core(self) -> chat_xdk_core::MarkConversationReadParams {
        let mut params = chat_xdk_core::MarkConversationReadParams::new(
            self.conversation_id,
            self.seen_until_sequence_id,
        );
        params.seen_at_msec = Some(self.seen_at_msec.unwrap_or_else(js_sys::Date::now) as i64);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsConversationKeyChangeParams {
    public_keys: Vec<JsPublicKeyInput>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupMembersChangeParams {
    public_keys: Vec<JsPublicKeyInput>,
    conversation_id: String,
    new_member_ids: Vec<String>,
    current_member_ids: Vec<String>,
    current_admin_ids: Vec<String>,
    current_pending_member_ids: Vec<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    current_title: Option<String>,
    current_avatar_url: Option<String>,
    current_ttl_msec: Option<f64>,
    current_screen_capture_blocking_enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupCreateParams {
    public_keys: Vec<JsPublicKeyInput>,
    conversation_id: String,
    member_ids: Vec<String>,
    admin_ids: Vec<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    title: Option<String>,
    avatar_url: Option<String>,
    ttl_msec: Option<f64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsDecryptEventParams {
    event_b64: String,
    #[serde(default, with = "serde_wasm_bindgen::preserve")]
    conversation_keys: JsValue,
    signing_keys: Option<Vec<JsSigningKeyEntry>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsDecryptEventsParams {
    events: Vec<String>,
    signing_keys: Option<Vec<JsSigningKeyEntry>>,
}

// Byte fields stay JS values so they are copied in one step rather than
// element by element.

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEncryptFileParams {
    #[serde(with = "serde_wasm_bindgen::preserve")]
    file: JsValue,
    event_b64: String,
    media_hash_key: String,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFileEncryptorParams {
    event_b64: String,
    media_hash_key: String,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsDecryptFileParams {
    #[serde(with = "serde_wasm_bindgen::preserve")]
    encrypted: JsValue,
    event_b64: String,
    #[serde(with = "serde_wasm_bindgen::preserve")]
    conversation_keys: JsValue,
    media_hash_key: String,
}

/// The params of `fileDecryptor`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFileParams {
    event_b64: String,
    #[serde(with = "serde_wasm_bindgen::preserve")]
    conversation_keys: JsValue,
    media_hash_key: String,
}

fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value
        .serialize(&serializer)
        .map_err(|e| JsError::new(&format!("Serialization failed: {:?}", e)))
}

// This crate has no Rust-side test module: `#[wasm_bindgen_test]` tests never
// execute on the host target, so the binding is covered by the Node suites in
// js/tests/, which exercise the built wasm artifact end to end.
