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
//! for (const { event } of result.events) {
//!   console.log(event.type, event.content?.text);
//! }
//!
//! // Single event with cached keys
//! const conversationKeys = result.conversationKeys.keys;
//! const event = chat.decryptEvent({ eventB64: newEventB64, conversationKeys, signingKeys });
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use chat_xdk_core::bindings::{self, FeatureSwitches};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::error::{ErrorKind, SdkError};

// Import generated camelCase JS types from core
use chat_xdk_core::js::{
    JsEvent, JsPreparedAction, JsPreparedConversationChange, JsPreparedGroupMetadataChange,
    JsPublicKeyInput, JsPublicKeyRegistrationPayload, JsSendPayload, JsSigningKeyEntry,
};

// Utility Functions (free functions, not methods)

/// Return the exact size of a file once encrypted: the size its upload
/// declares before the file is encrypted.
#[wasm_bindgen(js_name = encryptedFileSize)]
pub fn encrypted_file_size(plaintext_size: f64) -> Result<f64, JsValue> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

    if !plaintext_size.is_finite()
        || plaintext_size < 0.0
        || plaintext_size.fract() != 0.0
        || plaintext_size > MAX_SAFE_INTEGER
    {
        return Err(invalid_input(
            "Plaintext size must be a non-negative safe integer",
        ));
    }

    let encrypted_size = chat_xdk_core::utils::encrypted_file_size(plaintext_size as u64)
        .ok_or_else(|| invalid_input("Encrypted file size overflow"))?;
    if encrypted_size > MAX_SAFE_INTEGER as u64 {
        return Err(invalid_input(
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

// Feature switches (GET /2/chat/features). A chat reads them once, when it is
// created: the core decides what to fetch and what an answer means, and the JS
// wrapper performs the GET. None of this is API, and all of it is left out of
// the TypeScript declarations.

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

// Errors. Every error this module throws is a `ChatXdkError`, the class the
// JS wrapper registers once the module is loaded.

thread_local! {
    static ERROR_CLASS: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

/// Register the class of the errors this module throws. Not API.
#[wasm_bindgen(js_name = __setErrorClass, skip_typescript)]
pub fn set_error_class(class: js_sys::Function) {
    ERROR_CLASS.with(|current| *current.borrow_mut() = Some(class));
}

/// An error of `kind`, with the PIN attempts Juicebox reports left after an
/// invalid PIN: a `ChatXdkError`, or an `Error` with the same fields before
/// the wrapper registers that class.
fn js_error(kind: ErrorKind, message: &str, guesses_remaining: Option<u16>) -> JsValue {
    let kind = JsValue::from_str(kind_name(kind));
    let guesses_remaining = guesses_remaining.map_or(JsValue::NULL, JsValue::from);
    let registered = ERROR_CLASS.with(|class| {
        let args = js_sys::Array::of3(&kind, &message.into(), &guesses_remaining);
        class
            .borrow()
            .as_ref()
            .and_then(|class| js_sys::Reflect::construct(class, &args).ok())
    });
    registered.unwrap_or_else(|| {
        let error = js_sys::Error::new(message);
        error.set_name("ChatXdkError");
        js_sys::Reflect::set(&error, &"kind".into(), &kind).ok();
        js_sys::Reflect::set(&error, &"guessesRemaining".into(), &guesses_remaining).ok();
        error.into()
    })
}

/// The name `ChatXdkError.kind` gives an error kind.
fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::InvalidInput => "invalidInput",
        ErrorKind::InvalidState => "invalidState",
        ErrorKind::Parse => "parse",
        ErrorKind::Decryption => "decryption",
        ErrorKind::Verification => "verification",
        ErrorKind::InvalidPin => "invalidPin",
        ErrorKind::Juicebox => "juicebox",
        _ => "internal",
    }
}

fn sdk_error(error: impl Into<SdkError>) -> JsValue {
    let error = error.into();
    js_error(error.kind(), &error.to_string(), error.guesses_remaining())
}

/// An invalid argument, rejected in this layer.
fn invalid_input(message: impl AsRef<str>) -> JsValue {
    js_error(ErrorKind::InvalidInput, message.as_ref(), None)
}

/// A result that failed to convert to JS.
fn internal_error(message: impl AsRef<str>) -> JsValue {
    js_error(ErrorKind::Internal, message.as_ref(), None)
}

// Juicebox. The JS wrapper runs the Juicebox client; the core sets the PIN
// rule, reads the client config and words the errors. None of this is API.

/// Check a new PIN under the rule `setup` and `changePin` apply.
#[wasm_bindgen(js_name = __validateNewPin, skip_typescript)]
pub fn validate_new_pin(pin: Vec<u8>) -> Result<(), JsValue> {
    let pin = Zeroizing::new(pin);
    bindings::validate_new_pin(&pin).map_err(sdk_error)
}

/// The Juicebox client config and PIN guess budget of an X API Juicebox
/// config: `{ sdkConfig, maxGuessCount }`.
#[wasm_bindgen(js_name = __juiceboxClientConfig, skip_typescript)]
pub fn juicebox_client_config(config_json: &str) -> Result<JsValue, JsValue> {
    let (sdk_config, max_guess_count) =
        bindings::juicebox_client_config(config_json).map_err(sdk_error)?;
    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"sdkConfig".into(), &sdk_config.into()).ok();
    js_sys::Reflect::set(&result, &"maxGuessCount".into(), &max_guess_count.into()).ok();
    Ok(result.into())
}

/// The error a Juicebox call throws on a chat without a Juicebox config.
#[wasm_bindgen(js_name = __noJuiceboxConfig, skip_typescript)]
pub fn no_juicebox_config() -> JsValue {
    sdk_error(bindings::no_juicebox_config())
}

/// The error a Juicebox `operation` (`register`, `recover` or `delete`)
/// that failed for `reason` throws.
#[wasm_bindgen(js_name = __juiceboxError, skip_typescript)]
pub fn juicebox_error(operation: &str, reason: &str, guesses_remaining: Option<u16>) -> JsValue {
    sdk_error(bindings::juicebox_error(
        operation,
        reason,
        guesses_remaining,
    ))
}

/// Initialize panic hook for better error messages in console.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "panic_hook")]
    console_error_panic_hook::set_once();
    bindings::set_clock(feature_clock);
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
    pub fn generate_keypairs_impl(&mut self) -> Result<JsValue, JsValue> {
        let payload = self.inner.generate_keypairs().map_err(sdk_error)?;
        let js_payload: JsPublicKeyRegistrationPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Export private keys as raw bytes (`Uint8Array`).
    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_keys().map_err(sdk_error)
    }

    /// Import private keys: `{ keys, signingKeyVersion? }`, where `keys` is
    /// the `Uint8Array` `exportKeys` returned. The SDK's copy of the bytes is
    /// zeroized after import. When `signingKeyVersion` is given it also
    /// records the public key version the keys were registered under
    /// (participant-key filtering plus the session `signingKeyVersion`).
    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(&mut self, params: JsValue) -> Result<(), JsValue> {
        let mut p: JsImportKeysParams = from_js_params("importKeys", params)?;
        let mut core_params = chat_xdk_core::ImportKeysParams::new(std::mem::take(&mut p.keys));
        core_params.signing_key_version = p.signing_key_version.take().filter(|v| !v.is_empty());
        self.inner.import_keys(&core_params).map_err(sdk_error)
    }

    /// Set the session identity: `{ userId, signingKeyVersion }`, used as
    /// defaults wherever a params object omits `senderId` /
    /// `signingKeyVersion`.
    #[wasm_bindgen(js_name = setIdentity)]
    pub fn set_identity(&self, params: JsValue) -> Result<(), JsValue> {
        let p: JsSetIdentityParams = from_js_params("setIdentity", params)?;
        self.inner
            .set_identity(&chat_xdk_core::SetIdentityParams::new(
                p.user_id,
                p.signing_key_version,
            ))
            .map_err(sdk_error)
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

    /// For this repository's tests: read this chat's feature switches from
    /// `endpoint`, within `timeoutMs`. Call it before the wrapper starts the
    /// read. Not API.
    #[wasm_bindgen(js_name = __configureFeatures, skip_typescript)]
    pub fn configure_features(&self, endpoint: &str, timeout_ms: f64) {
        self.inner.configure_features(endpoint, timeout_ms as u64);
    }

    /// Start this chat's one read of the feature switches:
    /// `{ id, url, timeoutMs, maxBytes }` for the wrapper to GET, or
    /// `undefined` when the chat takes the answer of a GET in flight or has
    /// started its read already. Not API.
    #[wasm_bindgen(js_name = __featureStart, skip_typescript)]
    pub fn feature_start(&self) -> JsValue {
        let Some(fetch) = self.inner.start_features() else {
            return JsValue::UNDEFINED;
        };
        let request = js_sys::Object::new();
        for (name, value) in [
            ("id", JsValue::from(fetch.id as f64)),
            ("url", fetch.url.into()),
            ("timeoutMs", (fetch.timeout_ms as f64).into()),
            ("maxBytes", (fetch.max_bytes as f64).into()),
        ] {
            js_sys::Reflect::set(&request, &name.into(), &value).ok();
        }
        request.into()
    }

    /// Store signing keys to use when a decrypt call omits its `signingKeys`
    /// argument (same array shape as `decryptEvents`). Only this explicit
    /// call populates the store — a key carried inside an event is never
    /// trusted for verification. Each call replaces the previous set.
    #[wasm_bindgen(js_name = setSigningKeys)]
    pub fn set_signing_keys(&self, signing_keys: JsValue) -> Result<(), JsValue> {
        self.inner
            .set_signing_keys(&js_to_signing_keys(signing_keys)?);
        Ok(())
    }

    /// Get current public keys.
    #[wasm_bindgen(js_name = getPublicKeys)]
    pub fn get_public_keys(&self) -> Result<JsValue, JsValue> {
        let keys = self.inner.get_public_keys().map_err(sdk_error)?;
        to_js_value(&keys)
    }

    /// Get the fingerprint of the loaded identity public key.
    ///
    /// Returns a URL-safe base64 string that users can compare
    /// out-of-band (e.g. in person or over a trusted channel) to
    /// verify key authenticity.
    #[wasm_bindgen(js_name = getPublicKeyFingerprint)]
    pub fn get_public_key_fingerprint(&self) -> Result<String, JsValue> {
        self.inner.get_public_key_fingerprint().map_err(sdk_error)
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
    pub fn decrypt_conversation_key(&self, encrypted_key_b64: &str) -> Result<Vec<u8>, JsValue> {
        let ckey = self
            .inner
            .decrypt_conversation_key(encrypted_key_b64)
            .map_err(sdk_error)?;
        Ok(ckey.encoded().to_vec())
    }

    /// Extract and decrypt conversation keys from raw KeyChange event strings.
    ///
    /// Returns a `ConversationKeyResult` with:
    /// - `keys`: Object mapping key version strings to `Uint8Array` conversation keys
    /// - `latestVersion`: The highest key version (use for encrypting new messages)
    #[wasm_bindgen(js_name = extractConversationKeys)]
    pub fn extract_conversation_keys(&self, events: Vec<String>) -> Result<JsValue, JsValue> {
        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let result = self.inner.extract_conversation_keys(&refs);

        // Build JS object with keys map and latestVersion
        let obj = js_sys::Object::new();

        // Build the keys map
        let keys_obj = js_sys::Object::new();
        for (version, key) in &result.keys {
            let arr = js_sys::Uint8Array::from(key.encoded());
            js_sys::Reflect::set(&keys_obj, &JsValue::from_str(version), &arr.into())
                .map_err(|_| internal_error("Failed to build conversation key map"))?;
        }

        js_sys::Reflect::set(&obj, &"keys".into(), &keys_obj.into())
            .map_err(|_| internal_error("Failed to set keys"))?;

        js_sys::Reflect::set(
            &obj,
            &"latestVersion".into(),
            &result
                .latest_version
                .map(|v| JsValue::from_str(&v))
                .unwrap_or(JsValue::NULL),
        )
        .map_err(|_| internal_error("Failed to set latestVersion"))?;

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
    /// Returns `{ events, conversationKeys, errors }`.
    #[wasm_bindgen(js_name = decryptEvents)]
    pub fn decrypt_events(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsDecryptEventsParams = from_js_params("decryptEvents", params)?;
        let mut core_params = chat_xdk_core::DecryptEventsParams::new(p.events);
        core_params.signing_keys = p
            .signing_keys
            .map(|keys| keys.into_iter().map(Into::into).collect());

        let result = self.inner.decrypt_events(&core_params);

        // Build JS result object
        let obj = js_sys::Object::new();

        let events = js_sys::Array::new();
        for decrypted in result.events {
            let entry = js_sys::Object::new();
            let js_event: JsEvent = decrypted.event.into();
            let event_val = to_js_value(&js_event)?;
            js_sys::Reflect::set(&entry, &"event".into(), &event_val)
                .map_err(|_| internal_error("Failed to set event"))?;
            if let Some(b64) = decrypted.original_b64 {
                js_sys::Reflect::set(&entry, &"originalB64".into(), &JsValue::from_str(&b64))
                    .map_err(|_| internal_error("Failed to set originalB64"))?;
            }
            events.push(&entry);
        }
        js_sys::Reflect::set(&obj, &"events".into(), &events.into())
            .map_err(|_| internal_error("Failed to set events"))?;

        // Convert conversation keys
        let conv_keys_obj = js_sys::Object::new();
        let keys_obj = js_sys::Object::new();
        for (version, key) in &result.conversation_keys.keys {
            let arr = js_sys::Uint8Array::from(key.encoded());
            js_sys::Reflect::set(&keys_obj, &JsValue::from_str(version), &arr.into())
                .map_err(|_| internal_error("Failed to build conversation key map"))?;
        }
        js_sys::Reflect::set(&conv_keys_obj, &"keys".into(), &keys_obj.into())
            .map_err(|_| internal_error("Failed to set keys"))?;
        js_sys::Reflect::set(
            &conv_keys_obj,
            &"latestVersion".into(),
            &result
                .conversation_keys
                .latest_version
                .map(|v| JsValue::from_str(&v))
                .unwrap_or(JsValue::NULL),
        )
        .map_err(|_| internal_error("Failed to set latestVersion"))?;
        js_sys::Reflect::set(&obj, &"conversationKeys".into(), &conv_keys_obj.into())
            .map_err(|_| internal_error("Failed to set conversationKeys"))?;

        // Convert errors
        let errors_obj = js_sys::Object::new();
        for (idx, err) in result.errors {
            js_sys::Reflect::set(
                &errors_obj,
                &JsValue::from_f64(idx as f64),
                &JsValue::from_str(&err),
            )
            .map_err(|_| internal_error("Failed to set error"))?;
        }
        js_sys::Reflect::set(&obj, &"errors".into(), &errors_obj.into())
            .map_err(|_| internal_error("Failed to set errors"))?;

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
    pub fn decrypt_event(&self, params: JsValue) -> Result<JsValue, JsValue> {
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

        let event = self.inner.decrypt_event(&core_params).map_err(sdk_error)?;

        // Convert to camelCase JS type
        let js_event: JsEvent = event.into();
        to_js_value(&js_event)
    }

    /// Sign data. Returns raw signature bytes (`Uint8Array`).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.sign(data).map_err(sdk_error)
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
    pub fn encrypt_message(&self, params: JsValue) -> Result<JsValue, JsValue> {
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
            .map_err(sdk_error)?;
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
    pub fn encrypt_reply(&self, params: JsValue) -> Result<JsValue, JsValue> {
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
        let payload = self.inner.encrypt_reply(&core_params).map_err(sdk_error)?;
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
    pub fn encrypt_add_reaction(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsEncryptReactionParams = from_js_params("encryptAddReaction", params)?;
        let payload = self
            .inner
            .encrypt_add_reaction(&p.into_core())
            .map_err(sdk_error)?;
        let js_payload: JsSendPayload = payload.into();
        to_js_value(&js_payload)
    }

    /// Encrypt a reaction-remove.
    ///
    /// Takes the same params object shape as `encryptAddReaction`.
    #[wasm_bindgen(js_name = encryptRemoveReaction)]
    pub fn encrypt_remove_reaction(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsEncryptReactionParams = from_js_params("encryptRemoveReaction", params)?;
        let payload = self
            .inner
            .encrypt_remove_reaction(&p.into_core())
            .map_err(sdk_error)?;
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
    pub fn encrypt_edit(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsEncryptEditParams = from_js_params("encryptEdit", params)?;
        let payload = self.inner.encrypt_edit(&p.into_core()).map_err(sdk_error)?;
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
    pub fn prepare_message_delete(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsMessageDeleteParams = from_js_params("prepareMessageDelete", params)?;
        let prepared = self
            .inner
            .prepare_message_delete(&p.into_core())
            .map_err(sdk_error)?;
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
    pub fn prepare_mark_conversation_read(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsMarkConversationReadParams =
            from_js_params("prepareMarkConversationRead", params)?;
        let prepared = self
            .inner
            .prepare_mark_conversation_read(&p.into_core())
            .map_err(sdk_error)?;
        let js_prepared: JsPreparedAction = prepared.into();
        to_js_value(&js_prepared)
    }

    /// Sign a group member removal and rotate the conversation key for the
    /// members who stay.
    ///
    /// `publicKeys` are the identity keys of the members who stay. The
    /// result carries the new key and the action signatures: the removal,
    /// bound to the new key version, a title and a description change for
    /// each one the params set, re-encrypted under the new key, and the key
    /// change.
    #[wasm_bindgen(js_name = prepareGroupMembersRemove)]
    pub fn prepare_group_members_remove(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupMembersRemoveParams = from_js_params("prepareGroupMembersRemove", params)?;
        let prepared = self
            .inner
            .prepare_group_members_remove_with_version(&p.into_core(), &now_millis())
            .map_err(sdk_error)?;
        prepared_change_to_js(prepared)
    }

    /// Sign leaving a group: a removal of the sender, an admin add when
    /// `promoteAdminId` is set, and a conversation delete. Does not rotate
    /// the key.
    #[wasm_bindgen(js_name = prepareGroupLeave)]
    pub fn prepare_group_leave(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupLeaveParams = from_js_params("prepareGroupLeave", params)?;
        self.prepare_action(self.inner.prepare_group_leave(&p.into_core()))
    }

    /// Encrypt a new group title under the conversation key and sign the
    /// change. `newTitle` is plaintext; `conversationKey` /
    /// `conversationKeyVersion` resolve from the key cache when omitted.
    /// Returns `{ encryptedValue, conversationKeyVersion, actionSignatures }`.
    #[wasm_bindgen(js_name = prepareGroupTitleChange)]
    pub fn prepare_group_title_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupTitleChangeParams = from_js_params("prepareGroupTitleChange", params)?;
        self.prepare_metadata_change(self.inner.prepare_group_title_change(&p.into_core()))
    }

    /// Sign a group avatar change: `newAvatarUrl`, the avatar image's media
    /// URL, as is, and `conversationKeyVersion`, the version of the key the
    /// image is encrypted under. Returns `{ actionSignatures }`.
    #[wasm_bindgen(js_name = prepareGroupAvatarChange)]
    pub fn prepare_group_avatar_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupAvatarChangeParams = from_js_params("prepareGroupAvatarChange", params)?;
        self.prepare_action(self.inner.prepare_group_avatar_change(&p.into_core()))
    }

    /// Encrypt a new group description under the conversation key and sign
    /// the change; shaped as `prepareGroupTitleChange`.
    #[wasm_bindgen(js_name = prepareGroupDescriptionChange)]
    pub fn prepare_group_description_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupDescriptionChangeParams =
            from_js_params("prepareGroupDescriptionChange", params)?;
        self.prepare_metadata_change(self.inner.prepare_group_description_change(&p.into_core()))
    }

    /// Sign adding group admins.
    #[wasm_bindgen(js_name = prepareGroupAdminsAdd)]
    pub fn prepare_group_admins_add(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupAdminsAddParams = from_js_params("prepareGroupAdminsAdd", params)?;
        self.prepare_action(self.inner.prepare_group_admins_add(&p.into_core()))
    }

    /// Sign removing group admins.
    #[wasm_bindgen(js_name = prepareGroupAdminsRemove)]
    pub fn prepare_group_admins_remove(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupAdminsRemoveParams = from_js_params("prepareGroupAdminsRemove", params)?;
        self.prepare_action(self.inner.prepare_group_admins_remove(&p.into_core()))
    }

    /// Sign enabling a group invite. An omitted expiry or affiliate signs `null`.
    #[wasm_bindgen(js_name = prepareGroupInviteEnable)]
    pub fn prepare_group_invite_enable(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupInviteEnableParams = from_js_params("prepareGroupInviteEnable", params)?;
        self.prepare_action(self.inner.prepare_group_invite_enable(&p.into_core()))
    }

    /// Sign disabling a group invite. `disabledBy` defaults to the sender.
    #[wasm_bindgen(js_name = prepareGroupInviteDisable)]
    pub fn prepare_group_invite_disable(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupInviteDisableParams = from_js_params("prepareGroupInviteDisable", params)?;
        self.prepare_action(self.inner.prepare_group_invite_disable(&p.into_core()))
    }

    /// Sign a request to join a group. `requestingUserId` defaults to the sender.
    #[wasm_bindgen(js_name = prepareGroupJoinRequest)]
    pub fn prepare_group_join_request(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupJoinRequestParams = from_js_params("prepareGroupJoinRequest", params)?;
        self.prepare_action(self.inner.prepare_group_join_request(&p.into_core()))
    }

    /// Sign rejecting group join requests.
    #[wasm_bindgen(js_name = prepareGroupJoinReject)]
    pub fn prepare_group_join_reject(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsGroupJoinRejectParams = from_js_params("prepareGroupJoinReject", params)?;
        self.prepare_action(self.inner.prepare_group_join_reject(&p.into_core()))
    }

    /// Sign a message-TTL change. The signature covers `ttlMsec` only.
    #[wasm_bindgen(js_name = prepareMessageTtlChange)]
    pub fn prepare_message_ttl_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsMessageTtlChangeParams = from_js_params("prepareMessageTtlChange", params)?;
        self.prepare_action(self.inner.prepare_message_ttl_change(&p.into_core()))
    }

    /// Sign clearing a conversation's message TTL.
    #[wasm_bindgen(js_name = prepareMessageTtlRemove)]
    pub fn prepare_message_ttl_remove(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsMessageTtlRemoveParams = from_js_params("prepareMessageTtlRemove", params)?;
        self.prepare_action(self.inner.prepare_message_ttl_remove(&p.into_core()))
    }

    /// Sign one screen-capture setting. `change` is `blockingEnabled`,
    /// `blockingDisabled`, `detectionEnabled`, or `detectionDisabled`.
    #[wasm_bindgen(js_name = prepareScreenCapture)]
    pub fn prepare_screen_capture(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let p: JsScreenCaptureParams = from_js_params("prepareScreenCapture", params)?;
        let core = p.into_core().map_err(sdk_error)?;
        self.prepare_action(self.inner.prepare_screen_capture(&core))
    }

    fn prepare_action(
        &self,
        prepared: Result<chat_xdk_core::PreparedAction, chat_xdk_core::error::SdkError>,
    ) -> Result<JsValue, JsValue> {
        let prepared = prepared.map_err(sdk_error)?;
        let js_prepared: JsPreparedAction = prepared.into();
        to_js_value(&js_prepared)
    }

    fn prepare_metadata_change(
        &self,
        prepared: Result<
            chat_xdk_core::PreparedGroupMetadataChange,
            chat_xdk_core::error::SdkError,
        >,
    ) -> Result<JsValue, JsValue> {
        let prepared = prepared.map_err(sdk_error)?;
        let js_prepared: JsPreparedGroupMetadataChange = prepared.into();
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
    pub fn encrypt_file(&self, params: JsValue) -> Result<Vec<u8>, JsValue> {
        let p: JsEncryptFileParams = from_js_params("encryptFile", params)?;
        let mut core_params = chat_xdk_core::EncryptFileParams::new(
            js_to_bytes("encryptFile", "file", &p.file)?,
            p.event_b64,
            p.media_hash_key,
        );
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        self.inner.encrypt_file(&core_params).map_err(sdk_error)
    }

    /// Create an incremental encryptor for a file too large to hold in
    /// memory. Takes the params of `encryptFile` apart from `file`, which is
    /// fed to the encryptor.
    #[wasm_bindgen(js_name = fileEncryptor)]
    pub fn file_encryptor(&self, params: JsValue) -> Result<FileEncryptor, JsValue> {
        let p: JsFileEncryptorParams = from_js_params("fileEncryptor", params)?;
        let mut core_params =
            chat_xdk_core::FileEncryptorParams::new(p.event_b64, p.media_hash_key);
        core_params.conversation_key = p.conversation_key;
        core_params.conversation_key_version = p.conversation_key_version;
        let inner = self.inner.file_encryptor(&core_params).map_err(sdk_error)?;
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
    pub fn decrypt_file(&self, params: JsValue) -> Result<Vec<u8>, JsValue> {
        let p: JsDecryptFileParams = from_js_params("decryptFile", params)?;
        let core_params = chat_xdk_core::DecryptFileParams::new(
            js_to_bytes("decryptFile", "encrypted", &p.encrypted)?,
            p.event_b64,
            js_to_conv_keys("decryptFile", p.conversation_keys)?,
            p.media_hash_key,
        );
        self.inner.decrypt_file(&core_params).map_err(sdk_error)
    }

    /// Create an incremental decryptor for an encrypted file too large to
    /// hold in memory. Takes the params of `decryptFile` apart from
    /// `encrypted`, which is fed to the decryptor.
    #[wasm_bindgen(js_name = fileDecryptor)]
    pub fn file_decryptor(&self, params: JsValue) -> Result<FileDecryptor, JsValue> {
        let p: JsFileParams = from_js_params("fileDecryptor", params)?;
        let core_params = chat_xdk_core::FileDecryptorParams::new(
            p.event_b64,
            js_to_conv_keys("fileDecryptor", p.conversation_keys)?,
            p.media_hash_key,
        );
        let inner = self.inner.file_decryptor(&core_params).map_err(sdk_error)?;
        Ok(FileDecryptor { inner })
    }

    /// Decrypt a group title or description the X API returns for a
    /// conversation. Group changes in events need no call of their own:
    /// `decryptEvent` returns them decrypted.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: Vec<u8>,
    ) -> Result<String, JsValue> {
        let ckey = bindings::conversation_key(&conversation_key).map_err(sdk_error)?;
        self.inner.decrypt(ciphertext_b64, &ckey).map_err(sdk_error)
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
    /// conversationParticipantKeys, actionSignatures }`.
    #[wasm_bindgen(js_name = prepareConversationKeyChange)]
    pub fn prepare_conversation_key_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
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
            .map_err(sdk_error)?;

        prepared_change_to_js(result)
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Takes a single params object with camelCase keys: `publicKeys` (for
    /// the updated roster), `conversationId`, `newMemberIds`,
    /// `currentMemberIds`, `currentAdminIds`, `currentPendingMemberIds`,
    /// plus optional `senderId` / `signingKeyVersion` (resolved from the
    /// session identity when omitted), `currentTitle` and
    /// `currentDescription` (plaintext, encrypted under the new conversation
    /// key), `currentAvatarUrl` (the avatar's media URL, signed as is),
    /// `currentTtlMsec`, and `currentScreenCaptureBlockingEnabled`. Returns
    /// the same shape as [`Chat::prepare_conversation_key_change`], plus
    /// `encryptedTitle` and `encryptedDescription` for a title and
    /// description the params set.
    #[wasm_bindgen(js_name = prepareGroupMembersChange)]
    pub fn prepare_group_members_change(&self, params: JsValue) -> Result<JsValue, JsValue> {
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
        core_params.current_description = p.current_description;
        core_params.current_ttl_msec = p.current_ttl_msec.map(|t| t as i64);
        core_params.current_screen_capture_blocking_enabled =
            p.current_screen_capture_blocking_enabled;

        let result = self
            .inner
            .prepare_group_members_change_with_version(&core_params, &now_millis())
            .map_err(sdk_error)?;

        prepared_change_to_js(result)
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Takes a single params object with camelCase keys: `publicKeys` (for
    /// the new roster), `conversationId`, `memberIds`, `adminIds`, plus
    /// optional `senderId` / `signingKeyVersion` (resolved from the session
    /// identity when omitted), `title` (plaintext, encrypted under the new
    /// conversation key), and `ttlMsec`. Emits two action signatures (a
    /// conversation-key change and the group create). Returns the same
    /// shape as [`Chat::prepare_conversation_key_change`], plus
    /// `encryptedTitle` for a title the params set. A create sets no avatar;
    /// set it afterwards with `prepareGroupAvatarChange`.
    #[wasm_bindgen(js_name = prepareGroupCreate)]
    pub fn prepare_group_create(&self, params: JsValue) -> Result<JsValue, JsValue> {
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
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);

        let result = self
            .inner
            .prepare_group_create_with_version(&core_params, &now_millis())
            .map_err(sdk_error)?;

        prepared_change_to_js(result)
    }

    // Signing

    /// Verify a signature.
    pub fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, JsValue> {
        self.inner
            .verify(public_key_b64, signature, data)
            .map_err(sdk_error)
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
    ) -> Result<bool, JsValue> {
        self.inner
            .verify_key_binding(
                identity_public_key_b64,
                signing_public_key_b64,
                identity_public_key_signature_b64,
            )
            .map_err(sdk_error)
    }

    /// Report whether the loaded identity public key is the key in
    /// `publicKeyB64`.
    ///
    /// The X API returns the identity public key in SPKI/DER encoding while
    /// `getPublicKeys` returns the raw SEC1 point; this accepts either
    /// encoding, so use it to check whether the keys on this device belong
    /// to a key registered to the account.
    #[wasm_bindgen(js_name = matchesRegisteredKey)]
    pub fn matches_registered_key(&self, public_key_b64: &str) -> Result<bool, JsValue> {
        self.inner
            .matches_registered_key(public_key_b64)
            .map_err(sdk_error)
    }
}

/// Build the JS result object for a prepared key change, exposing
/// `conversationKey` as a `Uint8Array` and the rest as camelCase fields.
fn prepared_change_to_js(
    result: chat_xdk_core::PreparedConversationChange,
) -> Result<JsValue, JsValue> {
    use serde::Serialize;

    let obj = js_sys::Object::new();

    if let Some(ckey) = &result.conversation_key {
        let arr = js_sys::Uint8Array::from(ckey.encoded());
        js_sys::Reflect::set(&obj, &"conversationKey".into(), &arr.into())
            .map_err(|_| internal_error("Failed to set conversationKey"))?;
    }
    js_sys::Reflect::set(
        &obj,
        &"conversationId".into(),
        &JsValue::from_str(&result.conversation_id),
    )
    .map_err(|_| internal_error("Failed to set conversationId"))?;
    js_sys::Reflect::set(
        &obj,
        &"conversationKeyVersion".into(),
        &JsValue::from_str(&result.conversation_key_version),
    )
    .map_err(|_| internal_error("Failed to set conversationKeyVersion"))?;
    for (name, value) in [
        ("encryptedTitle", &result.encrypted_title),
        ("encryptedDescription", &result.encrypted_description),
    ] {
        if let Some(value) = value {
            js_sys::Reflect::set(&obj, &name.into(), &JsValue::from_str(value))
                .map_err(|_| internal_error(format!("Failed to set {name}")))?;
        }
    }

    let js_prepared: JsPreparedConversationChange = result.into();
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    let participant_keys_val = js_prepared
        .conversation_participant_keys
        .serialize(&serializer)
        .map_err(|e| internal_error(format!("Serialization failed: {:?}", e)))?;
    js_sys::Reflect::set(
        &obj,
        &"conversationParticipantKeys".into(),
        &participant_keys_val,
    )
    .map_err(|_| internal_error("Failed to set conversationParticipantKeys"))?;
    let action_signatures_val = js_prepared
        .action_signatures
        .serialize(&serializer)
        .map_err(|e| internal_error(format!("Serialization failed: {:?}", e)))?;
    js_sys::Reflect::set(&obj, &"actionSignatures".into(), &action_signatures_val)
        .map_err(|_| internal_error("Failed to set actionSignatures"))?;

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
    pub fn push(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        self.inner.push(&plaintext).map_err(sdk_error)
    }

    /// Emit the final frame and consume the encryptor.
    #[wasm_bindgen]
    pub fn finish(self) -> Result<Vec<u8>, JsValue> {
        self.inner.finish().map_err(sdk_error)
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
    pub fn push(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        self.inner.push(&ciphertext).map_err(sdk_error)
    }

    /// Decrypt the final frame and consume the decryptor.
    #[wasm_bindgen]
    pub fn finish(self) -> Result<Vec<u8>, JsValue> {
        self.inner.finish().map_err(sdk_error)
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
) -> Result<HashMap<String, XChatConversationKey>, JsValue> {
    if !js.is_object() || js_sys::Array::is_array(&js) {
        return Err(invalid_input(format!(
            "Invalid {method} params: conversationKeys must be an object mapping key version to \
             key bytes (the `keys` map of decryptEvents or extractConversationKeys)"
        )));
    }
    let mut entries = HashMap::new();
    let pairs = js_sys::Object::entries(&js_sys::Object::from(js));
    for i in 0..pairs.length() {
        let pair = js_sys::Array::from(&pairs.get(i));
        let version = pair.get(0).as_string().unwrap_or_default();
        let bytes = pair
            .get(1)
            .dyn_ref::<js_sys::Uint8Array>()
            .map(js_sys::Uint8Array::to_vec)
            .unwrap_or_default();
        entries.insert(version, bytes);
    }
    bindings::conversation_keys(entries).map_err(sdk_error)
}

/// Copy a params object's `Uint8Array` field in one step.
fn js_to_bytes(method: &str, field: &str, js: &JsValue) -> Result<Vec<u8>, JsValue> {
    js.dyn_ref::<js_sys::Uint8Array>()
        .map(js_sys::Uint8Array::to_vec)
        .ok_or_else(|| {
            invalid_input(format!(
                "Invalid {method} params: {field} must be a Uint8Array"
            ))
        })
}

/// Parse a JS `signingKeys` array into core entries. Absent/null yields an
/// empty list (the core falls back to the `setSigningKeys` store); a
/// malformed array is a caller error and is surfaced rather than silently
/// ignored.
fn js_to_signing_keys(js: JsValue) -> Result<Vec<chat_xdk_core::SigningKeyEntry>, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(Vec::new());
    }
    let entries: Vec<JsSigningKeyEntry> = serde_wasm_bindgen::from_value(js)
        .map_err(|e| invalid_input(format!("Invalid signingKeys: {}", e)))?;
    Ok(entries.into_iter().map(Into::into).collect())
}

/// Deserialize a JS params object into its camelCase mirror struct.
///
/// A missing required field surfaces as `Invalid <method> params: missing
/// field `<name>``, naming both the method and the field.
fn from_js_params<T: serde::de::DeserializeOwned>(
    method: &str,
    value: JsValue,
) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| invalid_input(format!("Invalid {} params: {}", method, e)))
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
        .map(|(start, end, entity_type)| {
            chat_xdk_core::EntityDescriptor::new(start, end, entity_type)
        })
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
struct JsGroupMembersRemoveParams {
    public_keys: Vec<JsPublicKeyInput>,
    conversation_id: String,
    user_ids: Vec<String>,
    title: Option<String>,
    description: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupMembersRemoveParams {
    fn into_core(self) -> chat_xdk_core::GroupMembersRemoveParams {
        let mut params = chat_xdk_core::GroupMembersRemoveParams::new(
            self.public_keys.into_iter().map(Into::into).collect(),
            self.conversation_id,
            self.user_ids,
        );
        params.title = self.title;
        params.description = self.description;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupLeaveParams {
    conversation_id: String,
    promote_admin_id: Option<String>,
    conversation_key_version: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupLeaveParams {
    fn into_core(self) -> chat_xdk_core::GroupLeaveParams {
        let mut params = chat_xdk_core::GroupLeaveParams::new(self.conversation_id);
        params.promote_admin_id = self.promote_admin_id;
        params.conversation_key_version = self.conversation_key_version;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupTitleChangeParams {
    conversation_id: String,
    new_title: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

impl JsGroupTitleChangeParams {
    fn into_core(self) -> chat_xdk_core::GroupTitleChangeParams {
        let mut params =
            chat_xdk_core::GroupTitleChangeParams::new(self.conversation_id, self.new_title);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params.conversation_key = self.conversation_key;
        params.conversation_key_version = self.conversation_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupAvatarChangeParams {
    conversation_id: String,
    new_avatar_url: String,
    conversation_key_version: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupAvatarChangeParams {
    fn into_core(self) -> chat_xdk_core::GroupAvatarChangeParams {
        let mut params = chat_xdk_core::GroupAvatarChangeParams::new(
            self.conversation_id,
            self.new_avatar_url,
            self.conversation_key_version,
        );
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupDescriptionChangeParams {
    conversation_id: String,
    new_description: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
}

impl JsGroupDescriptionChangeParams {
    fn into_core(self) -> chat_xdk_core::GroupDescriptionChangeParams {
        let mut params = chat_xdk_core::GroupDescriptionChangeParams::new(
            self.conversation_id,
            self.new_description,
        );
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params.conversation_key = self.conversation_key;
        params.conversation_key_version = self.conversation_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupAdminsAddParams {
    conversation_id: String,
    user_ids: Vec<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupAdminsAddParams {
    fn into_core(self) -> chat_xdk_core::GroupAdminsAddParams {
        let mut params =
            chat_xdk_core::GroupAdminsAddParams::new(self.conversation_id, self.user_ids);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupAdminsRemoveParams {
    conversation_id: String,
    user_ids: Vec<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupAdminsRemoveParams {
    fn into_core(self) -> chat_xdk_core::GroupAdminsRemoveParams {
        let mut params =
            chat_xdk_core::GroupAdminsRemoveParams::new(self.conversation_id, self.user_ids);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupInviteEnableParams {
    conversation_id: String,
    invite_url: String,
    expires_at_msec: Option<f64>,
    affiliate_id: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupInviteEnableParams {
    fn into_core(self) -> chat_xdk_core::GroupInviteEnableParams {
        let mut params =
            chat_xdk_core::GroupInviteEnableParams::new(self.conversation_id, self.invite_url);
        params.expires_at_msec = self.expires_at_msec.map(|msec| msec as i64);
        params.affiliate_id = self.affiliate_id;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupInviteDisableParams {
    conversation_id: String,
    disabled_by: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupInviteDisableParams {
    fn into_core(self) -> chat_xdk_core::GroupInviteDisableParams {
        let mut params = chat_xdk_core::GroupInviteDisableParams::new(self.conversation_id);
        params.disabled_by = self.disabled_by;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupJoinRequestParams {
    conversation_id: String,
    requesting_user_id: Option<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupJoinRequestParams {
    fn into_core(self) -> chat_xdk_core::GroupJoinRequestParams {
        let mut params = chat_xdk_core::GroupJoinRequestParams::new(self.conversation_id);
        params.requesting_user_id = self.requesting_user_id;
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroupJoinRejectParams {
    conversation_id: String,
    user_ids: Vec<String>,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsGroupJoinRejectParams {
    fn into_core(self) -> chat_xdk_core::GroupJoinRejectParams {
        let mut params =
            chat_xdk_core::GroupJoinRejectParams::new(self.conversation_id, self.user_ids);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMessageTtlChangeParams {
    conversation_id: String,
    ttl_msec: f64,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsMessageTtlChangeParams {
    fn into_core(self) -> chat_xdk_core::MessageTtlChangeParams {
        let mut params =
            chat_xdk_core::MessageTtlChangeParams::new(self.conversation_id, self.ttl_msec as i64);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMessageTtlRemoveParams {
    conversation_id: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsMessageTtlRemoveParams {
    fn into_core(self) -> chat_xdk_core::MessageTtlRemoveParams {
        let mut params = chat_xdk_core::MessageTtlRemoveParams::new(self.conversation_id);
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        params
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsScreenCaptureParams {
    conversation_id: String,
    change: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
}

impl JsScreenCaptureParams {
    fn into_core(
        self,
    ) -> Result<chat_xdk_core::ScreenCaptureParams, chat_xdk_core::error::SdkError> {
        let mut params = chat_xdk_core::ScreenCaptureParams::new(
            self.conversation_id,
            chat_xdk_core::ScreenCaptureChange::parse(&self.change)?,
        );
        params.sender_id = self.sender_id;
        params.signing_key_version = self.signing_key_version;
        Ok(params)
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
    current_description: Option<String>,
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

fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value
        .serialize(&serializer)
        .map_err(|e| internal_error(format!("Serialization failed: {:?}", e)))
}

// This crate has no Rust-side test module: `#[wasm_bindgen_test]` tests never
// execute on the host target, so the binding is covered by the Node suites in
// js/tests/, which exercise the built wasm artifact end to end.
