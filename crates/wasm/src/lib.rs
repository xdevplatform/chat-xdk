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
//! const result = chat.decryptEvents(rawEvents, signingKeys);
//! for (const dm of result.messages) {
//!   console.log(dm.event.type, dm.event.content?.text);
//! }
//!
//! // Single event with cached keys
//! const cachedKeys = result.conversationKeys.keys;
//! const event = chat.decryptEvent(newEventB64, cachedKeys, senderKeys);
//! ```

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use chat_xdk_core::crypto::keys::XChatConversationKey;

// Import generated camelCase JS types from core
use chat_xdk_core::js::{
    JsEvent, JsPreparedConversationChange, JsPublicKeyInput, JsPublicKeyRegistrationPayload,
    JsSendPayload, JsSigningKeyEntry,
};

// Utility Functions (free functions, not methods)

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
    ///
    /// The key version is read from the JS clock (`Date.now()`) because the
    /// `wasm32-unknown-unknown` target has no system clock.
    #[wasm_bindgen(js_name = generateKeypairs)]
    pub fn generate_keypairs_impl(&mut self) -> Result<JsValue, JsError> {
        let payload = self
            .inner
            .generate_keypairs_with_version(&now_millis())
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

    /// Import private keys from raw bytes (`Uint8Array`).
    ///
    /// The input bytes are zeroized after import. When `version` is given it
    /// also records the public key version the keys were registered under
    /// (participant-key filtering plus the session `signingKeyVersion`).
    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(
        &mut self,
        mut keys: Vec<u8>,
        version: Option<String>,
    ) -> Result<(), JsError> {
        let result = match version {
            Some(v) => self.inner.import_keys_with_version(&keys, &v),
            None => self.inner.import_keys(&keys),
        }
        .map_err(|e| JsError::new(&format!("{}", e)));
        keys.zeroize();
        result
    }

    /// Set the session identity: the owner's user id and signing-key
    /// version, used as defaults wherever a params object omits
    /// `senderId` / `signingKeyVersion`.
    #[wasm_bindgen(js_name = setIdentity)]
    pub fn set_identity(&self, user_id: &str, signing_key_version: &str) {
        self.inner.set_identity(user_id, signing_key_version);
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
    /// `signingKeys` is an array of `{ userId, publicKeyVersion, publicKey,
    /// identityPublicKey, identityPublicKeySignature }` objects for ALL
    /// participants in the conversation (pass the X API response through).
    /// Omitting it falls back to the keys stored via `setSigningKeys`.
    ///
    /// Returns `{ messages, conversationKeys, errors }`.
    #[wasm_bindgen(js_name = decryptEvents)]
    pub fn decrypt_events(
        &self,
        events: Vec<String>,
        signing_keys: JsValue,
    ) -> Result<JsValue, JsError> {
        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let signing_keys = js_to_signing_keys(signing_keys)?;

        let result = self.inner.decrypt_events(&refs, &signing_keys);

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
    /// `conversationKeys` is a plain `version → key bytes` map — the `.keys`
    /// property of the object returned by `extractConversationKeys` (passing
    /// the whole result object yields an empty map and every decrypt fails
    /// with "no matching key found"). Omitting it falls back to the opt-in
    /// key cache (`setCacheKeys(true)`).
    /// `signingKeys` is an array of `{ userId, publicKeyVersion, publicKey,
    /// identityPublicKey, identityPublicKeySignature }` objects; entries are
    /// filtered to the event's sender and the SDK picks the matching version
    /// automatically. Omitting it falls back to the keys stored via
    /// `setSigningKeys`. Under the default reject-unverified policy no
    /// signing keys from either source makes every signed event throw; only
    /// after `setRejectUnverified(false)` are such events returned with
    /// `verified: false`.
    #[wasm_bindgen(js_name = decryptEvent)]
    pub fn decrypt_event(
        &self,
        event_b64: &str,
        conversation_keys: JsValue,
        signing_keys: JsValue,
    ) -> Result<JsValue, JsError> {
        let conv_keys = js_to_conv_keys(conversation_keys)?;
        let signing_keys = js_to_signing_keys(signing_keys)?;

        let event = self
            .inner
            .decrypt_event(event_b64, &conv_keys, &signing_keys)
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
    /// `attachments` (array of attachment objects), `shouldNotify`, and
    /// `ttlMsec`.
    ///
    /// The SDK generates the message id and returns it as `messageId` on the
    /// result; callers do not pass one.
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
        core_params.should_notify = p.should_notify;
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);
        let payload = self
            .inner
            .encrypt_message(core_params)
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
    /// callers that no longer hold the raw event.
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
        core_params.reply_to_sender_id = p.reply_to_sender_id.map(sender_id_to_i64).transpose()?;
        core_params.reply_to_text = p.reply_to_text;
        core_params.entities = p.entities.map(entity_tuples_to_descs);
        core_params.attachments = p.attachments;
        core_params.reply_to_entities = p.reply_to_entities.map(entity_tuples_to_descs);
        core_params.reply_to_attachments = p.reply_to_attachments;
        core_params.should_notify = p.should_notify;
        core_params.ttl_msec = p.ttl_msec.map(|t| t as i64);
        let payload = self
            .inner
            .encrypt_reply(core_params)
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

    /// Encrypt a stream (e.g. media).
    #[wasm_bindgen(js_name = encryptStream)]
    pub fn encrypt_stream(
        &self,
        plaintext: Vec<u8>,
        conversation_key: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        self.inner
            .encrypt_stream(&plaintext, &ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Decrypt a streaming-encrypted payload (e.g. media).
    #[wasm_bindgen(js_name = decryptStream)]
    pub fn decrypt_stream(
        &self,
        encrypted: Vec<u8>,
        conversation_key: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        self.inner
            .decrypt_stream(&encrypted, &ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))
    }

    /// Create an incremental stream encryptor for large payloads.
    #[wasm_bindgen(js_name = streamEncryptor)]
    pub fn stream_encryptor(&self, conversation_key: Vec<u8>) -> Result<StreamEncryptor, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        let inner = self
            .inner
            .stream_encryptor(&ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(StreamEncryptor { inner })
    }

    /// Create an incremental stream decryptor for large payloads.
    #[wasm_bindgen(js_name = streamDecryptor)]
    pub fn stream_decryptor(&self, conversation_key: Vec<u8>) -> Result<StreamDecryptor, JsError> {
        let ckey = XChatConversationKey::from_bytes(conversation_key)
            .ok_or_else(|| JsError::new("Invalid conversation key (expected 32 bytes)"))?;
        let inner = self
            .inner
            .stream_decryptor(&ckey)
            .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(StreamDecryptor { inner })
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
            .prepare_conversation_key_change_with_version(core_params, &now_millis())
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
            .prepare_group_members_change_with_version(core_params, &now_millis())
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
            .prepare_group_create_with_version(core_params, &now_millis())
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

/// Incremental stream encryptor for large payloads.
///
/// Feed plaintext with `push`; call `finish` once to emit the final frame.
#[wasm_bindgen]
pub struct StreamEncryptor {
    inner: chat_xdk_core::StreamEncryptor,
}

#[wasm_bindgen]
impl StreamEncryptor {
    /// Encrypt a plaintext chunk, returning ciphertext available so far.
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

/// Incremental stream decryptor for large payloads.
///
/// Feed ciphertext with `push`; call `finish` once at end of input. `finish`
/// throws if the stream ended before its final frame (truncation), so callers
/// must not treat plaintext as complete until `finish` succeeds.
#[wasm_bindgen]
pub struct StreamDecryptor {
    inner: chat_xdk_core::StreamDecryptor,
}

#[wasm_bindgen]
impl StreamDecryptor {
    /// Decrypt a ciphertext chunk, returning plaintext available so far.
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
/// The `wasm32-unknown-unknown` target has no system clock, so key/conversation
/// versions come from JavaScript's `Date.now()` instead.
fn now_millis() -> String {
    (js_sys::Date::now() as u64).to_string()
}

/// Parse a JS object `{ [version: string]: Uint8Array }` into a key map.
fn js_to_conv_keys(js: JsValue) -> Result<HashMap<String, XChatConversationKey>, JsError> {
    let mut result = HashMap::new();
    if js.is_undefined() || js.is_null() {
        return Ok(result);
    }
    let obj = js_sys::Object::from(js);
    let entries = js_sys::Object::entries(&obj);
    for i in 0..entries.length() {
        let pair = js_sys::Array::from(&entries.get(i));
        let version = match pair.get(0).as_string() {
            Some(v) => v,
            None => continue,
        };
        let val = pair.get(1);
        let bytes = if val.is_instance_of::<js_sys::Uint8Array>() {
            js_sys::Uint8Array::from(val).to_vec()
        } else {
            continue;
        };
        if let Some(key) = XChatConversationKey::from_bytes(bytes) {
            result.insert(version, key);
        }
    }
    Ok(result)
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

/// `replyToSenderId` as received from JS: a string or an integral number.
///
/// User-id snowflakes exceed the 2^53 range where JS numbers stay exact, so
/// strings are the reliable form; numbers are accepted for ids that fit.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum JsSenderId {
    Num(f64),
    Str(String),
}

/// Parse a [`JsSenderId`] into the exact `i64` the reply preview signs,
/// rejecting non-integral numbers, numbers beyond `Number.MAX_SAFE_INTEGER`
/// (already rounded by JS), and non-numeric strings.
fn sender_id_to_i64(id: JsSenderId) -> Result<i64, JsError> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    match id {
        JsSenderId::Str(s) => s.parse::<i64>().map_err(|_| {
            JsError::new(&format!(
                "Invalid replyToSenderId: '{}' is not an integer user id",
                s
            ))
        }),
        JsSenderId::Num(n) => {
            if !n.is_finite() || n.fract() != 0.0 {
                return Err(JsError::new(
                    "Invalid replyToSenderId: must be an integer or an integer string",
                ));
            }
            if n.abs() > MAX_SAFE_INTEGER {
                return Err(JsError::new(
                    "Invalid replyToSenderId: number exceeds JavaScript's exact \
                     integer range; pass the id as a string",
                ));
            }
            Ok(n as i64)
        }
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
struct JsEncryptMessageParams {
    conversation_id: String,
    text: String,
    sender_id: Option<String>,
    signing_key_version: Option<String>,
    conversation_key: Option<Vec<u8>>,
    conversation_key_version: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
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
    reply_to_sender_id: Option<JsSenderId>,
    reply_to_text: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
    reply_to_entities: Option<Vec<(i32, i32, String)>>,
    reply_to_attachments: Option<Vec<chat_xdk_core::AttachmentDescriptor>>,
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

fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value
        .serialize(&serializer)
        .map_err(|e| JsError::new(&format!("Serialization failed: {:?}", e)))
}

// This crate has no Rust-side test module: `#[wasm_bindgen_test]` tests never
// execute on the host target, so the binding is covered by the Node suites in
// js/tests/, which exercise the built wasm artifact end to end.
