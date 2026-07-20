//! C FFI layer for Go bindings.
//!
//! All `*mut c_char` must be freed via `chat_xdk_free_string`.
//! The opaque `ChatHandle` must be freed via `chat_xdk_free`.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[cfg(feature = "juicebox")]
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use chat_xdk_core::crypto::keys::XChatConversationKey;
#[cfg(feature = "juicebox")]
use chat_xdk_core::keys::juicebox::{JuiceboxClient, JuiceboxConfig};
use chat_xdk_core::{
    AttachmentDescriptor, ConversationKeyChangeParams, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, EntityDescriptor, GroupCreateParams, GroupMembersChangeParams,
    PublicKeyInput, SigningKeyEntry,
};

// FFI result type

/// Result type returned by FFI functions.
///
/// On success: `data` contains the result (may be NULL for void operations),
///             `error` is NULL.
/// On error:   `data` is NULL, `error` contains the error message.
///
/// Both fields must be freed with `chat_xdk_free_string` when non-NULL.
#[repr(C)]
pub struct FfiResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

// Opaque handle

/// Opaque handle to a Chat SDK instance.
///
/// Created by [`chat_xdk_new`], freed by [`chat_xdk_free`].
pub struct ChatHandle {
    #[cfg(feature = "juicebox")]
    inner: chat_xdk_core::Chat,
    #[cfg(not(feature = "juicebox"))]
    inner: chat_xdk_core::ChatCore,
    #[cfg(feature = "juicebox")]
    runtime: tokio::runtime::Runtime,
}

// Helpers

fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        // C strings cannot carry interior NUL bytes. Replace them with U+FFFD
        // so a payload containing `\0` degrades visibly instead of silently
        // becoming an empty success result.
        Err(_) => CString::new(s.replace('\0', "\u{FFFD}"))
            .expect("NUL bytes were replaced")
            .into_raw(),
    }
}

/// Borrow a C string as UTF-8. NULL borrows as `""`. Invalid UTF-8 is a
/// caller error and is surfaced rather than silently read as an empty string.
unsafe fn from_c_str<'a>(s: *const c_char) -> Result<&'a str, std::str::Utf8Error> {
    if s.is_null() {
        return Ok("");
    }
    CStr::from_ptr(s).to_str()
}

/// Borrow a C-string argument as `&str`, returning an error `FfiResult` from
/// the enclosing function on invalid UTF-8.
macro_rules! try_str {
    ($p:expr) => {
        match unsafe { from_c_str($p) } {
            Ok(s) => s,
            Err(e) => return err_result(&format!("Invalid UTF-8 in argument: {}", e)),
        }
    };
}

fn ok_data(data: &str) -> FfiResult {
    FfiResult {
        data: to_c_string(data),
        error: std::ptr::null_mut(),
    }
}

fn ok_void() -> FfiResult {
    FfiResult {
        data: std::ptr::null_mut(),
        error: std::ptr::null_mut(),
    }
}

fn err_result(msg: &str) -> FfiResult {
    FfiResult {
        data: std::ptr::null_mut(),
        error: to_c_string(msg),
    }
}

fn format_error(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(err) = source {
        msg.push_str("\ncaused by: ");
        msg.push_str(&err.to_string());
        source = err.source();
    }
    msg
}

fn err_from(e: impl std::error::Error) -> FfiResult {
    err_result(&format_error(&e))
}

/// Best-effort text for a panic payload (typically `&str` or `String`).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

/// Run an FFI entry-point body, converting a panic into an error result so an
/// unwind never crosses the `extern "C"` boundary (which would abort the host
/// process).
fn catch_ffi(body: impl FnOnce() -> FfiResult) -> FfiResult {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
        .unwrap_or_else(|p| err_result(&format!("Internal panic: {}", panic_message(p.as_ref()))))
}

/// [`catch_ffi`] for entry points that cannot carry an error message: a panic
/// yields `fallback` (`-1`, NULL, or unit, depending on the signature).
fn catch_ffi_or<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Parse the signing-keys JSON passed across the FFI boundary.
///
/// `null`, an empty string, or `[]` yields an empty list — the decrypt calls
/// then fall back to the keys stored via `chat_xdk_set_signing_keys`, and
/// with nothing stored either, signed events fail decryption under the
/// default reject-unverified policy (they are returned with
/// `verified: false` only after reject-unverified is disabled).
/// A non-empty but malformed array is a caller error and is surfaced rather
/// than silently dropped (which would weaken verification).
fn parse_signing_keys(json: &str) -> Result<Vec<SigningKeyEntry>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("Invalid signing keys JSON: {}", e))
}

// Stateless utilities (same behavior as `chat_xdk_core::utils`)

unsafe fn bytes_from_ffi_ptr<'a>(data: *const u8, data_len: usize) -> &'a [u8] {
    if data.is_null() || data_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, data_len)
    }
}

/// Encode bytes to standard base64.
#[no_mangle]
pub extern "C" fn chat_xdk_bytes_to_base64(data: *const u8, data_len: usize) -> FfiResult {
    catch_ffi(|| {
        let slice = unsafe { bytes_from_ffi_ptr(data, data_len) };
        ok_data(&chat_xdk_core::utils::bytes_to_base64(slice))
    })
}

/// Decode base64 to bytes. On success, `data` holds base64 of the decoded bytes (FFI-safe).
#[no_mangle]
pub extern "C" fn chat_xdk_base64_to_bytes(b64: *const c_char) -> FfiResult {
    catch_ffi(|| {
        let s = try_str!(b64);
        match chat_xdk_core::utils::base64_to_bytes(s) {
            Some(bytes) => ok_data(&BASE64.encode(&bytes)),
            None => err_result("Invalid base64"),
        }
    })
}

/// Encode bytes to lowercase hex.
#[no_mangle]
pub extern "C" fn chat_xdk_bytes_to_hex(data: *const u8, data_len: usize) -> FfiResult {
    catch_ffi(|| {
        let slice = unsafe { bytes_from_ffi_ptr(data, data_len) };
        ok_data(&chat_xdk_core::utils::bytes_to_hex(slice))
    })
}

/// Decode hex to bytes. On success, `data` holds base64 of the decoded bytes (FFI-safe).
#[no_mangle]
pub extern "C" fn chat_xdk_hex_to_bytes(hex: *const c_char) -> FfiResult {
    catch_ffi(|| {
        let s = try_str!(hex);
        match chat_xdk_core::utils::hex_to_bytes(s) {
            Some(bytes) => ok_data(&BASE64.encode(&bytes)),
            None => err_result("Invalid hex"),
        }
    })
}

/// Detect MIME type from magic bytes. Empty string if unknown.
#[no_mangle]
pub extern "C" fn chat_xdk_detect_mime_type(data: *const u8, data_len: usize) -> FfiResult {
    catch_ffi(|| {
        let slice = unsafe { bytes_from_ffi_ptr(data, data_len) };
        match chat_xdk_core::utils::detect_mime_type(slice) {
            Some(mime) => ok_data(mime),
            None => ok_data(""),
        }
    })
}

/// JSON `{"width":N,"height":M}` or the literal `null` if dimensions cannot be determined.
#[no_mangle]
pub extern "C" fn chat_xdk_detect_image_dimensions(data: *const u8, data_len: usize) -> FfiResult {
    catch_ffi(|| {
        let slice = unsafe { bytes_from_ffi_ptr(data, data_len) };
        match chat_xdk_core::utils::detect_image_dimensions(slice) {
            Some(d) => ok_data(&format!(r#"{{"width":{},"height":{}}}"#, d.width, d.height)),
            None => ok_data("null"),
        }
    })
}

// Lifecycle functions

/// Create a new Chat SDK instance.
///
/// Returns an opaque handle that must be freed with [`chat_xdk_free`].
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn chat_xdk_new() -> *mut ChatHandle {
    catch_ffi_or(std::ptr::null_mut(), || {
        #[cfg(feature = "juicebox")]
        {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return std::ptr::null_mut(),
            };
            let config = JuiceboxConfig::from_json("{}".to_string());
            let inner = chat_xdk_core::Chat::with_juicebox(config, Arc::new(JuiceboxClient::new()));
            Box::into_raw(Box::new(ChatHandle { inner, runtime }))
        }
        #[cfg(not(feature = "juicebox"))]
        {
            Box::into_raw(Box::new(ChatHandle {
                inner: chat_xdk_core::ChatCore::new(),
            }))
        }
    })
}

/// Update the Juicebox configuration (e.g., to refresh auth tokens).
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_update_config(
    handle: *mut ChatHandle,
    config_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &mut *handle };
        let config_json = try_str!(config_json);
        let config = match parse_juicebox_config(config_json) {
            Ok(c) => c,
            Err(e) => return err_result(&e),
        };
        h.inner.update_config(config);
        ok_void()
    })
}

/// Register existing keys with Juicebox (first-time setup).
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_setup(
    handle: *mut ChatHandle,
    pin: *const c_char,
    config_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &mut *handle };
        let pin = try_str!(pin);
        let config_json = try_str!(config_json);
        let config = match parse_juicebox_config(config_json) {
            Ok(c) => c,
            Err(e) => return err_result(&e),
        };
        h.inner.update_config(config);
        match h
            .runtime
            .block_on(async { h.inner.setup(pin.as_bytes()).await })
        {
            Ok(keys) => match serde_json::to_string(&keys) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Unlock the SDK by recovering keys from Juicebox.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_unlock(
    handle: *mut ChatHandle,
    pin: *const c_char,
    config_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &mut *handle };
        let pin = try_str!(pin);
        let config_json = try_str!(config_json);
        let config = match parse_juicebox_config(config_json) {
            Ok(c) => c,
            Err(e) => return err_result(&e),
        };
        h.inner.update_config(config);
        match h
            .runtime
            .block_on(async { h.inner.unlock(pin.as_bytes()).await })
        {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Delete keys from Juicebox and clear from memory.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_delete(handle: *mut ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &mut *handle };
        match h.runtime.block_on(async { h.inner.delete().await }) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Change the PIN protecting keys in Juicebox.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_change_pin(
    handle: *mut ChatHandle,
    old_pin: *const c_char,
    new_pin: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &mut *handle };
        let old_pin = try_str!(old_pin);
        let new_pin = try_str!(new_pin);
        match h.runtime.block_on(async {
            h.inner
                .change_pin(old_pin.as_bytes(), new_pin.as_bytes())
                .await
        }) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

#[cfg(feature = "juicebox")]
fn parse_juicebox_config(config_json: &str) -> Result<JuiceboxConfig, String> {
    JuiceboxConfig::from_x_api_json(config_json)
}

/// Free a Chat SDK instance.
///
/// After calling this, the handle is invalid and must not be used.
/// Passing NULL is a no-op.
#[no_mangle]
pub extern "C" fn chat_xdk_free(handle: *mut ChatHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

/// Free a string returned by any chat_xdk function.
///
/// The buffer is zeroized before it is freed: some returns carry secrets
/// (e.g. exported keys), so every returned string is wiped rather than
/// deciding per call site.
///
/// Passing NULL is a no-op.
#[no_mangle]
pub extern "C" fn chat_xdk_free_string(s: *mut c_char) {
    catch_ffi_or((), || {
        if !s.is_null() {
            use zeroize::Zeroize;
            let mut bytes = unsafe { CString::from_raw(s) }.into_bytes();
            bytes.zeroize();
        }
    })
}

// Simple state functions

/// Check if the SDK is unlocked (both identity and signing keys loaded).
///
/// Returns 1 if unlocked, 0 if locked, -1 if handle is NULL.
#[no_mangle]
pub extern "C" fn chat_xdk_is_unlocked(handle: *const ChatHandle) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        if h.inner.is_unlocked() {
            1
        } else {
            0
        }
    })
}

/// Check if the identity key is loaded (sufficient for decryption).
///
/// Returns 1 if identity key loaded, 0 if not, -1 if handle is NULL.
#[no_mangle]
pub extern "C" fn chat_xdk_has_identity_key(handle: *const ChatHandle) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        if h.inner.has_identity_key() {
            1
        } else {
            0
        }
    })
}

/// Enable or disable rejection of unverified events.
///
/// When enabled — the default — `chat_xdk_decrypt_event` returns an error for
/// any signed event whose signature cannot be verified (invalid, missing, or
/// no matching signing key) instead of returning it with `verified: false`.
#[no_mangle]
pub extern "C" fn chat_xdk_set_reject_unverified(handle: *mut ChatHandle, reject: i32) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        h.inner.set_reject_unverified(reject != 0);
    })
}

/// Set the session identity: the owner's user id and signing-key version,
/// used as defaults wherever a params document leaves `sender_id` /
/// `signing_key_version` unset.
#[no_mangle]
pub extern "C" fn chat_xdk_set_identity(
    handle: *const ChatHandle,
    user_id: *const c_char,
    signing_key_version: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let user_id = try_str!(user_id);
        let signing_key_version = try_str!(signing_key_version);
        h.inner.set_identity(user_id, signing_key_version);
        ok_void()
    })
}

/// Enable (non-zero) or disable (0) the conversation-key cache (off by
/// default).
///
/// While enabled, `chat_xdk_decrypt_events` caches each conversation's
/// verified latest key and the encrypt functions resolve an omitted
/// `conversation_key`/`conversation_key_version` pair from it. Disabling
/// clears the cache.
#[no_mangle]
pub extern "C" fn chat_xdk_set_cache_keys(handle: *const ChatHandle, enabled: i32) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &*handle };
        h.inner.set_cache_keys(enabled != 0);
    })
}

/// Store signing keys used when a decrypt call passes an empty
/// `signing_keys_json`.
///
/// `signing_keys_json` takes the same array shape as
/// `chat_xdk_decrypt_events`. Each call replaces the previous set; only this
/// call populates the store — keys carried inside events are never trusted.
#[no_mangle]
pub extern "C" fn chat_xdk_set_signing_keys(
    handle: *const ChatHandle,
    signing_keys_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let signing_keys = match parse_signing_keys(try_str!(signing_keys_json)) {
            Ok(keys) => keys,
            Err(e) => return err_result(&e),
        };
        h.inner.set_signing_keys(signing_keys);
        ok_void()
    })
}

/// Lock the SDK, clearing keys from memory.
#[no_mangle]
pub extern "C" fn chat_xdk_lock(handle: *const ChatHandle) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &*handle };
        h.inner.lock();
    })
}

// Key generation / management

/// Generate new keypairs and return the registration payload as JSON.
///
/// Returns JSON matching `PublicKeyRegistrationPayload`.
#[no_mangle]
pub extern "C" fn chat_xdk_generate_keypairs(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.inner.generate_keypairs() {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Get the user's public keys as JSON.
///
/// Returns JSON `{"identity":"...","signing":"...","version":"..."}`.
#[no_mangle]
pub extern "C" fn chat_xdk_get_public_keys(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.inner.get_public_keys() {
            Ok(keys) => match serde_json::to_string(&keys) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Get the fingerprint of the loaded identity public key.
///
/// Returns a URL-safe base64 string (SHA-256 of the SPKI-encoded key)
/// that users can compare out-of-band to verify key authenticity.
#[no_mangle]
pub extern "C" fn chat_xdk_get_public_key_fingerprint(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.inner.get_public_key_fingerprint() {
            Ok(fp) => ok_data(&fp),
            Err(e) => err_from(e),
        }
    })
}

/// Export private keys as a base64 string.
///
/// Returns base64-encoded private key bytes (32 or 64), or NULL data if no
/// identity key is loaded.
#[no_mangle]
pub extern "C" fn chat_xdk_export_keys(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        // Mirror core's export requirement: identity key present (signing key
        // optional, giving a 32-byte export). NULL data = no identity key.
        if !h.inner.has_identity_key() {
            return ok_void();
        }
        match h.inner.export_keys() {
            // Both the raw exported bytes and their base64 re-encoding are
            // private key material; wipe both on drop. The C-string copy handed
            // to the caller is wiped in `chat_xdk_free_string`; any copy the
            // caller decodes on its side is the caller's to manage.
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let encoded = zeroize::Zeroizing::new(BASE64.encode(bytes.as_slice()));
                ok_data(&encoded)
            }
            Err(e) => err_from(e),
        }
    })
}

/// Import private keys from a base64 string.
#[no_mangle]
pub extern "C" fn chat_xdk_import_keys(
    handle: *const ChatHandle,
    keys_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let keys_b64 = try_str!(keys_b64);

        let key_bytes = match BASE64.decode(keys_b64) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };

        match h.inner.import_keys(&key_bytes) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Like `chat_xdk_import_keys` but also records the public key version the
/// keys were registered under, so participant-key filtering and the session
/// `signing_key_version` are set in one call.
///
/// `keys` are the raw private key bytes (32 or 64) — no base64 transport
/// copy, so the caller-owned buffer is the only copy to wipe.
#[no_mangle]
pub extern "C" fn chat_xdk_import_keys_with_version(
    handle: *const ChatHandle,
    keys: *const u8,
    keys_len: usize,
    version: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let version = try_str!(version);
        let key_bytes = unsafe { bytes_from_ffi_ptr(keys, keys_len) };

        match h.inner.import_keys_with_version(key_bytes, version) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

// Event decryption

fn json_conversation_key_bundle(
    ckr: &chat_xdk_core::ConversationKeyResult,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut keys = serde_json::Map::new();
    for (v, k) in &ckr.keys {
        keys.insert(
            v.clone(),
            serde_json::Value::String(BASE64.encode(k.encoded())),
        );
    }
    let mut o = serde_json::Map::new();
    o.insert("keys".into(), serde_json::Value::Object(keys));
    o.insert(
        "latest_version".into(),
        match &ckr.latest_version {
            Some(v) => serde_json::Value::String(v.clone()),
            None => serde_json::Value::Null,
        },
    );
    Ok(serde_json::Value::Object(o))
}

fn json_decrypt_events_result(
    r: &chat_xdk_core::DecryptEventsResult,
) -> Result<String, serde_json::Error> {
    let mut messages = Vec::new();
    for dm in &r.messages {
        let mut m = serde_json::Map::new();
        m.insert("event".into(), serde_json::to_value(&dm.event)?);
        if let Some(ref orig) = dm.original_b64 {
            m.insert(
                "original_b64".into(),
                serde_json::Value::String(orig.clone()),
            );
        }
        messages.push(serde_json::Value::Object(m));
    }
    let mut errors = serde_json::Map::new();
    for (k, v) in &r.errors {
        errors.insert(k.to_string(), serde_json::Value::String(v.clone()));
    }
    let mut root = serde_json::Map::new();
    root.insert("messages".into(), serde_json::Value::Array(messages));
    root.insert(
        "conversation_keys".into(),
        json_conversation_key_bundle(&r.conversation_keys)?,
    );
    root.insert("errors".into(), serde_json::Value::Object(errors));
    serde_json::to_string(&serde_json::Value::Object(root))
}

/// `events_json`: JSON array of base64-encoded event strings.
/// Returns JSON `{"keys":{version: key_b64,...},"latest_version": string|null}`.
#[no_mangle]
pub extern "C" fn chat_xdk_extract_conversation_keys(
    handle: *const ChatHandle,
    events_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let events_json = try_str!(events_json);

        let events: Vec<String> = match serde_json::from_str(events_json) {
            Ok(e) => e,
            Err(e) => return err_result(&format!("Invalid events JSON: {}", e)),
        };

        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let keys = h.inner.extract_conversation_keys(&refs);

        match json_conversation_key_bundle(&keys) {
            Ok(v) => match serde_json::to_string(&v) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_result(&e.to_string()),
        }
    })
}

/// Batch decrypt. `signing_keys_json`: `[{"user_id","public_key_version","public_key",
/// "identity_public_key","identity_public_key_signature"},...]`; an empty
/// array falls back to the keys stored via `chat_xdk_set_signing_keys`.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_events(
    handle: *const ChatHandle,
    events_json: *const c_char,
    signing_keys_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let events_json = try_str!(events_json);
        let signing_keys_json = try_str!(signing_keys_json);

        let events: Vec<String> = match serde_json::from_str(events_json) {
            Ok(e) => e,
            Err(e) => return err_result(&format!("Invalid events JSON: {}", e)),
        };
        let signing_keys = match parse_signing_keys(signing_keys_json) {
            Ok(keys) => keys,
            Err(e) => return err_result(&e),
        };

        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let result = h.inner.decrypt_events(&refs, &signing_keys);

        match json_decrypt_events_result(&result) {
            Ok(json) => ok_data(&json),
            Err(e) => err_result(&e.to_string()),
        }
    })
}

/// Serialize a prepared key change to JSON with the conversation key base64-encoded.
fn json_prepared_change(
    res: &chat_xdk_core::PreparedConversationChange,
) -> Result<String, serde_json::Error> {
    let mut out = serde_json::Map::new();
    out.insert(
        "conversation_id".into(),
        serde_json::Value::String(res.conversation_id.clone()),
    );
    if let Some(ref ck) = res.conversation_key {
        out.insert(
            "conversation_key".into(),
            serde_json::Value::String(BASE64.encode(ck.encoded())),
        );
    }
    out.insert(
        "conversation_key_version".into(),
        serde_json::Value::String(res.conversation_key_version.clone()),
    );
    out.insert(
        "participant_keys".into(),
        serde_json::to_value(&res.participant_keys)?,
    );
    out.insert(
        "action_signatures".into(),
        serde_json::to_value(&res.action_signatures)?,
    );
    serde_json::to_string(&serde_json::Value::Object(out))
}

// FFI params mirrors — one JSON document per method, snake_case keys matching
// the core param structs. Consolidating every argument into a single JSON
// document keeps the C ABI stable: a future optional field is an additive
// JSON key, not a new C argument. An absent or null key deserializes to
// `None`; `conversation_key` crosses the boundary as base64. Identity
// (`sender_id`, `signing_key_version`) and key
// (`conversation_key`, `conversation_key_version`) fields are optional
// overrides resolved by core from the session identity and the opt-in key
// cache when unset; core also treats an empty string as unset, so no
// filtering happens here. Entities are `[start, end, "type"]` tuples;
// attachment objects use the wire-format keys of `AttachmentDescriptor` and
// are parsed strictly (a missing required media field is an error — see
// `parse_attachments`).

#[derive(serde::Deserialize)]
struct FfiEncryptMessageParams {
    conversation_id: String,
    text: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    #[serde(default)]
    conversation_key: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<serde_json::Value>,
    should_notify: Option<bool>,
    ttl_msec: Option<i64>,
}

#[derive(serde::Deserialize)]
struct FfiEncryptReplyParams {
    conversation_id: String,
    text: String,
    #[serde(default)]
    reply_to_event: Option<String>,
    #[serde(default)]
    reply_to_edit_event: Option<String>,
    #[serde(default)]
    reply_to_ckces: Option<Vec<String>>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    #[serde(default)]
    conversation_key: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
    #[serde(default)]
    reply_to_sequence_id: Option<String>,
    reply_to_sender_id: Option<i64>,
    reply_to_text: Option<String>,
    entities: Option<Vec<(i32, i32, String)>>,
    attachments: Option<serde_json::Value>,
    reply_to_entities: Option<Vec<(i32, i32, String)>>,
    reply_to_attachments: Option<serde_json::Value>,
    should_notify: Option<bool>,
    ttl_msec: Option<i64>,
}

#[derive(serde::Deserialize)]
struct FfiEncryptReactionParams {
    emoji: String,
    #[serde(default)]
    target_event: Option<String>,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    target_message_sequence_id: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    #[serde(default)]
    conversation_key: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiConversationKeyChangeParams {
    public_keys: Vec<PublicKeyInput>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    conversation_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupMembersChangeParams {
    public_keys: Vec<PublicKeyInput>,
    conversation_id: String,
    new_member_ids: Vec<String>,
    current_member_ids: Vec<String>,
    current_admin_ids: Vec<String>,
    current_pending_member_ids: Vec<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    current_title: Option<String>,
    current_avatar_url: Option<String>,
    current_ttl_msec: Option<i64>,
    current_screen_capture_blocking_enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
struct FfiGroupCreateParams {
    public_keys: Vec<PublicKeyInput>,
    conversation_id: String,
    member_ids: Vec<String>,
    admin_ids: Vec<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    title: Option<String>,
    avatar_url: Option<String>,
    ttl_msec: Option<i64>,
}

/// Deserialize a single-JSON params document into its FFI mirror struct.
///
/// Parsing is strict: a missing required field or a type mismatch returns an
/// error result rather than being silently dropped or defaulted.
fn parse_params<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, FfiResult> {
    serde_json::from_str(json).map_err(|e| err_result(&format!("Invalid params JSON: {}", e)))
}

/// Convert entity tuples `[start, end, "type"]` into core descriptors.
fn entity_tuples_to_descs(tuples: Vec<(i32, i32, String)>) -> Vec<EntityDescriptor> {
    tuples
        .into_iter()
        .map(|(start, end, entity_type)| EntityDescriptor {
            start,
            end,
            entity_type,
        })
        .collect()
}

/// Prepare a signed conversation-key change.
///
/// `params_json` — single JSON document: `public_keys`
/// (`[{"user_id","public_key","key_version"},...]`), plus optional
/// `sender_id` / `signing_key_version` (unset resolves from the session
/// identity) and `conversation_id` (absent or empty derives the one-to-one
/// id).
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_conversation_key_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiConversationKeyChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params = ConversationKeyChangeParams::new(p.public_keys);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        // Core treats an absent or empty id as "derive the one-to-one id".
        params.conversation_id = p.conversation_id;

        match h.inner.prepare_conversation_key_change(params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Prepare a signed group member-add change.
///
/// `params_json` — single JSON document: `public_keys` (for the updated
/// roster), `conversation_id`, `new_member_ids`, `current_member_ids`,
/// `current_admin_ids`, `current_pending_member_ids`, plus optional
/// `sender_id` / `signing_key_version` (unset resolves from the session
/// identity), `current_title`, `current_avatar_url`, `current_ttl_msec`, and
/// `current_screen_capture_blocking_enabled` (an absent key means unset,
/// never false). Emits two action signatures.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_members_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupMembersChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params = GroupMembersChangeParams::new(
            p.public_keys,
            p.conversation_id,
            p.new_member_ids,
            p.current_member_ids,
            p.current_admin_ids,
            p.current_pending_member_ids,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.current_title = p.current_title;
        params.current_avatar_url = p.current_avatar_url;
        params.current_ttl_msec = p.current_ttl_msec;
        params.current_screen_capture_blocking_enabled = p.current_screen_capture_blocking_enabled;

        match h.inner.prepare_group_members_change(params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Prepare a signed group create.
///
/// `params_json` — single JSON document: `public_keys` (for the roster),
/// `conversation_id`, `member_ids`, `admin_ids`, plus optional `sender_id` /
/// `signing_key_version` (unset resolves from the session identity),
/// `title`, `avatar_url`, and `ttl_msec`. Emits two action signatures.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_create(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupCreateParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            GroupCreateParams::new(p.public_keys, p.conversation_id, p.member_ids, p.admin_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.title = p.title;
        params.avatar_url = p.avatar_url;
        params.ttl_msec = p.ttl_msec;

        match h.inner.prepare_group_create(params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt a webhook event.
///
/// `event_b64`: Base64-encoded event from webhook.
/// `conversation_keys_json`: JSON object mapping version strings to base64-encoded
///     raw conversation key bytes, from `extract_conversation_keys`. With "{}"
///     the opt-in conversation-key cache (see `chat_xdk_set_cache_keys`) is
///     consulted instead; pass "{}" for non-message events.
/// `signing_keys_json`: JSON array of `{"user_id","public_key_version","public_key",
///     "identity_public_key","identity_public_key_signature"}`. An empty array
///     falls back to the keys stored via `chat_xdk_set_signing_keys`; with
///     nothing stored either, signed events fail decryption under the default
///     reject-unverified policy (disable it via `chat_xdk_set_reject_unverified`
///     to have them returned with `verified: false` instead).
///
/// Returns JSON representation of the decrypted Event.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_event(
    handle: *const ChatHandle,
    event_b64: *const c_char,
    conversation_keys_json: *const c_char,
    signing_keys_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let event_b64 = try_str!(event_b64);
        let conv_keys_str = try_str!(conversation_keys_json);
        let signing_keys_str = try_str!(signing_keys_json);

        // Parse conversation keys: { "version": "base64_bytes", ... }
        let conv_keys_b64: HashMap<String, String> = match serde_json::from_str(conv_keys_str) {
            Ok(keys) => keys,
            Err(e) => return err_result(&format!("Invalid conversation keys JSON: {}", e)),
        };
        // A malformed document errors above; individual entries are best-effort.
        // An undecodable or wrong-length value is skipped and surfaces later
        // as a missing-key decrypt error.
        let mut conv_keys: HashMap<String, XChatConversationKey> = HashMap::new();
        for (version, key_b64) in conv_keys_b64 {
            if let Ok(bytes) = BASE64.decode(&key_b64) {
                if let Some(ckey) = XChatConversationKey::from_bytes(bytes) {
                    conv_keys.insert(version, ckey);
                }
            }
        }

        let signing_keys = match parse_signing_keys(signing_keys_str) {
            Ok(keys) => keys,
            Err(e) => return err_result(&e),
        };

        match h.inner.decrypt_event(event_b64, &conv_keys, &signing_keys) {
            Ok(event) => match serde_json::to_string(&event) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

// Message encryption

/// Parse raw conversation key bytes from base64.
fn parse_ckey(ckey_b64: &str) -> Result<XChatConversationKey, FfiResult> {
    let bytes = BASE64
        .decode(ckey_b64)
        .map_err(|e| err_result(&format!("Invalid conversation key base64: {}", e)))?;
    XChatConversationKey::from_bytes(bytes)
        .ok_or_else(|| err_result("Invalid conversation key (expected 32 bytes)"))
}

/// Decode raw conversation key bytes from base64 for the params structs,
/// which take the raw bytes and zeroize them on drop. An absent or empty
/// value means "no key passed" (resolve from the key cache); the key length
/// is validated in core so every binding reports the same error.
fn decode_ckey_bytes(ckey_b64: Option<&str>) -> Result<Option<Vec<u8>>, FfiResult> {
    match ckey_b64.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => BASE64
            .decode(s)
            .map(Some)
            .map_err(|e| err_result(&format!("Invalid conversation key base64: {}", e))),
    }
}

/// Encrypt a message for the X API.
///
/// `params_json` — single JSON document: `conversation_id`, `text`, plus
/// optional `sender_id` / `signing_key_version` (unset resolves from the
/// session identity), `conversation_key` (base64 raw 32-byte key) /
/// `conversation_key_version` (unset resolves from the opt-in key cache),
/// `entities` (`[[start,end,"type"],...]`), `attachments`
/// (`[{"attachment_type",...},...]`), `should_notify`, and `ttl_msec`.
///
/// Returns JSON `SendPayload`; the SDK-generated `message_id` is a field on it.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_message(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let mut p: FfiEncryptMessageParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let attachments = match p.attachments.take().map(parse_attachments).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };

        let mut params = EncryptMessageParams::new(p.conversation_id, p.text);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;
        params.entities = p.entities.map(entity_tuples_to_descs);
        params.attachments = attachments;
        params.should_notify = p.should_notify;
        params.ttl_msec = p.ttl_msec;

        match h.inner.encrypt_message(params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Parse attachment descriptors from a JSON array via the core serde types,
/// so the field requirements are defined once in core: an attachment missing
/// a required media field is rejected rather than silently defaulted.
fn parse_attachments(value: serde_json::Value) -> Result<Vec<AttachmentDescriptor>, FfiResult> {
    serde_json::from_value(value).map_err(|e| err_result(&format!("Invalid attachments: {}", e)))
}

/// Encrypt a reply message for the X API.
///
/// `params_json` — same document as `chat_xdk_encrypt_message` plus the
/// reply target: preferably `reply_to_event` (base64 raw signed event being
/// replied to; the preview is derived from it), with optional
/// `reply_to_edit_event` and `reply_to_ckces` (base64 raw key-change events
/// needed when the original used a different key version). The explicit
/// `reply_to_sequence_id`, `reply_to_sender_id`, `reply_to_text`,
/// `reply_to_entities`, and `reply_to_attachments` overrides remain for
/// callers that no longer hold the raw event.
///
/// Returns JSON `SendPayload`; the SDK-generated `message_id` is a field on it.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_reply(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let mut p: FfiEncryptReplyParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let attachments = match p.attachments.take().map(parse_attachments).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };
        let reply_to_attachments = match p
            .reply_to_attachments
            .take()
            .map(parse_attachments)
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let mut params = EncryptReplyParams::new(
            p.conversation_id,
            p.text,
            p.reply_to_event.unwrap_or_default(),
        );
        params.reply_to_edit_event = p.reply_to_edit_event;
        params.reply_to_ckces = p.reply_to_ckces;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;
        params.reply_to_sequence_id = p.reply_to_sequence_id;
        params.reply_to_sender_id = p.reply_to_sender_id;
        params.reply_to_text = p.reply_to_text;
        params.entities = p.entities.map(entity_tuples_to_descs);
        params.attachments = attachments;
        params.reply_to_entities = p.reply_to_entities.map(entity_tuples_to_descs);
        params.reply_to_attachments = reply_to_attachments;
        params.should_notify = p.should_notify;
        params.ttl_msec = p.ttl_msec;

        match h.inner.encrypt_reply(params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

// Reaction encryption

/// Encrypt a reaction-add for the X API.
///
/// `params_json` — single JSON document: `emoji` plus the reaction target:
/// preferably `target_event` (base64 raw event being reacted to; the
/// conversation id and target sequence id are derived from it), with
/// explicit `conversation_id` / `target_message_sequence_id` overrides for
/// callers that no longer hold the raw event. Optional `sender_id` /
/// `signing_key_version` (unset resolves from the session identity) and
/// `conversation_key` (base64) / `conversation_key_version` (unset resolves
/// from the opt-in key cache).
///
/// Returns JSON `SendPayload`; the SDK-generated `message_id` is a field on it.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_add_reaction(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| encrypt_reaction_impl(handle, params_json, false))
}

/// Encrypt a reaction-remove for the X API.
///
/// Same parameters as `chat_xdk_encrypt_add_reaction`.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_remove_reaction(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| encrypt_reaction_impl(handle, params_json, true))
}

fn encrypt_reaction_impl(
    handle: *const ChatHandle,
    params_json: *const c_char,
    remove: bool,
) -> FfiResult {
    if handle.is_null() {
        return err_result("Null handle");
    }
    let h = unsafe { &*handle };
    let p: FfiEncryptReactionParams = match parse_params(try_str!(params_json)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
        Ok(k) => k,
        Err(e) => return e,
    };

    let mut params = EncryptReactionParams::new(p.target_event.unwrap_or_default(), p.emoji);
    params.conversation_id = p.conversation_id;
    params.target_message_sequence_id = p.target_message_sequence_id;
    params.sender_id = p.sender_id;
    params.signing_key_version = p.signing_key_version;
    params.conversation_key = ckey_bytes;
    params.conversation_key_version = p.conversation_key_version;

    let result = if remove {
        h.inner.encrypt_remove_reaction(&params)
    } else {
        h.inner.encrypt_add_reaction(&params)
    };

    match result {
        Ok(payload) => match serde_json::to_string(&payload) {
            Ok(json) => ok_data(&json),
            Err(e) => err_result(&e.to_string()),
        },
        Err(e) => err_from(e),
    }
}

// Conversation key operations

/// Decrypt an encrypted conversation key.
///
/// Returns base64-encoded decrypted conversation key.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_conversation_key(
    handle: *const ChatHandle,
    encrypted_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let encrypted = try_str!(encrypted_key_b64);

        match h.inner.decrypt_conversation_key(encrypted) {
            Ok(ckey) => ok_data(&BASE64.encode(ckey.encoded())),
            Err(e) => err_from(e),
        }
    })
}

/// Encrypt a UTF-8 plaintext string; returns base64 ciphertext (XSalsa20-Poly1305).
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt(
    handle: *const ChatHandle,
    plaintext: *const c_char,
    conversation_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let plaintext = try_str!(plaintext);
        let ckey_b64 = try_str!(conversation_key_b64);

        let ckey_bytes = match BASE64.decode(ckey_b64) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        let ckey = match chat_xdk_core::crypto::keys::XChatConversationKey::from_bytes(ckey_bytes) {
            Some(k) => k,
            None => return err_result("Invalid conversation key"),
        };

        match h.inner.encrypt(plaintext, &ckey) {
            Ok(s) => ok_data(&s),
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt base64 ciphertext to UTF-8 plaintext (metadata fields, same wire as message content).
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt(
    handle: *const ChatHandle,
    ciphertext_b64: *const c_char,
    conversation_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let ciphertext_b64 = try_str!(ciphertext_b64);
        let ckey_b64 = try_str!(conversation_key_b64);

        let ckey_bytes = match BASE64.decode(ckey_b64) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        let ckey = match chat_xdk_core::crypto::keys::XChatConversationKey::from_bytes(ckey_bytes) {
            Some(k) => k,
            None => return err_result("Invalid conversation key"),
        };

        match h.inner.decrypt(ciphertext_b64, &ckey) {
            Ok(s) => ok_data(&s),
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt a streaming-encrypted payload.
///
/// Returns base64-encoded decrypted bytes.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_stream(
    handle: *const ChatHandle,
    encrypted_b64: *const c_char,
    conversation_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let encrypted_b64 = try_str!(encrypted_b64);
        let ckey_b64 = try_str!(conversation_key_b64);

        let encrypted = match BASE64.decode(encrypted_b64) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        let ckey = match parse_ckey(ckey_b64) {
            Ok(k) => k,
            Err(e) => return e,
        };

        match h.inner.decrypt_stream(&encrypted, &ckey) {
            Ok(output) => ok_data(&BASE64.encode(&output)),
            Err(e) => err_from(e),
        }
    })
}

/// Encrypt a stream (e.g., media) with a conversation key. Returns base64.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_stream(
    handle: *const ChatHandle,
    plaintext_b64: *const c_char,
    conversation_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let plaintext_b64 = try_str!(plaintext_b64);
        let ckey_b64 = try_str!(conversation_key_b64);

        let plaintext = match BASE64.decode(plaintext_b64) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        let ckey = match parse_ckey(ckey_b64) {
            Ok(k) => k,
            Err(e) => return e,
        };

        match h.inner.encrypt_stream(&plaintext, &ckey) {
            Ok(encrypted) => ok_data(&BASE64.encode(&encrypted)),
            Err(e) => err_from(e),
        }
    })
}

// Incremental streaming

/// Opaque handle to an incremental stream encryptor.
///
/// Created by [`chat_xdk_stream_encryptor_new`], freed by
/// [`chat_xdk_stream_encryptor_free`].
pub struct StreamEncryptorHandle {
    inner: Option<chat_xdk_core::StreamEncryptor>,
}

/// Opaque handle to an incremental stream decryptor.
///
/// Created by [`chat_xdk_stream_decryptor_new`], freed by
/// [`chat_xdk_stream_decryptor_free`].
pub struct StreamDecryptorHandle {
    inner: Option<chat_xdk_core::StreamDecryptor>,
}

/// Create a stream encryptor for a base64 conversation key. Returns NULL on a
/// bad key; free the handle with [`chat_xdk_stream_encryptor_free`].
#[no_mangle]
pub extern "C" fn chat_xdk_stream_encryptor_new(
    conversation_key_b64: *const c_char,
) -> *mut StreamEncryptorHandle {
    catch_ffi_or(std::ptr::null_mut(), || {
        let ckey = match parse_ckey(match unsafe { from_c_str(conversation_key_b64) } {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }) {
            Ok(k) => k,
            Err(_) => return std::ptr::null_mut(),
        };
        match chat_xdk_core::StreamEncryptor::new(&ckey) {
            Ok(enc) => Box::into_raw(Box::new(StreamEncryptorHandle { inner: Some(enc) })),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Encrypt a base64 plaintext chunk; returns base64 ciphertext available so far.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_encryptor_push(
    handle: *mut StreamEncryptorHandle,
    plaintext_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let enc = match unsafe { &mut *handle }.inner.as_mut() {
            Some(e) => e,
            None => return err_result("Stream encryptor already finished"),
        };
        let plaintext = match BASE64.decode(try_str!(plaintext_b64)) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        match enc.push(&plaintext) {
            Ok(out) => ok_data(&BASE64.encode(&out)),
            Err(e) => err_from(e),
        }
    })
}

/// Emit the final frame as base64. The handle must still be freed afterwards.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_encryptor_finish(
    handle: *mut StreamEncryptorHandle,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        match unsafe { &mut *handle }.inner.take() {
            Some(enc) => match enc.finish() {
                Ok(out) => ok_data(&BASE64.encode(&out)),
                Err(e) => err_from(e),
            },
            None => err_result("Stream encryptor already finished"),
        }
    })
}

/// Free a stream encryptor handle.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_encryptor_free(handle: *mut StreamEncryptorHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

/// Create a stream decryptor for a base64 conversation key. Returns NULL on a
/// bad key; free the handle with [`chat_xdk_stream_decryptor_free`].
#[no_mangle]
pub extern "C" fn chat_xdk_stream_decryptor_new(
    conversation_key_b64: *const c_char,
) -> *mut StreamDecryptorHandle {
    catch_ffi_or(std::ptr::null_mut(), || {
        let ckey = match parse_ckey(match unsafe { from_c_str(conversation_key_b64) } {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }) {
            Ok(k) => k,
            Err(_) => return std::ptr::null_mut(),
        };
        match chat_xdk_core::StreamDecryptor::new(&ckey) {
            Ok(dec) => Box::into_raw(Box::new(StreamDecryptorHandle { inner: Some(dec) })),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Decrypt a base64 ciphertext chunk; returns base64 plaintext available so far.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_decryptor_push(
    handle: *mut StreamDecryptorHandle,
    ciphertext_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let dec = match unsafe { &mut *handle }.inner.as_mut() {
            Some(d) => d,
            None => return err_result("Stream decryptor already finished"),
        };
        let ciphertext = match BASE64.decode(try_str!(ciphertext_b64)) {
            Ok(b) => b,
            Err(e) => return err_result(&format!("Base64 error: {}", e)),
        };
        match dec.push(&ciphertext) {
            Ok(out) => ok_data(&BASE64.encode(&out)),
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt the final frame as base64. Errors if the stream was truncated. The
/// handle must still be freed afterwards.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_decryptor_finish(
    handle: *mut StreamDecryptorHandle,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        match unsafe { &mut *handle }.inner.take() {
            Some(dec) => match dec.finish() {
                Ok(out) => ok_data(&BASE64.encode(&out)),
                Err(e) => err_from(e),
            },
            None => err_result("Stream decryptor already finished"),
        }
    })
}

/// Free a stream decryptor handle.
#[no_mangle]
pub extern "C" fn chat_xdk_stream_decryptor_free(handle: *mut StreamDecryptorHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

// Signing / verification

/// Sign data with the signing key. Returns base64-encoded signature.
#[no_mangle]
pub extern "C" fn chat_xdk_sign(
    handle: *const ChatHandle,
    data: *const u8,
    data_len: usize,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        if data.is_null() && data_len > 0 {
            return err_result("Null data pointer with non-zero length");
        }
        let h = unsafe { &*handle };
        let bytes = if data_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len) }
        };

        match h.inner.sign(bytes) {
            Ok(sig) => ok_data(&BASE64.encode(&sig)),
            Err(e) => err_from(e),
        }
    })
}

/// Verify a signature.
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
#[no_mangle]
pub extern "C" fn chat_xdk_verify(
    handle: *const ChatHandle,
    public_key_b64: *const c_char,
    signature_b64: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        let pk_b64 = match unsafe { from_c_str(public_key_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let sig_b64 = match unsafe { from_c_str(signature_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let sig = match BASE64.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return -1,
        };

        let bytes = if data_len == 0 || data.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len) }
        };

        match h.inner.verify(pk_b64, &sig, bytes) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    })
}

/// Verify that a signing key is authentically bound to an identity key.
///
/// All three arguments are base64 strings. Returns 1 if the binding is
/// valid, 0 if it is not, and -1 on error (e.g. malformed input).
#[no_mangle]
pub extern "C" fn chat_xdk_verify_key_binding(
    handle: *const ChatHandle,
    identity_public_key_b64: *const c_char,
    signing_public_key_b64: *const c_char,
    identity_public_key_signature_b64: *const c_char,
) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        let identity_b64 = match unsafe { from_c_str(identity_public_key_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let signing_b64 = match unsafe { from_c_str(signing_public_key_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let signature_b64 = match unsafe { from_c_str(identity_public_key_signature_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };

        match h
            .inner
            .verify_key_binding(identity_b64, signing_b64, signature_b64)
        {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    })
}

/// Report whether the loaded identity public key is the key in
/// `public_key_b64` (raw SEC1 point or SPKI/DER, base64-encoded).
///
/// Returns 1 on a match, 0 on a mismatch, and -1 on error (no identity
/// keypair loaded or malformed input).
#[no_mangle]
pub extern "C" fn chat_xdk_matches_registered_key(
    handle: *const ChatHandle,
    public_key_b64: *const c_char,
) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        let pk_b64 = match unsafe { from_c_str(public_key_b64) } {
            Ok(s) => s,
            Err(_) => return -1,
        };

        match h.inner.matches_registered_key(pk_b64) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    })
}
