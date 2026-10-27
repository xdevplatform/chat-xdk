//! The C ABI of the SDK: the one native layer under the Go, .NET and JVM
//! bindings. Go links it as a static archive; .NET (P/Invoke) and the JVM
//! (JNA) load it as a shared library.
//!
//! Every function returns an [`FfiResult`], apart from
//! [`chat_xdk_abi_version`] and the `_free` functions. Complex values cross
//! the boundary as JSON strings, booleans as `true` / `false`. All
//! `*mut c_char` must be freed via `chat_xdk_free_string`. The opaque
//! `ChatHandle` must be freed via `chat_xdk_free`, after every call on it
//! has returned; until then calls on one handle may run on any thread.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[cfg(feature = "juicebox")]
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use chat_xdk_core::bindings::{self, FeatureSwitches};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::error::{ErrorKind, SdkError};
#[cfg(feature = "juicebox")]
use chat_xdk_core::keys::juicebox::{JuiceboxClient, JuiceboxConfig};
use chat_xdk_core::{
    AttachmentDescriptor, ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams,
    DecryptFileParams, EncryptEditParams, EncryptFileParams, EncryptMessageParams,
    EncryptReactionParams, EncryptReplyParams, EntityDescriptor, FileDecryptorParams,
    FileEncryptorParams, GroupAdminsAddParams, GroupAdminsRemoveParams, GroupAvatarChangeParams,
    GroupCreateParams, GroupDescriptionChangeParams, GroupInviteDisableParams,
    GroupInviteEnableParams, GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams,
    GroupMembersChangeParams, GroupMembersRemoveParams, GroupTitleChangeParams, ImportKeysParams,
    MarkConversationReadParams, MessageDeleteParams, MessageTtlChangeParams,
    MessageTtlRemoveParams, PublicKeyInput, QuickReply, ScreenCaptureChange, ScreenCaptureParams,
    SetIdentityParams, SigningKeyEntry,
};

/// The version of this C ABI: the functions and the shapes of their
/// arguments and results. A header and a library with different versions
/// don't match; compare it with [`chat_xdk_abi_version`] at startup.
pub const CHAT_XDK_ABI_VERSION: u32 = 1;

// FFI result type

/// Result type returned by FFI functions.
///
/// On success: `data` contains the result (may be NULL for void operations),
///             `error` is NULL.
/// On error:   `data` is NULL, `error` is a JSON error document:
///             `{"kind": "...", "message": "..."}`, with
///             `"guesses_remaining": N` added to an `invalid_pin` error when
///             Juicebox reports the attempts left. `kind` is one of
///             `invalid_input`, `invalid_state`, `parse`, `decryption`,
///             `verification`, `invalid_pin`, `juicebox` and `internal`.
///
/// Both fields must be freed with `chat_xdk_free_string` when non-NULL.
#[repr(C)]
pub struct FfiResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

/// The version of this C ABI, [`CHAT_XDK_ABI_VERSION`] when the library
/// matches the header it was built with.
#[no_mangle]
pub extern "C" fn chat_xdk_abi_version() -> u32 {
    CHAT_XDK_ABI_VERSION
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

fn ok_bool(value: bool) -> FfiResult {
    ok_data(if value { "true" } else { "false" })
}

fn error_result(document: String) -> FfiResult {
    FfiResult {
        data: std::ptr::null_mut(),
        error: to_c_string(&document),
    }
}

/// An error of the given kind that arises in this layer rather than in the
/// core, such as a NULL handle or a params document that doesn't parse.
fn kind_error(kind: ErrorKind, msg: &str) -> FfiResult {
    error_result(serde_json::json!({ "kind": kind.as_str(), "message": msg }).to_string())
}

/// An invalid argument passed across the boundary.
fn err_result(msg: &str) -> FfiResult {
    kind_error(ErrorKind::InvalidInput, msg)
}

/// A result that failed to serialize.
fn internal_error(e: impl std::fmt::Display) -> FfiResult {
    kind_error(ErrorKind::Internal, &e.to_string())
}

fn err_from(e: impl Into<SdkError>) -> FfiResult {
    error_result(bindings::error_document(&e.into()))
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
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or_else(|p| {
        kind_error(
            ErrorKind::Internal,
            &format!("Internal panic: {}", panic_message(p.as_ref())),
        )
    })
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

/// Return the exact size of a file once encrypted: the size its upload
/// declares before the file is encrypted.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypted_file_size(plaintext_size: u64) -> FfiResult {
    catch_ffi(
        || match chat_xdk_core::utils::encrypted_file_size(plaintext_size) {
            Some(size) => ok_data(&size.to_string()),
            None => err_result("Encrypted file size overflow"),
        },
    )
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

/// Create a new Chat SDK instance and write its handle to `out_chat`.
///
/// `juicebox_config_json` is the Juicebox configuration JSON the X API
/// returns, which `chat_xdk_setup`, `chat_xdk_unlock`,
/// `chat_xdk_change_pin` and `chat_xdk_delete` use; NULL or an empty string
/// for a chat that manages its keys with `chat_xdk_import_keys` alone. On
/// failure `out_chat` is set to NULL. Free the handle with [`chat_xdk_free`].
#[no_mangle]
pub extern "C" fn chat_xdk_new(
    juicebox_config_json: *const c_char,
    out_chat: *mut *mut ChatHandle,
) -> FfiResult {
    catch_ffi(|| {
        if out_chat.is_null() {
            return err_result("Null out_chat");
        }
        unsafe { *out_chat = std::ptr::null_mut() };
        let config_json = try_str!(juicebox_config_json);
        #[cfg(feature = "juicebox")]
        let handle = {
            let config = if config_json.is_empty() {
                JuiceboxConfig::from_json("{}".to_string())
            } else {
                match parse_juicebox_config(config_json) {
                    Ok(c) => c,
                    Err(e) => return e,
                }
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => return internal_error(e),
            };
            let inner = chat_xdk_core::Chat::with_juicebox(config, Arc::new(JuiceboxClient::new()));
            ChatHandle { inner, runtime }
        };
        #[cfg(not(feature = "juicebox"))]
        let handle = {
            if !config_json.is_empty() {
                return err_result(
                    "this library is built without Juicebox: pass no Juicebox config",
                );
            }
            ChatHandle {
                inner: chat_xdk_core::ChatCore::new(),
            }
        };
        unsafe { *out_chat = Box::into_raw(Box::new(handle)) };
        ok_void()
    })
}

/// Replace the Juicebox configuration (e.g., to refresh auth tokens).
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_update_config(
    handle: *const ChatHandle,
    config_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let config = match parse_juicebox_config(try_str!(config_json)) {
            Ok(c) => c,
            Err(e) => return e,
        };
        h.inner.update_config(config);
        ok_void()
    })
}

/// Register the loaded keys with Juicebox under `pin` (first-time setup) and
/// return the public keys as JSON. `pin` / `pin_len` are the PIN's bytes,
/// which the caller can wipe once the call returns.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_setup(
    handle: *const ChatHandle,
    pin: *const u8,
    pin_len: usize,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let pin = unsafe { bytes_from_ffi_ptr(pin, pin_len) };
        match h.runtime.block_on(h.inner.setup(pin)) {
            Ok(keys) => match serde_json::to_string(&keys) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Recover the keys from Juicebox with `pin` and load them. `pin` /
/// `pin_len` are the PIN's bytes, which the caller can wipe once the call
/// returns.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_unlock(
    handle: *const ChatHandle,
    pin: *const u8,
    pin_len: usize,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let pin = unsafe { bytes_from_ffi_ptr(pin, pin_len) };
        match h.runtime.block_on(h.inner.unlock(pin)) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Delete keys from Juicebox and clear from memory.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_delete(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.runtime.block_on(h.inner.delete()) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Re-register the keys in Juicebox under a new PIN, after unlocking with
/// the old one. Both PINs are bytes the caller can wipe once the call
/// returns.
#[cfg(feature = "juicebox")]
#[no_mangle]
pub extern "C" fn chat_xdk_change_pin(
    handle: *const ChatHandle,
    old_pin: *const u8,
    old_pin_len: usize,
    new_pin: *const u8,
    new_pin_len: usize,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let old_pin = unsafe { bytes_from_ffi_ptr(old_pin, old_pin_len) };
        let new_pin = unsafe { bytes_from_ffi_ptr(new_pin, new_pin_len) };
        match h.runtime.block_on(h.inner.change_pin(old_pin, new_pin)) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

#[cfg(feature = "juicebox")]
fn parse_juicebox_config(config_json: &str) -> Result<JuiceboxConfig, FfiResult> {
    JuiceboxConfig::from_x_api_json(config_json)
        .map_err(|e| err_result(&format!("Invalid Juicebox config: {e}")))
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

/// Whether both the identity and the signing key are loaded: `true` or
/// `false`.
#[no_mangle]
pub extern "C" fn chat_xdk_is_unlocked(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        ok_bool(unsafe { &*handle }.inner.is_unlocked())
    })
}

/// Whether the identity key is loaded (sufficient for decryption): `true`
/// or `false`.
#[no_mangle]
pub extern "C" fn chat_xdk_has_identity_key(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        ok_bool(unsafe { &*handle }.inner.has_identity_key())
    })
}

/// Enable (non-zero) or disable (0) rejection of unverified events.
///
/// When enabled — the default — `chat_xdk_decrypt_event` returns an error for
/// any signed event whose signature cannot be verified (invalid, missing, or
/// no matching signing key) instead of returning it with `verified: false`.
#[no_mangle]
pub extern "C" fn chat_xdk_set_reject_unverified(
    handle: *const ChatHandle,
    reject: i32,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        unsafe { &*handle }.inner.set_reject_unverified(reject != 0);
        ok_void()
    })
}

/// Set the session identity from a params JSON document:
/// `{"user_id": "...", "signing_key_version": "..."}`. They become the
/// defaults wherever a params document omits `sender_id` /
/// `signing_key_version`.
#[no_mangle]
pub extern "C" fn chat_xdk_set_identity(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiSetIdentityParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match h
            .inner
            .set_identity(&SetIdentityParams::new(p.user_id, p.signing_key_version))
        {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
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
pub extern "C" fn chat_xdk_set_cache_keys(handle: *const ChatHandle, enabled: i32) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        unsafe { &*handle }.inner.set_cache_keys(enabled != 0);
        ok_void()
    })
}

/// Internal, for this repository's bindings; not part of the API.
///
/// Start this chat's one read of the feature switches. Returns in `data` the
/// GET to perform, as JSON: `{"id": …, "url": "…", "timeout_ms": …,
/// "max_bytes": …}`. Both fields are NULL when the chat takes the answer of a
/// GET already in flight, or has started its read already.
#[no_mangle]
pub extern "C" fn chat_xdk_internal_feature_start(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        match unsafe { &*handle }.inner.start_features() {
            Some(fetch) => match serde_json::to_string(&fetch) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            None => ok_void(),
        }
    })
}

/// Internal, for this repository's bindings; not part of the API.
///
/// Report the result of the feature-switch GET `id`: its HTTP status, 0 when
/// no response arrived, and `body_len` bytes of its body, read to the end or
/// to one byte past the GET's `max_bytes`. `body` may be NULL when
/// `body_len` is 0.
#[no_mangle]
pub extern "C" fn chat_xdk_internal_feature_complete(
    id: u64,
    status: i32,
    body: *const u8,
    body_len: usize,
) {
    catch_ffi_or((), || {
        let body = if body.is_null() || body_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(body, body_len) }
        };
        bindings::complete_fetch(id, u16::try_from(status).unwrap_or(0), body);
    })
}

/// Internal, for this repository's tests; not part of the API.
///
/// Read this chat's feature switches from `endpoint`, within `timeout_ms`
/// milliseconds, when its read starts.
#[no_mangle]
pub extern "C" fn chat_xdk_internal_feature_configure(
    handle: *const ChatHandle,
    endpoint: *const c_char,
    timeout_ms: u64,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let endpoint = try_str!(endpoint);
        unsafe { &*handle }
            .inner
            .configure_features(endpoint, timeout_ms);
        ok_void()
    })
}

/// Internal, for this repository's tests; not part of the API.
///
/// The feature-switch endpoint of every chat that does not set its own;
/// NULL for the X API's.
#[no_mangle]
pub extern "C" fn chat_xdk_internal_feature_set_default_endpoint(
    endpoint: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if endpoint.is_null() {
            bindings::set_default_endpoint(None);
        } else {
            bindings::set_default_endpoint(Some(try_str!(endpoint)));
        }
        ok_void()
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
        h.inner.set_signing_keys(&signing_keys);
        ok_void()
    })
}

/// Lock the SDK, clearing keys from memory.
#[no_mangle]
pub extern "C" fn chat_xdk_lock(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        unsafe { &*handle }.inner.lock();
        ok_void()
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
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Get the user's public keys as JSON.
///
/// Returns JSON `{"identity":"...","signing":"..."}`.
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
                Err(e) => internal_error(e),
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

/// Export the loaded private keys as a base64 string: 32 bytes for the
/// identity key, 64 with the signing key. Errors when no identity key is
/// loaded.
#[no_mangle]
pub extern "C" fn chat_xdk_export_keys(handle: *const ChatHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
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

/// Import private keys: `keys` / `keys_len` is the blob
/// `chat_xdk_export_keys` returns (32 bytes for the identity key, 64 with the
/// signing key), and `params_json` is `{}` or
/// `{"signing_key_version": "..."}` to record the `public_key_version` the
/// keys were registered under. The key bytes stay out of the JSON so they are
/// never copied into a string; NULL with length 0 is an empty blob.
#[no_mangle]
pub extern "C" fn chat_xdk_import_keys(
    handle: *const ChatHandle,
    keys: *const u8,
    keys_len: usize,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiImportKeysParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let key_bytes = unsafe { bytes_from_ffi_ptr(keys, keys_len) };
        let mut params = ImportKeysParams::new(key_bytes);
        params.signing_key_version = p.signing_key_version.filter(|v| !v.is_empty());
        match h.inner.import_keys(&params) {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

mod conversation;
mod encrypt;
mod events;
mod files;
mod params;
mod prepare;
mod signing;

use conversation::*;
use encrypt::*;
use events::*;
use params::*;
