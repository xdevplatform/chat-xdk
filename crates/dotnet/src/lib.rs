//! C FFI layer for .NET (C#) bindings via csbindgen.
//!
//! All `*mut c_char` strings returned by this module must be freed with
//! `chat_xdk_free_string`. The opaque `ChatHandle` must be freed with
//! `chat_xdk_free`. Passing NULL to any function that accepts a handle is
//! always safe (no-op or -1/error result).
//!
//! The FFI surface passes all complex types across the boundary as JSON
//! strings, keeping the C interface minimal.
//! csbindgen reads this file and generates the matching C# P/Invoke layer.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use chat_xdk_core::bindings::{self, FeatureSwitches};
use chat_xdk_core::crypto::keys::XChatConversationKey;
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

// FFI result type

/// Result returned by every fallible FFI function.
///
/// Exactly one of `data` / `error` is non-NULL on return.
/// The non-NULL field **must** be freed with `chat_xdk_free_string`.
/// If both are NULL the operation succeeded with no output (void).
#[repr(C)]
pub struct FfiResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

// Opaque handle

/// Opaque handle to a live Chat SDK session.
///
/// Allocated by `chat_xdk_new`, released by `chat_xdk_free`.
/// All methods require a non-NULL handle; passing NULL returns an error result
/// or -1 / no-op, depending on the function's return type.
pub struct ChatHandle {
    inner: chat_xdk_core::Chat,
    runtime: tokio::runtime::Runtime,
}

// ChatHandle crosses the FFI as a raw pointer, so nothing on the managed
// side enforces exclusive access. The handle is NOT safe for unsynchronized
// concurrent use: mutating operations (setup, unlock, delete, change_pin,
// update_config, set_reject_unverified, set_identity) take `&mut` through
// the pointer and must not race decrypt or any other call. Callers must
// serialize access externally. No `Send`/`Sync` impl is asserted here —
// nothing in this crate moves the handle across threads.

// Internal helpers

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
///
/// Safety: `s` must be a valid null-terminated C string or NULL.
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
    let mut src = e.source();
    while let Some(err) = src {
        msg.push_str("\ncaused by: ");
        msg.push_str(&err.to_string());
        src = err.source();
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
/// `null`, an empty string, or `[]` yields an empty list — under the default
/// reject-unverified policy signed events then fail decryption; they are
/// returned with `verified: false` only after reject-unverified is disabled.
/// A non-empty but malformed array is a caller error and is surfaced rather
/// than silently dropped (which would weaken verification).
fn parse_signing_keys(json: &str) -> Result<Vec<SigningKeyEntry>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("Invalid signing keys JSON: {}", e))
}

/// Parse the Juicebox config JSON accepted by the X API into our internal type.
fn parse_juicebox_config(config_json: &str) -> Result<JuiceboxConfig, String> {
    JuiceboxConfig::from_x_api_json(config_json)
}

/// Decode an optional base64 conversation-key override for the params
/// structs, which take the raw bytes and zeroize them on drop. Absent, null,
/// or empty means "not passed" and decodes to `None` (core then resolves the
/// key from the opt-in cache). The key length is validated in core so every
/// binding reports the same error.
fn decode_opt_ckey_bytes(ckey_b64: Option<&str>) -> Result<Option<Vec<u8>>, FfiResult> {
    match ckey_b64.filter(|s| !s.is_empty()) {
        Some(b64) => BASE64
            .decode(b64)
            .map(Some)
            .map_err(|e| err_result(&format!("Invalid conversation key base64: {}", e))),
        None => Ok(None),
    }
}

// FFI params mirrors — one JSON document per method, snake_case keys matching
// the core param structs. Consolidating every argument into a single JSON
// document keeps the C ABI stable: a future optional field is an additive
// JSON key, not a new C argument. An absent or null key deserializes to
// `None`; identity fields (`sender_id`, `signing_key_version`) and key fields
// (`conversation_key`, `conversation_key_version`) are optional overrides that
// resolve from the session identity / key cache when unset (core also treats
// an empty string as unset). `conversation_key` crosses the boundary as
// base64. Entities are `[start, end, "type"]` tuples; attachment objects use
// the wire-format keys of `AttachmentDescriptor` and are parsed strictly (a
// missing required media field is an error — see `parse_attachments`).

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
    #[serde(default)]
    entities: Option<Vec<(i32, i32, String)>>,
    #[serde(default)]
    attachments: Option<serde_json::Value>,
    #[serde(default)]
    quick_reply: Option<serde_json::Value>,
    #[serde(default)]
    should_notify: Option<bool>,
    #[serde(default)]
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
    #[serde(default)]
    reply_to_sender_id: Option<String>,
    #[serde(default)]
    reply_to_text: Option<String>,
    #[serde(default)]
    entities: Option<Vec<(i32, i32, String)>>,
    #[serde(default)]
    attachments: Option<serde_json::Value>,
    #[serde(default)]
    quick_reply: Option<serde_json::Value>,
    #[serde(default)]
    reply_to_entities: Option<Vec<(i32, i32, String)>>,
    #[serde(default)]
    reply_to_attachments: Option<serde_json::Value>,
    #[serde(default)]
    should_notify: Option<bool>,
    #[serde(default)]
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
struct FfiEncryptEditParams {
    updated_text: String,
    #[serde(default)]
    target_event: Option<String>,
    #[serde(default)]
    entities: Option<Vec<(i32, i32, String)>>,
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
struct FfiMessageDeleteParams {
    conversation_id: String,
    sequence_ids: Vec<String>,
    delete_for_all: bool,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupMembersRemoveParams {
    conversation_id: String,
    user_ids: Vec<String>,
    #[serde(default)]
    public_keys: Option<Vec<PublicKeyInput>>,
    #[serde(default)]
    conversation_key_version: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupLeaveParams {
    conversation_id: String,
    #[serde(default)]
    promote_admin_id: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupTitleChangeParams {
    conversation_id: String,
    conversation_key_version: String,
    custom_title: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupAvatarChangeParams {
    conversation_id: String,
    conversation_key_version: String,
    custom_avatar_url: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupDescriptionChangeParams {
    conversation_id: String,
    conversation_key_version: String,
    custom_description: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupAdminsAddParams {
    conversation_id: String,
    user_ids: Vec<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupAdminsRemoveParams {
    conversation_id: String,
    user_ids: Vec<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupInviteEnableParams {
    conversation_id: String,
    invite_url: String,
    #[serde(default)]
    expires_at_msec: Option<i64>,
    #[serde(default)]
    affiliate_id: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupInviteDisableParams {
    conversation_id: String,
    #[serde(default)]
    disabled_by: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupJoinRequestParams {
    conversation_id: String,
    #[serde(default)]
    requesting_user_id: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiGroupJoinRejectParams {
    conversation_id: String,
    user_ids: Vec<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiMessageTtlChangeParams {
    conversation_id: String,
    ttl_msec: i64,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiMessageTtlRemoveParams {
    conversation_id: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiScreenCaptureParams {
    conversation_id: String,
    change: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiMarkConversationReadParams {
    conversation_id: String,
    seen_until_sequence_id: String,
    #[serde(default)]
    seen_at_msec: Option<i64>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiConversationKeyChangeParams {
    public_keys: Vec<PublicKeyInput>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    signing_key_version: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    current_title: Option<String>,
    #[serde(default)]
    current_avatar_url: Option<String>,
    #[serde(default)]
    current_ttl_msec: Option<i64>,
    #[serde(default)]
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
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    ttl_msec: Option<i64>,
}

// The receive and file params carry `conversation_keys` as
// `{"version": "base64 raw 32-byte key"}` and byte fields as base64.

#[derive(serde::Deserialize)]
struct FfiSetIdentityParams {
    user_id: String,
    signing_key_version: String,
}

#[derive(serde::Deserialize)]
struct FfiImportKeysParams {
    #[serde(default)]
    signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiDecryptEventParams {
    event_b64: String,
    #[serde(default)]
    conversation_keys: HashMap<String, String>,
    #[serde(default)]
    signing_keys: Option<Vec<SigningKeyEntry>>,
}

#[derive(serde::Deserialize)]
struct FfiDecryptEventsParams {
    events: Vec<String>,
    #[serde(default)]
    signing_keys: Option<Vec<SigningKeyEntry>>,
}

#[derive(serde::Deserialize)]
struct FfiEncryptFileParams {
    file: String,
    event_b64: String,
    media_hash_key: String,
    #[serde(default)]
    conversation_key: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiFileEncryptorParams {
    event_b64: String,
    media_hash_key: String,
    #[serde(default)]
    conversation_key: Option<String>,
    #[serde(default)]
    conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
struct FfiDecryptFileParams {
    encrypted: String,
    event_b64: String,
    conversation_keys: HashMap<String, String>,
    media_hash_key: String,
}

/// The params of the file encryptor and decryptor.
#[derive(serde::Deserialize)]
struct FfiFileParams {
    event_b64: String,
    conversation_keys: HashMap<String, String>,
    media_hash_key: String,
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

/// Parse attachment descriptors from a JSON array via the core serde types,
/// so the field requirements are defined once in core: an attachment missing
/// a required media field is rejected rather than silently defaulted.
fn parse_attachments(value: serde_json::Value) -> Result<Vec<AttachmentDescriptor>, FfiResult> {
    serde_json::from_value(value).map_err(|e| err_result(&format!("Invalid attachments: {}", e)))
}

/// Parse a quick reply via the core serde type; the JSON shape is the
/// `quick_reply` of decrypted text content.
fn parse_quick_reply(value: serde_json::Value) -> Result<QuickReply, FfiResult> {
    serde_json::from_value(value).map_err(|e| err_result(&format!("Invalid quick reply: {}", e)))
}

// Lifecycle

/// Create a new Chat SDK instance.
///
/// Returns an opaque handle that must be freed with `chat_xdk_free`.
/// Returns NULL on allocation failure.
#[no_mangle]
pub extern "C" fn chat_xdk_new() -> *mut ChatHandle {
    catch_ffi_or(std::ptr::null_mut(), || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return std::ptr::null_mut(),
        };
        let config = JuiceboxConfig::from_json("{}".to_string());
        let inner = chat_xdk_core::Chat::with_juicebox(config, Arc::new(JuiceboxClient::new()));
        Box::into_raw(Box::new(ChatHandle { inner, runtime }))
    })
}

/// Free a Chat SDK handle.
///
/// After this call the handle is invalid. Passing NULL is a no-op.
#[no_mangle]
pub extern "C" fn chat_xdk_free(handle: *mut ChatHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) }
        }
    })
}

/// Free a string returned by any `chat_xdk_*` function.
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

// State queries

/// Returns 1 if both identity and signing keys are loaded, 0 if locked, -1 on null handle.
#[no_mangle]
pub extern "C" fn chat_xdk_is_unlocked(handle: *const ChatHandle) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        if unsafe { &*handle }.inner.is_unlocked() {
            1
        } else {
            0
        }
    })
}

/// Returns 1 if the identity key is loaded (sufficient for decryption), 0 if not, -1 on null handle.
#[no_mangle]
pub extern "C" fn chat_xdk_has_identity_key(handle: *const ChatHandle) -> i32 {
    catch_ffi_or(-1, || {
        if handle.is_null() {
            return -1;
        }
        if unsafe { &*handle }.inner.has_identity_key() {
            1
        } else {
            0
        }
    })
}

/// When `reject` is non-zero — the default — `chat_xdk_decrypt_event_params` returns
/// an error for any signed event whose signature cannot be verified (invalid,
/// missing, or no matching signing key) instead of returning it with
/// `verified: false`.
#[no_mangle]
pub extern "C" fn chat_xdk_set_reject_unverified(handle: *mut ChatHandle, reject: i32) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        unsafe { &mut *handle }
            .inner
            .set_reject_unverified(reject != 0);
    })
}

/// Set the session identity from a params JSON document:
/// `{"user_id": "...", "signing_key_version": "..."}`. They become the
/// defaults wherever a params document omits `sender_id` /
/// `signing_key_version`.
#[no_mangle]
pub extern "C" fn chat_xdk_set_identity_params(
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

/// Enable (non-zero) or disable (zero) the conversation-key cache (off by
/// default). While enabled, `chat_xdk_decrypt_events_params` caches, per
/// conversation, the key whose key change carried a valid signature at the
/// highest version seen, and the encrypt entry points resolve an omitted
/// `conversation_key`/`conversation_key_version` pair from it. Disabling
/// clears the cache.
#[no_mangle]
pub extern "C" fn chat_xdk_set_cache_keys(handle: *const ChatHandle, enabled: i32) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        unsafe { &*handle }.inner.set_cache_keys(enabled != 0);
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
                Err(e) => err_from(e),
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

/// Store signing keys to use when a decrypt call passes an empty
/// `signing_keys_json`. Only this explicit call populates the store — a key
/// carried inside an event is never trusted for verification. Each call
/// replaces the previous set.
///
/// `signing_keys_json`: same array shape as `chat_xdk_decrypt_events_params`.
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
            Ok(k) => k,
            Err(e) => return err_result(&e),
        };
        h.inner.set_signing_keys(signing_keys);
        ok_void()
    })
}

/// Lock the SDK, clearing all key material from memory.
#[no_mangle]
pub extern "C" fn chat_xdk_lock(handle: *const ChatHandle) {
    catch_ffi_or((), || {
        if handle.is_null() {
            return;
        }
        unsafe { &*handle }.inner.lock();
    })
}

// Juicebox lifecycle

/// Update the Juicebox configuration (e.g. to refresh short-lived auth tokens).
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
        match parse_juicebox_config(config_json) {
            Ok(config) => {
                h.inner.update_config(config);
                ok_void()
            }
            Err(e) => err_result(&e),
        }
    })
}

/// Register the SDK's keys with Juicebox (first-time setup).
///
/// `config_json` is the Juicebox configuration from the X API.
/// Returns JSON `{"identity":"...","signing":"...","version":"..."}` on success.
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
        match parse_juicebox_config(config_json) {
            Ok(config) => h.inner.update_config(config),
            Err(e) => return err_result(&e),
        }
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

/// Recover keys from Juicebox and unlock the SDK.
///
/// `config_json` is the Juicebox configuration from the X API.
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
        match parse_juicebox_config(config_json) {
            Ok(config) => h.inner.update_config(config),
            Err(e) => return err_result(&e),
        }
        match h
            .runtime
            .block_on(async { h.inner.unlock(pin.as_bytes()).await })
        {
            Ok(()) => ok_void(),
            Err(e) => err_from(e),
        }
    })
}

/// Delete keys from Juicebox and lock the SDK.
///
/// Warning: Irreversible — the user will lose access to their encrypted history.
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

/// Re-register keys under a new PIN.
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

// Key management

/// Generate new identity + signing keypairs.
///
/// Returns JSON matching `PublicKeyRegistrationPayload` for the X API.
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

/// Get the user's current public keys.
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
/// Returns a URL-safe base64 string (SHA-256 of the SPKI-encoded key) for
/// out-of-band verification.
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

/// Export private key material as a base64 string for secure backup.
///
/// Returns empty data (NULL `data` field) if no identity key is loaded.
/// Warning: Handle the result with extreme care — this is raw secret key material.
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

/// Import private keys: `keys` / `keys_len` is the blob
/// `chat_xdk_export_keys` returns (32 bytes for the identity key, 64 with the
/// signing key), and `params_json` is `{}` or
/// `{"signing_key_version": "..."}` to record the `public_key_version` the
/// keys were registered under. The key bytes stay out of the JSON so they are
/// never copied into a string; NULL with length 0 is an empty blob.
#[no_mangle]
pub extern "C" fn chat_xdk_import_keys_params(
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

/// Extract and decrypt conversation keys from raw KeyChange event strings.
///
/// `events_json` — JSON array of base64-encoded raw event strings from the webhook.
///
/// Returns JSON `{"keys":{"version":"base64_bytes",...},"latest_version":"..."|null}`.
/// Pass `keys` serialized as a flat map `{"version":"base64_bytes",...}` to `chat_xdk_decrypt_event_params`.
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

/// Batch decrypt.
///
/// `params_json` — single JSON document: `events` (the base64 events) plus
/// optional `signing_keys` (`[{"user_id","public_key_version","public_key",
/// "identity_public_key","identity_public_key_signature"},...]`); absent or
/// empty falls back to the keys stored via `chat_xdk_set_signing_keys`.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_events_params(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiDecryptEventsParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = DecryptEventsParams::new(p.events);
        params.signing_keys = p.signing_keys;
        let result = h.inner.decrypt_events(params);

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
        "conversation_participant_keys".into(),
        serde_json::to_value(&res.conversation_participant_keys)?,
    );
    out.insert(
        "action_signatures".into(),
        serde_json::to_value(&res.action_signatures)?,
    );
    serde_json::to_string(&serde_json::Value::Object(out))
}

/// Prepare a signed conversation-key change.
///
/// `params_json` — single JSON document: `public_keys`
/// (`[{"user_id","public_key","key_version"},...]`), plus optional
/// `sender_id` / `signing_key_version` (absent resolves from the session
/// identity set via `chat_xdk_set_identity_params`) and optional `conversation_id`
/// (absent or empty derives the one-to-one id).
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

        match h.inner.prepare_conversation_key_change(&params) {
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
/// `sender_id` / `signing_key_version` (absent resolves from the session
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

        match h.inner.prepare_group_members_change(&params) {
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
/// `signing_key_version` (absent resolves from the session identity),
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

        match h.inner.prepare_group_create(&params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Build the signed action for deleting messages from a conversation.
///
/// `params_json` — single JSON document: `conversation_id`, `sequence_ids`
/// (the messages to delete), `delete_for_all` (every participant vs only the
/// caller's view), plus optional `sender_id` / `signing_key_version` (absent
/// resolves from the session identity).
///
/// Returns JSON `PreparedAction`: `action_signatures`, one entry with its
/// signature nested under `message_event_signature`. The SDK-generated
/// `message_id` is a field on the entry.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_delete(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageDeleteParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            MessageDeleteParams::new(p.conversation_id, p.sequence_ids, p.delete_for_all);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;

        match h.inner.prepare_message_delete(&params) {
            Ok(prepared) => match serde_json::to_string(&prepared) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

fn ffi_prepared_action(
    prepared: Result<chat_xdk_core::PreparedAction, chat_xdk_core::error::SdkError>,
) -> FfiResult {
    match prepared {
        Ok(prepared) => match serde_json::to_string(&prepared) {
            Ok(json) => ok_data(&json),
            Err(e) => err_result(&e.to_string()),
        },
        Err(e) => err_from(e),
    }
}

fn ffi_prepared_change(
    prepared: Result<chat_xdk_core::PreparedConversationChange, chat_xdk_core::error::SdkError>,
) -> FfiResult {
    match prepared {
        Ok(res) => match json_prepared_change(&res) {
            Ok(s) => ok_data(&s),
            Err(e) => err_result(&e.to_string()),
        },
        Err(e) => err_from(e),
    }
}

/// Sign a group member removal.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `public_keys`
/// (the members who stay; set them to rotate the conversation key),
/// `conversation_key_version` (bound into a removal that does not rotate;
/// absent signs `null`), and `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedConversationChange`. With `public_keys`,
/// `action_signatures` is the removal and then the key change, and
/// `conversation_key` is the new raw key base64. Without them,
/// `conversation_key` is absent and `action_signatures` is the removal only.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_members_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupMembersRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupMembersRemoveParams::new(p.conversation_id, p.user_ids);
        params.public_keys = p.public_keys;
        params.conversation_key_version = p.conversation_key_version;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_change(h.inner.prepare_group_members_remove(&params))
    })
}

/// Sign leaving a group.
///
/// `params_json` — `conversation_id`, plus optional `promote_admin_id`,
/// `conversation_key_version` (absent signs `null` on the removal), and
/// `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`: the removal of the sender, an admin add
/// when `promote_admin_id` is set, and a conversation delete. Leave does not
/// rotate the conversation key.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_leave(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupLeaveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupLeaveParams::new(p.conversation_id);
        params.promote_admin_id = p.promote_admin_id;
        params.conversation_key_version = p.conversation_key_version;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_leave(&params))
    })
}

/// Sign a group title change.
///
/// `params_json` — `conversation_id`, `conversation_key_version`,
/// `custom_title` (the ciphertext the request sends), plus optional
/// `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`, shaped as `chat_xdk_prepare_message_delete`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_title_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupTitleChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupTitleChangeParams::new(
            p.conversation_id,
            p.conversation_key_version,
            p.custom_title,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_title_change(&params))
    })
}

/// Sign a group avatar change.
///
/// `params_json` — `conversation_id`, `conversation_key_version`,
/// `custom_avatar_url`, plus optional `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`, shaped as `chat_xdk_prepare_message_delete`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_avatar_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAvatarChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAvatarChangeParams::new(
            p.conversation_id,
            p.conversation_key_version,
            p.custom_avatar_url,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_avatar_change(&params))
    })
}

/// Sign a group description change.
///
/// `params_json` — `conversation_id`, `conversation_key_version`,
/// `custom_description` (the ciphertext the request sends), plus optional
/// `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`, shaped as `chat_xdk_prepare_message_delete`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_description_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupDescriptionChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupDescriptionChangeParams::new(
            p.conversation_id,
            p.conversation_key_version,
            p.custom_description,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_description_change(&params))
    })
}

/// Sign adding group admins.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_admins_add(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAdminsAddParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAdminsAddParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_admins_add(&params))
    })
}

/// Sign removing group admins.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_admins_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAdminsRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAdminsRemoveParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_admins_remove(&params))
    })
}

/// Sign enabling a group invite.
///
/// `params_json` — `conversation_id`, `invite_url`, plus optional
/// `expires_at_msec` and `affiliate_id` (absent or a negative expiry signs
/// `null`) and `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_invite_enable(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupInviteEnableParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupInviteEnableParams::new(p.conversation_id, p.invite_url);
        params.expires_at_msec = p.expires_at_msec;
        params.affiliate_id = p.affiliate_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_invite_enable(&params))
    })
}

/// Sign disabling a group invite.
///
/// `params_json` — `conversation_id`, plus optional `disabled_by` (the sender
/// when absent) and `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_invite_disable(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupInviteDisableParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupInviteDisableParams::new(p.conversation_id);
        params.disabled_by = p.disabled_by;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_invite_disable(&params))
    })
}

/// Sign a request to join a group.
///
/// `params_json` — `conversation_id`, plus optional `requesting_user_id` (the
/// sender when absent) and `sender_id` / `signing_key_version`. An invite
/// token is not part of the signature.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_join_request(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupJoinRequestParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupJoinRequestParams::new(p.conversation_id);
        params.requesting_user_id = p.requesting_user_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_join_request(&params))
    })
}

/// Sign rejecting group join requests.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_join_reject(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupJoinRejectParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupJoinRejectParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_join_reject(&params))
    })
}

/// Sign a message-TTL change.
///
/// `params_json` — `conversation_id`, `ttl_msec`, plus optional `sender_id` /
/// `signing_key_version`. The signature covers `ttl_msec` only.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_ttl_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageTtlChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = MessageTtlChangeParams::new(p.conversation_id, p.ttl_msec);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_message_ttl_change(&params))
    })
}

/// Sign clearing a conversation's message TTL.
///
/// `params_json` — `conversation_id`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_ttl_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageTtlRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = MessageTtlRemoveParams::new(p.conversation_id);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_message_ttl_remove(&params))
    })
}

/// Sign one screen-capture setting change.
///
/// `params_json` — `conversation_id`, `change` (`BlockingEnabled`,
/// `BlockingDisabled`, `DetectionEnabled`, or `DetectionDisabled`; camelCase
/// spellings are accepted), plus optional `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_screen_capture(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiScreenCaptureParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let change = match ScreenCaptureChange::parse(&p.change) {
            Ok(change) => change,
            Err(e) => return err_from(e),
        };
        let mut params = ScreenCaptureParams::new(p.conversation_id, change);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_screen_capture(&params))
    })
}

/// Build the signed action for marking a conversation read.
///
/// `params_json` — single JSON document: `conversation_id`,
/// `seen_until_sequence_id` (the sequence id of the newest event read), plus
/// optional `seen_at_msec` (when it was read, in milliseconds since the Unix
/// epoch; absent takes the current time) and `sender_id` /
/// `signing_key_version` (absent resolves from the session identity).
///
/// Returns JSON `PreparedAction`, shaped as `chat_xdk_prepare_message_delete`
/// returns it: the mark-read request's `action_signatures`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_mark_conversation_read(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMarkConversationReadParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            MarkConversationReadParams::new(p.conversation_id, p.seen_until_sequence_id);
        params.seen_at_msec = p.seen_at_msec;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;

        match h.inner.prepare_mark_conversation_read(&params) {
            Ok(prepared) => match serde_json::to_string(&prepared) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt a webhook event.
///
/// `params_json` — single JSON document: `event_b64` (the base64 event),
/// `conversation_keys` (`{"version": "base64 raw 32-byte key", ...}`, from
/// `chat_xdk_decrypt_events_params` or `chat_xdk_extract_conversation_keys`; `{}`
/// for events without message contents, which also falls back to the opt-in
/// key cache), plus optional `signing_keys` (as for
/// `chat_xdk_decrypt_events_params`). With no signing keys passed or stored, signed
/// events fail decryption under the default reject-unverified policy
/// (disable it via `chat_xdk_set_reject_unverified` to have them returned
/// with `verified: false` instead).
///
/// Returns JSON representation of the decrypted Event.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_event_params(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiDecryptEventParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let conversation_keys = match conversation_keys_from_b64(p.conversation_keys) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut params = DecryptEventParams::new(p.event_b64, conversation_keys);
        params.signing_keys = p.signing_keys;

        match h.inner.decrypt_event(params) {
            Ok(event) => match serde_json::to_string(&event) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

// Message encryption

/// Encrypt a message for the X API.
///
/// `params_json` — single JSON document: `conversation_id` and `text`, plus
/// optional overrides `sender_id` / `signing_key_version` (absent resolves
/// from the session identity) and `conversation_key` (base64 raw 32-byte
/// key) / `conversation_key_version` (absent resolves from the opt-in key
/// cache), plus optional `entities` (`[[start,end,"type"],...]`),
/// `attachments` (`[{"attachment_type",...},...]`), `quick_reply` (the
/// `quick_reply` shape of decrypted text content), `should_notify`, and
/// `ttl_msec`.
///
/// Returns JSON `SendPayload`, whose `message_id` is the message's id. A v1
/// message with files takes an id derived from its files, so building it
/// again gives the same id; other messages take a random id. Encrypt each
/// file afterwards with `chat_xdk_encrypt_file` or a file encryptor and the
/// payload's `event_b64`.
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
        let ckey_bytes = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let attachments = match p.attachments.take().map(parse_attachments).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };
        let quick_reply = match p.quick_reply.take().map(parse_quick_reply).transpose() {
            Ok(q) => q,
            Err(e) => return e,
        };

        let mut params = EncryptMessageParams::new(p.conversation_id, p.text);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;
        params.entities = p.entities.map(entity_tuples_to_descs);
        params.attachments = attachments;
        params.quick_reply = quick_reply;
        params.should_notify = p.should_notify;
        params.ttl_msec = p.ttl_msec;

        match h.inner.encrypt_message(&params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Encrypt a reply message for the X API.
///
/// `params_json` — same document as `chat_xdk_encrypt_message` plus
/// `reply_to_event` (base64 raw signed event being replied to; the reply
/// preview is derived from it) with optional `reply_to_edit_event` and
/// `reply_to_ckces` (base64 raw key-change events needed to decrypt the
/// original under an older key version). The explicit-preview overrides
/// `reply_to_sequence_id`, `reply_to_sender_id`, `reply_to_text`,
/// `reply_to_entities`, and `reply_to_attachments` remain for callers that no
/// longer hold the raw event.
///
/// Returns JSON `SendPayload`, whose `message_id` is the reply's id; its id
/// and files work as for `chat_xdk_encrypt_message`.
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
        let ckey_bytes = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let attachments = match p.attachments.take().map(parse_attachments).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };
        let quick_reply = match p.quick_reply.take().map(parse_quick_reply).transpose() {
            Ok(q) => q,
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
        params.quick_reply = quick_reply;
        params.should_notify = p.should_notify;
        params.ttl_msec = p.ttl_msec;

        match h.inner.encrypt_reply(&params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Encrypt a reaction-add for the X API.
///
/// `params_json` — single JSON document: `emoji` and `target_event` (base64
/// raw event being reacted to; the conversation id and target sequence id are
/// derived from it), plus optional explicit overrides `conversation_id` /
/// `target_message_sequence_id` for callers that no longer hold the raw
/// event, and the optional identity/key overrides described on
/// `chat_xdk_encrypt_message`.
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
    let ckey_bytes = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
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

/// Encrypt a message edit for the X API.
///
/// `params_json` — single JSON document: `updated_text` and `target_event`
/// (base64 raw event being edited; the conversation id and target sequence
/// id are derived from it), plus optional explicit overrides
/// `conversation_id` / `target_message_sequence_id` for callers that no
/// longer hold the raw event, `entities` (`[start, end, type]` tuples for
/// the replacement text), and the optional identity/key overrides described
/// on `chat_xdk_encrypt_message`.
///
/// Returns JSON `SendPayload`; the SDK-generated `message_id` is a field on it.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_edit(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiEncryptEditParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ckey_bytes = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let mut params = EncryptEditParams::new(p.target_event.unwrap_or_default(), p.updated_text);
        params.entities = p.entities.map(entity_tuples_to_descs);
        params.conversation_id = p.conversation_id;
        params.target_message_sequence_id = p.target_message_sequence_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;

        match h.inner.encrypt_edit(&params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => err_result(&e.to_string()),
            },
            Err(e) => err_from(e),
        }
    })
}

// Conversation key operations

/// Decrypt an ECIES-encrypted conversation key.
///
/// `encrypted_key_b64` — base64-encoded encrypted key from a `KeyChange` event.
///
/// Returns a base64-encoded raw 32-byte conversation key.
/// Call this once per key version; reuse the result for all subsequent operations.
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
        let ckey = match XChatConversationKey::from_bytes(ckey_bytes) {
            Some(k) => k,
            None => return err_result("Invalid conversation key"),
        };

        match h.inner.encrypt(plaintext, &ckey) {
            Ok(s) => ok_data(&s),
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt base64 ciphertext to UTF-8 plaintext (metadata fields).
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
        let ckey = match XChatConversationKey::from_bytes(ckey_bytes) {
            Some(k) => k,
            None => return err_result("Invalid conversation key"),
        };

        match h.inner.decrypt(ciphertext_b64, &ckey) {
            Ok(s) => ok_data(&s),
            Err(e) => err_from(e),
        }
    })
}

/// Decode a params document's `conversation_keys`. An entry that is not a
/// base64 32-byte key is an error.
fn conversation_keys_from_b64(
    entries: HashMap<String, String>,
) -> Result<HashMap<String, XChatConversationKey>, FfiResult> {
    entries
        .into_iter()
        .map(|(version, key_b64)| {
            let key = BASE64
                .decode(&key_b64)
                .ok()
                .and_then(XChatConversationKey::from_bytes)
                .ok_or_else(|| {
                    err_result(&format!(
                        "the key for version '{}' in the conversation key map is not 32 bytes: \
                         pass the raw 32-byte conversation keys",
                        version
                    ))
                })?;
            Ok((version, key))
        })
        .collect()
}

/// Decode a params document's base64 byte field.
fn bytes_from_b64(field: &str, b64: &str) -> Result<Vec<u8>, FfiResult> {
    BASE64
        .decode(b64)
        .map_err(|e| err_result(&format!("Invalid {field} base64: {e}")))
}

/// Encrypt a file of an outgoing message, after the message is built.
///
/// `params_json` — single JSON document: `file` (base64), `event_b64` (the
/// `event_b64` of the `SendPayload` that `chat_xdk_encrypt_message` or
/// `chat_xdk_encrypt_reply` returned for the message carrying the file),
/// `media_hash_key` (the media hash key the file's upload started with, as
/// listed in the message's attachments), and optionally `conversation_key`
/// (base64 raw 32-byte key) with `conversation_key_version`: the key the
/// message was encrypted under, resolved from the key cache when both are
/// omitted. The SDK finds that attachment and encrypts the file under its
/// key.
///
/// Returns the encrypted file, base64.
#[no_mangle]
pub extern "C" fn chat_xdk_encrypt_file(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiEncryptFileParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let file = match bytes_from_b64("file", &p.file) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let conversation_key = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut params = EncryptFileParams::new(file, p.event_b64, p.media_hash_key);
        params.conversation_key = conversation_key;
        params.conversation_key_version = p.conversation_key_version;
        match h.inner.encrypt_file(&params) {
            Ok(encrypted) => ok_data(&BASE64.encode(&encrypted)),
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt an encrypted file.
///
/// `params_json` — single JSON document: `encrypted` (base64, as
/// downloaded), `event_b64` (the event of the message that carries the
/// file), `conversation_keys` (`{"version": "base64 raw 32-byte key"}`
/// holding the key for the message's version), and `media_hash_key` (the
/// file's media hash key from the decrypted message).
///
/// Returns the decrypted file, base64.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_file(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiDecryptFileParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let encrypted = match bytes_from_b64("encrypted", &p.encrypted) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let conversation_keys = match conversation_keys_from_b64(p.conversation_keys) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let params =
            DecryptFileParams::new(encrypted, p.event_b64, conversation_keys, p.media_hash_key);
        match h.inner.decrypt_file(params) {
            Ok(output) => ok_data(&BASE64.encode(&output)),
            Err(e) => err_from(e),
        }
    })
}

// Incremental files

/// Opaque handle to an incremental file encryptor.
///
/// Created by `chat_xdk_file_encryptor_new`, freed by
/// `chat_xdk_file_encryptor_free`.
pub struct FileEncryptorHandle {
    inner: Option<chat_xdk_core::FileEncryptor>,
}

/// Opaque handle to an incremental file decryptor.
///
/// Created by `chat_xdk_file_decryptor_new`, freed by
/// `chat_xdk_file_decryptor_free`.
pub struct FileDecryptorHandle {
    inner: Option<chat_xdk_core::FileDecryptor>,
}

/// Create an incremental encryptor for a file too large to hold in memory.
/// `params_json` takes the fields of `chat_xdk_encrypt_file` apart from
/// `file`, which is fed to the encryptor.
///
/// On success writes the new handle to `out_encryptor` and returns an empty
/// result; free the handle with `chat_xdk_file_encryptor_free`. On
/// failure writes NULL and returns the error.
#[no_mangle]
pub extern "C" fn chat_xdk_file_encryptor_new(
    handle: *const ChatHandle,
    params_json: *const c_char,
    out_encryptor: *mut *mut FileEncryptorHandle,
) -> FfiResult {
    catch_ffi(|| {
        if out_encryptor.is_null() {
            return err_result("Null out_encryptor");
        }
        unsafe { *out_encryptor = std::ptr::null_mut() };
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiFileEncryptorParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let conversation_key = match decode_opt_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut params = FileEncryptorParams::new(p.event_b64, p.media_hash_key);
        params.conversation_key = conversation_key;
        params.conversation_key_version = p.conversation_key_version;
        match h.inner.file_encryptor(&params) {
            Ok(enc) => {
                let boxed = Box::new(FileEncryptorHandle { inner: Some(enc) });
                unsafe { *out_encryptor = Box::into_raw(boxed) };
                ok_void()
            }
            Err(e) => err_from(e),
        }
    })
}

/// Encrypt a base64 chunk of the file; returns the base64 encrypted bytes
/// available so far.
#[no_mangle]
pub extern "C" fn chat_xdk_file_encryptor_push(
    handle: *mut FileEncryptorHandle,
    plaintext_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let enc = match unsafe { &mut *handle }.inner.as_mut() {
            Some(e) => e,
            None => return err_result("File encryptor already finished"),
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
pub extern "C" fn chat_xdk_file_encryptor_finish(handle: *mut FileEncryptorHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        match unsafe { &mut *handle }.inner.take() {
            Some(enc) => match enc.finish() {
                Ok(out) => ok_data(&BASE64.encode(&out)),
                Err(e) => err_from(e),
            },
            None => err_result("File encryptor already finished"),
        }
    })
}

/// Free a file encryptor handle.
#[no_mangle]
pub extern "C" fn chat_xdk_file_encryptor_free(handle: *mut FileEncryptorHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

/// Create an incremental decryptor for an encrypted file too large to hold
/// in memory. `params_json` takes the fields of `chat_xdk_decrypt_file`
/// apart from `encrypted`, which is fed to the decryptor.
///
/// On success writes the new handle to `out_decryptor` and returns an empty
/// result; free the handle with `chat_xdk_file_decryptor_free`. On
/// failure writes NULL and returns the error.
#[no_mangle]
pub extern "C" fn chat_xdk_file_decryptor_new(
    handle: *const ChatHandle,
    params_json: *const c_char,
    out_decryptor: *mut *mut FileDecryptorHandle,
) -> FfiResult {
    catch_ffi(|| {
        if out_decryptor.is_null() {
            return err_result("Null out_decryptor");
        }
        unsafe { *out_decryptor = std::ptr::null_mut() };
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiFileParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let conversation_keys = match conversation_keys_from_b64(p.conversation_keys) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let params = FileDecryptorParams::new(p.event_b64, conversation_keys, p.media_hash_key);
        match h.inner.file_decryptor(params) {
            Ok(dec) => {
                let boxed = Box::new(FileDecryptorHandle { inner: Some(dec) });
                unsafe { *out_decryptor = Box::into_raw(boxed) };
                ok_void()
            }
            Err(e) => err_from(e),
        }
    })
}

/// Decrypt a base64 chunk of the encrypted file; returns the base64 bytes
/// available so far.
#[no_mangle]
pub extern "C" fn chat_xdk_file_decryptor_push(
    handle: *mut FileDecryptorHandle,
    ciphertext_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let dec = match unsafe { &mut *handle }.inner.as_mut() {
            Some(d) => d,
            None => return err_result("File decryptor already finished"),
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

/// Decrypt the final frame as base64. Errors if the file was truncated. The
/// handle must still be freed afterwards.
#[no_mangle]
pub extern "C" fn chat_xdk_file_decryptor_finish(handle: *mut FileDecryptorHandle) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        match unsafe { &mut *handle }.inner.take() {
            Some(dec) => match dec.finish() {
                Ok(out) => ok_data(&BASE64.encode(&out)),
                Err(e) => err_from(e),
            },
            None => err_result("File decryptor already finished"),
        }
    })
}

/// Free a file decryptor handle.
#[no_mangle]
pub extern "C" fn chat_xdk_file_decryptor_free(handle: *mut FileDecryptorHandle) {
    catch_ffi_or((), || {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

// Signing / verification

/// Sign application data with the signing key.
///
/// Returns a base64-encoded ECDSA signature (64 bytes), or an error for an
/// event signature payload or a public key, which only the SDK signs.
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

/// Verify an ECDSA signature.
///
/// `public_key_b64` — base64-encoded signing public key (SEC1 or SPKI).
/// `signature_b64` — base64-encoded signature from `chat_xdk_sign`.
/// `data` / `data_len` — the original signed data.
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
/// All three arguments are base64 strings. Returns 1 if valid, 0 if not,
/// and -1 on error.
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

// Stateless utilities wrapping `chat_xdk_core::utils`

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
