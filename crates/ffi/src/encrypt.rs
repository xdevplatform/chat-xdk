//! Message encryption: messages, replies, reactions and edits.

use super::*;

// Message encryption

/// Decode raw conversation key bytes from base64 for the params structs,
/// which take the raw bytes and zeroize them on drop. An absent or empty
/// value means "no key passed" (resolve from the key cache); the key length
/// is validated in core so every binding reports the same error.
pub(crate) fn decode_ckey_bytes(ckey_b64: Option<&str>) -> Result<Option<Vec<u8>>, FfiResult> {
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
/// (`[{"attachment_type",...},...]`), `quick_reply` (the `quick_reply` shape
/// of decrypted text content), `should_notify`, and `ttl_msec`.
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
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
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
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Parse attachment descriptors from a JSON array via the core serde types,
/// so the field requirements are defined once in core: an attachment missing
/// a required media field is rejected rather than silently defaulted.
pub(crate) fn parse_attachments(
    value: serde_json::Value,
) -> Result<Vec<AttachmentDescriptor>, FfiResult> {
    serde_json::from_value(value).map_err(|e| err_result(&format!("Invalid attachments: {}", e)))
}

/// Parse a quick reply via the core serde type; the JSON shape is the
/// `quick_reply` of decrypted text content.
pub(crate) fn parse_quick_reply(value: serde_json::Value) -> Result<QuickReply, FfiResult> {
    serde_json::from_value(value).map_err(|e| err_result(&format!("Invalid quick reply: {}", e)))
}

/// Encrypt a reply message for the X API.
///
/// `params_json` — same document as `chat_xdk_encrypt_message` plus the
/// reply target: preferably `reply_to_event` (base64 raw signed event being
/// replied to; the preview is derived from it), with optional
/// `reply_to_edit_event` and `reply_to_ckces` (base64 raw key-change events
/// needed when the original used a different key version). The explicit
/// `reply_to_sequence_id`, `reply_to_message_id`, `reply_to_sender_id`,
/// `reply_to_text`, `reply_to_entities`, and `reply_to_attachments`
/// overrides remain for callers that no longer hold the raw event; such a
/// reply needs `reply_to_message_id`, as recipients mark a v1 reply that
/// names no original invalid. With `reply_to_event`, a `reply_to_message_id`
/// other than the id the event carries fails with an invalid-input error.
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
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
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
        params.reply_to_message_id = p.reply_to_message_id;
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
                Err(e) => internal_error(e),
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

pub(crate) fn encrypt_reaction_impl(
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
            Err(e) => internal_error(e),
        },
        Err(e) => err_from(e),
    }
}

// Edit encryption

/// Encrypt a message edit for the X API.
///
/// `params_json` — single JSON document: `updated_text` plus the edit
/// target: preferably `target_event` (base64 raw event being edited; the
/// conversation id, target sequence id and target message id are derived
/// from it), with explicit `conversation_id` / `target_message_sequence_id`
/// / `target_message_id` overrides for callers that no longer hold the raw
/// event; a v1 edit built without `target_event` needs `target_message_id`
/// to name the message it edits. With `target_event`, a `target_message_id`
/// other than the id the event carries fails with an invalid-input error.
/// Optional `entities`
/// (`[start, end, type]` tuples for the replacement text), `sender_id` /
/// `signing_key_version` (unset resolves from the session identity), and
/// `conversation_key` (base64) / `conversation_key_version` (unset resolves
/// from the opt-in key cache).
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
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let mut params = EncryptEditParams::new(p.target_event.unwrap_or_default(), p.updated_text);
        params.entities = p.entities.map(entity_tuples_to_descs);
        params.conversation_id = p.conversation_id;
        params.target_message_sequence_id = p.target_message_sequence_id;
        params.target_message_id = p.target_message_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;

        match h.inner.encrypt_edit(&params) {
            Ok(payload) => match serde_json::to_string(&payload) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}
