//! Event decryption: the batch and single-event calls and their result documents.

use super::*;

// Event decryption

pub(crate) fn json_conversation_key_bundle(
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

pub(crate) fn json_decrypt_events_result(
    r: &chat_xdk_core::DecryptEventsResult,
) -> Result<String, serde_json::Error> {
    let mut events = Vec::new();
    for decrypted in &r.events {
        let mut m = serde_json::Map::new();
        m.insert("event".into(), serde_json::to_value(&decrypted.event)?);
        if let Some(ref orig) = decrypted.original_b64 {
            m.insert(
                "original_b64".into(),
                serde_json::Value::String(orig.clone()),
            );
        }
        events.push(serde_json::Value::Object(m));
    }
    let mut errors = serde_json::Map::new();
    for (k, v) in &r.errors {
        errors.insert(k.to_string(), serde_json::Value::String(v.clone()));
    }
    let mut root = serde_json::Map::new();
    root.insert("events".into(), serde_json::Value::Array(events));
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
                Err(e) => internal_error(e),
            },
            Err(e) => internal_error(e),
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
pub extern "C" fn chat_xdk_decrypt_events(
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
        let result = h.inner.decrypt_events(&params);

        match json_decrypt_events_result(&result) {
            Ok(json) => ok_data(&json),
            Err(e) => internal_error(e),
        }
    })
}

/// Serialize a prepared key change to JSON with the conversation key base64-encoded.
pub(crate) fn json_prepared_change(
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
    for (name, value) in [
        ("encrypted_title", &res.encrypted_title),
        ("encrypted_description", &res.encrypted_description),
    ] {
        if let Some(value) = value {
            out.insert(name.into(), serde_json::Value::String(value.clone()));
        }
    }
    serde_json::to_string(&serde_json::Value::Object(out))
}

/// Decrypt a webhook event.
///
/// `params_json` — single JSON document: `event_b64` (the base64 event),
/// `conversation_keys` (`{"version": "base64 raw 32-byte key", ...}`, from
/// `chat_xdk_decrypt_events` or `chat_xdk_extract_conversation_keys`; `{}`
/// for events without message contents, which also falls back to the opt-in
/// key cache), plus optional `signing_keys` (as for
/// `chat_xdk_decrypt_events`). With no signing keys passed or stored, signed
/// events fail decryption under the default reject-unverified policy
/// (disable it via `chat_xdk_set_reject_unverified` to have them returned
/// with `verified: false` instead).
///
/// Returns JSON representation of the decrypted Event.
#[no_mangle]
pub extern "C" fn chat_xdk_decrypt_event(
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

        match h.inner.decrypt_event(&params) {
            Ok(event) => match serde_json::to_string(&event) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}
