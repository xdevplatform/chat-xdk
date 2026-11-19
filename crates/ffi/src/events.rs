//! Event decryption: the batch and single-event calls and their result documents.

use super::*;

// Event decryption

/// A key map as a JSON object: each key version to its base64 key.
fn json_key_map(keys: &HashMap<String, XChatConversationKey>) -> serde_json::Value {
    let keys = keys
        .iter()
        .map(|(version, key)| {
            (
                version.clone(),
                serde_json::Value::String(BASE64.encode(key.encoded())),
            )
        })
        .collect();
    serde_json::Value::Object(keys)
}

pub(crate) fn json_conversation_key_bundle(
    ckr: &chat_xdk_core::ConversationKeyResult,
) -> Result<serde_json::Value, serde_json::Error> {
    let keys_by_conversation = ckr
        .keys_by_conversation
        .iter()
        .map(|(conversation_id, keys)| (conversation_id.clone(), json_key_map(keys)))
        .collect();
    let mut o = serde_json::Map::new();
    o.insert("keys".into(), json_key_map(&ckr.keys));
    o.insert(
        "keys_by_conversation".into(),
        serde_json::Value::Object(keys_by_conversation),
    );
    o.insert(
        "latest_version".into(),
        match &ckr.latest_version {
            Some(v) => serde_json::Value::String(v.clone()),
            None => serde_json::Value::Null,
        },
    );
    o.insert(
        "latest_versions".into(),
        serde_json::to_value(&ckr.latest_versions)?,
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
    root.insert(
        "unverified_key_changes".into(),
        serde_json::to_value(&r.unverified_key_changes)?,
    );
    root.insert(
        "undecryptable_key_changes".into(),
        serde_json::to_value(&r.undecryptable_key_changes)?,
    );
    root.insert(
        "rejected_signing_keys".into(),
        serde_json::to_value(&r.rejected_signing_keys)?,
    );
    root.insert(
        "missing_signing_keys".into(),
        serde_json::to_value(&r.missing_signing_keys)?,
    );
    serde_json::to_string(&serde_json::Value::Object(root))
}

/// `events_json`: JSON array of base64-encoded event strings.
/// Returns JSON `{"keys":{version: key_b64,...},
/// "keys_by_conversation":{conversation_id: {version: key_b64,...},...},
/// "latest_version": string|null,
/// "latest_versions":{conversation_id: version,...}}`. Signatures are not
/// checked. `keys_by_conversation` holds each key under its conversation;
/// `keys` holds them by version alone, less a version that key changes of
/// more than one conversation carry. `latest_versions` holds each
/// conversation's highest key version; `latest_version` is the batch's
/// highest when every event belongs to one conversation, and null when they
/// belong to more than one.
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
/// empty falls back to the stored keys (`chat_xdk_set_signing_keys`,
/// `chat_xdk_add_signing_keys`, `chat_xdk_add_public_keys`). They must
/// include the keys of every member who signed a key change in the batch;
/// the result's `missing_signing_keys` names the ones the call lacked.
///
/// The result's `errors` maps the index of each event left out of `events`,
/// as a string, to its error: one that failed, or one decrypt drops, such as
/// a member removal's title or description re-encrypted under the new key.
/// Its `conversation_keys` holds `keys`, `keys_by_conversation`,
/// `latest_version` and `latest_versions`, as
/// `chat_xdk_extract_conversation_keys` returns them, except that
/// `latest_versions` holds the newest verified key version of each
/// conversation, and `latest_version` that version when every event belongs
/// to one conversation (null for a batch of more than one).
///
/// Four more objects are keyed by index, as a string, like `errors`, and
/// are `{}` when they have nothing to report. `unverified_key_changes` maps
/// the index of each key change whose signature did not verify to
/// `{"reason","key_dropped","conversation_id","conversation_key_version",
/// "sender_id","public_key_version"}`, where `reason` is `MissingSigningKey`,
/// `RejectedSigningKey`, `InvalidSignature` or `Unverifiable`.
/// `undecryptable_key_changes` maps the index of each key change whose
/// conversation key this identity could not decrypt to
/// `{"reason","conversation_id","conversation_key_version","sender_id"}`,
/// where `reason` is `Locked`, `NotARecipient`, `OtherKeyVersion` or
/// `DecryptionFailed`. `rejected_signing_keys` maps the index, among the
/// signing keys the call verified with, of each one left out because its
/// identity binding does not verify to `{"user_id","public_key_version"}`.
/// `missing_signing_keys` maps the index of each signed event whose
/// sender's signing key was not among the signing keys the call verified
/// with to `{"user_id","public_key_version"}`: the sender, and the key
/// version the event's signature names. `chat_xdk_missing_public_keys`
/// reads the users to fetch keys for from this object.
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
/// with `verified: false` instead). A member removal's title and
/// description, re-encrypted under the new key, aren't changes: they fail
/// with an `invalid_input` error under either policy.
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
