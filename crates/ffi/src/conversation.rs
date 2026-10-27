//! Conversation keys and the group metadata the X API returns.

use super::*;

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

/// Decrypt a group title or description the X API returns for a
/// conversation: base64 ciphertext under the conversation key (base64 raw
/// 32-byte key), decrypted to UTF-8 plaintext.
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

        let ckey = match bytes_from_b64("conversation_key", ckey_b64)
            .and_then(|bytes| bindings::conversation_key(&bytes).map_err(err_from))
        {
            Ok(k) => k,
            Err(e) => return e,
        };

        match h.inner.decrypt(ciphertext_b64, &ckey) {
            Ok(s) => ok_data(&s),
            Err(e) => err_from(e),
        }
    })
}

/// Decode a params document's `conversation_keys`: base64 raw 32-byte keys
/// by key version.
pub(crate) fn conversation_keys_from_b64(
    entries: HashMap<String, String>,
) -> Result<HashMap<String, XChatConversationKey>, FfiResult> {
    let raw = entries
        .into_iter()
        .map(|(version, key_b64)| {
            let bytes = BASE64.decode(&key_b64).map_err(|e| {
                err_result(&format!(
                    "the key for version '{version}' in the conversation key map is not base64: {e}"
                ))
            })?;
            Ok((version, bytes))
        })
        .collect::<Result<HashMap<_, _>, FfiResult>>()?;
    bindings::conversation_keys(raw).map_err(err_from)
}

/// Decode a params document's base64 byte field.
pub(crate) fn bytes_from_b64(field: &str, b64: &str) -> Result<Vec<u8>, FfiResult> {
    BASE64
        .decode(b64)
        .map_err(|e| err_result(&format!("Invalid {field} base64: {e}")))
}
