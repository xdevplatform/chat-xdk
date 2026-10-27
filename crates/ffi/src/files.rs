//! File encryption and decryption, whole and incremental.

use super::*;

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
        let conversation_key = match decode_ckey_bytes(p.conversation_key.as_deref()) {
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
        match h.inner.decrypt_file(&params) {
            Ok(output) => ok_data(&BASE64.encode(&output)),
            Err(e) => err_from(e),
        }
    })
}

// Incremental files

/// Opaque handle to an incremental file encryptor.
///
/// Created by [`chat_xdk_file_encryptor_new`], freed by
/// [`chat_xdk_file_encryptor_free`].
pub struct FileEncryptorHandle {
    pub(crate) inner: Option<chat_xdk_core::FileEncryptor>,
}

/// Opaque handle to an incremental file decryptor.
///
/// Created by [`chat_xdk_file_decryptor_new`], freed by
/// [`chat_xdk_file_decryptor_free`].
pub struct FileDecryptorHandle {
    pub(crate) inner: Option<chat_xdk_core::FileDecryptor>,
}

/// Create an incremental encryptor for a file too large to hold in memory.
/// `params_json` takes the fields of [`chat_xdk_encrypt_file`] apart from
/// `file`, which is fed to the encryptor.
///
/// On success writes the new handle to `out_encryptor` and returns an empty
/// result; free the handle with [`chat_xdk_file_encryptor_free`]. On
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
        let conversation_key = match decode_ckey_bytes(p.conversation_key.as_deref()) {
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
/// in memory. `params_json` takes the fields of [`chat_xdk_decrypt_file`]
/// apart from `encrypted`, which is fed to the decryptor.
///
/// On success writes the new handle to `out_decryptor` and returns an empty
/// result; free the handle with [`chat_xdk_file_decryptor_free`]. On
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
        match h.inner.file_decryptor(&params) {
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
