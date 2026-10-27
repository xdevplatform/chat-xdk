//! Signing and verification.

use super::*;

// Signing / verification

/// Sign application data with the signing key. Returns base64-encoded
/// signature, or an error for an event signature payload or a public key,
/// which only the SDK signs.
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

/// Verify a raw r||s signature over `data` with a base64 P-256 public key:
/// `true` or `false`. A malformed public key or signature is an error.
/// Needs no loaded keys.
#[no_mangle]
pub extern "C" fn chat_xdk_verify(
    handle: *const ChatHandle,
    public_key_b64: *const c_char,
    signature_b64: *const c_char,
    data: *const u8,
    data_len: usize,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let public_key_b64 = try_str!(public_key_b64);
        let signature = match bytes_from_b64("signature", try_str!(signature_b64)) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let data = unsafe { bytes_from_ffi_ptr(data, data_len) };
        match h.inner.verify(public_key_b64, &signature, data) {
            Ok(valid) => ok_bool(valid),
            Err(e) => err_from(e),
        }
    })
}

/// Verify that a signing key is authentically bound to an identity key:
/// `true` or `false`. All three arguments are base64 strings; a malformed
/// one is an error.
#[no_mangle]
pub extern "C" fn chat_xdk_verify_key_binding(
    handle: *const ChatHandle,
    identity_public_key_b64: *const c_char,
    signing_public_key_b64: *const c_char,
    identity_public_key_signature_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.inner.verify_key_binding(
            try_str!(identity_public_key_b64),
            try_str!(signing_public_key_b64),
            try_str!(identity_public_key_signature_b64),
        ) {
            Ok(valid) => ok_bool(valid),
            Err(e) => err_from(e),
        }
    })
}

/// Whether the loaded identity public key is the key in `public_key_b64`
/// (raw SEC1 point or SPKI/DER, base64-encoded): `true` or `false`. Errors
/// when no identity key is loaded or the input is not base64.
#[no_mangle]
pub extern "C" fn chat_xdk_matches_registered_key(
    handle: *const ChatHandle,
    public_key_b64: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        match h.inner.matches_registered_key(try_str!(public_key_b64)) {
            Ok(matches) => ok_bool(matches),
            Err(e) => err_from(e),
        }
    })
}
