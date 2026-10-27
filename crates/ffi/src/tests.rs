use super::*;

/// Take a string the library returned, freeing it.
fn take(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
    chat_xdk_free_string(ptr);
    Some(text)
}

/// The data of a result that must succeed.
fn data(result: FfiResult) -> Option<String> {
    let error = take(result.error);
    assert!(error.is_none(), "unexpected error: {error:?}");
    take(result.data)
}

/// The error document of a result that must fail.
fn error(result: FfiResult) -> serde_json::Value {
    assert!(take(result.data).is_none());
    serde_json::from_str(&take(result.error).expect("an error")).unwrap()
}

fn c(text: &str) -> CString {
    CString::new(text).unwrap()
}

/// A chat with fresh keys, signing as user 1001, and no Juicebox config.
fn new_chat() -> *mut ChatHandle {
    let mut chat = std::ptr::null_mut();
    data(chat_xdk_new(std::ptr::null(), &mut chat));
    assert!(!chat.is_null());
    data(chat_xdk_generate_keypairs(chat));
    let identity = c(r#"{"user_id":"1001","signing_key_version":"1"}"#);
    data(chat_xdk_set_identity(chat, identity.as_ptr()));
    chat
}

#[cfg(feature = "juicebox")]
#[test]
fn juicebox_calls_without_a_config_fail_with_the_cores_invalid_state_error() {
    let chat = new_chat();
    let (pin, new_pin) = (b"2580", b"1359");
    let failures = [
        error(chat_xdk_setup(chat, pin.as_ptr(), pin.len())),
        error(chat_xdk_unlock(chat, pin.as_ptr(), pin.len())),
        error(chat_xdk_change_pin(
            chat,
            pin.as_ptr(),
            pin.len(),
            new_pin.as_ptr(),
            new_pin.len(),
        )),
        error(chat_xdk_delete(chat)),
    ];
    for document in failures {
        assert_eq!(
            document,
            serde_json::json!({
                "kind": "invalid_state",
                "message": "Invalid state: no Juicebox config: pass the juicebox_config the X \
                            API returns when you create the chat, or call update_config() first",
            })
        );
    }
    assert_eq!(data(chat_xdk_is_unlocked(chat)).as_deref(), Some("true"));
    chat_xdk_free(chat);
}
