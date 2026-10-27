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

/// The signature version a message sent from `chat` signs at: "7" for v0,
/// "10" for v1.
fn send(chat: *mut ChatHandle) -> String {
    let params = c(&serde_json::json!({
        "conversation_id": "1001:2002",
        "text": "hi",
        "conversation_key": BASE64.encode([7u8; 32]),
        "conversation_key_version": "1",
    })
    .to_string());
    let payload: serde_json::Value =
        serde_json::from_str(&data(chat_xdk_encrypt_message(chat, params.as_ptr())).unwrap())
            .unwrap();
    payload["signature_info"]["signature_version"]
        .as_str()
        .unwrap()
        .to_string()
}

fn answer(chat: *mut ChatHandle, status: i32, body: &[u8]) {
    data(chat_xdk_set_feature_switches(
        chat,
        status,
        body.as_ptr(),
        body.len(),
    ));
}

#[test]
fn the_feature_switch_constants_are_the_cores() {
    assert_eq!(
        CHAT_XDK_FEATURES_TIMEOUT_MS,
        chat_xdk_core::FEATURES_TIMEOUT_MS
    );
    assert_eq!(CHAT_XDK_FEATURES_MAX_BODY, chat_xdk_core::FEATURES_MAX_BODY);
    let header = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../go/chatxdk/include/chat_xdk.h"
    ))
    .unwrap();
    let endpoint = format!(
        "#define CHAT_XDK_FEATURES_ENDPOINT \"{}\"",
        chat_xdk_core::FEATURES_ENDPOINT
    );
    assert!(header.contains(&endpoint), "the header lacks {endpoint}");
}

#[test]
fn a_caller_hands_a_chat_its_feature_switches_once() {
    let on = br#"{"features":{"v1_send":true}}"#;
    let chat = new_chat();
    assert_eq!(send(chat), "7", "no answer: v0");
    answer(chat, 200, on);
    assert_eq!(send(chat), "10");
    answer(chat, 200, br#"{"features":{"v1_send":false}}"#);
    assert_eq!(send(chat), "10", "a chat takes one answer");
    chat_xdk_free(chat);

    let mut oversized = on.to_vec();
    oversized.resize(CHAT_XDK_FEATURES_MAX_BODY + 1, b' ');
    for (status, body) in [
        (404, on.as_slice()),
        (0, b"".as_slice()),
        (200, b"not json".as_slice()),
        (200, oversized.as_slice()),
    ] {
        let chat = new_chat();
        answer(chat, status, body);
        assert_eq!(send(chat), "7", "{status} {}", body.len());
        chat_xdk_free(chat);
    }

    let chat = new_chat();
    data(chat_xdk_set_feature_switches(
        chat,
        200,
        std::ptr::null(),
        0,
    ));
    assert_eq!(send(chat), "7", "an empty answer");
    chat_xdk_free(chat);
    assert_eq!(
        error(chat_xdk_set_feature_switches(
            std::ptr::null(),
            200,
            std::ptr::null(),
            0
        ))["kind"],
        "invalid_input"
    );
}

#[test]
fn invalid_entities_and_attachments_fail_with_invalid_input() {
    let chat = new_chat();
    let encrypt = |fields: serde_json::Value| {
        let mut params = serde_json::json!({
            "conversation_id": "1001:2002",
            "text": "hi @bob",
            "conversation_key": BASE64.encode([7u8; 32]),
            "conversation_key_version": "1",
        });
        params
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let params = c(&params.to_string());
        error(chat_xdk_encrypt_message(chat, params.as_ptr()))
    };
    let invalid_input = |message: String| {
        serde_json::json!({
            "kind": "invalid_input",
            "message": message,
        })
    };
    for entity_type in ["bogus", ""] {
        assert_eq!(
            encrypt(serde_json::json!({ "entities": [[3, 7, entity_type]] })),
            invalid_input(format!(
                "Invalid entity_type '{entity_type}': pass url, mention, hashtag, cashtag, \
                 email, address or phone_number"
            ))
        );
    }
    for (start, end, problem) in [
        (-1, 4, "offsets count bytes of the UTF-8 text, from 0"),
        (5, 3, "end is before start"),
        (
            3,
            8,
            "end is past the end of the text, which is 7 bytes of UTF-8",
        ),
    ] {
        assert_eq!(
            encrypt(serde_json::json!({ "entities": [[start, end, "mention"]] })),
            invalid_input(format!("Invalid entity offsets {start}..{end}: {problem}"))
        );
    }
    let photo = |filesize_bytes: i64, filename: &str| {
        serde_json::json!({
            "attachment_type": "media",
            "media_hash_key": "photo",
            "width": 100,
            "height": 100,
            "filesize_bytes": filesize_bytes,
            "filename": filename,
        })
    };
    let banner = serde_json::json!({
        "attachment_type": "url",
        "url": "https://example.com",
        "banner_image": { "media_hash_key": "banner", "filesize_bytes": 0, "filename": "b.png" },
    });
    let mut negative_width = photo(1000, "photo.jpg");
    negative_width["width"] = (-1).into();
    for (attachment, message) in [
        (
            photo(1000, ""),
            "media_hash_key 'photo' has an empty filename: pass the file's original name",
        ),
        (
            banner,
            "media_hash_key 'banner' has filesize_bytes 0: pass the encrypted file's size, \
             which encrypted_file_size gives",
        ),
        (
            negative_width,
            "media_hash_key 'photo' has width -1: pass the width in pixels, 0 or more",
        ),
        (
            serde_json::json!({ "attachment_type": "url", "url": "" }),
            "a URL card's url is empty: pass the link the card shows",
        ),
        (
            serde_json::json!({ "attachment_type": "post" }),
            "a post attachment has neither rest_id nor post_url: pass the post's id or its URL",
        ),
    ] {
        assert_eq!(
            encrypt(serde_json::json!({ "attachments": [attachment] })),
            invalid_input(message.to_string())
        );
    }
    chat_xdk_free(chat);
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
