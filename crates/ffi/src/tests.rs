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
fn a_caller_hands_a_chat_its_feature_switches_until_one_answer_holds() {
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
        answer(chat, 200, on);
        assert_eq!(send(chat), "10", "the answer to a retried request");
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
fn a_group_leave_signs_at_the_version_sends_sign_at() {
    let chat = new_chat();
    let leave = || {
        let params = c(r#"{"conversation_id":"g100"}"#);
        let prepared: serde_json::Value = serde_json::from_str(
            &data(prepare::chat_xdk_prepare_group_leave(chat, params.as_ptr())).unwrap(),
        )
        .unwrap();
        prepared["action_signatures"].as_array().unwrap().clone()
    };
    let signed_at = |signatures: &[serde_json::Value]| -> Vec<String> {
        signatures
            .iter()
            .map(|s| s["message_event_signature"]["signature_version"].to_string())
            .collect()
    };
    assert_eq!(signed_at(&leave()), [r#""7""#, r#""7""#]);
    answer(chat, 200, br#"{"features":{"v1_send":true}}"#);
    let signatures = leave();
    assert_eq!(signed_at(&signatures), [r#""10""#, r#""10""#]);
    for (signature, fields) in signatures.iter().zip([
        "GroupChangeEvent.GroupMemberRemoveChange,{id},1001,g100,1001,signature_version=10",
        "ConversationDeleteEvent,{id},1001,g100,signature_version=10",
    ]) {
        let payload = fields.replace("{id}", signature["message_id"].as_str().unwrap());
        let signed = &signature["message_event_signature"];
        let public_key = c(signed["signing_public_key"].as_str().unwrap());
        let unpadded = signed["signature"].as_str().unwrap();
        let raw = c(&format!(
            "{unpadded}{}",
            "=".repeat((4 - unpadded.len() % 4) % 4)
        ));
        let valid = data(signing::chat_xdk_verify(
            chat,
            public_key.as_ptr(),
            raw.as_ptr(),
            payload.as_ptr(),
            payload.len(),
        ));
        assert_eq!(valid.as_deref(), Some("true"), "{payload}");
    }
    chat_xdk_free(chat);
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
    let mut short_hash = photo(1000, "photo.jpg");
    short_hash["plaintext_sha256"] = "c2hvcnQ=".into();
    for (attachment, message) in [
        (
            short_hash,
            "media_hash_key 'photo' has plaintext_sha256 'c2hvcnQ=': pass the base64 SHA-256 \
             of the file's plaintext bytes (32 bytes)",
        ),
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

#[test]
fn files_round_trip_under_a_key_the_caller_holds() {
    use crate::files::{chat_xdk_decrypt_file_with_key, chat_xdk_encrypt_file_with_key};
    let chat = new_chat();
    let key = BASE64.encode([7u8; 32]);
    let encrypt = |document: serde_json::Value| {
        let params = c(&document.to_string());
        chat_xdk_encrypt_file_with_key(chat, params.as_ptr())
    };
    let decrypt = |document: serde_json::Value| {
        let params = c(&document.to_string());
        chat_xdk_decrypt_file_with_key(chat, params.as_ptr())
    };
    for size in [0usize, 1500, 2048] {
        let file: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let encrypted = data(encrypt(
            serde_json::json!({ "file": BASE64.encode(&file), "key": key }),
        ))
        .unwrap();
        assert_eq!(
            Some(BASE64.decode(&encrypted).unwrap().len() as u64),
            chat_xdk_core::utils::encrypted_file_size(size as u64),
            "size {size}"
        );
        let opened = data(decrypt(
            serde_json::json!({ "encrypted": encrypted, "key": key }),
        ));
        assert_eq!(BASE64.decode(opened.unwrap()).unwrap(), file, "size {size}");
    }

    // The avatar-shaped file 0.5.2 encrypted with encrypt_stream opens under
    // the same key.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/compat_v0_5_2.json")).unwrap();
    let opened = data(decrypt(serde_json::json!({
        "encrypted": fixture["avatar_file"]["ciphertext_b64"],
        "key": fixture["conversation_key_b64"],
    })));
    assert_eq!(
        opened.as_deref(),
        fixture["avatar_file"]["plaintext_b64"].as_str()
    );

    let short_key = BASE64.encode([7u8; 31]);
    for document in [
        error(encrypt(
            serde_json::json!({ "file": "AAAA", "key": short_key }),
        )),
        error(decrypt(
            serde_json::json!({ "encrypted": "AAAA", "key": short_key }),
        )),
        error(encrypt(serde_json::json!({ "file": "AAAA" }))),
        error(encrypt(
            serde_json::json!({ "file": "AAAA", "key": "not base64" }),
        )),
    ] {
        assert_eq!(document["kind"], "invalid_input", "{document}");
    }
    let bad = error(decrypt(serde_json::json!({
        "encrypted": BASE64.encode([0u8; 60]),
        "key": key,
    })));
    assert_eq!(bad["kind"], "decryption", "{bad}");
    chat_xdk_free(chat);
}

#[test]
fn a_group_removal_drops_the_title_and_description_reencryptions() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/sdk_vectors.json")).unwrap();
    let text = |key: &str| v[key].as_str().unwrap().to_string();
    let mut chat = std::ptr::null_mut();
    data(chat_xdk_new(std::ptr::null(), &mut chat));
    let keys = BASE64.decode(text("private_keys_concat_b64")).unwrap();
    let import = c(&serde_json::json!({
        "signing_key_version": text("event_recipient_key_version"),
    })
    .to_string());
    data(chat_xdk_import_keys(
        chat,
        keys.as_ptr(),
        keys.len(),
        import.as_ptr(),
    ));
    let signing_keys = serde_json::json!([{
        "user_id": text("event_sender_id"),
        "public_key_version": text("event_signing_key_version"),
        "public_key": text("signing_public_b64"),
        "identity_public_key": text("identity_public_b64"),
        "identity_public_key_signature": text("identity_public_key_signature_b64"),
    }]);
    let flow = v["event_group_removal_flow_b64"].as_array().unwrap();
    let params =
        c(&serde_json::json!({ "events": flow, "signing_keys": signing_keys }).to_string());
    let result: serde_json::Value =
        serde_json::from_str(&data(chat_xdk_decrypt_events(chat, params.as_ptr())).unwrap())
            .unwrap();

    let mut dropped: Vec<u64> = result["errors"]
        .as_object()
        .unwrap()
        .keys()
        .map(|index| index.parse().unwrap())
        .collect();
    dropped.sort_unstable();
    let expected: Vec<u64> = v["event_group_removal_dropped_indices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect();
    assert_eq!(dropped, expected);
    let version = text("event_group_removal_conversation_key_version");
    assert_eq!(result["conversation_keys"]["latest_version"], version);
    let kept: Vec<&serde_json::Value> = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| &event["event"])
        .collect();
    assert_eq!(kept.len(), 3, "{kept:?}");
    assert_eq!(kept[0]["change"]["change_type"], "MembersRemoved");
    assert_eq!(
        kept[0]["change"]["member_ids"],
        serde_json::json!([text("event_group_removed_member_id")])
    );
    assert_eq!(kept[1]["type"], "KeyChange");
    assert_eq!(kept[1]["conversation_key_version"], version);
    assert_eq!(kept[2]["change"]["change_type"], "TitleChanged");
    assert_eq!(
        kept[2]["change"]["new_title"],
        serde_json::json!({ "kind": "Text", "text": text("event_group_renamed_title") })
    );
    for event in &kept {
        assert_eq!(event["verified"], true, "{event}");
    }

    for index in expected {
        let params = c(&serde_json::json!({
            "event_b64": flow[index as usize],
            "conversation_keys": result["conversation_keys"]["keys"],
            "signing_keys": signing_keys,
        })
        .to_string());
        assert_eq!(
            error(chat_xdk_decrypt_event(chat, params.as_ptr())),
            serde_json::json!({
                "kind": "invalid_input",
                "message": result["errors"][index.to_string()],
            })
        );
    }
    chat_xdk_free(chat);
}

#[cfg(feature = "juicebox")]
#[test]
fn an_empty_juicebox_config_fails_with_the_no_config_error() {
    let no_config = serde_json::json!({
        "kind": "invalid_state",
        "message": "Invalid state: no Juicebox config: pass the juicebox_config the X API \
                    returns when you create the chat, or call update_config() first",
    });
    for empty in ["", "  "] {
        let config = c(empty);
        let mut chat = std::ptr::null_mut();
        assert_eq!(error(chat_xdk_new(config.as_ptr(), &mut chat)), no_config);
        assert!(chat.is_null());
    }
    let chat = new_chat();
    let empty = c("");
    assert_eq!(
        error(chat_xdk_update_config(chat, empty.as_ptr())),
        no_config
    );
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
