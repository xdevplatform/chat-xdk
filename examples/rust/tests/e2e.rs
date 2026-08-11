//! Live end-to-end test against the X Chat API.
//!
//! Skipped unless `CHATXDK_E2E=1` and the credential env vars are set, so the
//! normal offline `cargo test` is unaffected. Requires the default `http`
//! feature.
//!
//!   CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... CHAT_SIGNING_KEY_VERSION=... \
//!   CHAT_CONVERSATION_ID=... cargo test --test e2e -- --nocapture
//!
//! Flow (each numbered step asserts against the live API):
//!   1. batch-decrypt inbound history (pagination when a second page exists)
//!   2. rotate the conversation key (prepare -> POST /keys -> decrypt own CKCE)
//!   3. send a threaded reply with an entity + TTL under the rotated key,
//!      fetch it back, decrypt it via the single-event path, and verify it
//!   4. react to the sent message (add + remove), decrypting the add back
//!
//! Optional extras:
//!   CHATXDK_E2E_MEDIA=1   also stream-encrypts a media blob, uploads it,
//!                         sends a message referencing it, then downloads and
//!                         stream-decrypts it back to the original bytes
//!   CHATXDK_E2E_GROUPS=1  also creates a group (two-signature create), sends
//!                         a group message, and adds the 1:1 partner as a member

#![cfg(feature = "http")]

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{
    AttachmentDescriptor, EntityDescriptor, Event, MessageAttachment, MessageContent,
    PublicKeyInput, SigningKeyEntry,
};
use chatbot_rs::chat_core::{message_text, prep_to_request, ChatCore, ReplyOptions};
use chatbot_rs::x_api::{ChatApi, HttpChatApi};
use serde_json::json;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Signing entries -> the flat entries the prepare methods take.
fn key_entries(pks: &[SigningKeyEntry]) -> Vec<PublicKeyInput> {
    pks.iter()
        .map(|pk| PublicKeyInput {
            user_id: pk.user_id.clone(),
            public_key: pk.identity_public_key.clone(),
            key_version: pk.public_key_version.clone(),
        })
        .collect()
}

/// Poll the conversation until the event for `message_id` lands, and return it
/// decrypted via the single-event path (`decrypt_one`) plus its sequence id.
///
/// The target envelope is matched by its raw event id before decrypting, so a
/// decrypt failure on our own event (e.g. a broken sign->verify loop) surfaces
/// in the timeout message instead of being silently swallowed.
fn await_decrypted(
    api: &HttpChatApi,
    core: &ChatCore,
    conversation_id: &str,
    conv_keys: &HashMap<String, XChatConversationKey>,
    signing: &[SigningKeyEntry],
    message_id: &str,
) -> (Event, String, String) {
    let mut last_err: Option<String> = None;
    for _ in 0..10 {
        let (events, _, _) = api
            .get_events(conversation_id, 25, None)
            .expect("get_events");
        for e in &events {
            if e.encoded_event.is_empty() {
                continue;
            }
            let is_target = e.id == message_id;
            let one = match core.decrypt_one(&e.encoded_event, conv_keys, signing) {
                Ok(one) => one,
                Err(err) => {
                    if is_target {
                        last_err = Some(err.to_string());
                    }
                    continue;
                }
            };
            let Event::Message(msg) = &one else { continue };
            if is_target || msg.meta.id.as_deref() == Some(message_id) {
                // The REST item's id IS the event's sequence id.
                let seq = msg
                    .meta
                    .sequence_id
                    .clone()
                    .unwrap_or_else(|| e.id.clone());
                return (one, seq, e.encoded_event.clone());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    match last_err {
        Some(err) => {
            panic!(
                "event for sent message {message_id:?} never appeared (last decrypt error: {err})"
            )
        }
        None => panic!("event for sent message {message_id:?} never appeared"),
    }
}

#[test]
fn e2e_live() {
    if env("CHATXDK_E2E").as_deref() != Some("1") {
        eprintln!("skipping live e2e (set CHATXDK_E2E=1)");
        return;
    }
    let token = env("X_ACCESS_TOKEN").expect("X_ACCESS_TOKEN");
    let blob = env("CHAT_PRIVATE_KEYS_B64").expect("CHAT_PRIVATE_KEYS_B64");
    let ver = env("CHAT_SIGNING_KEY_VERSION").expect("CHAT_SIGNING_KEY_VERSION");
    let conv = env("CHAT_CONVERSATION_ID").expect("CHAT_CONVERSATION_ID");

    let api = HttpChatApi::new(token, Some("https://api.x.com".to_string()));
    let mut core = ChatCore::new();
    core.load_keys(&blob, &ver).expect("load_keys");
    let my_id = api.get_my_user_id().expect("get_my_user_id");
    core.set_identity(&my_id);

    // -- 1. Inbound history: batch decrypt (+ pagination when available) ----
    let (mut raw, key_events, next_token) = api.get_events(&conv, 10, None).expect("get_events");
    if let Some(next_token) = next_token {
        let (raw2, _, _) = api
            .get_events(&conv, 10, Some(&next_token))
            .expect("get_events page 2");
        let ids1: Vec<&str> = raw.iter().map(|e| e.id.as_str()).collect();
        assert!(
            !raw2.is_empty() && raw2.iter().all(|e| !ids1.contains(&e.id.as_str())),
            "pagination made no progress"
        );
        eprintln!("pagination: fetched second page with {} events", raw2.len());
        raw.extend(raw2);
    }

    let mut ids = vec![my_id.clone()];
    for e in &raw {
        if !e.sender_id.is_empty() && !ids.contains(&e.sender_id) {
            ids.push(e.sender_id.clone());
        }
    }
    let mut signing: Vec<SigningKeyEntry> = Vec::new();
    let mut pks_by_user: HashMap<String, Vec<SigningKeyEntry>> = HashMap::new();
    for id in &ids {
        if let Ok(pks) = api.get_public_keys(id) {
            signing.extend(pks.iter().cloned());
            pks_by_user.insert(id.clone(), pks);
        }
    }

    // The KeyChange events from meta.conversation_key_events carry the
    // conversation keys; they must be in the same batch as the messages.
    let refs: Vec<&str> = key_events
        .iter()
        .map(String::as_str)
        .chain(
            raw.iter()
                .filter(|e| !e.encoded_event.is_empty())
                .map(|e| e.encoded_event.as_str()),
        )
        .collect();
    let batch = core.decrypt_batch(&refs, &signing);
    let decrypted = batch
        .messages
        .iter()
        .filter(|m| message_text(&m.event).is_some())
        .count();
    eprintln!(
        "live inbound messages decrypted: {decrypted}; conversation keys: {}",
        batch.conversation_keys.keys.len()
    );
    assert!(
        decrypted > 0,
        "expected to decrypt at least one live message"
    );

    // Canonical conversation_id + partner id + last inbound sequence id from
    // the decrypted events.
    let mut canonical_conv = conv.clone();
    let mut last_inbound_event: Option<String> = None;
    let mut key_change_events: Vec<String> = Vec::new();
    for m in &batch.messages {
        if let Event::KeyChange(_) = &m.event {
            if let Some(raw) = &m.original_b64 {
                key_change_events.push(raw.clone());
            }
        }
        if let Event::Message(msg) = &m.event {
            if let Some(cid) = msg
                .meta
                .conversation_id
                .as_deref()
                .filter(|c| !c.is_empty())
            {
                canonical_conv = cid.to_string();
            }
            if msg.meta.sender_id.as_deref() != Some(my_id.as_str()) {
                last_inbound_event = m.original_b64.clone().or(last_inbound_event);
            }
        }
    }
    let partner_id = ids
        .iter()
        .find(|id| **id != my_id)
        .cloned()
        .expect("expected a conversation partner among the senders");

    // -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE ---------
    let mut both_keys = key_entries(pks_by_user.get(&my_id).map(Vec::as_slice).unwrap_or(&[]));
    both_keys.extend(key_entries(
        pks_by_user
            .get(&partner_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    ));
    let prep = core
        .prepare_conversation_key_change(&both_keys, None)
        .expect("prepare_conversation_key_change");
    let signing_pub = core.public_keys().expect("public_keys").signing;
    let resp = api
        .add_conversation_keys(&conv, &prep_to_request(&prep, &signing_pub))
        .expect("add_conversation_keys");
    let data = &resp["data"];
    // The ack sequence id may arrive as a JSON string or number.
    assert!(
        !data["sequence_id"].is_null() || !data["conversation_key_change_sequence_id"].is_null(),
        "key rotation not acknowledged: {resp}"
    );
    let server_conv = data["conversation_id"].as_str().unwrap_or("");
    eprintln!(
        "rotated conversation key to version {}{}",
        prep.conversation_key_version,
        if server_conv.is_empty() {
            String::new()
        } else {
            format!("; server conversation_id: {server_conv}")
        }
    );

    // The rotated key becomes the sending key; re-fetch (polling briefly, in
    // case the CKCE has not propagated yet) so our own CKCE decrypts and the
    // cache includes the new version.
    let kv = prep.conversation_key_version.clone();
    let mut conv_keys = HashMap::new();
    for _ in 0..5 {
        let (raw, page_key_events, _) = api.get_events(&conv, 10, None).expect("get_events");
        let refs: Vec<&str> = page_key_events
            .iter()
            .map(String::as_str)
            .chain(
                raw.iter()
                    .filter(|e| !e.encoded_event.is_empty())
                    .map(|e| e.encoded_event.as_str()),
            )
            .collect();
        conv_keys = core.decrypt_batch(&refs, &signing).conversation_keys.keys;
        if conv_keys.contains_key(&kv) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1500));
    }
    let key = conv_keys
        .get(&kv)
        .unwrap_or_else(|| panic!("own rotated CKCE (version {kv}) did not decrypt+verify"))
        .clone();

    // -- 3. Send under the rotated key; fetch back; single-event decrypt ----
    let marker = format!("chat-xdk e2e [rust] {}", unix_secs());
    let body = core
        .encrypt_reply(
            &canonical_conv,
            &format!("@user {marker}"),
            &key,
            &kv,
            ReplyOptions {
                // Threading by raw event: the SDK derives the preview from it
                // and embeds it; the key changes cover an original encrypted
                // under an older key version.
                reply_to_event: last_inbound_event.clone(),
                reply_to_ckces: (!key_change_events.is_empty()).then(|| key_change_events.clone()),
                entities: Some(vec![EntityDescriptor {
                    start: 0,
                    end: 5,
                    entity_type: "mention".to_string(),
                }]),
                attachments: None,
                ttl_msec: Some(24 * 60 * 60 * 1000),
            },
        )
        .expect("encrypt_reply");
    api.send_message(&canonical_conv, &body)
        .expect("send_message");
    eprintln!("sent live encrypted message: {marker:?}");

    let (one, seq, sent_event_b64) =
        await_decrypted(&api, &core, &conv, &conv_keys, &signing, &body.message_id);
    assert_eq!(
        message_text(&one),
        Some(format!("@user {marker}").as_str()),
        "round-trip text mismatch: {one:?}"
    );
    let Event::Message(msg) = &one else {
        unreachable!()
    };
    assert!(
        msg.verified,
        "own sent message failed signature verification"
    );
    assert!(
        !seq.is_empty(),
        "sent message has no sequence id to react to"
    );
    eprintln!("sent message decrypted + verified via the single-event path");

    // -- 4. Reactions: add (round-trip) then remove --------------------------
    let add = core
        .encrypt_reaction(true, &sent_event_b64, "\u{1f44d}", &key, &kv)
        .expect("encrypt_reaction add");
    api.send_message(&canonical_conv, &add)
        .expect("send reaction add");
    let (one, _, _) = await_decrypted(&api, &core, &conv, &conv_keys, &signing, &add.message_id);
    let Event::Message(reaction) = &one else {
        unreachable!()
    };
    assert!(
        matches!(&reaction.content, MessageContent::Reaction { emoji, .. } if emoji == "\u{1f44d}"),
        "expected a Reaction event, got {:?}",
        reaction.content
    );
    assert!(reaction.verified, "reaction failed signature verification");
    eprintln!("reaction add decrypted + verified");

    let remove = core
        .encrypt_reaction(false, &sent_event_b64, "\u{1f44d}", &key, &kv)
        .expect("encrypt_reaction remove");
    api.send_message(&canonical_conv, &remove)
        .expect("send reaction remove");
    eprintln!("reaction remove sent");

    // -- 5. Optional: media — stream-encrypt, upload, send, download, decrypt
    if env("CHATXDK_E2E_MEDIA").as_deref() == Some("1") {
        // A deterministic multi-chunk payload, so the incremental encryptor
        // emits several frames and any corruption is byte-attributable.
        let plaintext: Vec<u8> = (0..300_000u32)
            .map(|i| ((i * 31 + 7) % 256) as u8)
            .collect();
        let ciphertext = core.encrypt_media(&plaintext, &key).expect("encrypt_media");
        let media_hash_key = api
            .upload_media(&canonical_conv, &ciphertext)
            .expect("upload_media");
        eprintln!(
            "encrypted media uploaded: {media_hash_key} ({} bytes)",
            ciphertext.len()
        );

        let media_msg = core
            .encrypt_reply(
                &canonical_conv,
                &format!("chat-xdk e2e media [rust] {}", unix_secs()),
                &key,
                &kv,
                ReplyOptions {
                    reply_to_event: None,
                    reply_to_ckces: None,
                    entities: None,
                    attachments: Some(vec![AttachmentDescriptor::Media {
                        media_hash_key: media_hash_key.clone(),
                        width: 0,
                        height: 0,
                        filesize_bytes: plaintext.len() as i64,
                        filename: "e2e.bin".to_string(),
                        media_type: Some(5),
                        duration_millis: None,
                    }]),
                    ttl_msec: Some(24 * 60 * 60 * 1000),
                },
            )
            .expect("encrypt media message");
        api.send_message(&canonical_conv, &media_msg)
            .expect("send media message");
        let (one, _, _) = await_decrypted(
            &api,
            &core,
            &conv,
            &conv_keys,
            &signing,
            &media_msg.message_id,
        );
        let Event::Message(media_one) = &one else {
            unreachable!()
        };
        assert!(
            media_one.verified,
            "media message failed signature verification"
        );
        let atts = match &media_one.content {
            MessageContent::Text { attachments, .. } => attachments.as_deref().unwrap_or(&[]),
            other => panic!("expected a text message with attachments, got {other:?}"),
        };
        let got_key = atts.iter().find_map(|a| match a {
            MessageAttachment::Media { media } => media.media_hash_key.as_deref(),
            _ => None,
        });
        assert_eq!(
            got_key,
            Some(media_hash_key.as_str()),
            "attachment did not round-trip: {atts:?}"
        );

        let downloaded = api
            .download_media(&canonical_conv, &media_hash_key)
            .expect("download_media");
        assert_eq!(
            core.decrypt_media(&downloaded, &key)
                .expect("decrypt_media"),
            plaintext,
            "downloaded media did not decrypt to the original bytes"
        );
        eprintln!("media downloaded + stream-decrypted to the original bytes");
    }

    // -- 6. Optional: group create + message + member add --------------------
    if env("CHATXDK_E2E_GROUPS").as_deref() == Some("1") {
        groups_flow(
            &api,
            &core,
            &my_id,
            &partner_id,
            &both_keys,
            &signing,
            &signing_pub,
        );
    }

    eprintln!("E2E RUST: PASS");
}

fn groups_flow(
    api: &HttpChatApi,
    core: &ChatCore,
    my_id: &str,
    partner_id: &str,
    both_keys: &[PublicKeyInput],
    signing: &[SigningKeyEntry],
    signing_pub: &str,
) {
    let my_keys: Vec<PublicKeyInput> = both_keys
        .iter()
        .filter(|k| k.user_id == my_id)
        .cloned()
        .collect();

    let group_id = api.initialize_group().expect("initialize_group");
    assert!(
        group_id.starts_with('g'),
        "unexpected group id: {group_id:?}"
    );

    // Create with the caller as sole member/admin so the member add below
    // exercises prepare_group_members_change with the partner.
    let mut prep = core
        .prepare_group_create(
            &my_keys,
            &group_id,
            &[my_id.to_string()],
            &[my_id.to_string()],
        )
        .expect("prepare_group_create");
    let mut members = vec![my_id.to_string()];
    let mut body = prep_to_request(&prep, signing_pub);
    body["conversation_id"] = json!(group_id);
    body["group_members"] = json!(members);
    body["group_admins"] = json!([my_id]);
    body["group_name"] = json!("chat-xdk e2e");
    if api.create_conversation(&body).is_err() {
        // Some deployments reject single-member groups; fall back to creating
        // with both participants (skipping the member-add below).
        prep = core
            .prepare_group_create(
                both_keys,
                &group_id,
                &[my_id.to_string(), partner_id.to_string()],
                &[my_id.to_string()],
            )
            .expect("prepare_group_create fallback");
        members = vec![my_id.to_string(), partner_id.to_string()];
        let mut body = prep_to_request(&prep, signing_pub);
        body["conversation_id"] = json!(group_id);
        body["group_members"] = json!(members);
        body["group_admins"] = json!([my_id]);
        body["group_name"] = json!("chat-xdk e2e");
        api.create_conversation(&body).expect("create_conversation");
    }
    let kv = prep.conversation_key_version.clone();
    let key = prep
        .conversation_key
        .clone()
        .expect("group conversation key");
    eprintln!("group created: {group_id} with {} member(s)", members.len());

    let marker = format!("chat-xdk e2e group [rust] {}", unix_secs());
    let msg = core
        .encrypt_reply(&group_id, &marker, &key, &kv, ReplyOptions::default())
        .expect("encrypt group message");
    api.send_message(&group_id, &msg)
        .expect("send group message");
    let conv_keys = HashMap::from([(kv, key)]);
    let (one, _, _) = await_decrypted(api, core, &group_id, &conv_keys, signing, &msg.message_id);
    let Event::Message(gmsg) = &one else {
        unreachable!()
    };
    assert!(
        message_text(&one) == Some(marker.as_str()) && gmsg.verified,
        "group message round-trip failed: {one:?}"
    );
    eprintln!("group message decrypted + verified");

    if !members.contains(&partner_id.to_string()) {
        let prep = core
            .prepare_group_members_change(
                both_keys,
                &group_id,
                &[partner_id.to_string()],
                &members,
                &[my_id.to_string()],
            )
            .expect("prepare_group_members_change");
        let mut body = prep_to_request(&prep, signing_pub);
        body["user_ids"] = json!([partner_id]);
        api.add_group_members(&group_id, &body)
            .expect("add_group_members");
        eprintln!(
            "group member add: {partner_id} added (key rotated to {})",
            prep.conversation_key_version
        );
    }
}
