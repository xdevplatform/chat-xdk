//! The conversation-key cache and the signing-key store: what fills them
//! and which calls read them.

use super::key_change_signers::{key_change, recipient, sent_message, ENFORCED_SEQUENCE, GROUP};
use super::*;
use crate::core::test_support::{frame, keys, Party, SIGNING_KEY_VERSION};
use crate::params::{GroupAvatarChangeParams, GroupMembersRemoveParams};

/// A party with a session identity whose key cache is on.
fn caching(user_id: &str) -> Party {
    let party = Party::new(user_id);
    party
        .core
        .set_identity(&SetIdentityParams::new(user_id, SIGNING_KEY_VERSION))
        .unwrap();
    party.core.set_cache_keys(true);
    party
}

/// The key version `sender` encrypts under in `conversation_id` when the
/// call passes no key.
fn send_version(sender: &Party, conversation_id: &str) -> Result<String, SdkError> {
    sender
        .core
        .encrypt_message(&crate::EncryptMessageParams::new(conversation_id, "hello"))
        .map(|payload| payload.conversation_key_version)
}

/// The text of `message` from `author`, as `receiver` decrypts it on its own
/// with no key map.
fn read(receiver: &Party, message: &str, author: &Party) -> Result<String, SdkError> {
    let signing_keys = std::slice::from_ref(&author.entry);
    match receiver
        .core
        .decrypt_event_with(message, &HashMap::new(), signing_keys)?
    {
        Event::Message(message) => Ok(message.text().unwrap_or_default().to_string()),
        other => panic!("expected a message, got {other:?}"),
    }
}

fn user_ids(parties: &[&Party]) -> Vec<String> {
    parties.iter().map(|party| party.user_id.clone()).collect()
}

fn photo_message(sender: &Party, conversation_id: &str) -> SendPayload {
    let mut params = crate::EncryptMessageParams::new(conversation_id, "a photo");
    params.attachments = Some(vec![AttachmentDescriptor::Media {
        media_hash_key: "photo".into(),
        width: 1,
        height: 1,
        filesize_bytes: 10,
        filename: "photo.jpg".into(),
        media_type: Some(1),
        duration_millis: None,
        plaintext_sha256: None,
    }]);
    sender.core.encrypt_message(&params).unwrap()
}

#[test]
fn decrypt_event_caches_the_key_of_a_key_change_that_verifies() {
    let admin = Party::new("5001");
    let member = Party::new("5002");
    let bot = caching("5003");
    let (change, key) = key_change(
        &admin,
        &[&admin, &member, &bot],
        GROUP,
        "3001",
        ENFORCED_SEQUENCE,
    );
    let message = sent_message(&member, GROUP, &key, "3001", "hello group");

    // Nothing is cached yet: neither a send nor the message finds a key.
    assert!(matches!(
        send_version(&bot, GROUP),
        Err(SdkError::InvalidState(_))
    ));
    assert!(read(&bot, &message, &member).is_err());

    let event = bot
        .core
        .decrypt_event_with(
            &frame(&change),
            &HashMap::new(),
            std::slice::from_ref(&admin.entry),
        )
        .unwrap();
    assert!(matches!(
        event,
        Event::KeyChange(KeyChangeEvent { verified: true, .. })
    ));

    assert_eq!(send_version(&bot, GROUP).unwrap(), "3001");
    assert_eq!(read(&bot, &message, &member).unwrap(), "hello group");
    // A later batch reports the version the single call recorded.
    let batch = bot
        .core
        .decrypt_events_with(&[&message], std::slice::from_ref(&member.entry));
    assert_eq!(
        batch.conversation_keys.latest_version.as_deref(),
        Some("3001")
    );
}

#[test]
fn decrypt_event_does_not_cache_a_key_change_that_does_not_verify() {
    let admin = Party::new("5001");
    let bot = caching("5003");
    bot.core.set_reject_unverified(false);
    let (change, _) = key_change(&admin, &[&admin, &bot], GROUP, "3001", ENFORCED_SEQUENCE);

    // Without the admin's signing keys the key change is returned unverified.
    let event = bot
        .core
        .decrypt_event_with(&frame(&change), &HashMap::new(), &[])
        .unwrap();
    assert!(matches!(
        event,
        Event::KeyChange(KeyChangeEvent {
            verified: false,
            ..
        })
    ));
    assert!(matches!(
        send_version(&bot, GROUP),
        Err(SdkError::InvalidState(_))
    ));
}

#[test]
fn prepare_calls_cache_the_key_they_make() {
    let admin = caching("5001");
    let member = Party::new("5002");
    let joiner = Party::new("5004");
    let both = || vec![recipient(&admin), recipient(&member)];

    let created = admin
        .core
        .prepare_group_create_with_version(
            &GroupCreateParams::new(
                both(),
                GROUP,
                user_ids(&[&admin, &member]),
                user_ids(&[&admin]),
            ),
            "4001",
        )
        .unwrap();
    assert_eq!(send_version(&admin, GROUP).unwrap(), "4001");

    let added = admin
        .core
        .prepare_group_members_change_with_version(
            &GroupMembersChangeParams::new(
                vec![recipient(&admin), recipient(&member), recipient(&joiner)],
                GROUP,
                user_ids(&[&joiner]),
                user_ids(&[&admin, &member]),
                user_ids(&[&admin]),
                Vec::new(),
            ),
            "4002",
        )
        .unwrap();
    assert_eq!(send_version(&admin, GROUP).unwrap(), "4002");

    let removed = admin
        .core
        .prepare_group_members_remove_with_version(
            &GroupMembersRemoveParams::new(both(), GROUP, user_ids(&[&joiner])),
            "4003",
        )
        .unwrap();
    assert_eq!(send_version(&admin, GROUP).unwrap(), "4003");

    let rotated = admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(both()).with_conversation_id(GROUP),
            "4004",
        )
        .unwrap();
    assert_eq!(send_version(&admin, GROUP).unwrap(), "4004");

    // Every prepared key stays cached: a message under it decrypts with no
    // key map.
    for (prepared, version) in [
        (&created, "4001"),
        (&added, "4002"),
        (&removed, "4003"),
        (&rotated, "4004"),
    ] {
        let key = prepared.conversation_key.as_ref().unwrap();
        let message = sent_message(&member, GROUP, key, version, version);
        assert_eq!(read(&admin, &message, &member).unwrap(), version);
    }

    // A one-to-one is cached under the id the call derives.
    let direct = admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(both()),
            "4005",
        )
        .unwrap();
    assert_eq!(direct.conversation_id, "5001:5002");
    assert_eq!(send_version(&admin, "5001:5002").unwrap(), "4005");
}

#[test]
fn prepared_keys_are_not_cached_while_the_cache_is_off() {
    let admin = Party::new("5001");
    admin
        .core
        .set_identity(&SetIdentityParams::new("5001", SIGNING_KEY_VERSION))
        .unwrap();
    admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(vec![recipient(&admin)]).with_conversation_id(GROUP),
            "4001",
        )
        .unwrap();

    assert!(matches!(
        send_version(&admin, GROUP),
        Err(SdkError::InvalidState(_))
    ));
    // Turning the cache on later does not bring the key back.
    admin.core.set_cache_keys(true);
    assert!(matches!(
        send_version(&admin, GROUP),
        Err(SdkError::InvalidState(_))
    ));
}

#[test]
fn cache_keeps_every_verified_version_and_sends_use_the_newest() {
    let admin = Party::new("5001");
    let member = Party::new("5002");
    let bot = caching("5003");
    let members = [&admin, &member, &bot];
    let admin_keys = std::slice::from_ref(&admin.entry);

    let (first, first_key) = key_change(&admin, &members, GROUP, "3001", ENFORCED_SEQUENCE);
    let (second, second_key) = key_change(&admin, &members, GROUP, "3002", ENFORCED_SEQUENCE);
    bot.core
        .decrypt_events_with(&[&frame(&first), &frame(&second)], admin_keys);
    assert_eq!(send_version(&bot, GROUP).unwrap(), "3002");

    // An older key change that arrives later is kept for decryption and
    // does not become the key sends use.
    let (older, older_key) = key_change(&admin, &members, GROUP, "3000", ENFORCED_SEQUENCE);
    bot.core.decrypt_events_with(&[&frame(&older)], admin_keys);
    assert_eq!(send_version(&bot, GROUP).unwrap(), "3002");

    for (key, version) in [
        (&older_key, "3000"),
        (&first_key, "3001"),
        (&second_key, "3002"),
    ] {
        let message = sent_message(&member, GROUP, key, version, version);
        assert_eq!(read(&bot, &message, &member).unwrap(), version);
    }
}

#[test]
fn files_decrypt_with_the_cached_keys_when_no_key_map_is_passed() {
    let sender = caching("5001");
    sender
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(vec![recipient(&sender)]).with_conversation_id(GROUP),
            "4001",
        )
        .unwrap();
    let payload = photo_message(&sender, GROUP);
    let encrypted = sender
        .core
        .encrypt_file(&EncryptFileParams::new(
            b"photo bytes".to_vec(),
            payload.event_b64.clone(),
            "photo",
        ))
        .unwrap();
    let decrypt = |conversation_keys: HashMap<String, XChatConversationKey>| {
        sender.core.decrypt_file(&DecryptFileParams::new(
            encrypted.clone(),
            payload.event_b64.clone(),
            conversation_keys,
            "photo",
        ))
    };

    // No key map: the keys come from the cache.
    assert_eq!(decrypt(HashMap::new()).unwrap(), b"photo bytes");
    let mut decryptor = sender
        .core
        .file_decryptor(&FileDecryptorParams::new(
            payload.event_b64.clone(),
            HashMap::new(),
            "photo",
        ))
        .unwrap();
    let mut streamed = decryptor.push(&encrypted).unwrap();
    streamed.extend(decryptor.finish().unwrap());
    assert_eq!(streamed, b"photo bytes");

    // A key map that is passed is the only source, as before: one without
    // the message's version fails though the cache holds that version.
    let other_version = keys("9", &KeyFactory::generate_conversation_key().unwrap());
    let err = decrypt(other_version).unwrap_err().to_string();
    assert!(
        err.contains("conversation_keys has no key for version '4001'"),
        "{err}"
    );

    // With the cache off there are no keys to read.
    sender.core.set_cache_keys(false);
    let err = decrypt(HashMap::new()).unwrap_err().to_string();
    assert!(
        err.contains("conversation_keys has no key for version '4001'"),
        "{err}"
    );
}

#[test]
fn avatar_change_signs_the_newest_cached_version_when_none_is_passed() {
    let admin = caching("5001");
    let url = "https://ton.x.com/xchat_media/g900/avatar";
    let omitted = GroupAvatarChangeParams::new(GROUP, url, "");

    let err = admin
        .core
        .prepare_group_avatar_change(&omitted)
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err:?}");
    assert!(
        err.to_string().contains(
            "conversation_key_version is not set and no conversation key is cached for 'g900'"
        ),
        "{err}"
    );

    for version in ["4001", "4002"] {
        admin
            .core
            .prepare_conversation_key_change_with_version(
                &ConversationKeyChangeParams::new(vec![recipient(&admin)])
                    .with_conversation_id(GROUP),
                version,
            )
            .unwrap();
    }
    let signed = |params: &GroupAvatarChangeParams| {
        let prepared = admin.core.prepare_group_avatar_change(params).unwrap();
        prepared.action_signatures[0].signature_payload.clone()
    };
    let payload = signed(&omitted);
    assert!(payload.ends_with(&format!(",4002,{url}")), "{payload}");
    // A version that is passed is signed as is.
    let payload = signed(&GroupAvatarChangeParams::new(GROUP, url, "4001"));
    assert!(payload.ends_with(&format!(",4001,{url}")), "{payload}");
}

#[test]
fn add_signing_keys_merges_by_user_and_version() {
    let alice = Party::new("5001");
    let bob = Party::new("5002");
    let reader = Party::new("5003");
    let key = KeyFactory::generate_conversation_key().unwrap();
    let from = |author: &Party| sent_message(author, GROUP, &key, "7", "hi");
    // Whether `reader` verifies and decrypts `message` with its stored keys.
    let reads = |message: String| {
        reader
            .core
            .decrypt_event_with(&message, &keys("7", &key), &[])
            .is_ok()
    };

    reader
        .core
        .set_signing_keys(std::slice::from_ref(&alice.entry));
    assert!(reads(from(&alice)));
    assert!(!reads(from(&bob)));

    // Adding keeps what is stored.
    reader
        .core
        .add_signing_keys(std::slice::from_ref(&bob.entry));
    assert!(reads(from(&alice)));
    assert!(reads(from(&bob)));

    // An entry for a stored user and version replaces that entry alone.
    let mut wrong = bob.entry.clone();
    wrong.user_id = alice.user_id.clone();
    reader.core.add_signing_keys(&[wrong]);
    assert!(!reads(from(&alice)));
    assert!(reads(from(&bob)));

    // set_signing_keys still replaces the whole set.
    reader
        .core
        .set_signing_keys(std::slice::from_ref(&alice.entry));
    assert!(reads(from(&alice)));
    assert!(!reads(from(&bob)));
}
