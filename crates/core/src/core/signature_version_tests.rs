//! Signature versions 8 through 11 on received events.
//!
//! Signed payloads are spelled out in each test for the version it signs at,
//! so the verifier is checked against the payload layout rather than against
//! its own output.

use super::test_support::{
    decrypt_message, envelope, frame, key, keys, message_event, Party, CONVERSATION,
};
use super::*;
use crate::pipeline::build_message_content;
use crate::thrift::event::{
    ConversationKeyChangeEvent, ConversationParticipantKey, GroupChange as ThriftGroupChange,
    GroupChangeEvent as ThriftGroupChangeEvent, GroupCreate, GroupMemberAddChange,
    GroupMemberRemoveChange, GroupType, MessageCreateEvent, MessageEvent as ThriftEvent,
    MessageEventDetail as Detail, MessageEventSignature,
};

fn payload_string(event: &ThriftEvent, plaintext_ckey_b64: Option<&str>) -> String {
    let payload =
        build_event_signature_payload(event, event.detail.as_ref().unwrap(), plaintext_ckey_b64)
            .unwrap();
    String::from_utf8(payload.to_vec()).unwrap()
}

// Payload known answers.

const KAT_MESSAGE_ID: &str = "11111111-2222-3333-4444-555555555555";
const KAT_SENDER: &str = "1491585161162473473";

fn kat_message_event(version: i32, key_version: &str, cev: Option<i16>) -> ThriftEvent {
    ThriftEvent {
        message_id: Some(KAT_MESSAGE_ID.to_string()),
        sender_id: Some(KAT_SENDER.to_string()),
        conversation_id: Some(CONVERSATION.to_string()),
        detail: Some(Detail::MessageCreateEvent(MessageCreateEvent {
            contents: Some(b"Hello".to_vec()),
            conversation_key_version: Some(key_version.to_string()),
            contents_encryption_version: cev,
            ..Default::default()
        })),
        message_event_signature: Some(MessageEventSignature {
            signature_version: Some(version.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn message_payloads_match_known_answers() {
    let prefix = format!(
        "MessageCreateEvent,{},{},{}",
        KAT_MESSAGE_ID, KAT_SENDER, CONVERSATION
    );
    assert_eq!(
        payload_string(&kat_message_event(8, "8", None), None),
        format!("{},8,SGVsbG8", prefix)
    );
    assert_eq!(
        payload_string(&kat_message_event(9, "5", None), None),
        format!("{},5,SGVsbG8,signature_version=9", prefix)
    );
    assert_eq!(
        payload_string(&kat_message_event(10, "5", None), None),
        format!("{},5,SGVsbG8,null,signature_version=10", prefix)
    );
    assert_eq!(
        payload_string(&kat_message_event(10, "5", Some(1)), None),
        format!("{},5,SGVsbG8,1,signature_version=10", prefix)
    );
    assert_eq!(
        payload_string(&kat_message_event(11, "5", Some(1)), None),
        format!("{},5,SGVsbG8,1,signature_version=11", prefix)
    );
}

#[test]
fn key_change_payload_at_v9_matches_known_answer() {
    let ckey: Vec<u8> = (0u8..32).collect();
    let event = ThriftEvent {
        message_id: Some(KAT_MESSAGE_ID.to_string()),
        sender_id: Some(KAT_SENDER.to_string()),
        conversation_id: Some(CONVERSATION.to_string()),
        detail: Some(Detail::ConversationKeyChangeEvent(
            ConversationKeyChangeEvent {
                conversation_key_version: Some("42".to_string()),
                ..Default::default()
            },
        )),
        message_event_signature: Some(MessageEventSignature {
            signature_version: Some("9".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        payload_string(&event, Some(&STANDARD_NO_PAD.encode(&ckey))),
        format!(
            "ConversationKeyChangeEvent,{},{},{},42,AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8,\
             signature_version=9",
            KAT_MESSAGE_ID, KAT_SENDER, CONVERSATION
        )
    );
}

#[test]
fn known_signature_verifies_only_with_the_signed_contents_encryption_version() {
    const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+t366VDnLsZibo8mWYxvPQDuALQPpSydiQnR6GgvlHWaL2hjFuGhB6bkwqOgQMgpLNmtTd4sPVaXjxIkNLmKDg==";
    const SIGNATURE: &str =
        "W5rdZk1q13OBfVCSwyaWF+jTSotcS0Xrae24qOxntrrda81+BneKT8b3s0ZNHORaFd+QnzcQlzYNDSTF5vjn9A==";
    let core = ChatCore::new();
    let signature = base64_decode(SIGNATURE).unwrap();

    let signed = payload_string(&kat_message_event(10, "5", Some(1)), None);
    assert!(core
        .verify(PUBLIC_KEY, &signature, signed.as_bytes())
        .unwrap());

    let stripped = payload_string(&kat_message_event(10, "5", None), None);
    assert!(!core
        .verify(PUBLIC_KEY, &signature, stripped.as_bytes())
        .unwrap());
}

// Signature versions on received events.

#[test]
fn messages_verify_at_every_supported_version() {
    let author = Party::new("1001");
    let ckey = key(5);
    for version in 2..=11 {
        let event = message_event(
            &author,
            &format!("m-{}", version),
            "100",
            "7",
            None,
            version,
            &ckey,
            &build_message_content("hi", None, None, None).unwrap(),
        );
        let message = decrypt_message(
            &ChatCore::new(),
            &event,
            &keys("7", &ckey),
            std::slice::from_ref(&author.entry),
        )
        .unwrap_or_else(|e| panic!("v{} failed: {}", version, e));
        assert!(message.verified, "v{}", version);
        assert_eq!(message.text(), Some("hi"));
    }
}

#[test]
fn a_version_above_eleven_is_rejected() {
    let author = Party::new("1001");
    let ckey = key(5);
    let event = message_event(
        &author,
        "m-12",
        "100",
        "7",
        None,
        12,
        &ckey,
        &build_message_content("hi", None, None, None).unwrap(),
    );
    let err = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap_err();
    assert!(err.to_string().contains("maximum: 11"), "{}", err);

    let mut lenient = ChatCore::new();
    lenient.set_reject_unverified(false);
    let message = decrypt_message(
        &lenient,
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(!message.verified);
}

#[test]
fn a_v7_message_signed_over_a_non_integer_key_version_still_verifies() {
    let author = Party::new("1001");
    let ckey = key(9);
    let event = message_event(
        &author,
        "m-1",
        "100",
        "v1",
        None,
        7,
        &ckey,
        &build_message_content("signed at v7", None, None, None).unwrap(),
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("v1", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
}

#[test]
fn a_message_without_contents_encryption_version_verifies_at_v9() {
    let author = Party::new("1001");
    let ckey = key(5);
    let event = message_event(
        &author,
        "m-1",
        "100",
        "7",
        None,
        9,
        &ckey,
        &build_message_content("before", None, None, None).unwrap(),
    );
    let message = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap();
    assert!(message.verified);
}

#[test]
fn a_v9_signature_relabeled_as_v10_fails_verification() {
    let author = Party::new("1001");
    let ckey = key(5);
    let mut event = message_event(
        &author,
        "m-1",
        "100",
        "7",
        None,
        9,
        &ckey,
        &build_message_content("signed", None, None, None).unwrap(),
    );
    event
        .message_event_signature
        .as_mut()
        .unwrap()
        .signature_version = Some("10".to_string());
    let err = decrypt_message(
        &ChatCore::new(),
        &event,
        &keys("7", &ckey),
        std::slice::from_ref(&author.entry),
    )
    .unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{}", err);
}

// Group changes and key changes at versions 8 through 11.

const OWNER: &str = "1491585161162473473";
const USER_2: &str = "2";
const USER_3: &str = "3";

fn group_change_event(
    signer: &Party,
    change: ThriftGroupChange,
    payload: &str,
    version: i32,
) -> ThriftEvent {
    envelope(
        "gc-1",
        signer,
        "100",
        Detail::GroupChangeEvent(ThriftGroupChangeEvent {
            group_change: Some(change),
            for_key_rotation: None,
        }),
        signer.sign(payload, version),
    )
}

fn group_change_verified(event: &ThriftEvent, signer: &Party) -> bool {
    let mut core = ChatCore::new();
    core.set_reject_unverified(false);
    match core
        .decrypt_event_with(
            &frame(event),
            &HashMap::new(),
            std::slice::from_ref(&signer.entry),
        )
        .unwrap()
    {
        Event::GroupChange(change) => change.verified,
        other => panic!("expected a group change, got {:?}", other),
    }
}

fn member_add(description: Option<&str>) -> ThriftGroupChange {
    ThriftGroupChange::GroupMemberAdd(GroupMemberAddChange {
        member_ids: Some(vec![USER_3.to_string()]),
        current_member_ids: Some(vec![OWNER.to_string(), USER_2.to_string()]),
        current_admin_ids: Some(vec![OWNER.to_string()]),
        current_title: Some("encrypted-title".to_string()),
        conversation_key_version: Some("1".to_string()),
        current_description: description.map(str::to_string),
        ..Default::default()
    })
}

#[test]
fn a_member_add_signs_the_description_from_v8() {
    let owner = Party::new(OWNER);
    let prefix = format!(
        "GroupChangeEvent.GroupMemberAddChange,gc-1,{},{},{},{},{},{},encrypted-title,null,null,1,null",
        OWNER, CONVERSATION, USER_3, OWNER, USER_2, OWNER
    );
    let with_description = format!("{},encrypted-description", prefix);
    assert!(group_change_verified(
        &group_change_event(
            &owner,
            member_add(Some("encrypted-description")),
            &with_description,
            8
        ),
        &owner
    ));
    let without_description = format!("{},null", prefix);
    assert!(group_change_verified(
        &group_change_event(&owner, member_add(None), &without_description, 8),
        &owner
    ));
    // At v7 the description is not signed.
    assert!(group_change_verified(
        &group_change_event(
            &owner,
            member_add(Some("encrypted-description")),
            &prefix,
            7
        ),
        &owner
    ));
}

fn group_create(group_type: Option<GroupType>, ttl_msec: Option<i64>) -> ThriftGroupChange {
    ThriftGroupChange::GroupCreate(GroupCreate {
        member_ids: Some(vec![
            OWNER.to_string(),
            USER_2.to_string(),
            USER_3.to_string(),
        ]),
        admin_ids: Some(vec![OWNER.to_string()]),
        conversation_key_version: Some("2".to_string()),
        group_type,
        ttl_msec,
        ..Default::default()
    })
}

fn group_create_prefix() -> String {
    format!(
        "GroupChangeEvent.GroupCreate,gc-1,{},2,{},{},{},null,null,null",
        OWNER, OWNER, USER_2, USER_3
    )
}

#[test]
fn a_group_create_signs_the_group_type_from_v9() {
    let owner = Party::new(OWNER);
    let change = group_create(Some(GroupType::SUBSCRIBER_CHAT), None);
    let v11 = format!("{},1,null,signature_version=11", group_create_prefix());
    assert!(group_change_verified(
        &group_change_event(&owner, change.clone(), &v11, 11),
        &owner
    ));
    let v8 = group_create_prefix();
    assert!(group_change_verified(
        &group_change_event(&owner, change, &v8, 8),
        &owner
    ));
}

#[test]
fn a_group_create_signs_the_ttl_from_v10() {
    let owner = Party::new(OWNER);
    let change = group_create(None, Some(300_000));
    let v11 = format!("{},null,300000,signature_version=11", group_create_prefix());
    assert!(group_change_verified(
        &group_change_event(&owner, change.clone(), &v11, 11),
        &owner
    ));
    let v9 = format!("{},null,signature_version=9", group_create_prefix());
    assert!(group_change_verified(
        &group_change_event(&owner, change, &v9, 9),
        &owner
    ));
}

#[test]
fn a_tampered_group_create_fails_verification() {
    let owner = Party::new(OWNER);
    let ttl_payload = format!("{},null,300000,signature_version=10", group_create_prefix());
    let tampered_ttl =
        group_change_event(&owner, group_create(None, Some(600_000)), &ttl_payload, 10);
    assert!(!group_change_verified(&tampered_ttl, &owner));

    let type_payload = format!("{},1,null,signature_version=11", group_create_prefix());
    let tampered_type = group_change_event(
        &owner,
        group_create(Some(GroupType::NORMAL), None),
        &type_payload,
        11,
    );
    assert!(!group_change_verified(&tampered_type, &owner));
}

fn member_remove(key_version: Option<&str>) -> ThriftGroupChange {
    ThriftGroupChange::GroupMemberRemove(GroupMemberRemoveChange {
        member_ids: Some(vec![USER_3.to_string()]),
        conversation_key_version: key_version.map(str::to_string),
    })
}

fn member_remove_payload(key_version: Option<&str>, version: i32) -> String {
    let mut payload = format!(
        "GroupChangeEvent.GroupMemberRemoveChange,gc-1,{},{},{}",
        OWNER, CONVERSATION, USER_3
    );
    if let Some(key_version) = key_version {
        payload.push_str(&format!(",{}", key_version));
    }
    payload.push_str(&format!(",signature_version={}", version));
    payload
}

#[test]
fn a_member_remove_signs_the_key_version_from_v11() {
    let owner = Party::new(OWNER);
    let v11 = member_remove_payload(Some("2"), 11);
    assert!(group_change_verified(
        &group_change_event(&owner, member_remove(Some("2")), &v11, 11),
        &owner
    ));
    let v10 = member_remove_payload(None, 10);
    assert!(group_change_verified(
        &group_change_event(&owner, member_remove(Some("2")), &v10, 10),
        &owner
    ));
}

#[test]
fn a_v11_member_remove_with_a_changed_or_dropped_key_version_fails() {
    let owner = Party::new(OWNER);
    let signed = member_remove_payload(Some("2"), 11);
    for key_version in [Some("3"), None] {
        let event = group_change_event(&owner, member_remove(key_version), &signed, 11);
        assert!(!group_change_verified(&event, &owner), "{:?}", key_version);
    }
}

#[test]
fn a_v10_member_remove_with_a_changed_key_version_still_verifies() {
    let owner = Party::new(OWNER);
    let signed = member_remove_payload(None, 10);
    let event = group_change_event(&owner, member_remove(Some("3")), &signed, 10);
    assert!(group_change_verified(&event, &owner));
}

fn key_change_event(
    signer: &Party,
    ckey: &XChatConversationKey,
    signed_at: i32,
    labeled: i32,
) -> ThriftEvent {
    let mut payload = format!(
        "ConversationKeyChangeEvent,kc-1,{},{},2,{}",
        signer.user_id,
        CONVERSATION,
        STANDARD_NO_PAD.encode(ckey.encoded())
    );
    if signed_at >= 9 {
        payload.push_str(&format!(",signature_version={}", signed_at));
    }
    let mut signature = signer.sign(&payload, signed_at);
    signature.signature_version = Some(labeled.to_string());
    envelope(
        "kc-1",
        signer,
        "100",
        Detail::ConversationKeyChangeEvent(ConversationKeyChangeEvent {
            conversation_key_version: Some("2".to_string()),
            conversation_participant_keys: Some(vec![ConversationParticipantKey::default()]),
            ..Default::default()
        }),
        signature,
    )
}

fn key_change_verified(event: &ThriftEvent, signer: &Party, ckey: &XChatConversationKey) -> bool {
    let mut core = ChatCore::new();
    core.set_reject_unverified(false);
    match core
        .decrypt_event_with(
            &frame(event),
            &keys("2", ckey),
            std::slice::from_ref(&signer.entry),
        )
        .unwrap()
    {
        Event::KeyChange(change) => change.verified,
        other => panic!("expected a key change, got {:?}", other),
    }
}

#[test]
fn a_key_change_verifies_only_at_the_version_it_was_signed_at() {
    let owner = Party::new(OWNER);
    let ckey = key(4);
    assert!(key_change_verified(
        &key_change_event(&owner, &ckey, 8, 8),
        &owner,
        &ckey
    ));
    assert!(key_change_verified(
        &key_change_event(&owner, &ckey, 9, 9),
        &owner,
        &ckey
    ));
    assert!(!key_change_verified(
        &key_change_event(&owner, &ckey, 8, 9),
        &owner,
        &ckey
    ));
    assert!(!key_change_verified(
        &key_change_event(&owner, &ckey, 9, 8),
        &owner,
        &ckey
    ));
    assert!(!key_change_verified(
        &key_change_event(&owner, &ckey, 9, 10),
        &owner,
        &ckey
    ));
}
