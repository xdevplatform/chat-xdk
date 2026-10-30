//! The signature version of every signed action: the legacy one while sends
//! are v0, and the version v1 sends sign at while they are v1.
//!
//! Each expected payload is spelled out in the layout of the version it signs
//! at, so the signer is checked against the layout rather than against the
//! verifier that shares its builder; a round trip through `decrypt_event`
//! checks the signature covers it.

use super::test_support::{enable_v1_send, frame, Party, SIGNING_KEY_VERSION};
use super::*;
use crate::params::{
    GroupAdminsAddParams, GroupAdminsRemoveParams, GroupAvatarChangeParams,
    GroupDescriptionChangeParams, GroupInviteDisableParams, GroupInviteEnableParams,
    GroupJoinRejectParams, GroupJoinRequestParams, GroupTitleChangeParams, MessageTtlChangeParams,
    MessageTtlRemoveParams, ScreenCaptureParams,
};
use crate::signatures::ActionSignature;
use crate::thrift::event::{
    MessageEvent as ThriftEvent, MessageEventDetail as Detail, MessageEventSignature,
};

const SENDER: &str = "910004";
const GROUP: &str = "g100";
const ONE_TO_ONE: &str = "910004:910005";

fn signer() -> Party {
    let party = Party::new(SENDER);
    party
        .core
        .set_identity(&SetIdentityParams::new(SENDER, SIGNING_KEY_VERSION))
        .unwrap();
    party
}

fn public_keys(party: &Party) -> Vec<PublicKeyInput> {
    vec![PublicKeyInput::new(
        SENDER,
        party.core.get_public_keys().unwrap().identity,
        SIGNING_KEY_VERSION,
    )]
}

fn decode_detail(signature: &ActionSignature) -> Detail {
    let bytes = base64_decode(&signature.encoded_message_event_detail).unwrap();
    let mut raw = TBinaryInputProtocol::new(Cursor::new(bytes), true);
    let mut protocol = BoundedProtocol::new(&mut raw);
    Detail::read_from_in_protocol(&mut protocol).unwrap()
}

/// The event recipients receive for `signature`.
fn delivered(signature: &ActionSignature, conversation_id: &str) -> ThriftEvent {
    delivered_from(signature, conversation_id, SENDER)
}

/// The event recipients receive for `signature`, signed by `sender_id`.
fn delivered_from(
    signature: &ActionSignature,
    conversation_id: &str,
    sender_id: &str,
) -> ThriftEvent {
    let signed = &signature.message_event_signature;
    ThriftEvent {
        sequence_id: Some("100".to_string()),
        message_id: Some(signature.message_id.clone()),
        sender_id: Some(sender_id.to_string()),
        conversation_id: Some(conversation_id.to_string()),
        detail: Some(decode_detail(signature)),
        message_event_signature: Some(MessageEventSignature {
            signature: Some(signed.signature.clone()),
            public_key_version: Some(signed.public_key_version.clone()),
            signature_version: Some(signed.signature_version.clone()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Whether `signature` verifies on a recipient that holds `keys`.
fn verifies(
    party: &Party,
    signature: &ActionSignature,
    conversation_id: &str,
    keys: &HashMap<String, XChatConversationKey>,
) -> bool {
    let receiver = ChatCore::new();
    receiver.set_reject_unverified(false);
    let event = receiver
        .decrypt_event_with(
            &frame(&delivered(signature, conversation_id)),
            keys,
            std::slice::from_ref(&party.entry),
        )
        .unwrap();
    match event {
        Event::KeyChange(e) => e.verified,
        Event::GroupChange(e) => e.verified,
        Event::SettingsChange(e) => e.verified,
        Event::MessageDeleted(e) => e.verified,
        Event::ReadReceipt(e) => e.verified,
        Event::ConversationDeleted(e) => e.verified,
        other => panic!("expected a signed action, got {other:?}"),
    }
}

/// Every single-signature action a chat prepares in group `GROUP`, with the
/// payload each signs after the event name, message id, sender and group.
fn single_actions(party: &Party) -> Vec<(ActionSignature, String)> {
    let core = &party.core;
    let key = vec![7u8; 32];
    let first = |prepared: PreparedAction| prepared.action_signatures[0].clone();
    let mut actions = vec![
        (
            first(
                core.prepare_message_delete(&MessageDeleteParams::new(
                    GROUP,
                    vec!["101".into(), "102".into()],
                    true,
                ))
                .unwrap(),
            ),
            "MessageDeleteEvent,{id},910004,g100,2,101,102".to_string(),
        ),
        (
            first(
                core.prepare_mark_conversation_read(
                    &MarkConversationReadParams::new(GROUP, "102").with_seen_at_msec(1_700_000_000_000),
                )
                .unwrap(),
            ),
            "MarkConversationReadEvent,{id},910004,g100,102,1700000000000".to_string(),
        ),
        (
            first(
                core.prepare_group_admins_add(&GroupAdminsAddParams::new(
                    GROUP,
                    vec!["910005".into()],
                ))
                .unwrap(),
            ),
            "GroupChangeEvent.GroupAdminAddChange,{id},910004,g100,910005".to_string(),
        ),
        (
            first(
                core.prepare_group_admins_remove(&GroupAdminsRemoveParams::new(
                    GROUP,
                    vec!["910005".into()],
                ))
                .unwrap(),
            ),
            "GroupChangeEvent.GroupAdminRemoveChange,{id},910004,g100,910005".to_string(),
        ),
        (
            first(
                core.prepare_group_invite_enable(
                    &GroupInviteEnableParams::new(GROUP, "https://x.com/i/chat/group_join/g100")
                        .with_expires_at_msec(1_800_000_000_000),
                )
                .unwrap(),
            ),
            "GroupChangeEvent.GroupInviteEnable,{id},910004,g100,https://x.com/i/chat/group_join/g100,1800000000000,null"
                .to_string(),
        ),
        (
            first(
                core.prepare_group_invite_disable(&GroupInviteDisableParams::new(GROUP))
                    .unwrap(),
            ),
            "GroupChangeEvent.GroupInviteDisable,{id},910004,g100,910004".to_string(),
        ),
        (
            first(
                core.prepare_group_join_request(&GroupJoinRequestParams::new(GROUP))
                    .unwrap(),
            ),
            "GroupChangeEvent.GroupJoinRequest,{id},910004,g100,910004".to_string(),
        ),
        (
            first(
                core.prepare_group_join_reject(&GroupJoinRejectParams::new(
                    GROUP,
                    vec!["910006".into()],
                ))
                .unwrap(),
            ),
            "GroupChangeEvent.GroupJoinReject,{id},910004,g100,910006".to_string(),
        ),
        (
            first(
                core.prepare_message_ttl_change(&MessageTtlChangeParams::new(GROUP, 86_400_000))
                    .unwrap(),
            ),
            "ConversationMetadataChangeEvent.MessageDurationChange,{id},910004,g100,86400000"
                .to_string(),
        ),
        (
            first(
                core.prepare_message_ttl_remove(&MessageTtlRemoveParams::new(GROUP))
                    .unwrap(),
            ),
            "ConversationMetadataChangeEvent.MessageDurationRemove,{id},910004,g100".to_string(),
        ),
        (
            first(
                core.prepare_screen_capture(&ScreenCaptureParams::new(
                    GROUP,
                    ScreenCaptureChange::BlockingEnabled,
                ))
                .unwrap(),
            ),
            "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,{id},910004,g100"
                .to_string(),
        ),
        (
            first(
                core.prepare_group_avatar_change(&GroupAvatarChangeParams::new(
                    GROUP,
                    "https://ton.x.com/avatar.jpg",
                    "5",
                ))
                .unwrap(),
            ),
            "GroupChangeEvent.GroupAvatarUrlChange,{id},910004,g100,5,https://ton.x.com/avatar.jpg"
                .to_string(),
        ),
    ];
    let title = core
        .prepare_group_title_change(
            &GroupTitleChangeParams::new(GROUP, "Board").with_conversation_key(key.clone(), "5"),
        )
        .unwrap();
    actions.push((
        title.action_signatures[0].clone(),
        format!(
            "GroupChangeEvent.GroupTitleChange,{{id}},910004,g100,5,{}",
            title.encrypted_value
        ),
    ));
    let description = core
        .prepare_group_description_change(
            &GroupDescriptionChangeParams::new(GROUP, "About").with_conversation_key(key, "5"),
        )
        .unwrap();
    actions.push((
        description.action_signatures[0].clone(),
        format!(
            "GroupChangeEvent.GroupDescriptionChange,{{id}},910004,g100,5,{}",
            description.encrypted_value
        ),
    ));
    actions
}

#[test]
fn every_single_action_signs_at_10_in_the_v10_layout_while_sends_are_v1() {
    let party = signer();
    enable_v1_send(&party.core);
    for (signature, layout) in single_actions(&party) {
        let expected = format!(
            "{},signature_version=10",
            layout.replace("{id}", &signature.message_id)
        );
        assert_eq!(signature.signature_payload, expected);
        assert_eq!(signature.message_event_signature.signature_version, "10");
        assert!(
            verifies(&party, &signature, GROUP, &HashMap::new()),
            "{expected}"
        );
    }
}

#[test]
fn every_single_action_keeps_version_7_while_sends_are_v0() {
    let party = signer();
    for (signature, layout) in single_actions(&party) {
        let expected = layout.replace("{id}", &signature.message_id);
        assert_eq!(signature.signature_payload, expected);
        assert_eq!(signature.message_event_signature.signature_version, "7");
        assert!(
            verifies(&party, &signature, GROUP, &HashMap::new()),
            "{expected}"
        );
    }
}

/// Check that `signature` is a key change to `key` signed at `version`: its
/// signature covers the key version and the plaintext key, and the payload,
/// which embeds the key, is not kept.
fn assert_key_change(
    party: &Party,
    signature: &ActionSignature,
    conversation_id: &str,
    key: &XChatConversationKey,
    version: &str,
) {
    assert_eq!(signature.message_event_signature.signature_version, version);
    assert!(
        signature.signature_payload.is_empty(),
        "the key stays inside"
    );
    let Detail::ConversationKeyChangeEvent(change) = decode_detail(signature) else {
        panic!("expected a key change");
    };
    let key_version = change.conversation_key_version.unwrap();
    let mut payload = format!(
        "ConversationKeyChangeEvent,{},{SENDER},{conversation_id},{key_version},{}",
        signature.message_id,
        STANDARD_NO_PAD.encode(key.encoded())
    );
    if version != "7" {
        payload.push_str(&format!(",signature_version={version}"));
    }
    let signature_bytes = base64_decode(&signature.message_event_signature.signature).unwrap();
    assert!(
        party
            .core
            .verify(
                &party.entry.public_key,
                &signature_bytes,
                payload.as_bytes()
            )
            .unwrap(),
        "{payload}"
    );
    let keys = HashMap::from([(key_version, key.clone())]);
    assert!(verifies(party, signature, conversation_id, &keys));
}

#[test]
fn key_changes_sign_at_the_version_of_the_send_format() {
    for (v1, version) in [(false, "7"), (true, "10")] {
        let party = signer();
        if v1 {
            enable_v1_send(&party.core);
        }
        let mut keys = public_keys(&party);
        keys.push(PublicKeyInput::new(
            "910005",
            party.core.get_public_keys().unwrap().identity,
            SIGNING_KEY_VERSION,
        ));
        let change = party
            .core
            .prepare_conversation_key_change_with_version(
                &ConversationKeyChangeParams::new(keys),
                "1700000000123",
            )
            .unwrap();
        assert_key_change(
            &party,
            &change.action_signatures[0],
            ONE_TO_ONE,
            change.conversation_key.as_ref().unwrap(),
            version,
        );
    }
}

const PEER: &str = "910005";

/// A v1 chat of `PEER`, the other member of `ONE_TO_ONE`, and the key change
/// it signs there at version 10, which carries `signer`'s key too.
fn peer_key_change(signer: &Party) -> (Party, PreparedConversationChange) {
    let peer = Party::new(PEER);
    peer.core
        .set_identity(&SetIdentityParams::new(PEER, SIGNING_KEY_VERSION))
        .unwrap();
    enable_v1_send(&peer.core);
    let keys = vec![
        PublicKeyInput::new(
            PEER,
            peer.core.get_public_keys().unwrap().identity,
            SIGNING_KEY_VERSION,
        ),
        public_keys(signer).remove(0),
    ];
    let change = peer
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(keys),
            "1700000000001",
        )
        .unwrap();
    assert_eq!(
        change.action_signatures[0]
            .message_event_signature
            .signature_version,
        "10"
    );
    (peer, change)
}

/// The signature version of the key change `party` signs next with `PEER`,
/// in `ONE_TO_ONE`, and with another user, in a conversation of its own.
fn next_key_change_versions(party: &Party) -> [String; 2] {
    ["910005", "910006"].map(|other| {
        let keys = vec![
            public_keys(party).remove(0),
            PublicKeyInput::new(
                other,
                party.core.get_public_keys().unwrap().identity,
                SIGNING_KEY_VERSION,
            ),
        ];
        let change = party
            .core
            .prepare_conversation_key_change_with_version(
                &ConversationKeyChangeParams::new(keys),
                "1700000000002",
            )
            .unwrap();
        let signature = &change.action_signatures[0];
        if other == PEER {
            assert_key_change(
                party,
                signature,
                ONE_TO_ONE,
                change.conversation_key.as_ref().unwrap(),
                &signature.message_event_signature.signature_version,
            );
        }
        signature.message_event_signature.signature_version.clone()
    })
}

#[test]
fn a_key_change_never_signs_below_one_the_chat_verified_in_its_conversation() {
    let party = signer();
    assert_eq!(next_key_change_versions(&party), ["7", "7"]);

    let (peer, change) = peer_key_change(&party);
    let event = frame(&delivered_from(
        &change.action_signatures[0],
        ONE_TO_ONE,
        PEER,
    ));
    let key = HashMap::from([(
        "1700000000001".to_string(),
        change.conversation_key.clone().unwrap(),
    )]);
    let decrypted = party
        .core
        .decrypt_event_with(&event, &key, std::slice::from_ref(&peer.entry))
        .unwrap();
    assert!(matches!(decrypted, Event::KeyChange(e) if e.verified));
    assert_eq!(
        next_key_change_versions(&party),
        ["10", "7"],
        "a v0 chat signs its next key change with the peer at 10, and others at 7"
    );
}

#[test]
fn a_key_change_verified_in_a_batch_raises_the_floor_too() {
    let party = signer();
    let (peer, change) = peer_key_change(&party);
    let event = frame(&delivered_from(
        &change.action_signatures[0],
        ONE_TO_ONE,
        PEER,
    ));
    let mut params = DecryptEventsParams::new(vec![event]);
    params.signing_keys = Some(vec![peer.entry.clone()]);
    let result = party.core.decrypt_events(&params);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(next_key_change_versions(&party), ["10", "7"]);
}

#[test]
fn a_key_change_that_does_not_verify_leaves_the_floor_where_it_was() {
    let party = signer();
    party.core.set_reject_unverified(false);
    let (_, change) = peer_key_change(&party);
    let event = frame(&delivered_from(
        &change.action_signatures[0],
        ONE_TO_ONE,
        PEER,
    ));
    let key = HashMap::from([(
        "1700000000001".to_string(),
        change.conversation_key.clone().unwrap(),
    )]);
    let impostor = Party::new(PEER);
    let decrypted = party
        .core
        .decrypt_event_with(&event, &key, std::slice::from_ref(&impostor.entry))
        .unwrap();
    assert!(matches!(decrypted, Event::KeyChange(e) if !e.verified));
    assert_eq!(next_key_change_versions(&party), ["7", "7"]);
}

#[test]
fn a_v1_chat_signs_key_changes_at_10() {
    let party = signer();
    enable_v1_send(&party.core);
    assert_eq!(next_key_change_versions(&party), ["10", "10"]);
}

#[test]
fn a_key_change_verified_at_11_raises_even_a_v1_chat_to_11() {
    let party = signer();
    enable_v1_send(&party.core);
    let (peer, _) = peer_key_change(&party);
    peer.core.raise_key_change_signature_floor(ONE_TO_ONE, 11);
    let keys = vec![
        PublicKeyInput::new(
            PEER,
            peer.core.get_public_keys().unwrap().identity,
            SIGNING_KEY_VERSION,
        ),
        public_keys(&party).remove(0),
    ];
    let change = peer
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(keys),
            "1700000000003",
        )
        .unwrap();
    assert_eq!(
        change.action_signatures[0]
            .message_event_signature
            .signature_version,
        "11"
    );
    let event = frame(&delivered_from(
        &change.action_signatures[0],
        ONE_TO_ONE,
        PEER,
    ));
    let key = HashMap::from([(
        "1700000000003".to_string(),
        change.conversation_key.clone().unwrap(),
    )]);
    let decrypted = party
        .core
        .decrypt_event_with(&event, &key, std::slice::from_ref(&peer.entry))
        .unwrap();
    assert!(matches!(decrypted, Event::KeyChange(e) if e.verified));
    assert_eq!(next_key_change_versions(&party), ["11", "10"]);
}

#[test]
fn a_group_create_signs_its_type_and_ttl_while_sends_are_v1() {
    for (v1, version) in [(false, "7"), (true, "10")] {
        let party = signer();
        if v1 {
            enable_v1_send(&party.core);
        }
        let created = party
            .core
            .prepare_group_create_with_version(
                &GroupCreateParams::new(
                    public_keys(&party),
                    GROUP,
                    vec![SENDER.into(), "910005".into()],
                    vec![SENDER.into()],
                )
                .with_title("Team")
                .with_ttl_msec(86_400_000),
                "1700000000123",
            )
            .unwrap();
        let key = created.conversation_key.clone().unwrap();
        assert_key_change(&party, &created.action_signatures[0], GROUP, &key, version);
        let create = &created.action_signatures[1];
        let title = created.encrypted_title.as_deref().unwrap();
        let v7 = format!(
            "GroupChangeEvent.GroupCreate,{},{SENDER},1700000000123,{SENDER},910005,null,{title},null",
            create.message_id
        );
        let expected = if v1 {
            // Version 9 adds the group type, unset here, and 10 the TTL.
            format!("{v7},null,86400000,signature_version=10")
        } else {
            v7
        };
        assert_eq!(create.signature_payload, expected);
        assert_eq!(create.message_event_signature.signature_version, version);
        assert!(verifies(&party, create, GROUP, &HashMap::new()));
    }
}

#[test]
fn a_member_add_signs_its_description_slot_while_sends_are_v1() {
    for (v1, description, version) in [
        (false, None, "7"),
        (false, Some("About"), "8"),
        (true, None, "10"),
        (true, Some("About"), "10"),
    ] {
        let party = signer();
        if v1 {
            enable_v1_send(&party.core);
        }
        let mut params = GroupMembersChangeParams::new(
            public_keys(&party),
            GROUP,
            vec!["910006".into()],
            vec![SENDER.into(), "910005".into()],
            vec![SENDER.into()],
            vec![],
        )
        .with_current_title("Team")
        .with_current_screen_capture_blocking_enabled(true);
        if let Some(description) = description {
            params = params.with_current_description(description);
        }
        let changed = party
            .core
            .prepare_group_members_change_with_version(&params, "1700000000123")
            .unwrap();
        let key = changed.conversation_key.clone().unwrap();
        let key_change_version = if v1 { "10" } else { "7" };
        assert_key_change(
            &party,
            &changed.action_signatures[0],
            GROUP,
            &key,
            key_change_version,
        );
        let add = &changed.action_signatures[1];
        let title = changed.encrypted_title.as_deref().unwrap();
        let mut expected = format!(
            "GroupChangeEvent.GroupMemberAddChange,{},{SENDER},{GROUP},910006,{SENDER},910005,{SENDER},{title},null,null,1700000000123,true",
            add.message_id
        );
        if version != "7" {
            let slot = changed.encrypted_description.as_deref().unwrap_or("null");
            expected.push_str(&format!(",{slot}"));
        }
        if v1 {
            expected.push_str(",signature_version=10");
        }
        assert_eq!(add.signature_payload, expected, "{description:?}");
        assert_eq!(add.message_event_signature.signature_version, version);
        assert!(verifies(&party, add, GROUP, &HashMap::new()));
    }
}
