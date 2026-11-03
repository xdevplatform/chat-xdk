use super::*;
use crate::core::build_event_signature_payload;
use crate::crypto::key_factory::KeyFactory;
use crate::params::{
    ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams, GroupAdminsAddParams,
    GroupAdminsRemoveParams, GroupAvatarChangeParams, GroupCreateParams,
    GroupDescriptionChangeParams, GroupInviteDisableParams, GroupInviteEnableParams,
    GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams, GroupMembersRemoveParams,
    GroupTitleChangeParams, MessageTtlChangeParams, MessageTtlRemoveParams, ScreenCaptureParams,
};
use crate::protocol::safe_reader::BoundedProtocol;
use crate::protocol::serialization::base64_decode;
use crate::types::{
    Event, GroupChange as Change, GroupText, PublicKeyInput, ScreenCaptureChange, SigningKeyEntry,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use std::collections::HashMap;
use std::io::Cursor;
use thrift::protocol::{TBinaryInputProtocol, TSerializable};

fn ready_core() -> ChatCore {
    ready_core_and_signing_keys().0
}

/// An unlocked core and the signing key that verifies what it signs as
/// [`identity`].
fn ready_core_and_signing_keys() -> (ChatCore, Vec<SigningKeyEntry>) {
    let core = ChatCore::new();
    let registration = core.generate_keypairs().unwrap().public_key;
    let (sender, version) = identity();
    let signing_keys = vec![SigningKeyEntry::new(
        sender,
        version,
        registration.signing_public_key,
        registration.public_key,
        registration.identity_public_key_signature,
    )];
    (core, signing_keys)
}

fn identity() -> (String, String) {
    ("910004".to_string(), "1".to_string())
}

fn text(value: &str) -> GroupText {
    GroupText::Text {
        text: value.to_string(),
    }
}

/// Whether a signed group action's event is marked as a key-rotation
/// re-encryption.
fn for_key_rotation(signature: &ActionSignature) -> Option<bool> {
    match decode_detail(&signature.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(event) => event.for_key_rotation,
        other => panic!("expected a group change event, got {other:?}"),
    }
}

fn decode_detail(b64: &str) -> MessageEventDetail {
    let bytes = base64_decode(b64).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
    let mut proto = BoundedProtocol::new(&mut raw);
    MessageEventDetail::read_from_in_protocol(&mut proto).unwrap()
}

/// `signature` with its event's `for_key_rotation` set to `flag`. The flag
/// is outside the signed payload, so the signature still verifies.
fn with_for_key_rotation(signature: &ActionSignature, flag: bool) -> ActionSignature {
    let detail = match decode_detail(&signature.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(mut event) => {
            event.for_key_rotation = Some(flag);
            MessageEventDetail::GroupChangeEvent(event)
        }
        MessageEventDetail::ConversationKeyChangeEvent(mut event) => {
            event.for_key_rotation = Some(flag);
            MessageEventDetail::ConversationKeyChangeEvent(event)
        }
        other => panic!("expected a group or key change event, got {other:?}"),
    };
    let mut flagged = signature.clone();
    flagged.encoded_message_event_detail = encode_detail(detail).unwrap();
    flagged
}

/// The title or description a signed group change carries, decrypted
/// under `keys`.
fn reencrypted_text(
    core: &ChatCore,
    keys: &HashMap<String, XChatConversationKey>,
    signature: &ActionSignature,
) -> GroupText {
    let (version, value) = match decode_detail(&signature.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
            group_change: Some(GroupChange::GroupTitleChange(change)),
            ..
        }) => (change.conversation_key_version, change.custom_title),
        MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
            group_change: Some(GroupChange::GroupDescriptionChange(change)),
            ..
        }) => (change.conversation_key_version, change.custom_description),
        other => panic!("expected a title or description change, got {other:?}"),
    };
    core.group_text(
        None,
        keys,
        version.as_deref(),
        value.as_deref().unwrap_or_default(),
    )
}

/// The event recipients receive for a signed action.
fn signed_event(
    signature: &ActionSignature,
    sender_id: &str,
    conversation_id: &str,
) -> crate::thrift::event::MessageEvent {
    let signed = &signature.message_event_signature;
    let event_sig = crate::thrift::event::MessageEventSignature::new(
        Some(signed.signature.clone()),
        Some(signed.public_key_version.clone()),
        Some(signed.signature_version.clone()),
        None::<String>,
        None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
    );
    crate::thrift::event::MessageEvent::new(
        Some("seq-1".to_string()),
        Some(signature.message_id.clone()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(decode_detail(&signature.encoded_message_event_detail)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(event_sig),
        None::<String>,
        None::<bool>,
        None,
    )
}

/// [`signed_event`] as the base64 a webhook delivers.
fn signed_event_b64(signature: &ActionSignature, sender_id: &str, conversation_id: &str) -> String {
    base64_encode(
        &crate::pipeline::serialize_thrift(&signed_event(signature, sender_id, conversation_id))
            .unwrap(),
    )
}

fn decrypted_change(event: Event) -> Change {
    match event {
        Event::GroupChange(change) => {
            assert!(change.verified, "the group change must verify");
            change.change
        }
        other => panic!("expected a group change, got {other:?}"),
    }
}

fn assert_round_trip(
    core: &ChatCore,
    signature: &ActionSignature,
    sender_id: &str,
    conversation_id: &str,
    plaintext_ckey_b64: Option<&str>,
) {
    let event = signed_event(signature, sender_id, conversation_id);
    let detail = event.detail.clone().unwrap();
    let signed = &signature.message_event_signature;
    let reconstructed = build_event_signature_payload(&event, &detail, plaintext_ckey_b64)
        .expect("verifier could not reconstruct the signed payload");
    if !signature.signature_payload.is_empty() {
        assert_eq!(
            reconstructed.as_slice(),
            signature.signature_payload.as_bytes(),
            "signer payload and verifier reconstruction diverge"
        );
    }
    let signing_pubkey = core.get_public_keys().unwrap().signing;
    let sig_bytes = base64_decode(&signed.signature).unwrap();
    assert!(
        core.verify(&signing_pubkey, &sig_bytes, &reconstructed)
            .unwrap(),
        "signature did not verify against the reconstructed payload"
    );
}

fn assert_actions(
    core: &ChatCore,
    signatures: &[ActionSignature],
    sender_id: &str,
    conversation_id: &str,
    plaintext_ckey_b64: Option<&str>,
) {
    for signature in signatures {
        assert_round_trip(
            core,
            signature,
            sender_id,
            conversation_id,
            plaintext_ckey_b64,
        );
    }
}

fn remaining_keys(core: &ChatCore, user_id: &str) -> Vec<PublicKeyInput> {
    vec![PublicKeyInput::new(
        user_id,
        core.get_public_keys().unwrap().identity,
        "1",
    )]
}

#[test]
fn group_create_encrypts_the_title_it_signs() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    // The plaintext never enters the comma-joined payload, so a comma in
    // it is fine.
    let params = GroupCreateParams::new(
        remaining_keys(&core, &sender),
        "g100",
        vec![sender.clone()],
        vec![sender.clone()],
    )
    .with_identity(&sender, &version)
    .with_title("Team, the sequel");
    let created = core.prepare_group_create(&params).unwrap();
    let encrypted_title = created.encrypted_title.clone().unwrap();
    let create = &created.action_signatures[1];
    // A create sets no avatar: the title slot is followed by `null`.
    assert!(create
        .signature_payload
        .ends_with(&format!(",{encrypted_title},null")));
    assert!(!create.signature_payload.contains("Team"));

    let event_b64 = signed_event_b64(create, &sender, "g100");
    let keys = HashMap::from([(
        created.conversation_key_version.clone(),
        created.conversation_key.clone().unwrap(),
    )]);
    match decrypted_change(
        core.decrypt_event_with(&event_b64, &keys, &signing_keys)
            .unwrap(),
    ) {
        Change::Created {
            title,
            avatar_url,
            conversation_key_version,
            ..
        } => {
            assert_eq!(title, Some(text("Team, the sequel")));
            assert_eq!(avatar_url, None);
            assert_eq!(
                conversation_key_version,
                Some(created.conversation_key_version.clone())
            );
        }
        other => panic!("expected Created, got {other:?}"),
    }

    // Without the new key the title is unavailable, and the rest of the
    // create still decrypts.
    match decrypted_change(
        core.decrypt_event_with(&event_b64, &HashMap::new(), &signing_keys)
            .unwrap(),
    ) {
        Change::Created {
            member_ids, title, ..
        } => {
            assert_eq!(member_ids, std::slice::from_ref(&sender));
            assert_eq!(
                title,
                Some(GroupText::Unavailable {
                    raw: encrypted_title
                })
            );
        }
        other => panic!("expected Created, got {other:?}"),
    }
}

#[test]
fn decrypt_events_reads_a_group_create_with_the_key_change_it_carries() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let created = core
        .prepare_group_create(
            &GroupCreateParams::new(
                remaining_keys(&core, &sender),
                "g100",
                vec![sender.clone()],
                vec![sender.clone()],
            )
            .with_identity(&sender, &version)
            .with_title("Board"),
        )
        .unwrap();
    let events = created
        .action_signatures
        .iter()
        .map(|signature| signed_event_b64(signature, &sender, "g100"))
        .collect();

    let batch =
        core.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys));
    assert!(batch.errors.is_empty(), "{:?}", batch.errors);
    let titles: Vec<GroupText> = batch
        .events
        .into_iter()
        .filter_map(|message| match message.event {
            Event::GroupChange(change) => match change.change {
                Change::Created { title, .. } => title,
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(titles, [text("Board")]);
}

#[test]
fn group_create_without_a_title_encrypts_nothing() {
    let core = ready_core();
    let (sender, version) = identity();
    let created = core
        .prepare_group_create(
            &GroupCreateParams::new(
                remaining_keys(&core, &sender),
                "g100",
                vec![sender.clone()],
                vec![sender.clone()],
            )
            .with_identity(&sender, &version),
        )
        .unwrap();
    assert_eq!(created.encrypted_title, None);
    assert_eq!(created.encrypted_description, None);
    assert!(created.action_signatures[1]
        .signature_payload
        .ends_with(",null,null,null"));
}

#[test]
fn member_remove_signs_the_new_key_then_the_key_change() {
    let core = ready_core();
    let (sender, version) = identity();
    let params = GroupMembersRemoveParams::new(
        remaining_keys(&core, &sender),
        "222-111",
        vec!["910007".into()],
    )
    .with_identity(&sender, &version);
    let prepared = core
        .prepare_group_members_remove_with_version(&params, "42")
        .unwrap();
    assert_eq!(prepared.conversation_id, "111:222");
    assert_eq!(prepared.conversation_key_version, "42");
    assert!(prepared.conversation_key.is_some());
    assert_eq!(prepared.conversation_participant_keys.len(), 1);
    assert_eq!(prepared.action_signatures.len(), 2);
    let removal = &prepared.action_signatures[0];
    assert_eq!(
        removal.message_event_signature.signature_version,
        CURRENT_SIGNATURE_VERSION.to_string()
    );
    // Version 7 signs the removed members only; the event still names the
    // new key version.
    assert_eq!(
        removal.signature_payload,
        format!(
            "GroupChangeEvent.GroupMemberRemoveChange,{},{sender},111:222,910007",
            removal.message_id
        )
    );
    assert_eq!(removed_key_version(removal), Some("42".to_string()));
    assert!(prepared.action_signatures[1].signature_payload.is_empty());
    assert_eq!(
        prepared.action_signatures[1]
            .message_event_signature
            .signature_version,
        CURRENT_SIGNATURE_VERSION.to_string()
    );
    let ckey_b64 = STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
    assert_actions(
        &core,
        &prepared.action_signatures,
        &sender,
        "111:222",
        Some(&ckey_b64),
    );
}

#[test]
fn member_remove_rotates_with_the_clock_version() {
    let core = ready_core();
    let (sender, version) = identity();
    let prepared = core
        .prepare_group_members_remove(
            &GroupMembersRemoveParams::new(
                remaining_keys(&core, &sender),
                "g100",
                vec!["910007".into()],
            )
            .with_identity(&sender, &version),
        )
        .unwrap();
    let key_version = &prepared.conversation_key_version;
    assert!(key_version.parse::<u64>().unwrap() > 0, "{key_version}");
    assert_eq!(
        removed_key_version(&prepared.action_signatures[0]),
        Some(key_version.clone())
    );
    assert_eq!(prepared.action_signatures.len(), 2);
}

/// The conversation-key version a signed member removal's event names.
fn removed_key_version(signature: &ActionSignature) -> Option<String> {
    match decode_detail(&signature.encoded_message_event_detail) {
        MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
            group_change: Some(GroupChange::GroupMemberRemove(change)),
            ..
        }) => change.conversation_key_version,
        other => panic!("expected a member removal, got {other:?}"),
    }
}

#[test]
fn every_action_of_a_member_removal_signs_at_10_while_sends_are_v1() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    crate::core::test_support::enable_v1_send(&core);
    let (sender, version) = identity();
    let prepared = core
        .prepare_group_members_remove_with_version(
            &GroupMembersRemoveParams::new(
                remaining_keys(&core, &sender),
                "g100",
                vec!["910007".into()],
            )
            .with_identity(&sender, &version)
            .with_title("Board"),
            "42",
        )
        .unwrap();
    let versions: Vec<&str> = prepared
        .action_signatures
        .iter()
        .map(|s| s.message_event_signature.signature_version.as_str())
        .collect();
    assert_eq!(versions, ["10", "10", "10"]);
    let removal = &prepared.action_signatures[0];
    // Version 10 does not sign the key version either: 11 is the first.
    assert_eq!(
        removal.signature_payload,
        format!(
            "GroupChangeEvent.GroupMemberRemoveChange,{},{sender},g100,910007,signature_version=10",
            removal.message_id
        )
    );
    let ckey_b64 = STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
    assert_actions(
        &core,
        &prepared.action_signatures,
        &sender,
        "g100",
        Some(&ckey_b64),
    );
    let keys = HashMap::from([("42".to_string(), prepared.conversation_key.clone().unwrap())]);
    let event = core
        .decrypt_event_with(
            &signed_event_b64(removal, &sender, "g100"),
            &keys,
            &signing_keys,
        )
        .unwrap();
    assert!(matches!(
        decrypted_change(event),
        Change::MembersRemoved { .. }
    ));
}

#[test]
fn member_remove_rejects_a_removed_member_in_the_new_key() {
    let core = ready_core();
    let (sender, version) = identity();
    let params = GroupMembersRemoveParams::new(
        remaining_keys(&core, "910007"),
        "g100",
        vec!["910007".into()],
    )
    .with_identity(&sender, &version);
    let err = core
        .prepare_group_members_remove_with_version(&params, "42")
        .unwrap_err();
    assert!(err.to_string().contains("remaining members"), "got: {err}");
}

#[test]
fn member_remove_requires_the_remaining_members_keys() {
    let core = ready_core();
    let (sender, version) = identity();
    let err = core
        .prepare_group_members_remove(
            &GroupMembersRemoveParams::new(vec![], "g100", vec!["910007".into()])
                .with_identity(&sender, &version),
        )
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err:?}");
    assert_eq!(
        err.to_string(),
        "public_keys is empty: pass the public keys of the remaining members"
    );
}

#[test]
fn leave_appends_a_conversation_delete_and_optional_admin_add() {
    let core = ready_core();
    let (sender, version) = identity();
    let params = GroupLeaveParams::new("g100")
        .with_identity(&sender, &version)
        .with_conversation_key_version("7")
        .with_promote_admin_id("910008");
    let prepared = core.prepare_group_leave(&params).unwrap();
    assert_eq!(prepared.action_signatures.len(), 3);
    let removal = &prepared.action_signatures[0];
    assert_eq!(removal.message_event_signature.signature_version, "7");
    assert_eq!(
        removal.signature_payload,
        format!(
            "GroupChangeEvent.GroupMemberRemoveChange,{},{sender},g100,{sender}",
            removal.message_id
        )
    );
    assert_eq!(removed_key_version(removal), Some("7".to_string()));
    assert!(prepared.action_signatures[1]
        .signature_payload
        .ends_with(",910008"));
    assert_eq!(
        prepared.action_signatures[1]
            .message_event_signature
            .signature_version,
        "7"
    );
    let delete = &prepared.action_signatures[2];
    assert_eq!(
        delete.signature_payload,
        format!(
            "ConversationDeleteEvent,{},{sender},g100",
            delete.message_id
        )
    );
    assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);

    let plain = core
        .prepare_group_leave(&GroupLeaveParams::new("g100").with_identity(&sender, &version))
        .unwrap();
    assert_eq!(plain.action_signatures.len(), 2);
    assert_eq!(removed_key_version(&plain.action_signatures[0]), None);
    assert!(plain.action_signatures[0]
        .signature_payload
        .ends_with(&format!(",g100,{sender}")));

    crate::core::test_support::enable_v1_send(&core);
    let v1 = core.prepare_group_leave(&params).unwrap();
    for signature in &v1.action_signatures {
        assert_eq!(signature.message_event_signature.signature_version, "10");
        assert!(signature
            .signature_payload
            .ends_with(",signature_version=10"));
    }
    assert_eq!(
        v1.action_signatures[2].signature_payload,
        format!(
            "ConversationDeleteEvent,{},{sender},g100,signature_version=10",
            v1.action_signatures[2].message_id
        )
    );
    assert_actions(&core, &v1.action_signatures, &sender, "g100", None);
}

#[test]
fn group_metadata_actions_round_trip_through_the_verifier() {
    let core = ready_core();
    let (sender, version) = identity();
    let cases: Vec<PreparedAction> = vec![
        core.prepare_group_admins_add(
            &GroupAdminsAddParams::new("g100", vec!["910008".into(), "910009".into()])
                .with_identity(&sender, &version),
        )
        .unwrap(),
        core.prepare_group_admins_remove(
            &GroupAdminsRemoveParams::new("g100", vec!["910008".into()])
                .with_identity(&sender, &version),
        )
        .unwrap(),
        core.prepare_group_join_reject(
            &GroupJoinRejectParams::new("g100", vec!["910010".into()])
                .with_identity(&sender, &version),
        )
        .unwrap(),
        core.prepare_message_ttl_change(
            &MessageTtlChangeParams::new("g100", 86_400_000).with_identity(&sender, &version),
        )
        .unwrap(),
        core.prepare_message_ttl_remove(
            &MessageTtlRemoveParams::new("g100").with_identity(&sender, &version),
        )
        .unwrap(),
    ];
    let expected_prefixes = [
        "GroupChangeEvent.GroupAdminAddChange,",
        "GroupChangeEvent.GroupAdminRemoveChange,",
        "GroupChangeEvent.GroupJoinReject,",
        "ConversationMetadataChangeEvent.MessageDurationChange,",
        "ConversationMetadataChangeEvent.MessageDurationRemove,",
    ];
    for (prepared, prefix) in cases.iter().zip(expected_prefixes) {
        assert_eq!(prepared.action_signatures.len(), 1);
        let payload = &prepared.action_signatures[0].signature_payload;
        assert!(payload.starts_with(prefix), "{payload}");
        assert_eq!(
            prepared.action_signatures[0]
                .message_event_signature
                .signature_version,
            "7"
        );
        assert!(!payload.contains("signature_version="));
        assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);
    }
    let ttl = &cases[3].action_signatures[0].signature_payload;
    assert!(ttl.ends_with(",86400000"), "{ttl}");
}

#[test]
fn title_and_description_changes_sign_ciphertext_that_decrypts_on_receive() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let key = KeyFactory::generate_conversation_key().unwrap();
    let keys = HashMap::from([("7".to_string(), key.clone())]);
    let title = core
        .prepare_group_title_change(
            &GroupTitleChangeParams::new("g100", "Board: layoffs, Q3")
                .with_identity(&sender, &version)
                .with_conversation_key(key.to_bytes(), "7"),
        )
        .unwrap();
    let description = core
        .prepare_group_description_change(
            &GroupDescriptionChangeParams::new("g100", "Rules: be kind")
                .with_identity(&sender, &version)
                .with_conversation_key(key.to_bytes(), "7"),
        )
        .unwrap();
    let cases = [
        (
            title,
            "GroupChangeEvent.GroupTitleChange,",
            "Board: layoffs, Q3",
        ),
        (
            description,
            "GroupChangeEvent.GroupDescriptionChange,",
            "Rules: be kind",
        ),
    ];
    for (prepared, prefix, plaintext) in cases {
        assert_eq!(prepared.conversation_key_version, "7");
        assert_eq!(prepared.action_signatures.len(), 1);
        let signature = &prepared.action_signatures[0];
        let payload = &signature.signature_payload;
        assert!(payload.starts_with(prefix), "{payload}");
        assert!(
            payload.ends_with(&format!(",7,{}", prepared.encrypted_value)),
            "{payload}"
        );
        assert!(!payload.contains(plaintext), "{payload}");
        assert_eq!(signature.message_event_signature.signature_version, "7");
        assert_eq!(for_key_rotation(signature), Some(false));
        let detail = base64_decode(&signature.encoded_message_event_detail).unwrap();
        assert!(!String::from_utf8_lossy(&detail).contains(plaintext));
        assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);

        let change = decrypted_change(
            core.decrypt_event(
                &DecryptEventParams::new(
                    signed_event_b64(signature, &sender, "g100"),
                    keys.clone(),
                )
                .with_signing_keys(signing_keys.clone()),
            )
            .unwrap(),
        );
        let decrypted = match change {
            Change::TitleChanged { new_title } => new_title,
            Change::DescriptionChanged { new_description } => new_description,
            other => panic!("expected a title or description change, got {other:?}"),
        };
        assert_eq!(decrypted, text(plaintext));
    }
}

#[test]
fn avatar_change_signs_the_media_url_as_is() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let url = "https://ton.x.com/xchat_media/g100/avatar";
    let prepared = core
        .prepare_group_avatar_change(
            &GroupAvatarChangeParams::new("g100", url, "7").with_identity(&sender, &version),
        )
        .unwrap();
    assert_eq!(prepared.action_signatures.len(), 1);
    let signature = &prepared.action_signatures[0];
    let payload = &signature.signature_payload;
    assert!(
        payload.starts_with("GroupChangeEvent.GroupAvatarUrlChange,"),
        "{payload}"
    );
    assert!(payload.ends_with(&format!(",7,{url}")), "{payload}");
    assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);

    // Recipients read the URL and the version of the key the image is
    // encrypted under, whether or not they hold that key.
    let change = decrypted_change(
        core.decrypt_event(
            &DecryptEventParams::new(signed_event_b64(signature, &sender, "g100"), HashMap::new())
                .with_signing_keys(signing_keys),
        )
        .unwrap(),
    );
    match change {
        Change::AvatarChanged {
            new_avatar_url,
            conversation_key_version,
        } => {
            assert_eq!(new_avatar_url, url);
            assert_eq!(conversation_key_version.as_deref(), Some("7"));
        }
        other => panic!("expected AvatarChanged, got {other:?}"),
    }
}

#[test]
fn metadata_change_resolves_the_cached_key_like_encrypt_message() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let params = GroupTitleChangeParams::new("g100", "Cached").with_identity(&sender, &version);
    let err = core.prepare_group_title_change(&params).unwrap_err();
    assert!(matches!(err, SdkError::InvalidState(_)), "got: {err:?}");
    assert!(err
        .to_string()
        .contains("no cached conversation key for 'g100'"));

    core.set_cache_keys(true);
    let mut key_change = ConversationKeyChangeParams::new(remaining_keys(&core, &sender))
        .with_identity(&sender, &version);
    key_change.conversation_id = Some("g100".into());
    let rotated = core
        .prepare_conversation_key_change_with_version(&key_change, "42")
        .unwrap();
    let batch = core.decrypt_events(
        &DecryptEventsParams::new(vec![signed_event_b64(
            &rotated.action_signatures[0],
            &sender,
            "g100",
        )])
        .with_signing_keys(signing_keys.clone()),
    );
    assert!(batch.errors.is_empty(), "{:?}", batch.errors);

    let title = core.prepare_group_title_change(&params).unwrap();
    assert_eq!(title.conversation_key_version, "42");
    let change = decrypted_change(
        core.decrypt_event(
            &DecryptEventParams::new(
                signed_event_b64(&title.action_signatures[0], &sender, "g100"),
                HashMap::new(),
            )
            .with_signing_keys(signing_keys),
        )
        .unwrap(),
    );
    assert!(
        matches!(change, Change::TitleChanged { ref new_title } if *new_title == text("Cached"))
    );
}

#[test]
fn metadata_change_without_its_key_is_unavailable_on_receive() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let key = KeyFactory::generate_conversation_key().unwrap();
    let description = core
        .prepare_group_description_change(
            &GroupDescriptionChangeParams::new("g100", "Rules")
                .with_identity(&sender, &version)
                .with_conversation_key(key.to_bytes(), "7"),
        )
        .unwrap();
    let change = decrypted_change(
        core.decrypt_event(
            &DecryptEventParams::new(
                signed_event_b64(&description.action_signatures[0], &sender, "g100"),
                HashMap::new(),
            )
            .with_signing_keys(signing_keys),
        )
        .unwrap(),
    );
    match change {
        Change::DescriptionChanged { new_description } => assert_eq!(
            new_description,
            GroupText::Unavailable {
                raw: description.encrypted_value
            }
        ),
        other => panic!("expected DescriptionChanged, got {other:?}"),
    }
}

#[test]
fn member_remove_reencrypts_the_metadata_under_the_new_key() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let params = GroupMembersRemoveParams::new(
        remaining_keys(&core, &sender),
        "g100",
        vec!["910007".into()],
    )
    .with_identity(&sender, &version)
    .with_title("Board")
    .with_description("Rules: be kind");
    let prepared = core
        .prepare_group_members_remove_with_version(&params, "42")
        .unwrap();
    let payloads: Vec<&str> = prepared
        .action_signatures
        .iter()
        .map(|signature| signature.signature_payload.as_str())
        .collect();
    assert_eq!(payloads.len(), 4, "{payloads:?}");
    assert!(payloads[0].starts_with("GroupChangeEvent.GroupMemberRemoveChange,"));
    assert!(payloads[1].starts_with("GroupChangeEvent.GroupTitleChange,"));
    assert!(payloads[2].starts_with("GroupChangeEvent.GroupDescriptionChange,"));
    assert!(
        payloads[3].is_empty(),
        "the key change withholds its payload"
    );
    assert!(payloads[1].contains(",42,"), "{}", payloads[1]);
    // The re-encryptions are marked as such, so recipients don't show
    // them as changes; the removal itself is not.
    let rotation: Vec<Option<bool>> = prepared.action_signatures[..3]
        .iter()
        .map(for_key_rotation)
        .collect();
    assert_eq!(rotation, [Some(false), Some(true), Some(true)]);

    let keys = HashMap::from([("42".to_string(), prepared.conversation_key.clone().unwrap())]);
    assert_eq!(
        reencrypted_text(&core, &keys, &prepared.action_signatures[1]),
        text("Board")
    );
    assert_eq!(
        reencrypted_text(&core, &keys, &prepared.action_signatures[2]),
        text("Rules: be kind")
    );
    // Recipients drop the re-encryptions, which still verify.
    for index in [1, 2] {
        let err = core
            .decrypt_event(
                &DecryptEventParams::new(
                    signed_event_b64(&prepared.action_signatures[index], &sender, "g100"),
                    keys.clone(),
                )
                .with_signing_keys(signing_keys.clone()),
            )
            .unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput, "{err}");
    }
    let ckey_b64 = STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
    assert_actions(
        &core,
        &prepared.action_signatures,
        &sender,
        "g100",
        Some(&ckey_b64),
    );
}

/// A removal of 910007 with the group's title and description, under key
/// version 42, as recipients receive it: the removal, the title and the
/// description re-encryptions, then the key change.
fn removal_events(core: &ChatCore, sender: &str, version: &str) -> Vec<String> {
    let params =
        GroupMembersRemoveParams::new(remaining_keys(core, sender), "g100", vec!["910007".into()])
            .with_identity(sender, version)
            .with_title("Board")
            .with_description("Rules: be kind");
    core.prepare_group_members_remove_with_version(&params, "42")
        .unwrap()
        .action_signatures
        .iter()
        .map(|signature| signed_event_b64(signature, sender, "g100"))
        .collect()
}

#[test]
fn decrypt_drops_the_metadata_a_member_remove_reencrypts() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let events = removal_events(&core, &sender, &version);
    assert_eq!(events.len(), 4);

    for reject_unverified in [true, false] {
        core.set_reject_unverified(reject_unverified);
        let batch = core.decrypt_events(
            &DecryptEventsParams::new(events.clone()).with_signing_keys(signing_keys.clone()),
        );
        let kept: Vec<&Event> = batch.events.iter().map(|event| &event.event).collect();
        assert_eq!(kept.len(), 2, "{kept:?}");
        match kept[0] {
            Event::GroupChange(change) => {
                assert!(change.verified);
                assert!(matches!(
                    change.change,
                    Change::MembersRemoved { ref member_ids } if member_ids == &["910007"]
                ));
            }
            other => panic!("expected the removal, got {other:?}"),
        }
        match kept[1] {
            Event::KeyChange(key_change) => {
                assert!(key_change.verified);
                assert_eq!(key_change.conversation_key_version, "42");
            }
            other => panic!("expected the key change, got {other:?}"),
        }
        let mut dropped: Vec<usize> = batch.errors.keys().copied().collect();
        dropped.sort_unstable();
        assert_eq!(dropped, [1, 2], "{:?}", batch.errors);
        for (index, field) in [(1, "title"), (2, "description")] {
            assert_eq!(
                batch.errors[&index],
                format!(
                    "GroupChange re-encrypts the group's {field} for a key rotation \
                     (for_key_rotation), not a {field} change: decrypt does not return it"
                )
            );
        }
        assert_eq!(
            batch.conversation_keys.latest_version.as_deref(),
            Some("42")
        );
        assert!(batch.conversation_keys.keys.contains_key("42"));

        let keys = batch.conversation_keys.keys.clone();
        for index in [1, 2] {
            let err = core
                .decrypt_event(
                    &DecryptEventParams::new(events[index].clone(), keys.clone())
                        .with_signing_keys(signing_keys.clone()),
                )
                .unwrap_err();
            assert!(matches!(err, SdkError::InvalidInput(_)), "{err:?}");
            assert_eq!(err.to_string(), batch.errors[&index]);
        }
    }
}

#[test]
fn decrypt_verifies_a_reencryption_before_dropping_it() {
    let (core, _) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let events = removal_events(&core, &sender, &version);
    let err = core
        .decrypt_event(&DecryptEventParams::new(events[1].clone(), HashMap::new()))
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::Verification, "{err}");
}

#[test]
fn decrypt_keeps_changes_that_are_not_metadata_reencryptions() {
    let (core, signing_keys) = ready_core_and_signing_keys();
    let (sender, version) = identity();
    let key = KeyFactory::generate_conversation_key().unwrap();
    let keys = HashMap::from([("42".to_string(), key.clone())]);
    let decrypt = |signature: &ActionSignature| {
        core.decrypt_event(
            &DecryptEventParams::new(signed_event_b64(signature, &sender, "g100"), keys.clone())
                .with_signing_keys(signing_keys.clone()),
        )
    };

    let rename = core
        .prepare_group_title_change(
            &GroupTitleChangeParams::new("g100", "Renamed")
                .with_identity(&sender, &version)
                .with_conversation_key(key.to_bytes(), "42"),
        )
        .unwrap();
    assert!(matches!(
        decrypted_change(decrypt(&rename.action_signatures[0]).unwrap()),
        Change::TitleChanged { ref new_title } if *new_title == text("Renamed")
    ));
    // The flag alone makes a title a re-encryption, and the signature
    // doesn't cover it: the flagged rename still verifies, and is dropped.
    let flagged = with_for_key_rotation(&rename.action_signatures[0], true);
    assert!(matches!(
        decrypt(&flagged).unwrap_err(),
        SdkError::InvalidInput(_)
    ));

    let avatar = core
        .prepare_group_avatar_change(
            &GroupAvatarChangeParams::new("g100", "https://ton.x.com/xchat_media/g100/a", "42")
                .with_identity(&sender, &version),
        )
        .unwrap();
    let flagged = with_for_key_rotation(&avatar.action_signatures[0], true);
    assert!(matches!(
        decrypted_change(decrypt(&flagged).unwrap()),
        Change::AvatarChanged { .. }
    ));

    let mut key_change = ConversationKeyChangeParams::new(remaining_keys(&core, &sender))
        .with_identity(&sender, &version);
    key_change.conversation_id = Some("g100".into());
    let rotated = core
        .prepare_conversation_key_change_with_version(&key_change, "43")
        .unwrap();
    let flagged = with_for_key_rotation(&rotated.action_signatures[0], true);
    let batch = core.decrypt_events(
        &DecryptEventsParams::new(vec![signed_event_b64(&flagged, &sender, "g100")])
            .with_signing_keys(signing_keys.clone()),
    );
    assert!(batch.errors.is_empty(), "{:?}", batch.errors);
    assert!(matches!(
        batch.events[0].event,
        Event::KeyChange(ref change) if change.verified
    ));
    assert_eq!(
        batch.conversation_keys.latest_version.as_deref(),
        Some("43")
    );
}

#[test]
fn invite_and_join_sign_null_sentinels_and_sender_defaults() {
    let core = ready_core();
    let (sender, version) = identity();
    let mut enable = GroupInviteEnableParams::new("g100", "https://x.com/i/invite/abc")
        .with_identity(&sender, &version);
    enable.expires_at_msec = Some(-1);
    enable.affiliate_id = Some(String::new());
    let enabled = core.prepare_group_invite_enable(&enable).unwrap();
    assert!(enabled.action_signatures[0]
        .signature_payload
        .ends_with(",https://x.com/i/invite/abc,null,null"));
    assert_actions(&core, &enabled.action_signatures, &sender, "g100", None);

    let mut timed = GroupInviteEnableParams::new("g100", "https://x.com/i/invite/abc")
        .with_identity(&sender, &version);
    timed.expires_at_msec = Some(1_700_000_000_000);
    timed.affiliate_id = Some("aff-1".into());
    let timed = core.prepare_group_invite_enable(&timed).unwrap();
    assert!(timed.action_signatures[0]
        .signature_payload
        .ends_with(",https://x.com/i/invite/abc,1700000000000,aff-1"));

    let disabled = core
        .prepare_group_invite_disable(
            &GroupInviteDisableParams::new("g100").with_identity(&sender, &version),
        )
        .unwrap();
    assert!(disabled.action_signatures[0]
        .signature_payload
        .ends_with(&format!(",{sender}")));
    assert_actions(&core, &disabled.action_signatures, &sender, "g100", None);

    let request = core
        .prepare_group_join_request(
            &GroupJoinRequestParams::new("g100").with_identity(&sender, &version),
        )
        .unwrap();
    assert!(request.action_signatures[0]
        .signature_payload
        .starts_with("GroupChangeEvent.GroupJoinRequest,"));
    assert!(request.action_signatures[0]
        .signature_payload
        .ends_with(&format!(",{sender}")));
    assert_actions(&core, &request.action_signatures, &sender, "g100", None);
}

#[test]
fn screen_capture_signs_each_verifier_event_name() {
    let core = ready_core();
    let (sender, version) = identity();
    let expected = [
        (
            ScreenCaptureChange::BlockingEnabled,
            "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,",
        ),
        (
            ScreenCaptureChange::BlockingDisabled,
            "ConversationMetadataChangeEvent.DisableScreenCaptureBlocking,",
        ),
        (
            ScreenCaptureChange::DetectionEnabled,
            "ConversationMetadataChangeEvent.EnableScreenCaptureDetection,",
        ),
        (
            ScreenCaptureChange::DetectionDisabled,
            "ConversationMetadataChangeEvent.DisableScreenCaptureDetection,",
        ),
    ];
    for (change, prefix) in expected {
        let prepared = core
            .prepare_screen_capture(
                &ScreenCaptureParams::new("g100", change).with_identity(&sender, &version),
            )
            .unwrap();
        let payload = &prepared.action_signatures[0].signature_payload;
        let message_id = &prepared.action_signatures[0].message_id;
        assert_eq!(payload, &format!("{prefix}{message_id},{sender},g100"));
        assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);
    }
}

#[test]
fn invalid_group_action_inputs_name_the_value() {
    let core = ready_core();
    let (sender, version) = identity();
    let err = core
        .prepare_group_members_remove(
            &GroupMembersRemoveParams::new(remaining_keys(&core, &sender), "g100", vec![])
                .with_identity(&sender, &version),
        )
        .unwrap_err();
    assert!(err.to_string().contains("user_ids"), "got: {err}");

    let key = KeyFactory::generate_conversation_key().unwrap();
    let err = core
        .prepare_group_title_change(
            &GroupTitleChangeParams::new("g100", "")
                .with_identity(&sender, &version)
                .with_conversation_key(key.to_bytes(), "4"),
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "new_title is empty: pass the value this action signs"
    );

    let avatar_change = |url: &str, key_version: &str| {
        core.prepare_group_avatar_change(
            &GroupAvatarChangeParams::new("g100", url, key_version)
                .with_identity(&sender, &version),
        )
        .unwrap_err()
        .to_string()
    };
    assert_eq!(
        avatar_change("", "4"),
        "new_avatar_url is empty: pass the value this action signs"
    );
    assert!(
        avatar_change("https://img/a.png", "v4").contains("conversation_key_version 'v4'"),
        "got: {}",
        avatar_change("https://img/a.png", "v4")
    );
    assert!(
        avatar_change("https://img/a,b.png", "4").contains("comma"),
        "got: {}",
        avatar_change("https://img/a,b.png", "4")
    );

    let err = ScreenCaptureChange::parse("nope").unwrap_err();
    assert_eq!(err.to_string(), "Invalid screen capture change: 'nope'");
}
