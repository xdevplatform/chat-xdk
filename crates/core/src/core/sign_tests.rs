//! The public `sign` refuses data only the SDK signs, so it can't produce a
//! signature that verifies as a protocol event or a key binding, and it signs
//! any other data with the SDK's signer, byte for byte.

use super::test_support::{
    envelope, frame, message_payload, Party, CONVERSATION, SIGNING_KEY_VERSION,
};
use super::*;
use crate::params::{
    GroupAdminsAddParams, GroupAdminsRemoveParams, GroupAvatarChangeParams,
    GroupDescriptionChangeParams, GroupInviteDisableParams, GroupInviteEnableParams,
    GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams, GroupMembersRemoveParams,
    GroupTitleChangeParams, MessageTtlChangeParams, MessageTtlRemoveParams, ScreenCaptureParams,
};
use crate::signatures::{MAX_SIGNATURE_VERSION, MIN_SIGNATURE_VERSION};
use crate::thrift::event::{
    ConversationKeyChangeEvent as ThriftKeyChange, ConversationMetadataChange,
    ConversationMetadataChangeEvent, ConversationParticipantKey as ThriftParticipantKey,
    MarkConversationUnreadEvent, MessageEvent as ThriftEvent, MessageEventDetail as Detail,
    MessageEventSignature as ThriftSignature, MuteConversation, UnmuteConversation,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePublicKey;

fn refused(core: &ChatCore, data: &[u8]) -> bool {
    matches!(core.sign(data), Err(SdkError::InvalidInput(_)))
}

fn signer(user_id: &str) -> ChatCore {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new(user_id, "1"))
        .unwrap();
    core
}

#[test]
fn sign_refuses_every_action_payload_the_sdk_signs() {
    let core = signer("111");
    let keys = vec![PublicKeyInput::new(
        "111",
        core.get_public_keys().unwrap().identity,
        "1",
    )];
    let ids = |list: &[&str]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    let conversation_key = core.generate_conversation_key().unwrap().to_bytes();

    let removal = GroupMembersRemoveParams::new(keys.clone(), "g1", ids(&["222"]))
        .with_title("title")
        .with_description("desc");
    let mut leave = GroupLeaveParams::new("g1");
    leave.promote_admin_id = Some("222".to_string());

    let mut actions = Vec::new();
    actions.extend(
        core.prepare_message_delete(&MessageDeleteParams::new("111:222", ids(&["5"]), true))
            .unwrap()
            .action_signatures,
    );
    actions.extend(
        core.prepare_mark_conversation_read(&MarkConversationReadParams::new("111:222", "5"))
            .unwrap()
            .action_signatures,
    );
    actions.extend(
        core.prepare_group_create(&GroupCreateParams::new(
            keys.clone(),
            "g1",
            ids(&["111", "222"]),
            ids(&["111"]),
        ))
        .unwrap()
        .action_signatures,
    );
    actions.extend(
        core.prepare_group_members_change(&GroupMembersChangeParams::new(
            keys.clone(),
            "g1",
            ids(&["333"]),
            ids(&["111"]),
            ids(&["111"]),
            vec![],
        ))
        .unwrap()
        .action_signatures,
    );
    actions.extend(
        core.prepare_group_members_remove(&removal)
            .unwrap()
            .action_signatures,
    );
    actions.extend(core.prepare_group_leave(&leave).unwrap().action_signatures);
    let title = GroupTitleChangeParams::new("g1", "title")
        .with_conversation_key(conversation_key.clone(), "1");
    actions.extend(
        core.prepare_group_title_change(&title)
            .unwrap()
            .action_signatures,
    );
    let avatar = GroupAvatarChangeParams::new("g1", "avatar", "1");
    actions.extend(
        core.prepare_group_avatar_change(&avatar)
            .unwrap()
            .action_signatures,
    );
    let description = GroupDescriptionChangeParams::new("g1", "desc")
        .with_conversation_key(conversation_key.clone(), "1");
    actions.extend(
        core.prepare_group_description_change(&description)
            .unwrap()
            .action_signatures,
    );
    let admins_add = GroupAdminsAddParams::new("g1", ids(&["222"]));
    actions.extend(
        core.prepare_group_admins_add(&admins_add)
            .unwrap()
            .action_signatures,
    );
    let admins_remove = GroupAdminsRemoveParams::new("g1", ids(&["222"]));
    actions.extend(
        core.prepare_group_admins_remove(&admins_remove)
            .unwrap()
            .action_signatures,
    );
    let invite = GroupInviteEnableParams::new("g1", "https://x.com/i/chat/invite");
    actions.extend(
        core.prepare_group_invite_enable(&invite)
            .unwrap()
            .action_signatures,
    );
    let uninvite = GroupInviteDisableParams::new("g1");
    actions.extend(
        core.prepare_group_invite_disable(&uninvite)
            .unwrap()
            .action_signatures,
    );
    let join = GroupJoinRequestParams::new("g1");
    actions.extend(
        core.prepare_group_join_request(&join)
            .unwrap()
            .action_signatures,
    );
    let reject = GroupJoinRejectParams::new("g1", ids(&["333"]));
    actions.extend(
        core.prepare_group_join_reject(&reject)
            .unwrap()
            .action_signatures,
    );
    let ttl = MessageTtlChangeParams::new("g1", 86_400_000);
    actions.extend(
        core.prepare_message_ttl_change(&ttl)
            .unwrap()
            .action_signatures,
    );
    let no_ttl = MessageTtlRemoveParams::new("g1");
    actions.extend(
        core.prepare_message_ttl_remove(&no_ttl)
            .unwrap()
            .action_signatures,
    );
    for change in [
        ScreenCaptureChange::BlockingEnabled,
        ScreenCaptureChange::BlockingDisabled,
        ScreenCaptureChange::DetectionEnabled,
        ScreenCaptureChange::DetectionDisabled,
    ] {
        let params = ScreenCaptureParams::new("g1", change);
        actions.extend(
            core.prepare_screen_capture(&params)
                .unwrap()
                .action_signatures,
        );
    }

    // Key-change payloads embed the key and are withheld from
    // `signature_payload`; the next test covers them.
    let payloads: Vec<&str> = actions
        .iter()
        .map(|action| action.signature_payload.as_str())
        .filter(|payload| !payload.is_empty())
        .collect();
    assert_eq!(payloads.len(), 25);
    for payload in payloads {
        assert!(refused(&core, payload.as_bytes()), "signed {payload}");
    }
}

#[test]
fn sign_refuses_every_other_signed_event_payload() {
    let core = signer("111");
    let contents = [7u8; 40];
    for version in MIN_SIGNATURE_VERSION..=MAX_SIGNATURE_VERSION {
        let payload = message_payload("m1", "111", "1", &contents, Some(1), version);
        assert!(refused(&core, payload.as_bytes()), "signed {payload}");
    }

    let key = STANDARD_NO_PAD.encode([9u8; 32]);
    let event = |detail: &Detail, version: i32| ThriftEvent {
        message_id: Some("m1".to_string()),
        sender_id: Some("111".to_string()),
        conversation_id: Some(CONVERSATION.to_string()),
        detail: Some(detail.clone()),
        message_event_signature: Some(ThriftSignature {
            signature_version: Some(version.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let metadata = |change| {
        Detail::ConversationMetadataChangeEvent(ConversationMetadataChangeEvent::new(change))
    };
    let details = [
        Detail::ConversationKeyChangeEvent(ThriftKeyChange::new(
            Some("1800000000000".to_string()),
            Some(vec![ThriftParticipantKey::new(
                Some("111".to_string()),
                Some("ekey".to_string()),
                Some("1".to_string()),
            )]),
            None,
            None,
        )),
        Detail::MarkConversationUnreadEvent(MarkConversationUnreadEvent::new("5".to_string())),
        metadata(ConversationMetadataChange::MuteConversation(
            MuteConversation::new(vec!["c1".to_string()]),
        )),
        metadata(ConversationMetadataChange::UnmuteConversation(
            UnmuteConversation::new(vec!["c1".to_string()]),
        )),
    ];
    for detail in &details {
        for version in [5, 7, 9, 11] {
            let rebuilt =
                build_event_signature_payload(&event(detail, version), detail, Some(key.as_str()))
                    .expect("a signed event type has a payload");
            assert!(
                refused(&core, &rebuilt),
                "signed {}",
                String::from_utf8_lossy(&rebuilt)
            );
        }
    }
}

#[test]
fn sign_refuses_public_keys_in_every_encoding_the_sdk_reads() {
    let core = signer("111");
    let other = signer("222");
    for owner in [&core, &other] {
        let keys = owner.get_public_keys().unwrap();
        for public_key_b64 in [keys.identity, keys.signing] {
            let sec1 = base64_decode(&public_key_b64).unwrap();
            let key = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
            let compressed = key.to_encoded_point(true).as_bytes().to_vec();
            let spki = key.to_public_key_der().unwrap().as_bytes().to_vec();
            // The 23-byte algorithm header, then a BIT STRING of the compressed point.
            let compressed_spki = {
                let mut der = spki[..23].to_vec();
                der[1] = 0x39;
                der.extend_from_slice(&[0x03, 0x22, 0x00]);
                der.extend_from_slice(&compressed);
                der
            };
            // The SDK reads any 91-byte key by its last 65 bytes.
            let foreign_header = [vec![0u8; 26], sec1.clone()].concat();
            for encoding in [&sec1, &compressed, &spki, &compressed_spki, &foreign_header] {
                assert!(
                    refused(&core, encoding),
                    "signed a {}-byte key",
                    encoding.len()
                );
            }
        }
    }
    let registration = signer("333").generate_keypairs().unwrap();
    let identity_spki = base64_decode(&registration.public_key.public_key).unwrap();
    assert!(refused(&core, &identity_spki));
}

#[test]
fn sign_signs_application_data_with_the_sdk_signer() {
    let core = signer("111");
    let signing_key = core.get_signing_private_key().unwrap();
    let signing_public = core.get_public_keys().unwrap().signing;
    let delete = core
        .prepare_message_delete(&MessageDeleteParams::new(
            "111:222",
            vec!["5".to_string()],
            true,
        ))
        .unwrap();
    let payload = delete.action_signatures[0].signature_payload.clone();
    let data: Vec<Vec<u8>> = vec![
        b"chat-xdk test vector message".to_vec(),
        Vec::new(),
        vec![0u8; 65],
        b"MessageCreateEvent".to_vec(),
        b"GroupChangeEvent,1".to_vec(),
        b"messagedeleteevent,1,2,3".to_vec(),
        format!(" {payload}").into_bytes(),
        format!("\u{feff}{payload}").into_bytes(),
        payload.replacen(',', ";", 1).into_bytes(),
        payload
            .replacen("MessageDeleteEvent", "MessageDeleteEvent ", 1)
            .into_bytes(),
        STANDARD_NO_PAD.encode(&payload).into_bytes(),
    ];
    for item in data {
        let signature = core.sign(&item).unwrap();
        assert_eq!(signature, KeyFactory::sign(&signing_key, &item).unwrap());
        assert!(core.verify(&signing_public, &signature, &item).unwrap());
    }
}

/// The forged key change of the review's probe: Alice's app signs an opaque
/// "challenge" that is a key-change payload for a key the relay knows.
#[test]
fn sign_cannot_forge_a_key_change() {
    let alice = Party::new("1001");
    let version = "1800000000000";
    let relay_key = KeyFactory::generate_conversation_key().unwrap();
    let payload = format!(
        "ConversationKeyChangeEvent,mk1,1001,{CONVERSATION},{version},{}",
        STANDARD_NO_PAD.encode(relay_key.encoded())
    );

    let recipient = || {
        let bob = Party::new("1002");
        bob.core
            .set_identity(&SetIdentityParams::new("1002", SIGNING_KEY_VERSION))
            .unwrap();
        bob.core.set_cache_keys(true);
        bob.core
            .set_signing_keys(std::slice::from_ref(&alice.entry));
        bob
    };
    let key_change_to = |bob: &Party, signature: Vec<u8>| {
        let encrypted = alice
            .core
            .encrypt_conversation_key_for_recipients(
                &relay_key,
                &[RecipientInput {
                    user_id: "1002".to_string(),
                    public_key: bob.core.get_public_keys().unwrap().identity,
                    key_version: SIGNING_KEY_VERSION.to_string(),
                }],
            )
            .unwrap();
        let detail = Detail::ConversationKeyChangeEvent(ThriftKeyChange::new(
            Some(version.to_string()),
            Some(vec![ThriftParticipantKey::new(
                Some("1002".to_string()),
                Some(encrypted[0].encrypted_conversation_key.clone()),
                Some(SIGNING_KEY_VERSION.to_string()),
            )]),
            None,
            None,
        ));
        frame(&envelope(
            "mk1",
            &alice,
            "1",
            detail,
            ThriftSignature {
                signature: Some(STANDARD_NO_PAD.encode(signature)),
                public_key_version: Some(SIGNING_KEY_VERSION.to_string()),
                signature_version: Some("7".to_string()),
                ..Default::default()
            },
        ))
    };
    let accepted = |bob: &Party, event: String| {
        let verified = matches!(
            bob.core
                .decrypt_event(&DecryptEventParams::new(event.clone(), HashMap::new())),
            Ok(Event::KeyChange(KeyChangeEvent { verified: true, .. }))
        );
        bob.core
            .decrypt_events(&DecryptEventsParams::new(vec![event]));
        let sent = bob
            .core
            .encrypt_message(&EncryptMessageParams::new(CONVERSATION, "bob's secret"));
        verified || sent.is_ok()
    };

    // A signature over exactly this payload is what a recipient accepts.
    let genuine = alice
        .core
        .sign_key_change(
            SIGNING_KEY_VERSION,
            "mk1",
            "1001",
            CONVERSATION,
            version,
            relay_key.encoded(),
        )
        .unwrap();
    let genuine = base64_decode(&genuine.message_event_signature.signature).unwrap();
    let bob = recipient();
    assert!(accepted(&bob, key_change_to(&bob, genuine)));

    // The public sign() refuses to produce it.
    assert!(refused(&alice.core, payload.as_bytes()));

    // What it signs instead differs in its first bytes, and no recipient
    // verifies a key change with that signature or caches its key.
    for variant in [
        format!(" {payload}"),
        format!("\u{feff}{payload}"),
        payload.to_lowercase(),
    ] {
        let signature = alice.core.sign(variant.as_bytes()).unwrap();
        let bob = recipient();
        assert!(
            !accepted(&bob, key_change_to(&bob, signature)),
            "accepted {variant:?}"
        );
    }
}
