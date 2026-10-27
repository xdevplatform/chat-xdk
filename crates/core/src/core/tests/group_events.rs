//! Group and conversation-settings changes as `decrypt_event` reads them,
//! and the encrypted group titles `decrypt` reads.

use super::*;

#[test]
fn decrypt_reads_the_title_a_title_change_sends() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    for title in ["Board: layoffs, Q3", "Équipe 🚀", "x"] {
        let prepared = core
            .prepare_group_title_change(
                &crate::GroupTitleChangeParams::new("g100", title)
                    .with_identity("910004", "1")
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        assert_ne!(prepared.encrypted_value, title);
        assert_eq!(
            core.decrypt(&prepared.encrypted_value, &key).unwrap(),
            title
        );
    }
}

#[test]
fn decrypt_wrong_key_fails() {
    let core = ChatCore::new();
    let key1 = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let key2 = XChatConversationKey::from_bytes(vec![0x43u8; 32]).unwrap();
    let ciphertext_b64 = encrypted_metadata(&key1, "secret");
    assert!(core.decrypt(&ciphertext_b64, &key2).is_err());
}

// GroupChange sub-variants

fn group_create_event(title: &str, conversation_key_version: Option<&str>) -> String {
    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupCreate(
            GroupCreate::new(
                Some(vec!["m1".to_string(), "m2".to_string()]),
                Some(vec!["a1".to_string()]),
                Some(title.to_string()),
                Some("https://ton.x.com/xchat_media/g1/avatar".to_string()),
                conversation_key_version.map(str::to_string),
                None::<bool>,
                None::<i64>,
                None,
            ),
        )),
        None,
    );
    build_test_event(ThriftDetail::GroupChangeEvent(gc))
}

fn received_group_change(
    core: &ChatCore,
    event_b64: &str,
    keys: &HashMap<String, XChatConversationKey>,
) -> GroupChange {
    match core.decrypt_event_with(event_b64, keys, &[]).unwrap() {
        Event::GroupChange(gc) => gc.change,
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_group_create() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let encrypted_title = encrypted_metadata(&key, "Test Group");
    let event_b64 = group_create_event(&encrypted_title, Some("1"));
    let created = |keys: &HashMap<String, XChatConversationKey>| match received_group_change(
        &core, &event_b64, keys,
    ) {
        GroupChange::Created {
            member_ids,
            admin_ids,
            title,
            avatar_url,
            conversation_key_version,
        } => (
            member_ids,
            admin_ids,
            title,
            avatar_url,
            conversation_key_version,
        ),
        other => panic!("Expected GroupChange::Created, got {:?}", other),
    };

    // Without the key the create names, the title is unavailable and the
    // rest of the create still reads.
    let (member_ids, admin_ids, title, avatar_url, version) = created(&HashMap::new());
    assert_eq!(member_ids, ["m1", "m2"]);
    assert_eq!(admin_ids, ["a1"]);
    assert_eq!(
        title,
        Some(GroupText::Unavailable {
            raw: encrypted_title
        })
    );
    assert_eq!(
        avatar_url.as_deref(),
        Some("https://ton.x.com/xchat_media/g1/avatar")
    );
    assert_eq!(version.as_deref(), Some("1"));

    let (_, _, title, avatar_url, _) = created(&HashMap::from([("1".to_string(), key)]));
    assert_eq!(title, Some(text("Test Group")));
    assert_eq!(
        avatar_url.as_deref(),
        Some("https://ton.x.com/xchat_media/g1/avatar")
    );
}

#[test]
fn decrypt_event_group_titles_without_ciphertext_read_as_carried() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let keys = HashMap::from([("1".to_string(), key)]);
    let title = |event_b64: &str| match received_group_change(&core, event_b64, &keys) {
        GroupChange::Created { title, .. } => title,
        other => panic!("Expected GroupChange::Created, got {:?}", other),
    };

    // A create that names no key version carries its title as plaintext.
    assert_eq!(
        title(&group_create_event("Plain Group", None)),
        Some(text("Plain Group"))
    );
    // A plaintext title that names a key version, as 0.5.x apps sent it,
    // doesn't decrypt even with the key; the event carries it in `raw`.
    assert_eq!(
        title(&group_create_event("Plain Group", Some("1"))),
        Some(GroupText::Unavailable {
            raw: "Plain Group".to_string()
        })
    );
}

#[test]
fn decrypt_event_group_change_avatar_changed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAvatarChange(
            GroupAvatarUrlChange::new(
                Some("https://ton.x.com/xchat_media/g1/avatar".to_string()),
                Some("2".to_string()),
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    // The URL is not encrypted, so it reads without any conversation key.
    match received_group_change(&core, &event_b64, &HashMap::new()) {
        GroupChange::AvatarChanged {
            new_avatar_url,
            conversation_key_version,
        } => {
            assert_eq!(new_avatar_url, "https://ton.x.com/xchat_media/g1/avatar");
            assert_eq!(conversation_key_version.as_deref(), Some("2"));
        }
        other => panic!("Expected AvatarChanged, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_admins_added() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAdminAdd(
            GroupAdminAddChange::new(Some(vec!["admin-new".to_string()])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::AdminsAdded { ref admin_ids } => {
                assert_eq!(admin_ids, &["admin-new"]);
            }
            other => panic!("Expected AdminsAdded, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_admins_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupAdminRemove(
            GroupAdminRemoveChange::new(Some(vec!["admin-old".to_string()])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::AdminsRemoved { ref admin_ids } => {
                assert_eq!(admin_ids, &["admin-old"]);
            }
            other => panic!("Expected AdminsRemoved, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_members_added() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberAdd(
            GroupMemberAddChange::new(
                Some(vec!["new-member".to_string()]),
                Some(vec!["m1".to_string(), "m2".to_string()]),
                Some(vec!["a1".to_string()]),
                Some("Title".to_string()),
                Some("avatar".to_string()),
                Some("v3".to_string()),
                Some(30000i64),
                None::<Vec<String>>,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::MembersAdded {
                ref member_ids,
                ref current_member_ids,
                ref current_admin_ids,
            } => {
                assert_eq!(member_ids, &["new-member"]);
                assert_eq!(current_member_ids, &["m1", "m2"]);
                assert_eq!(current_admin_ids, &["a1"]);
            }
            other => panic!("Expected MembersAdded, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_members_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupMemberRemove(
            GroupMemberRemoveChange::new(Some(vec!["removed-user".to_string()]), None),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::MembersRemoved { ref member_ids } => {
                assert_eq!(member_ids, &["removed-user"]);
            }
            other => panic!("Expected MembersRemoved, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_invite_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupInviteEnable(
            GroupInviteEnable::new(
                Some(1700000100000i64),
                Some("https://invite.link".to_string()),
                None::<String>,
            ),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::InviteEnabled {
                ref invite_url,
                expires_at_msec,
            } => {
                assert_eq!(invite_url, "https://invite.link");
                assert_eq!(expires_at_msec, Some(1700000100000));
            }
            other => panic!("Expected InviteEnabled, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_invite_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupInviteDisable(
            GroupInviteDisable::new(Some("admin-1".to_string())),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::InviteDisabled { ref disabled_by } => {
                assert_eq!(disabled_by.as_deref(), Some("admin-1"));
            }
            other => panic!("Expected InviteDisabled, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_join_requested() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupJoinRequest(
            GroupJoinRequest::new(Some("requester-1".to_string())),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::JoinRequested { ref user_id } => {
                assert_eq!(user_id, "requester-1");
            }
            other => panic!("Expected JoinRequested, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_group_change_join_rejected() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let gc = ThriftGCE::new(
        Some(crate::thrift::event::GroupChange::GroupJoinReject(
            GroupJoinReject::new(Some(vec![
                "rejected-1".to_string(),
                "rejected-2".to_string(),
            ])),
        )),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::GroupChangeEvent(gc));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::GroupChange(gc) => match gc.change {
            GroupChange::JoinRejected { ref user_ids } => {
                assert_eq!(user_ids, &["rejected-1", "rejected-2"]);
            }
            other => panic!("Expected JoinRejected, got {:?}", other),
        },
        other => panic!("Expected Event::GroupChange, got {:?}", other),
    }
}

// ConversationMetadataChangeEvent (SettingsChange) sub-variants

#[test]
fn decrypt_event_settings_change_message_duration() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MessageDurationChange(MessageDurationChange::new(
        Some(60000i64),
        Some(true),
    ));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => match sc.change {
            SettingsChange::MessageDuration {
                ttl_msec,
                apply_to_all,
            } => {
                assert_eq!(ttl_msec, 60000);
                assert!(apply_to_all);
            }
            other => panic!("Expected MessageDuration, got {:?}", other),
        },
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_message_duration_removed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MessageDurationRemove(MessageDurationRemove::new(
        Some(30000i64),
    ));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::MessageDurationRemoved));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_muted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::MuteConversation(MuteConversation::new(Some(vec![
        "conv-1".to_string(),
    ])));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Muted));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_unmuted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change =
        ConversationMetadataChange::UnmuteConversation(UnmuteConversation::new(Some(vec![
            "conv-1".to_string(),
        ])));
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Unmuted));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_detection_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::EnableScreenCaptureDetection(
        EnableScreenCaptureDetection::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureDetectionEnabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_detection_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::DisableScreenCaptureDetection(
        DisableScreenCaptureDetection::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureDetectionDisabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_blocking_enabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::EnableScreenCaptureBlocking(
        EnableScreenCaptureBlocking::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureBlockingEnabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_screen_capture_blocking_disabled() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let change = ConversationMetadataChange::DisableScreenCaptureBlocking(
        DisableScreenCaptureBlocking::new(None::<String>),
    );
    let cmce = ThriftCMCE::new(Some(change));
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(
                sc.change,
                SettingsChange::ScreenCaptureBlockingDisabled
            ));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}

#[test]
fn decrypt_event_settings_change_none_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let cmce = ThriftCMCE::new(None::<ConversationMetadataChange>);
    let event_b64 = build_test_event(ThriftDetail::ConversationMetadataChangeEvent(cmce));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::SettingsChange(sc) => {
            assert!(matches!(sc.change, SettingsChange::Unknown));
        }
        other => panic!("Expected Event::SettingsChange, got {:?}", other),
    }
}
