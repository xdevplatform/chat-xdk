//! `decrypt_event` for the events that are not group or settings changes:
//! unencrypted and encrypted messages, typing, read markers, deletes,
//! failures, account deletions, and events it does not know.

use super::*;

#[test]
fn decrypt_event_unencrypted_mce_with_none_key_returns_message() {
    let core = ChatCore::new();
    // generate_keypairs loads keys into the manager so verify works
    core.generate_keypairs().unwrap();
    // Unencrypted messages have no signature; allow them through.
    core.set_reject_unverified(false);

    let content = build_plaintext_content("Hello unencrypted!");
    let event_b64 = build_test_message_event(&content, None);

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Hello unencrypted!"));
            assert!(
                msg.conversation_key_version.is_none(),
                "conversation_key_version should be None"
            );
            assert!(!msg.verified, "verified should be false");
            assert_eq!(msg.should_notify, Some(true));
            assert_eq!(msg.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_unencrypted_mce_with_key_still_works() {
    // Even if the caller passes a conversation key, the SDK should
    // recognise the MCE is unencrypted and skip decryption.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(false);

    let content = build_plaintext_content("Plaintext with key present");
    let event_b64 = build_test_message_event(&content, None);

    // Unencrypted MCE — key map is unused, any map works
    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Plaintext with key present"));
            assert!(msg.conversation_key_version.is_none());
            assert!(!msg.verified);
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_unencrypted_mce_reject_unverified_errors() {
    // Unencrypted MCEs carry no signature, so under reject_unverified
    // (the default) they are unverifiable and must be rejected.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("No sig");
    let event_b64 = build_test_message_event(&content, None);

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(
        result.is_err(),
        "unencrypted message must be rejected under reject_unverified"
    );
}

#[test]
fn decrypt_event_encrypted_mce_without_key_errors() {
    // An encrypted MCE with no signing keys and reject_unverified=true
    // (default) should be rejected at the signature check before
    // reaching the missing-key error.
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let content = build_plaintext_content("will be 'encrypted'");
    let event_b64 = build_test_message_event(&content, Some("3"));

    let result = core.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result.is_err());

    // With reject_unverified=false, the signature check passes and
    // we get the missing conversation key error instead.
    let core2 = ChatCore::new();
    core2.generate_keypairs().unwrap();
    core2.set_reject_unverified(false);

    let result2 = core2.decrypt_event_with(&event_b64, &Default::default(), &[]);
    assert!(result2.is_err());
    let err_msg = format!("{}", result2.unwrap_err());
    assert!(
        err_msg.contains("no matching key found"),
        "Error should mention missing key, got: {}",
        err_msg
    );
}

#[test]
fn decrypt_event_unencrypted_mce_empty_content_returns_unknown() {
    // An MCE with no contents at all (None) should return Unknown,
    // regardless of encryption status.
    let mce = ThriftMCE::new(
        None::<Vec<u8>>, // no contents
        None::<String>,  // no key version
        Some(true),
        None::<i64>,
        None::<i64>,
        None::<bool>,
        None::<crate::thrift::event::EventQueuePriority>,
        None::<Vec<crate::thrift::event::AdditionalAction>>,
        None,
        None,
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::MessageCreateEvent(mce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).unwrap();
    let event_b64 = base64_encode(&bytes);

    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let result = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    assert!(
        matches!(result, Event::Unknown(_)),
        "MCE with no contents should return Unknown"
    );
}

#[test]
fn decrypt_event_unencrypted_mce_preserves_metadata() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    core.set_reject_unverified(false);

    let content = build_plaintext_content("metadata check");
    let event_b64 = build_test_message_event(&content, None);

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Message(msg) => {
            assert_eq!(msg.meta.sequence_id.as_deref(), Some("seq-1"));
            assert_eq!(msg.meta.id.as_deref(), Some("msg-1"));
            assert_eq!(msg.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(msg.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(msg.meta.created_at_msec, Some(1700000000000));
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_encrypted_mce_roundtrip() {
    // Verify the normal encrypted path still works end-to-end.
    // Disable reject_unverified since we don't supply signing keys.
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let ckey = core.generate_conversation_key().unwrap();
    let plaintext = build_plaintext_content("Encrypted roundtrip");

    // Encrypt the content the same way the pipeline does.
    let encrypted = crate::crypto::encryption::encrypt_message(&ckey, &plaintext).unwrap();
    let event_b64 = build_test_message_event(&encrypted, Some("42"));

    let event = core
        .decrypt_event_with(
            &event_b64,
            &[("42".to_string(), ckey.clone())].into_iter().collect(),
            &[],
        )
        .unwrap();

    match event {
        Event::Message(msg) => {
            assert_eq!(msg.text(), Some("Encrypted roundtrip"));
            assert_eq!(msg.conversation_key_version.as_deref(), Some("42"));
            // No trusted signing key provided → verified is false
            assert!(!msg.verified);
        }
        other => panic!("Expected Event::Message, got {:?}", other),
    }
}

#[test]
fn decrypt_event_typing_event() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let typing = ThriftMTE::new(Some("conv-1".to_string()), None, None, None, None);
    let event_b64 = build_test_event(ThriftDetail::MessageTypingEvent(typing));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Typing(t) => {
            assert_eq!(t.meta.sender_id.as_deref(), Some("910003"));
            assert_eq!(t.meta.conversation_id.as_deref(), Some("conv-1"));
            assert_eq!(t.meta.sequence_id.as_deref(), Some("seq-1"));
        }
        other => panic!("Expected Event::Typing, got {:?}", other),
    }
}

#[test]
fn decrypt_event_mark_conversation_read() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let read = ThriftMCRE::new(Some("seq-50".to_string()), Some(1700000050000i64), None);
    let event_b64 = build_test_event(ThriftDetail::MarkConversationReadEvent(read));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ReadReceipt(r) => {
            assert_eq!(r.seen_until_sequence_id.as_deref(), Some("seq-50"));
            assert_eq!(r.seen_at_msec, Some(1700000050000));
            assert!(!r.verified);
            assert_eq!(r.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::ReadReceipt, got {:?}", other),
    }
}

#[test]
fn decrypt_event_mark_conversation_unread() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let unread = ThriftMCUE::new(Some("seq-42".to_string()));
    let event_b64 = build_test_event(ThriftDetail::MarkConversationUnreadEvent(unread));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MarkedUnread(u) => {
            assert_eq!(u.seen_until_sequence_id.as_deref(), Some("seq-42"));
            assert!(!u.verified);
        }
        other => panic!("Expected Event::MarkedUnread, got {:?}", other),
    }
}

#[test]
fn decrypt_event_message_delete_for_self() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let del = ThriftMDE::new(
        Some(vec!["seq-10".to_string(), "seq-11".to_string()]),
        Some(DeleteMessageAction::DELETE_FOR_SELF),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MessageDeleted(md) => {
            assert_eq!(md.sequence_ids, vec!["seq-10", "seq-11"]);
            assert!(!md.delete_for_all);
            assert!(!md.verified);
        }
        other => panic!("Expected Event::MessageDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_message_delete_for_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let del = ThriftMDE::new(
        Some(vec!["seq-20".to_string()]),
        Some(DeleteMessageAction::DELETE_FOR_ALL),
        None,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageDeleteEvent(del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MessageDeleted(md) => {
            assert_eq!(md.sequence_ids, vec!["seq-20"]);
            assert!(md.delete_for_all);
        }
        other => panic!("Expected Event::MessageDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_conversation_delete_with_clear_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let conv_del = ThriftConvDel::new(
        Some("conv-99".to_string()),
        Some(ClearConversationOptions::new(
            Some(true),
            Some(1700000000000i64),
        )),
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ConversationDeleted(cd) => {
            assert!(cd.clear_all_messages);
            assert!(!cd.verified);
        }
        other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_conversation_delete_without_clear_all() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let conv_del = ThriftConvDel::new(
        Some("conv-100".to_string()),
        None::<ClearConversationOptions>,
    );
    let event_b64 = build_test_event(ThriftDetail::ConversationDeleteEvent(conv_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::ConversationDeleted(cd) => {
            assert!(!cd.clear_all_messages);
        }
        other => panic!("Expected Event::ConversationDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_internal_error() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INTERNAL_ERROR),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::InternalError);
            assert_eq!(f.rate_limit_tier, None);
            assert_eq!(f.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_rate_limit_tier() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RATE_LIMIT_UPSELL),
        Some(ThriftRateLimitTier::PREMIUM),
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::RateLimitUpsell);
            assert_eq!(f.rate_limit_tier, Some(RateLimitTier::Premium));
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_contents_too_large() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::CONTENTS_TOO_LARGE),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => {
            assert_eq!(f.failure, FailureType::ContentsTooLarge);
        }
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_too_many_messages() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::TOO_MANY_MESSAGES),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::TooManyMessages),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_invalid_sender_signature() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::INVALID_SENDER_SIGNATURE),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::InvalidSenderSignature),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_non_latest_ckey_version() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::NON_LATEST_CKEY_VERSION),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::NonLatestKeyVersion),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_recipient_not_trusted() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientNotTrusted),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_recipient_key_changed() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::RECIPIENT_KEY_HAS_CHANGED),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::RecipientKeyChanged),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_empty_detail() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(
        Some(ThriftFailureType::EMPTY_DETAIL),
        None::<ThriftRateLimitTier>,
    );
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::EmptyDetail),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_failure_none_type_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let failure = ThriftMFE::new(None::<ThriftFailureType>, None::<ThriftRateLimitTier>);
    let event_b64 = build_test_event(ThriftDetail::MessageFailureEvent(failure));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Failure(f) => assert_eq!(f.failure, FailureType::Unknown),
        other => panic!("Expected Event::Failure, got {:?}", other),
    }
}

#[test]
fn decrypt_event_member_account_delete() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);
    core.generate_keypairs().unwrap();

    let member_del = ThriftMADE::new(Some("deleted-user-42".to_string()), None);
    let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MemberDeleted(md) => {
            assert_eq!(md.member_id, "deleted-user-42");
            assert_eq!(md.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::MemberDeleted, got {:?}", other),
    }
}

#[test]
fn decrypt_event_member_account_delete_no_member_id() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let member_del = ThriftMADE::new(None::<String>, None);
    let event_b64 = build_test_event(ThriftDetail::MemberAccountDeleteEvent(member_del));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::MemberDeleted(md) => {
            assert_eq!(md.member_id, ""); // defaults to empty
        }
        other => panic!("Expected Event::MemberDeleted, got {:?}", other),
    }
}

// Unknown/missing detail → Event::Unknown

#[test]
fn decrypt_event_no_detail_returns_unknown() {
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    // Build event with no detail (detail = None)
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        None::<ThriftDetail>, // no detail
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).expect("serialize");
    let event_b64 = base64_encode(&bytes);

    let result = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match result {
        Event::Unknown(u) => {
            assert!(u.event_type_id.is_none());
            assert_eq!(u.meta.sender_id.as_deref(), Some("910003"));
        }
        other => panic!("Expected Event::Unknown, got {:?}", other),
    }
}

#[test]
fn decrypt_event_grok_search_response_returns_unknown() {
    // GrokSearchResponseEvent is handled by the catch-all `_` branch
    let core = ChatCore::new();
    core.set_reject_unverified(false);

    let grok = ThriftGSRE::new(Some("search-1".to_string()));
    let event_b64 = build_test_event(ThriftDetail::GrokSearchResponseEvent(grok));

    let event = core
        .decrypt_event_with(&event_b64, &Default::default(), &[])
        .unwrap();
    match event {
        Event::Unknown(u) => {
            assert!(u.event_type_id.is_none());
        }
        other => panic!(
            "Expected Event::Unknown for GrokSearchResponse, got {:?}",
            other
        ),
    }
}

// decrypt_event with invalid base64 errors

#[test]
fn decrypt_event_invalid_base64_errors() {
    let core = ChatCore::new();
    let result = core.decrypt_event_with("not_valid_base64!!!", &Default::default(), &[]);
    assert!(result.is_err());
}

// convert_failure_type coverage

#[test]
fn convert_failure_type_all_variants() {
    use crate::thrift::event::FailureType as TFT;
    for (thrift, expected) in [
        (TFT::EMPTY_DETAIL, FailureType::EmptyDetail),
        (TFT::INTERNAL_ERROR, FailureType::InternalError),
        (TFT::CONTENTS_TOO_LARGE, FailureType::ContentsTooLarge),
        (TFT::TOO_MANY_MESSAGES, FailureType::TooManyMessages),
        (
            TFT::INVALID_SENDER_SIGNATURE,
            FailureType::InvalidSenderSignature,
        ),
        (
            TFT::NON_LATEST_CKEY_VERSION,
            FailureType::NonLatestKeyVersion,
        ),
        (
            TFT::RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION,
            FailureType::RecipientNotTrusted,
        ),
        (
            TFT::RECIPIENT_KEY_HAS_CHANGED,
            FailureType::RecipientKeyChanged,
        ),
        (
            TFT::ONLY_ENCRYPTED_MESSAGES_ALLOWED,
            FailureType::OnlyEncryptedMessagesAllowed,
        ),
        (TFT::REQUESTER_NOT_ADMIN, FailureType::RequesterNotAdmin),
        (TFT::FLAGGED_AS_SPAM, FailureType::FlaggedAsSpam),
        (TFT::RATE_LIMIT_UPSELL, FailureType::RateLimitUpsell),
        (
            TFT::SIGNATURE_FAILED_TO_VERIFY_AGAINST_PUBLIC_KEY,
            FailureType::SignatureFailedToVerifyAgainstPublicKey,
        ),
        (TFT::GENERIC_ERROR, FailureType::GenericError),
        (
            TFT::SENDER_NOT_GROUP_MEMBER,
            FailureType::SenderNotGroupMember,
        ),
        (
            TFT::INVALID_SIGNATURE_VERSION,
            FailureType::InvalidSignatureVersion,
        ),
        (TFT::INVALID_PIN_REQUEST, FailureType::InvalidPinRequest),
        (TFT::TOO_MANY_PINS, FailureType::TooManyPins),
    ] {
        assert_eq!(convert_failure_type(Some(&thrift)), expected);
    }
    assert_eq!(convert_failure_type(Some(&TFT(99))), FailureType::Unknown);
    assert_eq!(convert_failure_type(None), FailureType::Unknown);
}

#[test]
fn convert_rate_limit_tier_all_variants() {
    use crate::thrift::event::RateLimitTier as TRT;
    for (thrift, expected) in [
        (TRT::FREE, RateLimitTier::Free),
        (TRT::VERIFIED_PHONE, RateLimitTier::VerifiedPhone),
        (TRT::PREMIUM, RateLimitTier::Premium),
        (TRT::PREMIUM_PLUS, RateLimitTier::PremiumPlus),
        (TRT::PREMIUM_BUSINESS, RateLimitTier::PremiumBusiness),
    ] {
        assert_eq!(convert_rate_limit_tier(Some(&thrift)), Some(expected));
    }
    assert_eq!(
        convert_rate_limit_tier(Some(&TRT(99))),
        Some(RateLimitTier::Unknown)
    );
    assert_eq!(convert_rate_limit_tier(None), None);
}

#[test]
fn group_change_none_returns_unknown() {
    let change = ChatCore::new().group_change(None, None, &HashMap::new());
    assert!(matches!(change, GroupChange::Unknown));
}

// convert_settings_change coverage

#[test]
fn convert_settings_change_none_returns_unknown() {
    let change = convert_settings_change(None);
    assert!(matches!(change, SettingsChange::Unknown));
}
