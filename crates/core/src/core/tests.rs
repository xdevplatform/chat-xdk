//! Tests of `ChatCore`'s calls, one module per topic, and the helpers the
//! modules share to build the events they decrypt.

use super::*;
use crate::pipeline::serialize_thrift;
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{
    ClearConversationOptions, ConversationDeleteEvent as ThriftConvDel,
    ConversationKeyChangeEvent as ThriftCKCE, ConversationMetadataChange,
    ConversationMetadataChangeEvent as ThriftCMCE, ConversationParticipantKey, DeleteMessageAction,
    DisableScreenCaptureBlocking, DisableScreenCaptureDetection, EnableScreenCaptureBlocking,
    EnableScreenCaptureDetection, FailureType as ThriftFailureType,
    GrokSearchResponseEvent as ThriftGSRE, GroupAdminAddChange, GroupAdminRemoveChange,
    GroupAvatarUrlChange, GroupChangeEvent as ThriftGCE, GroupCreate, GroupInviteDisable,
    GroupInviteEnable, GroupJoinReject, GroupJoinRequest, GroupMemberAddChange,
    GroupMemberRemoveChange, GroupTitleChange, MarkConversationReadEvent as ThriftMCRE,
    MarkConversationUnreadEvent as ThriftMCUE, MemberAccountDeleteEvent as ThriftMADE,
    MessageCreateEvent as ThriftMCE, MessageDeleteEvent as ThriftMDE, MessageDurationChange,
    MessageDurationRemove, MessageEvent as ThriftMessageEvent, MessageEventDetail as ThriftDetail,
    MessageFailureEvent as ThriftMFE, MessageTypingEvent as ThriftMTE, MuteConversation,
    RateLimitTier as ThriftRateLimitTier, UnmuteConversation,
};

/// Build a base64-encoded MessageEvent wrapping a MessageCreateEvent.
///
/// When `conversation_key_version` is `None` the MCE is unencrypted and
/// `content_bytes` should be raw (plaintext) Thrift `MessageEntryHolder`.
/// When it is `Some`, `content_bytes` should be ciphertext produced by
/// `encrypt_message()`.
fn build_test_message_event(
    content_bytes: &[u8],
    conversation_key_version: Option<&str>,
) -> String {
    let mce = ThriftMCE::new(
        Some(content_bytes.to_vec()),
        conversation_key_version.map(|s| s.to_string()),
        Some(true),   // should_notify
        None::<i64>,  // ttl_msec
        None::<i64>,  // delivered_at_msec
        None::<bool>, // is_pending_public_key
        None::<crate::thrift::event::EventQueuePriority>,
        None::<Vec<crate::thrift::event::AdditionalAction>>,
        None,
        None,
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),         // sequence_id
        Some("msg-1".to_string()),         // message_id
        Some("910003".to_string()),        // sender_id
        Some("conv-1".to_string()),        // conversation_id
        None::<String>,                    // conversation_token
        Some("1700000000000".to_string()), // created_at_msec
        Some(ThriftDetail::MessageCreateEvent(mce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>, // previous_sequence_id
        None::<bool>,   // is_trusted
        None::<String>, // conversation_event_counter
    );
    let bytes = serialize_thrift(&event).expect("serialize MessageEvent");
    base64_encode(&bytes)
}

/// Build plaintext Thrift content bytes for a simple text message.
fn build_plaintext_content(text: &str) -> Vec<u8> {
    crate::pipeline::build_message_content(text, None, None, None).expect("build_message_content")
}

/// Build a base64-encoded MessageEvent wrapping an arbitrary detail.
fn build_test_event(detail: ThriftDetail) -> String {
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some("msg-1".to_string()),
        Some("910003".to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(detail),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    let bytes = serialize_thrift(&event).expect("serialize");
    base64_encode(&bytes)
}

/// Base64 ciphertext of `value` under `key`, as a group change carries
/// a title or description.
fn encrypted_metadata(key: &XChatConversationKey, value: &str) -> String {
    base64_encode(&crate::crypto::encryption::encrypt_message(key, value.as_bytes()).unwrap())
}

fn text(value: &str) -> GroupText {
    GroupText::Text {
        text: value.to_string(),
    }
}

/// The one action signature of a prepared delete or read receipt.
fn only_action(prepared: PreparedAction) -> crate::signatures::ActionSignature {
    assert_eq!(prepared.action_signatures.len(), 1);
    prepared.action_signatures.into_iter().next().unwrap()
}

/// Wrap a `SendPayload` (the MCE + signature produced by an `encrypt_*`
/// call) into a full base64 `MessageEvent` with the embedded signature,
/// mirroring what the backend delivers. `message_id`/`sender_id`/
/// `conversation_id` must match the values passed to the `encrypt_*`
/// call so the signature payload reconstructs identically.
fn wrap_signed_payload(
    payload: &SendPayload,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
) -> String {
    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let mce = parse_message_event(&mce_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            let cursor = Cursor::new(mce_bytes.clone());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .ok()
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        })
        .expect("parse MCE");

    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-1".to_string()),
        Some(message_id.to_string()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

/// Build a `ConversationKeyChangeEvent` (base64) that carries `ckey`
/// self-encrypted to the loaded identity key, so that
/// `extract_conversation_keys` can recover it. `reg_version` is the
/// participant entry's key version, which must match the signing-key
/// version when one is set.
fn build_self_keychange_event(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    ckey_version: &str,
    sender_id: &str,
    reg_version: Option<String>,
) -> String {
    let pubkeys = core.get_public_keys().unwrap();
    let recipients = [RecipientInput {
        user_id: sender_id.to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(ckey, &recipients)
        .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some(sender_id.to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            reg_version,
        )]),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-kc".to_string()),
        Some("msg-kc".to_string()),
        Some(sender_id.to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        None::<crate::thrift::event::MessageEventSignature>,
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

/// Like `build_self_keychange_event`, but embeds a v7
/// `MessageEventSignature` produced by `sign_key_change`, mirroring
/// what a legitimate client publishes.
fn build_signed_self_keychange_event(
    core: &ChatCore,
    ckey: &XChatConversationKey,
    ckey_version: &str,
    sender_id: &str,
    signing_key_version: &str,
    reg_version: Option<String>,
) -> String {
    let pubkeys = core.get_public_keys().unwrap();
    let recipients = [RecipientInput {
        user_id: sender_id.to_string(),
        public_key: pubkeys.identity.clone(),
        key_version: "pkv-self".to_string(),
    }];
    let encrypted = core
        .encrypt_conversation_key_for_recipients(ckey, &recipients)
        .unwrap();

    let action_sig = super::test_support::key_change_signature(
        core,
        signing_key_version,
        "msg-kc",
        sender_id,
        "conv-1",
        ckey_version,
        ckey.encoded(),
    )
    .unwrap();

    let kce = ThriftCKCE::new(
        Some(ckey_version.to_string()),
        Some(vec![ConversationParticipantKey::new(
            Some(sender_id.to_string()),
            Some(encrypted[0].encrypted_conversation_key.clone()),
            reg_version,
        )]),
        None,
        None,
    );
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(action_sig.message_event_signature.signature.clone()),
        Some(
            action_sig
                .message_event_signature
                .public_key_version
                .clone(),
        ),
        Some(action_sig.message_event_signature.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some("seq-kc".to_string()),
        Some("msg-kc".to_string()),
        Some(sender_id.to_string()),
        Some("conv-1".to_string()),
        None::<String>,
        None::<String>,
        Some(ThriftDetail::ConversationKeyChangeEvent(kce)),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

fn signing_key_entry_for(reg: &PublicKeyRegistrationPayload, user_id: &str) -> SigningKeyEntry {
    SigningKeyEntry::new(
        user_id,
        "61",
        &reg.public_key.signing_public_key,
        &reg.public_key.public_key,
        &reg.public_key.identity_public_key_signature,
    )
}

/// Like `wrap_signed_payload` but with an explicit sequence id, for tests
/// that reference a message by sequence (replies, reactions).
fn wrap_signed_payload_with_seq(
    payload: &SendPayload,
    sender_id: &str,
    conversation_id: &str,
    sequence_id: &str,
) -> String {
    let mce_bytes = base64_decode(&payload.encoded_message_create_event).unwrap();
    let mce = parse_message_event(&mce_bytes)
        .ok()
        .and_then(|e| e.detail)
        .or_else(|| {
            let cursor = Cursor::new(mce_bytes.clone());
            let mut raw = TBinaryInputProtocol::new(cursor, true);
            let mut p = BoundedProtocol::new(&mut raw);
            crate::thrift::event::MessageCreateEvent::read_from_in_protocol(&mut p)
                .ok()
                .map(crate::thrift::event::MessageEventDetail::MessageCreateEvent)
        })
        .expect("parse MCE");
    let sig_struct = crate::thrift::event::MessageEventSignature::new(
        Some(payload.signature.clone()),
        Some(payload.signature_info.public_key_version.clone()),
        Some(payload.signature_info.signature_version.clone()),
        None,
        None,
    );
    let event = ThriftMessageEvent::new(
        Some(sequence_id.to_string()),
        Some(payload.message_id.clone()),
        Some(sender_id.to_string()),
        Some(conversation_id.to_string()),
        None::<String>,
        Some("1700000000000".to_string()),
        Some(mce),
        None::<crate::thrift::event::MessageEventRelaySource>,
        Some(sig_struct),
        None::<String>,
        None::<bool>,
        None,
    );
    base64_encode(&serialize_thrift(&event).unwrap())
}

mod caches;
mod conversation_keys;
mod decrypt_events;
mod events;
mod file_encryption;
mod group_events;
mod identity;
mod keys;
mod messages;
mod prepare;
mod replies;
mod verification;
