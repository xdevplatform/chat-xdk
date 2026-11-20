//! `decrypt_events` and the members who sign a batch's key changes: a key
//! change needs its signer's keys to verify, the result says which key
//! changes did not verify or could not be decrypted and why, and keys and
//! the version to encrypt with are reported per conversation.

use super::*;
use crate::core::test_support::{frame, Party, SIGNING_KEY_VERSION};

/// A sequence id past the cut-over, where a key change that does not verify
/// has its key dropped.
pub(super) const ENFORCED_SEQUENCE: &str = "2100000000000000000";
/// A sequence id before the cut-over, where every decryptable key is kept.
const UNENFORCED_SEQUENCE: &str = "100";
pub(super) const GROUP: &str = "g900";
const OTHER_GROUP: &str = "g901";

/// The key change `signer` makes in `conversation_id`, to a new key at
/// `version` for `members`, as delivered at `sequence_id`, and that key.
pub(super) fn key_change(
    signer: &Party,
    members: &[&Party],
    conversation_id: &str,
    version: &str,
    sequence_id: &str,
) -> (ThriftMessageEvent, XChatConversationKey) {
    let public_keys = members.iter().copied().map(recipient).collect();
    key_change_for(signer, public_keys, conversation_id, version, sequence_id)
}

/// The entry a key change holds for `member`: the new key encrypted to the
/// member's identity key.
pub(super) fn recipient(member: &Party) -> PublicKeyInput {
    PublicKeyInput::new(
        member.user_id.as_str(),
        member.entry.identity_public_key.as_str(),
        SIGNING_KEY_VERSION,
    )
}

/// [`key_change`] for explicit recipient entries.
fn key_change_for(
    signer: &Party,
    public_keys: Vec<PublicKeyInput>,
    conversation_id: &str,
    version: &str,
    sequence_id: &str,
) -> (ThriftMessageEvent, XChatConversationKey) {
    let prepared = signer
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(public_keys)
                .with_conversation_id(conversation_id)
                .with_identity(signer.user_id.as_str(), SIGNING_KEY_VERSION),
            version,
        )
        .unwrap();
    let action = &prepared.action_signatures[0];
    let mut raw = TBinaryInputProtocol::new(
        Cursor::new(base64_decode(&action.encoded_message_event_detail).unwrap()),
        true,
    );
    let mut protocol = BoundedProtocol::new(&mut raw);
    let detail = ThriftDetail::read_from_in_protocol(&mut protocol).unwrap();
    let signed = &action.message_event_signature;
    let event = ThriftMessageEvent {
        sequence_id: Some(sequence_id.to_string()),
        message_id: Some(action.message_id.clone()),
        sender_id: Some(signer.user_id.clone()),
        conversation_id: Some(conversation_id.to_string()),
        detail: Some(detail),
        message_event_signature: Some(crate::thrift::event::MessageEventSignature {
            signature: Some(signed.signature.clone()),
            public_key_version: Some(signed.public_key_version.clone()),
            signature_version: Some(signed.signature_version.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };
    (event, prepared.conversation_key.unwrap())
}

/// The message `author` sends in `conversation_id` under `key` at
/// `version`, as delivered.
pub(super) fn sent_message(
    author: &Party,
    conversation_id: &str,
    key: &XChatConversationKey,
    version: &str,
    text: &str,
) -> String {
    let payload = author
        .core
        .encrypt_message(
            &crate::EncryptMessageParams::new(conversation_id, text)
                .with_identity(author.user_id.as_str(), SIGNING_KEY_VERSION)
                .with_conversation_key(key.to_bytes(), version),
        )
        .unwrap();
    let mut event = parse_message_event(&base64_decode(&payload.event_b64).unwrap()).unwrap();
    event.sequence_id = Some("2100000000000000001".to_string());
    frame(&event)
}

/// A `latest_versions` map of conversation id and key version pairs.
fn versions(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(conversation, version)| (conversation.to_string(), version.to_string()))
        .collect()
}

/// The text of each message among a batch's decrypted events.
pub(super) fn message_texts(result: &DecryptEventsResult) -> Vec<&str> {
    result
        .events
        .iter()
        .filter_map(|decrypted| match &decrypted.event {
            Event::Message(message) => message.text(),
            _ => None,
        })
        .collect()
}

/// An admin who rotates a group's key, a member who then sends a message
/// under it, and the bot that receives both.
pub(super) struct Group {
    pub(super) admin: Party,
    pub(super) member: Party,
    pub(super) bot: Party,
}

impl Group {
    pub(super) fn new() -> Self {
        Self {
            admin: Party::new("5001"),
            member: Party::new("5002"),
            bot: Party::new("5003"),
        }
    }

    /// The admin's key change at `sequence_id`, and a message from the
    /// member under its key.
    pub(super) fn page(&self, sequence_id: &str) -> (ThriftMessageEvent, String) {
        let (change, key) = key_change(
            &self.admin,
            &[&self.admin, &self.member, &self.bot],
            GROUP,
            "3001",
            sequence_id,
        );
        let message = sent_message(&self.member, GROUP, &key, "3001", "hello group");
        (change, message)
    }
}

#[test]
fn key_change_without_its_signers_keys_is_reported_and_its_key_dropped() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);

    // The bot holds the keys of the member who wrote the message, not of the
    // admin who made the key change.
    let member_keys = std::slice::from_ref(&group.member.entry);
    let result = group
        .bot
        .core
        .decrypt_events_with(&[&change, &message], member_keys);

    assert!(result.events.is_empty());
    assert!(result.conversation_keys.keys.is_empty());
    assert!(result.conversation_keys.keys_by_conversation.is_empty());
    assert_eq!(result.conversation_keys.latest_version, None);
    assert!(result.conversation_keys.latest_versions.is_empty());
    assert_eq!(
        result.unverified_key_changes,
        HashMap::from([(
            0,
            UnverifiedKeyChange {
                reason: UnverifiedKeyChangeReason::MissingSigningKey,
                key_dropped: true,
                conversation_id: Some(GROUP.to_string()),
                conversation_key_version: "3001".to_string(),
                sender_id: Some("5001".to_string()),
                public_key_version: Some(SIGNING_KEY_VERSION.to_string()),
            }
        )])
    );
    assert!(result.undecryptable_key_changes.is_empty());
    assert!(result.rejected_signing_keys.is_empty());
    let missing = "no signing key for sender 5001 at public_key_version 1";
    assert!(result.errors[&0].contains(missing), "{}", result.errors[&0]);
    assert!(
        result.errors[&1].contains("no matching key found")
            && result.errors[&1].contains("event 0 of the batch")
            && result.errors[&1].contains(missing),
        "{}",
        result.errors[&1]
    );

    // The single-event path names the same missing key.
    let error = group
        .bot
        .core
        .decrypt_event_with(&change, &HashMap::new(), member_keys)
        .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::Verification);
    assert!(error.to_string().contains(missing), "{error}");
}

#[test]
fn key_change_with_its_signers_keys_verifies_and_its_messages_decrypt() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);

    let result = group.bot.core.decrypt_events_with(
        &[&change, &message],
        &[group.member.entry.clone(), group.admin.entry.clone()],
    );

    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.unverified_key_changes.is_empty());
    assert!(result.undecryptable_key_changes.is_empty());
    assert!(result.rejected_signing_keys.is_empty());
    assert_eq!(message_texts(&result), ["hello group"]);
    assert!(result.conversation_keys.keys.contains_key("3001"));
    assert!(result.conversation_keys.get_for(GROUP, "3001").is_some());
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("3001")
    );
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[(GROUP, "3001")])
    );
}

#[test]
fn key_change_checked_with_another_key_is_reported_invalid() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);

    // A signing key registered to the admin's user id, at the version the
    // signature names, that is not the key the admin signed with.
    let other_key = Party::new(&group.admin.user_id).entry;
    let result = group.bot.core.decrypt_events_with(
        &[&change, &message],
        &[group.member.entry.clone(), other_key],
    );

    assert!(result.events.is_empty());
    assert!(result.conversation_keys.keys.is_empty());
    assert_eq!(result.unverified_key_changes.len(), 1);
    let unverified = &result.unverified_key_changes[&0];
    assert_eq!(
        unverified.reason,
        UnverifiedKeyChangeReason::InvalidSignature
    );
    assert!(unverified.key_dropped);
    assert!(
        result.errors[&0].contains("ECDSA mismatch"),
        "{}",
        result.errors[&0]
    );
    assert!(
        result.errors[&1].contains("does not verify against its sender's signing key"),
        "{}",
        result.errors[&1]
    );
}

#[test]
fn unsigned_key_change_is_reported_unverifiable() {
    let group = Group::new();
    let (mut change, message) = group.page(ENFORCED_SEQUENCE);
    change.message_event_signature = None;
    let change = frame(&change);

    let result = group.bot.core.decrypt_events_with(
        &[&change, &message],
        &[group.member.entry.clone(), group.admin.entry.clone()],
    );

    assert!(result.events.is_empty());
    assert_eq!(result.unverified_key_changes.len(), 1);
    let unverified = &result.unverified_key_changes[&0];
    assert_eq!(unverified.reason, UnverifiedKeyChangeReason::Unverifiable);
    assert!(unverified.key_dropped);
    assert_eq!(unverified.public_key_version, None);
    assert!(
        result.errors[&0].contains("the event carries no signature"),
        "{}",
        result.errors[&0]
    );
    assert!(
        result.errors[&1].contains("carries no signature this SDK can check"),
        "{}",
        result.errors[&1]
    );
}

#[test]
fn unverified_key_change_before_the_cut_over_keeps_its_key() {
    let group = Group::new();
    let (change, message) = group.page(UNENFORCED_SEQUENCE);
    let change = frame(&change);

    let result = group.bot.core.decrypt_events_with(
        &[&change, &message],
        std::slice::from_ref(&group.member.entry),
    );

    // The key decrypts the message but is not the version to encrypt with.
    assert_eq!(message_texts(&result), ["hello group"]);
    assert!(result.conversation_keys.keys.contains_key("3001"));
    assert_eq!(result.conversation_keys.latest_version, None);
    assert_eq!(result.unverified_key_changes.len(), 1);
    let unverified = &result.unverified_key_changes[&0];
    assert_eq!(
        unverified.reason,
        UnverifiedKeyChangeReason::MissingSigningKey
    );
    assert!(!unverified.key_dropped);
    assert_eq!(result.errors.keys().copied().collect::<Vec<_>>(), [0]);
}

#[test]
fn latest_versions_are_reported_per_conversation() {
    let admin = Party::new("5001");
    let bot = Party::new("5003");
    let members = [&admin, &bot];
    let (change, _) = key_change(&admin, &members, GROUP, "3001", ENFORCED_SEQUENCE);
    let (other_change, other_key) =
        key_change(&admin, &members, OTHER_GROUP, "4001", ENFORCED_SEQUENCE);
    let (change, other_change) = (frame(&change), frame(&other_change));
    let signing_keys = std::slice::from_ref(&admin.entry);

    // Unverified, each conversation has its highest version, and no one
    // version stands for both.
    let extracted = bot
        .core
        .extract_conversation_keys(&[&change, &other_change]);
    assert_eq!(extracted.latest_version, None);
    assert_eq!(
        extracted.latest_versions,
        versions(&[(GROUP, "3001"), (OTHER_GROUP, "4001")])
    );
    let extracted = bot.core.extract_conversation_keys(&[&other_change]);
    assert_eq!(extracted.latest_version.as_deref(), Some("4001"));

    bot.core.set_cache_keys(true);
    let result = bot
        .core
        .decrypt_events_with(&[&change, &other_change], signing_keys);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[(GROUP, "3001"), (OTHER_GROUP, "4001")])
    );
    // No one version is the one to encrypt with for both conversations.
    assert_eq!(result.conversation_keys.latest_version, None);

    // A batch of one conversation reports that conversation's version,
    // whatever the chat verified for others before.
    let result = bot.core.decrypt_events_with(&[&change], signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("3001")
    );
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[(GROUP, "3001")])
    );
    let other_message = sent_message(&admin, OTHER_GROUP, &other_key, "4001", "hello other group");
    let result = bot
        .core
        .decrypt_events_with(&[&other_message], signing_keys);
    assert_eq!(message_texts(&result), ["hello other group"]);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("4001")
    );

    // The key cache resolves each conversation's own key for a send.
    for (conversation, version) in [(GROUP, "3001"), (OTHER_GROUP, "4001")] {
        let payload = bot
            .core
            .encrypt_message(
                &crate::EncryptMessageParams::new(conversation, "reply")
                    .with_identity(bot.user_id.as_str(), SIGNING_KEY_VERSION),
            )
            .unwrap();
        assert_eq!(payload.conversation_key_version, version);
    }
}

#[test]
fn latest_version_is_reported_for_a_batch_of_one_conversation_only() {
    let admin = Party::new("5001");
    let bot = Party::new("5003");
    let members = [&admin, &bot];
    let (change, _) = key_change(&admin, &members, GROUP, "3001", ENFORCED_SEQUENCE);
    let (_, other_key) = key_change(&admin, &members, OTHER_GROUP, "4001", ENFORCED_SEQUENCE);
    let change = frame(&change);
    let other_message = sent_message(&admin, OTHER_GROUP, &other_key, "4001", "hello other group");
    let signing_keys = std::slice::from_ref(&admin.entry);

    // Only one of the batch's two conversations has a verified version. It
    // is not reported as the batch's: for the other conversation it would
    // name a key that is not that conversation's.
    let result = bot
        .core
        .decrypt_events_with(&[&change, &other_message], signing_keys);
    assert_eq!(result.conversation_keys.latest_version, None);
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[(GROUP, "3001")])
    );
    let extracted = bot
        .core
        .extract_conversation_keys(&[&change, &other_message]);
    assert_eq!(extracted.latest_version, None);
    assert_eq!(extracted.latest_versions, versions(&[(GROUP, "3001")]));

    let result = bot.core.decrypt_events_with(&[&change], signing_keys);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("3001")
    );
}

#[test]
fn one_to_one_events_are_one_conversation_whichever_way_they_write_its_id() {
    let admin = Party::new("5001");
    let bot = Party::new("5003");
    let (change, _) = key_change(
        &admin,
        &[&admin, &bot],
        "5001:5003",
        "3001",
        ENFORCED_SEQUENCE,
    );
    assert_eq!(change.conversation_id.as_deref(), Some("5001:5003"));
    // An unsigned event of the same two users whose id is written the other
    // way round, with the other separator.
    let typing = frame(&ThriftMessageEvent {
        sender_id: Some("5003".to_string()),
        conversation_id: Some("5003-5001".to_string()),
        detail: Some(ThriftDetail::MessageTypingEvent(ThriftMTE::new(
            None::<String>,
            None,
            None,
            None,
            None,
        ))),
        ..Default::default()
    });
    let change = frame(&change);

    let result = bot
        .core
        .decrypt_events_with(&[&change, &typing], std::slice::from_ref(&admin.entry));
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(
        result.conversation_keys.latest_version.as_deref(),
        Some("3001")
    );
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[("5001:5003", "3001")])
    );
    assert!(result
        .conversation_keys
        .get_for("5001:5003", "3001")
        .is_some());
    let extracted = bot.core.extract_conversation_keys(&[&change, &typing]);
    assert_eq!(extracted.latest_version.as_deref(), Some("3001"));
}

#[test]
fn unverified_key_change_is_not_another_conversations_latest_version() {
    let admin = Party::new("5001");
    let other_admin = Party::new("5002");
    let bot = Party::new("5003");
    let (change, _) = key_change(&admin, &[&admin, &bot], GROUP, "3001", ENFORCED_SEQUENCE);
    let (other_change, _) = key_change(
        &other_admin,
        &[&other_admin, &bot],
        OTHER_GROUP,
        "4001",
        ENFORCED_SEQUENCE,
    );
    let (change, other_change) = (frame(&change), frame(&other_change));

    // The other conversation's higher version did not verify, so it is not
    // the one to encrypt with, here or there.
    let result = bot.core.decrypt_events_with(
        &[&change, &other_change],
        std::slice::from_ref(&admin.entry),
    );
    assert_eq!(result.conversation_keys.latest_version, None);
    assert_eq!(
        result.conversation_keys.latest_versions,
        versions(&[(GROUP, "3001")])
    );
    assert_eq!(
        result
            .unverified_key_changes
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [1]
    );
    let unverified = &result.unverified_key_changes[&1];
    assert_eq!(unverified.conversation_id.as_deref(), Some(OTHER_GROUP));
    assert_eq!(unverified.sender_id.as_deref(), Some("5002"));
    assert!(unverified.key_dropped);
}

#[test]
fn keys_of_two_conversations_at_one_version_stay_apart() {
    let admin = Party::new("5001");
    let other_admin = Party::new("5002");
    let bot = Party::new("5003");
    // Two conversations whose keys have the same version.
    let (change, key) = key_change(&admin, &[&admin, &bot], GROUP, "3001", ENFORCED_SEQUENCE);
    let (other_change, other_key) = key_change(
        &other_admin,
        &[&other_admin, &bot],
        OTHER_GROUP,
        "3001",
        ENFORCED_SEQUENCE,
    );
    assert_ne!(key.encoded(), other_key.encoded());
    let message = sent_message(&admin, GROUP, &key, "3001", "hello group");
    let other_message = sent_message(&admin, OTHER_GROUP, &other_key, "3001", "hello other group");
    let (change, other_change) = (frame(&change), frame(&other_change));
    let batch = [
        change.as_str(),
        other_change.as_str(),
        message.as_str(),
        other_message.as_str(),
    ];

    // Each key change verifies against its own conversation's key, and each
    // message decrypts under it.
    let result = bot
        .core
        .decrypt_events_with(&batch, &[admin.entry.clone(), other_admin.entry.clone()]);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.unverified_key_changes.is_empty());
    assert_eq!(message_texts(&result), ["hello group", "hello other group"]);
    let keys = &result.conversation_keys;
    assert_eq!(
        keys.get_for(GROUP, "3001").map(|key| key.encoded()),
        Some(key.encoded())
    );
    assert_eq!(
        keys.get_for(OTHER_GROUP, "3001").map(|key| key.encoded()),
        Some(other_key.encoded())
    );
    // By version alone, "3001" names neither.
    assert!(keys.keys.is_empty());
    assert_eq!(keys.latest_version, None);
    assert_eq!(
        keys.latest_versions,
        versions(&[(GROUP, "3001"), (OTHER_GROUP, "3001")])
    );

    let extracted = bot.core.extract_conversation_keys(&batch);
    assert!(extracted.keys.is_empty());
    assert_eq!(
        extracted
            .get_for(OTHER_GROUP, "3001")
            .map(|key| key.encoded()),
        Some(other_key.encoded())
    );

    // A key change that does not verify costs its own conversation its key,
    // and leaves the other conversation's key at that version in place.
    let result = bot
        .core
        .decrypt_events_with(&batch, std::slice::from_ref(&admin.entry));
    assert_eq!(message_texts(&result), ["hello group"]);
    let keys = &result.conversation_keys;
    assert!(keys.get_for(GROUP, "3001").is_some());
    assert!(keys.get_for(OTHER_GROUP, "3001").is_none());
    assert_eq!(
        keys.get("3001").map(|key| key.encoded()),
        Some(key.encoded())
    );
    assert_eq!(
        result
            .unverified_key_changes
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [1]
    );
    assert!(
        result.errors[&3].contains("event 1 of the batch, did not verify"),
        "{}",
        result.errors[&3]
    );
}

#[test]
fn signing_key_with_an_invalid_binding_is_reported_rejected() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);

    // The admin's entry, with a binding signature that is not the signing
    // key's signature over the identity key.
    let mut unbound = group.admin.entry.clone();
    let mut signature = base64_decode(&unbound.identity_public_key_signature).unwrap();
    signature[0] ^= 0xff;
    unbound.identity_public_key_signature = base64_encode(&signature);
    let signing_keys = [group.member.entry.clone(), unbound];

    let result = group
        .bot
        .core
        .decrypt_events_with(&[&change, &message], &signing_keys);

    assert!(result.events.is_empty());
    assert_eq!(
        result.rejected_signing_keys,
        HashMap::from([(
            1,
            RejectedSigningKey {
                user_id: "5001".to_string(),
                public_key_version: SIGNING_KEY_VERSION.to_string(),
            }
        )])
    );
    assert_eq!(result.unverified_key_changes.len(), 1);
    let unverified = &result.unverified_key_changes[&0];
    assert_eq!(
        unverified.reason,
        UnverifiedKeyChangeReason::RejectedSigningKey
    );
    assert!(unverified.key_dropped);
    let rejected = "the signing key given for sender 5001 at public_key_version 1 was rejected: \
                    its identity binding does not verify";
    assert!(
        result.errors[&0].contains(rejected),
        "{}",
        result.errors[&0]
    );
    assert!(
        result.errors[&1].contains("event 0 of the batch, did not verify")
            && result.errors[&1].contains(rejected),
        "{}",
        result.errors[&1]
    );

    // The single-event path names the rejected key the same way.
    let error = group
        .bot
        .core
        .decrypt_event_with(&change, &HashMap::new(), &signing_keys)
        .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::Verification);
    assert!(error.to_string().contains(rejected), "{error}");
}

/// A bot whose session identity is user 5003 at `key_version`.
fn bot_at(key_version: &str) -> Party {
    let bot = Party::new("5003");
    bot.core
        .set_identity(&SetIdentityParams::new("5003", key_version))
        .unwrap();
    bot
}

/// The one key change `chat` could not decrypt in a batch of `change` and a
/// message under its key, and the error of that message.
fn undecryptable(
    chat: &ChatCore,
    change: &ThriftMessageEvent,
    message: &str,
    signing_keys: &[SigningKeyEntry],
) -> (UndecryptableKeyChange, String) {
    let change = frame(change);
    let mut result = chat.decrypt_events_with(&[&change, message], signing_keys);
    assert!(result.events.is_empty());
    assert!(result.conversation_keys.keys.is_empty());
    assert!(result.unverified_key_changes.is_empty());
    assert_eq!(result.undecryptable_key_changes.len(), 1);
    assert!(
        result.errors[&0].contains(
            "it signs the conversation key, which this chat could not decrypt from the event"
        ),
        "{}",
        result.errors[&0]
    );
    (
        result.undecryptable_key_changes.remove(&0).unwrap(),
        result.errors.remove(&1).unwrap(),
    )
}

#[test]
fn key_change_this_chat_cannot_decrypt_is_reported_with_why() {
    let admin = Party::new("5001");
    let member = Party::new("5002");
    let signing_keys = [admin.entry.clone(), member.entry.clone()];
    let no_key = "no matching key found: the key change for that version, event 0 of the batch, \
                  holds no key this chat can decrypt";

    // A key change made for the admin and the member: the bot is not among
    // its recipients.
    let (change, key) = key_change(&admin, &[&admin, &member], GROUP, "3001", ENFORCED_SEQUENCE);
    let message = sent_message(&member, GROUP, &key, "3001", "hello group");
    let (change_info, error) = undecryptable(&bot_at("1").core, &change, &message, &signing_keys);
    assert_eq!(
        change_info,
        UndecryptableKeyChange {
            reason: UndecryptableKeyChangeReason::NotARecipient,
            conversation_id: Some(GROUP.to_string()),
            conversation_key_version: "3001".to_string(),
            sender_id: Some("5001".to_string()),
        }
    );
    assert!(
        error.contains(no_key) && error.contains("it holds no key for this chat's user"),
        "{error}"
    );

    // A chat with no session identity cannot tell whose entries are whose.
    let (change_info, _) =
        undecryptable(&Party::new("5003").core, &change, &message, &signing_keys);
    assert_eq!(
        change_info.reason,
        UndecryptableKeyChangeReason::DecryptionFailed
    );

    // A chat with no keys loaded.
    let (change_info, error) = undecryptable(&ChatCore::new(), &change, &message, &signing_keys);
    assert_eq!(change_info.reason, UndecryptableKeyChangeReason::Locked);
    assert!(error.contains("no identity key is loaded"), "{error}");

    // A key change made for the bot's keys at version 1, read by a chat
    // whose identity says its keys are version 2.
    let bot = bot_at("2");
    let (change, key) = key_change(&admin, &[&admin, &bot], GROUP, "3001", ENFORCED_SEQUENCE);
    let message = sent_message(&admin, GROUP, &key, "3001", "hello group");
    let (change_info, error) = undecryptable(&bot.core, &change, &message, &signing_keys);
    assert_eq!(
        change_info.reason,
        UndecryptableKeyChangeReason::OtherKeyVersion
    );
    assert!(
        error.contains("it holds no key for this chat's key version"),
        "{error}"
    );

    // A key change whose entry for the bot is encrypted to another key.
    let bot = bot_at("1");
    let stranger = Party::new("5009");
    let for_bot = PublicKeyInput::new(
        "5003",
        stranger.entry.identity_public_key.as_str(),
        SIGNING_KEY_VERSION,
    );
    let (change, key) = key_change_for(
        &admin,
        vec![recipient(&admin), for_bot],
        GROUP,
        "3001",
        ENFORCED_SEQUENCE,
    );
    let message = sent_message(&admin, GROUP, &key, "3001", "hello group");
    let (change_info, error) = undecryptable(&bot.core, &change, &message, &signing_keys);
    assert_eq!(
        change_info.reason,
        UndecryptableKeyChangeReason::DecryptionFailed
    );
    assert!(
        error.contains("its key for this chat does not decrypt under the loaded identity key"),
        "{error}"
    );
}
