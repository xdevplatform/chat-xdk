//! Other users' public keys: the signing keys a batch reports missing, the
//! records `add_public_keys` stores, the lookups that are not repeated at
//! once, the keys prepare calls read from the store, and the hook.

use super::key_change_signers::{message_texts, recipient, Group, ENFORCED_SEQUENCE, GROUP};
use super::*;
use crate::core::test_support::{frame, Party, SIGNING_KEY_VERSION};
use crate::params::GroupMembersRemoveParams;
use std::sync::{Arc, Mutex};

/// The record the X API returns for `party`'s keys.
fn record(party: &Party) -> PublicKeyRecord {
    PublicKeyRecord::new(
        SIGNING_KEY_VERSION,
        party.entry.identity_public_key.as_str(),
        party.entry.public_key.as_str(),
        party.entry.identity_public_key_signature.as_str(),
    )
}

/// The records of `parties`, by user id.
fn records(parties: &[&Party]) -> HashMap<String, Vec<PublicKeyRecord>> {
    parties
        .iter()
        .map(|party| (party.user_id.clone(), vec![record(party)]))
        .collect()
}

fn user_ids(parties: &[&Party]) -> Vec<String> {
    parties.iter().map(|party| party.user_id.clone()).collect()
}

fn with_identity(user_id: &str) -> Party {
    let party = Party::new(user_id);
    party
        .core
        .set_identity(&SetIdentityParams::new(user_id, SIGNING_KEY_VERSION))
        .unwrap();
    party
}

/// The users a prepared change encrypted its key to, sorted.
fn recipients(prepared: &PreparedConversationChange) -> Vec<String> {
    let mut ids: Vec<String> = prepared
        .conversation_participant_keys
        .iter()
        .map(|key| key.user_id.clone())
        .collect();
    ids.sort();
    ids
}

/// A hook that answers from `directory`, and the user ids of each call it
/// gets.
fn hook(
    directory: HashMap<String, Vec<PublicKeyRecord>>,
) -> (ResolvePublicKeys, Arc<Mutex<Vec<Vec<String>>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let resolve: ResolvePublicKeys = Arc::new(
        move |user_ids: &[String]| -> HashMap<String, Vec<PublicKeyRecord>> {
            seen.lock().unwrap().push(user_ids.to_vec());
            user_ids
                .iter()
                .filter_map(|id| directory.get(id).map(|found| (id.clone(), found.clone())))
                .collect()
        },
    );
    (resolve, calls)
}

#[test]
fn missing_signing_keys_lists_each_event_whose_senders_key_was_not_given() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);
    let bot = &group.bot.core;

    let result = bot.decrypt_events_with(&[&change, &message], &[]);
    assert_eq!(
        result.missing_signing_keys,
        [
            (0, MissingSigningKey::new("5001", "1")),
            (1, MissingSigningKey::new("5002", "1")),
        ]
        .into()
    );
    assert_eq!(bot.missing_public_keys(&result), ["5001", "5002"]);

    // With the member's keys given, only the admin's is missing.
    let member_keys = std::slice::from_ref(&group.member.entry);
    let result = bot.decrypt_events_with(&[&change, &message], member_keys);
    assert_eq!(
        result.missing_signing_keys,
        [(0, MissingSigningKey::new("5001", "1"))].into()
    );

    // A key that was given and rejected is not missing.
    let mut unbound = group.admin.entry.clone();
    unbound.identity_public_key_signature =
        group.member.entry.identity_public_key_signature.clone();
    let result =
        bot.decrypt_events_with(&[&change, &message], &[unbound, group.member.entry.clone()]);
    assert!(result.missing_signing_keys.is_empty());
    assert_eq!(result.rejected_signing_keys.len(), 1);

    // An event that is returned unverified is listed too.
    bot.set_reject_unverified(false);
    let result = bot.decrypt_events_with(&[&message], &[]);
    assert_eq!(
        result.missing_signing_keys,
        [(0, MissingSigningKey::new("5002", "1"))].into()
    );
}

#[test]
fn add_public_keys_stores_the_records_the_api_returns() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);
    let bot = &group.bot.core;

    // A record without its signing key is left out.
    let mut partial = record(&group.admin);
    partial.signing_public_key.clear();
    bot.add_public_keys(&[("5001".to_string(), vec![partial])].into());
    let result = bot.decrypt_events_with(&[&change, &message], &[]);
    assert!(result.events.is_empty());

    bot.add_public_keys(&records(&[&group.admin, &group.member]));
    let result = bot.decrypt_events_with(&[&change, &message], &[]);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.missing_signing_keys.is_empty());
    assert_eq!(message_texts(&result), ["hello group"]);
}

#[test]
fn a_lookup_that_brought_no_key_is_not_repeated_until_the_retry_time() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let change = frame(&change);
    let bot = &group.bot.core;

    let result = bot.decrypt_events_with(&[&change, &message], &[]);
    assert_eq!(bot.missing_public_keys(&result), ["5001", "5002"]);
    // Nothing was added: neither key is asked for again.
    assert!(bot.missing_public_keys(&result).is_empty());

    // The admin's keys arrive; the member's lookup found nothing.
    bot.add_public_keys(&records(&[&group.admin]));
    let result = bot.decrypt_events_with(&[&change, &message], &[]);
    assert_eq!(result.missing_signing_keys.len(), 1);
    assert!(bot.missing_public_keys(&result).is_empty());

    // A key version of the member not asked for before is asked for at once.
    let newer = [MissingSigningKey::new("5002", "2")];
    assert_eq!(bot.missing_public_keys_among(&newer), ["5002"]);

    // A remembered lookup is repeated once the retry time has passed.
    let need = || vec![("5009".to_string(), Some("1".to_string()))];
    assert_eq!(bot.users_to_look_up_at(need(), 1_000), ["5009"]);
    assert!(bot
        .users_to_look_up_at(need(), 1_000 + PUBLIC_KEYS_RETRY_MS - 1)
        .is_empty());
    assert_eq!(
        bot.users_to_look_up_at(need(), 1_000 + PUBLIC_KEYS_RETRY_MS),
        ["5009"]
    );
}

#[test]
fn decrypt_events_fetches_missing_keys_through_the_hook_and_decrypts_once_more() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let events = vec![frame(&change), message];
    let bot = &group.bot.core;
    bot.set_identity(&SetIdentityParams::new("5003", SIGNING_KEY_VERSION))
        .unwrap();
    let (resolve, calls) = hook(records(&[&group.admin, &group.member]));
    bot.set_resolve_public_keys(Some(resolve));

    let result = bot.decrypt_events(&DecryptEventsParams::new(events.clone()));
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.missing_signing_keys.is_empty());
    assert_eq!(message_texts(&result), ["hello group"]);
    assert_eq!(*calls.lock().unwrap(), [["5001", "5002"]]);

    // Setting a hook turned the key cache on: a send finds the verified key.
    let payload = bot
        .encrypt_message(&crate::EncryptMessageParams::new(GROUP, "hi"))
        .unwrap();
    assert_eq!(payload.conversation_key_version, "3001");

    // The keys are stored: the next batch needs no lookup.
    bot.decrypt_events(&DecryptEventsParams::new(events));
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn the_hook_is_not_called_for_keys_that_were_passed_or_that_it_could_not_find() {
    let group = Group::new();
    let (change, message) = group.page(ENFORCED_SEQUENCE);
    let events = vec![frame(&change), message];
    let bot = &group.bot.core;
    // The hook knows the admin alone.
    let (resolve, calls) = hook(records(&[&group.admin]));
    bot.set_resolve_public_keys(Some(resolve));

    // Signing keys that are passed are what the call verifies with.
    let passed = DecryptEventsParams::new(events.clone())
        .with_signing_keys(vec![group.member.entry.clone()]);
    let result = bot.decrypt_events(&passed);
    assert_eq!(result.missing_signing_keys.len(), 1);
    assert!(calls.lock().unwrap().is_empty());

    // The member's keys are not found: the result says so, and the next
    // call does not ask again.
    let result = bot.decrypt_events(&DecryptEventsParams::new(events.clone()));
    assert_eq!(
        result.missing_signing_keys,
        [(1, MissingSigningKey::new("5002", "1"))].into()
    );
    assert_eq!(*calls.lock().unwrap(), [["5001", "5002"]]);
    bot.decrypt_events(&DecryptEventsParams::new(events));
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn prepare_calls_take_public_keys_from_the_store_when_none_are_passed() {
    let admin = with_identity("5001");
    let member = Party::new("5002");
    let joiner = Party::new("5004");
    admin
        .core
        .add_public_keys(&records(&[&admin, &member, &joiner]));

    let created = admin
        .core
        .prepare_group_create_with_version(
            &GroupCreateParams::new(
                Vec::new(),
                GROUP,
                user_ids(&[&admin, &member]),
                user_ids(&[&admin]),
            ),
            "4001",
        )
        .unwrap();
    assert_eq!(recipients(&created), ["5001", "5002"]);
    // The member decrypts the key the create holds for it.
    let for_member = created
        .conversation_participant_keys
        .iter()
        .find(|key| key.user_id == "5002")
        .unwrap();
    let key = member
        .core
        .decrypt_conversation_key(&for_member.encrypted_conversation_key)
        .unwrap();
    assert_eq!(
        key.to_bytes(),
        created.conversation_key.as_ref().unwrap().to_bytes()
    );

    let added = admin
        .core
        .prepare_group_members_change_with_version(
            &GroupMembersChangeParams::new(
                Vec::new(),
                GROUP,
                user_ids(&[&joiner]),
                user_ids(&[&admin, &member]),
                user_ids(&[&admin]),
                Vec::new(),
            ),
            "4002",
        )
        .unwrap();
    assert_eq!(recipients(&added), ["5001", "5002", "5004"]);

    let removed = admin
        .core
        .prepare_group_members_remove_with_version(
            &GroupMembersRemoveParams::new(Vec::new(), GROUP, user_ids(&[&joiner]))
                .with_remaining_member_ids(user_ids(&[&admin, &member])),
            "4003",
        )
        .unwrap();
    assert_eq!(recipients(&removed), ["5001", "5002"]);

    let rotated = admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(Vec::new())
                .with_conversation_id(GROUP)
                .with_member_ids(user_ids(&[&admin, &member])),
            "4004",
        )
        .unwrap();
    assert_eq!(recipients(&rotated), ["5001", "5002"]);

    // A one-to-one names its two users by its id, in any form the call
    // takes: here the other user's id alone.
    let direct = admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(Vec::new()).with_conversation_id("5002"),
            "4005",
        )
        .unwrap();
    assert_eq!(direct.conversation_id, "5001:5002");
    assert_eq!(recipients(&direct), ["5001", "5002"]);
}

#[test]
fn prepare_calls_say_whose_public_keys_the_store_lacks() {
    let admin = with_identity("5001");
    let member = Party::new("5002");
    admin.core.add_public_keys(&records(&[&admin]));
    // A key whose identity binding does not verify is not encrypted to.
    let mut unbound = record(&member);
    unbound.identity_public_key_signature = admin.entry.identity_public_key_signature.clone();
    admin
        .core
        .add_public_keys(&[("5002".to_string(), vec![unbound])].into());

    let params = GroupCreateParams::new(
        Vec::new(),
        GROUP,
        user_ids(&[&admin, &member]),
        user_ids(&[&admin]),
    );
    let err = admin
        .core
        .prepare_group_create_with_version(&params, "4001")
        .unwrap_err();
    assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err:?}");
    assert!(
        err.to_string()
            .contains("public_keys is empty and no public keys are stored for user(s) 5002"),
        "{err}"
    );

    // The call names that user to look up, once.
    let call = KeyChangeCall::GroupCreate(&params);
    assert_eq!(admin.core.missing_public_keys_for(call), ["5002"]);
    assert!(admin.core.missing_public_keys_for(call).is_empty());

    // Without members to read keys for, a call reports its empty public
    // keys as it does without a store.
    let err = admin
        .core
        .prepare_group_members_remove_with_version(
            &GroupMembersRemoveParams::new(Vec::new(), GROUP, vec!["5004".to_string()]),
            "4002",
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("public_keys is empty: pass the public keys of the remaining members"),
        "{err}"
    );
    let err = admin
        .core
        .prepare_conversation_key_change_with_version(
            &ConversationKeyChangeParams::new(Vec::new()).with_conversation_id(GROUP),
            "4003",
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("public_keys must not be empty"), "{err}");
}

#[test]
fn the_hook_supplies_the_public_keys_of_prepare_calls_that_pass_none() {
    let admin = with_identity("5001");
    let member = Party::new("5002");
    let (resolve, calls) = hook(records(&[&admin, &member]));
    admin.core.set_resolve_public_keys(Some(resolve));
    let params = GroupCreateParams::new(
        Vec::new(),
        GROUP,
        user_ids(&[&admin, &member]),
        user_ids(&[&admin]),
    );

    let created = admin
        .core
        .prepare_group_create_with_version(&params, "4001")
        .unwrap();
    assert_eq!(recipients(&created), ["5001", "5002"]);
    assert_eq!(*calls.lock().unwrap(), [["5001", "5002"]]);

    // The keys are stored: the next call needs no lookup.
    admin
        .core
        .prepare_group_create_with_version(&params, "4002")
        .unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);

    // Public keys that are passed are used as they are.
    let stranger = Party::new("5004");
    let passed = GroupCreateParams::new(
        vec![recipient(&admin), recipient(&stranger)],
        GROUP,
        user_ids(&[&admin, &stranger]),
        user_ids(&[&admin]),
    );
    let created = admin
        .core
        .prepare_group_create_with_version(&passed, "4003")
        .unwrap();
    assert_eq!(recipients(&created), ["5001", "5004"]);
    assert_eq!(calls.lock().unwrap().len(), 1);
}
