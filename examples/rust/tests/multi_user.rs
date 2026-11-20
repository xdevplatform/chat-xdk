//! Offline tests for the Rust example's multi-user helpers: one chat per
//! signed-in user, all fetching public keys through one shared cache.
//!
//! Like `tests/chat_core.rs`, these drive the real `chat_xdk_core` binding.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use chat_xdk_core::PublicKeyRecord;
use chatbot_rs::chat_core::ReplyOptions;
use chatbot_rs::multi_user::{SharedPublicKeys, UserChats};
use common::{key_change_and_message, party, party_with_keys, public_keys_of, texts, Party};

/// A `SharedPublicKeys` over a fake X API that holds the public keys of
/// `parties`, and the users whose keys it then fetches, in order.
fn shared_public_keys_of(parties: &[&Party]) -> (Arc<SharedPublicKeys>, Arc<Mutex<Vec<String>>>) {
    let directory = public_keys_of(parties);
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let fetched = Arc::clone(&asked);
    let shared = SharedPublicKeys::new(move |user_id: &str| {
        fetched.lock().unwrap().push(user_id.to_string());
        directory
            .get(user_id)
            .cloned()
            .ok_or_else(|| format!("no public keys for user {user_id}"))
    });
    (Arc::new(shared), asked)
}

/// `user_ids` as the public-key hook takes them.
fn ids(user_ids: &[&str]) -> Vec<String> {
    user_ids.iter().map(|user_id| user_id.to_string()).collect()
}

/// The answer that holds one record for each of `users`: a user id, and the
/// key version of the user's record.
fn answer(users: &[(&str, &str)]) -> HashMap<String, Vec<PublicKeyRecord>> {
    users
        .iter()
        .map(|(user_id, version)| {
            let record = PublicKeyRecord::new(*version, "", "", "");
            (user_id.to_string(), vec![record])
        })
        .collect()
}

#[test]
fn the_chats_of_two_signed_in_users_fetch_the_keys_of_a_user_they_both_meet_once() {
    let (admin, member) = (party("5001"), party("5002"));
    let (alice, alice_keys) = party_with_keys("5003");
    let (bob, bob_keys) = party_with_keys("5004");
    let (public_keys, asked) = shared_public_keys_of(&[&admin, &member]);
    let chats = UserChats::new(public_keys);
    let (key_change, message) = key_change_and_message(
        &admin,
        &[&admin, &member, &alice, &bob],
        &member,
        "g900",
        "hello group",
    );
    let events = [key_change.as_str(), message.as_str()];

    for (user, private_keys_b64) in [(&alice, &alice_keys), (&bob, &bob_keys)] {
        let chat = chats
            .chat_for(&user.user_id, private_keys_b64, "1")
            .expect("chat_for");
        let page = chat.decrypt_batch(&events);
        assert!(page.errors.is_empty(), "{:?}", page.errors);
        assert!(page.missing_signing_keys.is_empty());
        assert_eq!(texts(&page), [None, Some("hello group")]);
    }
    // Each chat needed the keys of the admin and the member: the second chat
    // took them from the cache the first one filled.
    assert_eq!(*asked.lock().unwrap(), ["5001", "5002"]);
}

#[test]
fn a_signed_in_user_has_one_chat_which_serves_every_conversation_of_the_user() {
    let (admin, member) = (party("5001"), party("5002"));
    let (alice, alice_keys) = party_with_keys("5003");
    let (bob, bob_keys) = party_with_keys("5004");
    let (public_keys, _) = shared_public_keys_of(&[&admin, &member]);
    let chats = UserChats::new(public_keys);

    // Two threads that ask for one user's chat get the same chat.
    let (chat, again) = thread::scope(|scope| {
        let sign_in = || {
            chats
                .chat_for(&alice.user_id, &alice_keys, "1")
                .expect("chat_for")
        };
        let (first, second) = (scope.spawn(sign_in), scope.spawn(sign_in));
        (first.join().unwrap(), second.join().unwrap())
    });
    assert!(Arc::ptr_eq(&chat, &again));
    let other = chats
        .chat_for(&bob.user_id, &bob_keys, "1")
        .expect("chat_for");
    assert!(!Arc::ptr_eq(&chat, &other));

    for conversation_id in ["g900", "g901"] {
        let (key_change, message) = key_change_and_message(
            &admin,
            &[&admin, &member, &alice],
            &member,
            conversation_id,
            "hello group",
        );
        let page = chat.decrypt_batch(&[key_change.as_str(), message.as_str()]);
        assert!(page.errors.is_empty(), "{:?}", page.errors);
        assert_eq!(texts(&page), [None, Some("hello group")]);
        // The reply takes the conversation's key from the chat's key cache.
        chat.encrypt_reply(conversation_id, "hi", ReplyOptions::default())
            .expect("encrypt_reply");
    }
    // The chat holds no key for a conversation it has not read.
    assert!(chat
        .encrypt_reply("g902", "hi", ReplyOptions::default())
        .is_err());

    // After a sign-out, the next sign-in makes another chat.
    chats.close(&alice.user_id);
    let reopened = chats
        .chat_for(&alice.user_id, &alice_keys, "1")
        .expect("chat_for");
    assert!(!Arc::ptr_eq(&chat, &reopened));
}

#[test]
fn a_shared_lookup_is_fetched_once_retried_after_a_failure_and_fetched_again_after_the_ttl() {
    let time = Arc::new(Mutex::new(Duration::from_millis(1_000)));
    let failing = Arc::new(AtomicBool::new(true));
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    // The first fetch says that it has started, then waits to be released.
    let (started, has_started) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);

    let (clock, fails, fetched) = (Arc::clone(&time), Arc::clone(&failing), Arc::clone(&asked));
    let shared = SharedPublicKeys::new(move |user_id: &str| {
        let count = {
            let mut fetched = fetched.lock().unwrap();
            fetched.push(user_id.to_string());
            fetched.len()
        };
        if count == 1 {
            started.send(()).unwrap();
            released.lock().unwrap().recv().unwrap();
        }
        if user_id == "7" && fails.load(Ordering::SeqCst) {
            return Err("HTTP 503".to_string());
        }
        // The key version of an answer's record is the number of its fetch.
        Ok(vec![PublicKeyRecord::new(count.to_string(), "", "", "")])
    })
    .with_ttl(Duration::from_millis(100))
    .with_clock(move || *clock.lock().unwrap());

    // Two calls at once: user 5 is fetched once, and both calls get the
    // answer. The second call starts while the first one's fetch is under
    // way, and finds the lookup in the cache before or after the fetch ends.
    let (first, second) = thread::scope(|scope| {
        let first = scope.spawn(|| shared.resolve(&ids(&["5"])));
        has_started.recv().unwrap();
        let second = scope.spawn(|| shared.resolve(&ids(&["5", "6"])));
        release.send(()).unwrap();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(*asked.lock().unwrap(), ["5", "6"]);
    assert_eq!(first, answer(&[("5", "1")]));
    assert_eq!(second, answer(&[("5", "1"), ("6", "2")]));

    // A lookup that fails leaves its user out of the answer, which still
    // holds the other users, and is not kept: the next call fetches again.
    assert_eq!(shared.resolve(&ids(&["7", "6"])), answer(&[("6", "2")]));
    failing.store(false, Ordering::SeqCst);
    assert_eq!(shared.resolve(&ids(&["7"])), answer(&[("7", "4")]));
    assert_eq!(*asked.lock().unwrap(), ["5", "6", "7", "7"]);

    // An answer is served until its time is up, then fetched again.
    *time.lock().unwrap() += Duration::from_millis(99);
    assert_eq!(shared.resolve(&ids(&["5"])), first);
    assert_eq!(asked.lock().unwrap().len(), 4);
    *time.lock().unwrap() += Duration::from_millis(1);
    assert_eq!(shared.resolve(&ids(&["5"])), answer(&[("5", "5")]));
}
