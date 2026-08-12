//! The receive -> decrypt -> reply -> encrypt -> send loop.
//!
//! Generic over [`ChatApi`] so it has no direct HTTP dependency.

use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{Event, SigningKeyEntry};

use crate::chat_core::{message_text, ChatCore, ReplyOptions};
use crate::x_api::{ChatApi, EventItem};

/// Turn an incoming message into a reply (a simple echo).
pub fn generate_reply(text: &str) -> String {
    match text.trim() {
        "ping" | "!ping" => "pong".to_string(),
        other => format!("You said: {other}"),
    }
}

/// In-memory state for one conversation.
#[derive(Default)]
struct ConversationState {
    conversation_keys: HashMap<String, XChatConversationKey>,
    latest_key_version: Option<String>,
    seen_event_ids: HashSet<String>,
    pagination_token: Option<String>,
}

pub struct Bot<A: ChatApi> {
    core: ChatCore,
    api: A,
    bot_user_id: String,
    state: HashMap<String, ConversationState>,
}

impl<A: ChatApi> Bot<A> {
    pub fn new(core: ChatCore, api: A, bot_user_id: String) -> Self {
        // One identity per bot instance: signed actions default their
        // sender_id and signing_key_version to these values.
        core.set_identity(&bot_user_id);
        Self {
            core,
            api,
            bot_user_id,
            state: HashMap::new(),
        }
    }

    fn signing_keys_for(&self, events: &[EventItem]) -> Vec<SigningKeyEntry> {
        let mut seen = HashSet::new();
        let mut keys = Vec::new();
        for e in events {
            if e.sender_id.is_empty()
                || e.sender_id == self.bot_user_id
                || !seen.insert(e.sender_id.clone())
            {
                continue;
            }
            match self.api.get_public_keys(&e.sender_id) {
                Ok(mut pks) => keys.append(&mut pks),
                Err(err) => eprintln!("public_keys_fetch_failed sender={} err={err}", e.sender_id),
            }
        }
        keys
    }

    /// Initial load: batch-decrypt the backlog (decrypt_events path).
    pub fn load_backlog(&mut self, conversation_id: &str) -> Result<(), String> {
        let (events, key_events, next) = self.api.get_events(conversation_id, 100, None)?;
        let signing_keys = self.signing_keys_for(&events);
        // The key events carry the conversation keys the messages decrypt
        // under; they must be in the same batch.
        let refs: Vec<&str> = key_events
            .iter()
            .map(String::as_str)
            .chain(
                events
                    .iter()
                    .filter(|e| !e.encoded_event.is_empty())
                    .map(|e| e.encoded_event.as_str()),
            )
            .collect();
        let result = self.core.decrypt_batch(&refs, &signing_keys);

        let st = self.state.entry(conversation_id.to_string()).or_default();
        let key_count = result.conversation_keys.keys.len();
        st.conversation_keys.extend(result.conversation_keys.keys);
        st.latest_key_version = result.conversation_keys.latest_version;
        st.pagination_token = next;
        println!(
            "backlog_loaded conv={conversation_id} messages={} keys={key_count}",
            result.messages.len()
        );
        Ok(())
    }

    /// Fetch new events and reply to each new incoming message
    /// (single-event decrypt path).
    pub fn poll_once(&mut self, conversation_id: &str) -> Result<(), String> {
        let token = self
            .state
            .get(conversation_id)
            .and_then(|s| s.pagination_token.clone());
        let (events, key_events, next) =
            self.api.get_events(conversation_id, 50, token.as_deref())?;
        let signing_keys = self.signing_keys_for(&events);

        // Key changes for this page arrive in meta, not data; adopt their
        // keys before decrypting the messages that need them.
        if !key_events.is_empty() {
            let refs: Vec<&str> = key_events.iter().map(String::as_str).collect();
            let rotated = self.core.decrypt_batch(&refs, &signing_keys);
            let st = self.state.entry(conversation_id.to_string()).or_default();
            st.conversation_keys.extend(rotated.conversation_keys.keys);
            // The sending key only moves forward: a replayed older key change
            // stays usable for decryption but must not roll the version we
            // encrypt with backwards.
            if let Some(v) = rotated.conversation_keys.latest_version {
                let newer = match (&st.latest_key_version, v.parse::<u64>()) {
                    (Some(cur), Ok(new)) => cur.parse::<u64>().map_or(true, |cur| new > cur),
                    _ => true,
                };
                if newer {
                    st.latest_key_version = Some(v);
                }
            }
        }

        for item in &events {
            if item.encoded_event.is_empty() {
                continue;
            }
            let st = self.state.entry(conversation_id.to_string()).or_default();
            let event = match self.core.decrypt_one(
                &item.encoded_event,
                &st.conversation_keys,
                &signing_keys,
            ) {
                Ok(ev) => ev,
                Err(e) => {
                    eprintln!("decrypt_failed conv={conversation_id} err={e}");
                    continue;
                }
            };

            if let Event::KeyChange(kc) = &event {
                for pk in &kc.participant_keys {
                    if pk.encrypted_key.is_empty() {
                        continue;
                    }
                    if let Ok(key) = self.core.decrypt_conversation_key(&pk.encrypted_key) {
                        st.conversation_keys.insert(kc.key_version.clone(), key);
                        // The sending key only moves forward: a replayed older
                        // key change stays usable for decryption but must not
                        // roll the version we encrypt with backwards.
                        let newer = match (&st.latest_key_version, kc.key_version.parse::<u64>()) {
                            (Some(cur), Ok(new)) => {
                                cur.parse::<u64>().map_or(true, |cur| new > cur)
                            }
                            _ => true,
                        };
                        if newer {
                            st.latest_key_version = Some(kc.key_version.clone());
                        }
                        break;
                    }
                }
                continue;
            }

            self.maybe_reply(conversation_id, &event);
        }

        if let Some(next) = next {
            if let Some(st) = self.state.get_mut(conversation_id) {
                st.pagination_token = Some(next);
            }
        }
        Ok(())
    }

    fn maybe_reply(&mut self, conversation_id: &str, event: &Event) {
        let Event::Message(msg) = event else { return };
        let event_id = msg.meta.id.clone().unwrap_or_default();
        let sender_id = msg.meta.sender_id.clone().unwrap_or_default();

        let st = self.state.entry(conversation_id.to_string()).or_default();
        if event_id.is_empty() || !st.seen_event_ids.insert(event_id) {
            return;
        }
        if sender_id == self.bot_user_id {
            return;
        }
        let Some(text) = message_text(event) else {
            return;
        };

        let key_version = msg
            .key_version
            .clone()
            .or_else(|| st.latest_key_version.clone());
        let Some(key_version) = key_version else {
            eprintln!("no_key_version conv={conversation_id}");
            return;
        };
        let Some(conv_key) = st.conversation_keys.get(&key_version) else {
            eprintln!("no_conversation_key conv={conversation_id}");
            return;
        };

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        let reply_conv_id = msg
            .meta
            .conversation_id
            .clone()
            .unwrap_or_else(|| conversation_id.to_string());
        let reply = generate_reply(text);
        let body = match self.core.encrypt_reply(
            &reply_conv_id,
            &reply,
            conv_key,
            &key_version,
            ReplyOptions::default(),
        ) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("encrypt_failed conv={reply_conv_id} err={e}");
                return;
            }
        };
        if let Err(e) = self.api.send_message(&reply_conv_id, &body) {
            eprintln!("send_failed conv={reply_conv_id} err={e}");
            return;
        }
        println!("reply_sent conv={reply_conv_id} len={}", reply.len());
    }

    /// Load the backlog then poll forever.
    pub fn run(&mut self, conversation_id: &str, poll_interval: Duration) -> Result<(), String> {
        self.load_backlog(conversation_id)?;
        println!("bot_running conv={conversation_id} polling every {poll_interval:?}");
        loop {
            if let Err(e) = self.poll_once(conversation_id) {
                eprintln!("poll_error conv={conversation_id} err={e}");
            }
            sleep(poll_interval);
        }
    }
}
