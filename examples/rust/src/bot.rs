//! The receive -> decrypt -> reply -> encrypt -> send loop.
//!
//! Generic over [`ChatApi`] so it has no direct HTTP dependency.

use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use chat_xdk_core::error::SdkError;
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

/// In-memory state for one conversation. Its conversation keys live in the
/// SDK's cache.
#[derive(Default)]
struct ConversationState {
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
    pub fn new(core: ChatCore, api: A, bot_user_id: String) -> Result<Self, SdkError> {
        // One identity per bot instance: signed actions default their
        // sender_id and signing_key_version to these values.
        core.set_identity(&bot_user_id)?;
        Ok(Self {
            core,
            api,
            bot_user_id,
            state: HashMap::new(),
        })
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

    /// Initial load: batch-decrypt the backlog (decrypt_events path), filling
    /// the SDK's conversation-key cache from the key changes.
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
        st.pagination_token = next;
        println!(
            "backlog_loaded conv={conversation_id} messages={} keys={key_count}",
            result.events.len()
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

        // Key changes for this page arrive in meta, not data; only the batch
        // path feeds the key cache, so route them through it before
        // decrypting the messages that need them.
        if !key_events.is_empty() {
            let refs: Vec<&str> = key_events.iter().map(String::as_str).collect();
            self.core.decrypt_batch(&refs, &signing_keys);
        }

        for item in &events {
            if item.encoded_event.is_empty() {
                continue;
            }
            // An empty key map: the conversation keys come from the cache.
            let event =
                match self
                    .core
                    .decrypt_one(&item.encoded_event, &HashMap::new(), &signing_keys)
                {
                    Ok(ev) => ev,
                    Err(e) => {
                        eprintln!("decrypt_failed conv={conversation_id} err={e}");
                        continue;
                    }
                };

            if let Event::KeyChange(_) = &event {
                // Only the batch path adopts keys into the cache; replay the
                // key change through it so the rotated key becomes the
                // sending key.
                self.core
                    .decrypt_batch(&[item.encoded_event.as_str()], &signing_keys);
                continue;
            }

            self.maybe_reply(conversation_id, &item.encoded_event, &event);
        }

        if let Some(next) = next {
            if let Some(st) = self.state.get_mut(conversation_id) {
                st.pagination_token = Some(next);
            }
        }
        Ok(())
    }

    /// Answer a decrypted message with a threaded reply anchored on the raw
    /// incoming event.
    fn maybe_reply(&mut self, conversation_id: &str, raw_event_b64: &str, event: &Event) {
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

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        let reply_conv_id = msg
            .meta
            .conversation_id
            .clone()
            .unwrap_or_else(|| conversation_id.to_string());
        let reply = generate_reply(text);
        // Reply by raw event: the SDK derives the preview from it, and the
        // conversation key resolves from the key cache.
        let options = ReplyOptions {
            reply_to_event: Some(raw_event_b64.to_string()),
            ..Default::default()
        };
        let body = match self.core.encrypt_reply(&reply_conv_id, &reply, options) {
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
