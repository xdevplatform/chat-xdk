//! Crypto core for the Rust chat-xdk example bot.
//!
//! A thin, network-free wrapper around the `chat_xdk_core` binding.
//! Everything that touches the SDK lives here so it can be unit-tested directly
//! (see `tests/chat_core.rs`). The four core feature touchpoints are all here:
//!
//! - key management     -> [`ChatCore::load_keys`] / [`ChatCore::generate_and_register`]
//! - conversation keys  -> [`ChatCore::prepare_conversation_key_change`] / [`ChatCore::decrypt_conversation_key`]
//! - message encryption -> [`ChatCore::encrypt_reply`]
//! - event decryption   -> [`ChatCore::decrypt_batch`] (decrypt_events) and
//!   [`ChatCore::decrypt_one`] (decrypt_event)

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::error::SdkError;
use chat_xdk_core::{
    AttachmentDescriptor, ChatCore as SdkCore, ConversationKeyChangeParams, DecryptEventsResult,
    EncryptMessageParams, EncryptReactionParams, EncryptReplyParams, EntityDescriptor, Event,
    GroupCreateParams, GroupMembersChangeParams, PreparedConversationChange, PublicKeyInput,
    PublicKeyRegistrationPayload, PublicKeys, SigningKeyEntry,
};
use serde_json::{json, Value};

/// Optional extras for [`ChatCore::encrypt_reply`].
#[derive(Debug, Clone, Default)]
pub struct ReplyOptions {
    /// Base64 raw event of the message to thread the reply under; `None`
    /// sends a fresh (unthreaded) message. The SDK derives the reply preview
    /// from it and embeds it so recipients can validate the preview.
    pub reply_to_event: Option<String>,
    /// Base64 raw key-change events, needed when the original message was
    /// encrypted under a different key version than the reply.
    pub reply_to_ckces: Option<Vec<String>>,
    /// Rich-text entities (mentions, URLs, etc.) as byte ranges in the text.
    pub entities: Option<Vec<EntityDescriptor>>,
    /// Attachment descriptors (e.g. a media reference) to embed.
    pub attachments: Option<Vec<AttachmentDescriptor>>,
    /// Disappearing-message lifetime in milliseconds.
    pub ttl_msec: Option<i64>,
}

/// Fields the X API expects for an encrypted message send.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendBody {
    pub message_id: String,
    pub encoded_message_create_event: String,
    pub encoded_message_event_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_token: Option<String>,
}

/// Wraps a single unlocked `chat_xdk_core::ChatCore` for one bot identity.
pub struct ChatCore {
    inner: SdkCore,
    pub signing_key_version: String,
}

impl ChatCore {
    pub fn new() -> Self {
        Self {
            inner: SdkCore::new(),
            signing_key_version: "1".to_string(),
        }
    }

    // -- Key management -----------------------------------------------------

    /// Import an existing base64 private-key blob (identity[+signing]) and unlock.
    pub fn load_keys(
        &mut self,
        private_keys_b64: &str,
        signing_key_version: &str,
    ) -> Result<(), SdkError> {
        let bytes = B64
            .decode(private_keys_b64)
            .map_err(|e| SdkError::Parse(format!("invalid base64 private keys: {e}")))?;
        self.inner
            .import_keys_with_version(&bytes, signing_key_version)?;
        self.signing_key_version = signing_key_version.to_string();
        Ok(())
    }

    /// Generate a fresh identity. Returns the registration payload to POST to
    /// the X API plus the exported private blob (base64) to persist locally.
    pub fn generate_and_register(
        &self,
    ) -> Result<(PublicKeyRegistrationPayload, String), SdkError> {
        let payload = self.inner.generate_keypairs()?;
        let exported = self.inner.export_keys()?;
        Ok((payload, B64.encode(exported)))
    }

    pub fn public_keys(&self) -> Result<PublicKeys, SdkError> {
        self.inner.get_public_keys()
    }

    /// Record the version the X API assigned to the registered public key;
    /// [`ChatCore::set_identity`] passes it to the SDK together with the
    /// user id.
    pub fn set_registered_version(&mut self, version: &str) {
        self.signing_key_version = version.to_string();
    }

    /// Set the session identity once; every signed action then defaults its
    /// `sender_id` and `signing_key_version` to these values.
    pub fn set_identity(&self, user_id: &str) {
        self.inner.set_identity(user_id, &self.signing_key_version);
    }

    // -- Conversation keys --------------------------------------------------

    pub fn prepare_conversation_key_change(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: Option<&str>,
    ) -> Result<PreparedConversationChange, SdkError> {
        let mut params = ConversationKeyChangeParams::new(public_keys.to_vec());
        params.conversation_id = conversation_id.map(String::from);
        self.inner.prepare_conversation_key_change(params)
    }

    pub fn decrypt_conversation_key(
        &self,
        encrypted_key_b64: &str,
    ) -> Result<XChatConversationKey, SdkError> {
        self.inner.decrypt_conversation_key(encrypted_key_b64)
    }

    // -- Decryption: the two paths -----------------------------------------

    /// Batch path — used on initial conversation load (extracts conversation
    /// keys from KeyChange events, then decrypts every message).
    pub fn decrypt_batch(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
    ) -> DecryptEventsResult {
        self.inner.decrypt_events(events, signing_keys)
    }

    /// Single-event path — used for each new event after the initial load.
    pub fn decrypt_one(
        &self,
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        self.inner
            .decrypt_event(event_b64, conversation_keys, signing_keys)
    }

    // -- Message encryption -------------------------------------------------

    /// Encrypt + sign a message, returning fields ready for the X API send.
    ///
    /// Without `reply_to_event` this sends a fresh message via
    /// `encrypt_message`; with it, the SDK's `encrypt_reply` builds a
    /// *threaded* reply whose preview is derived from that raw event.
    /// `entities` are byte ranges into the text; `attachments` are attachment
    /// descriptors (e.g. a media reference); `ttl_msec` makes the message
    /// disappear after the given lifetime. The sender identity comes from
    /// [`ChatCore::set_identity`].
    pub fn encrypt_reply(
        &self,
        conversation_id: &str,
        text: &str,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
        options: ReplyOptions,
    ) -> Result<SendBody, SdkError> {
        let payload = match &options.reply_to_event {
            None => {
                let mut params = EncryptMessageParams::new(conversation_id, text)
                    .with_conversation_key(conversation_key.to_bytes(), conversation_key_version);
                params.entities = options.entities;
                params.attachments = options.attachments;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_message(params)?
            }
            Some(reply_to_event) => {
                let mut params =
                    EncryptReplyParams::new(conversation_id, text, reply_to_event.clone())
                        .with_conversation_key(
                            conversation_key.to_bytes(),
                            conversation_key_version,
                        );
                params.reply_to_ckces = options.reply_to_ckces.clone();
                params.entities = options.entities;
                params.attachments = options.attachments;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_reply(params)?
            }
        };
        Ok(SendBody {
            // The SDK generates the message id and returns it in the payload.
            message_id: payload.message_id,
            encoded_message_create_event: payload.encrypted_content,
            encoded_message_event_signature: payload.encoded_event_signature,
            conversation_token: None,
        })
    }

    /// Encrypt + sign a reaction add/remove targeting a raw event: the SDK
    /// derives the conversation id and target sequence id from it.
    pub fn encrypt_reaction(
        &self,
        add: bool,
        target_event: &str,
        emoji: &str,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
    ) -> Result<SendBody, SdkError> {
        let params = EncryptReactionParams::new(target_event, emoji)
            .with_conversation_key(conversation_key.to_bytes(), conversation_key_version);
        let payload = if add {
            self.inner.encrypt_add_reaction(&params)?
        } else {
            self.inner.encrypt_remove_reaction(&params)?
        };
        Ok(SendBody {
            // The SDK generates the message id and returns it in the payload.
            message_id: payload.message_id,
            encoded_message_create_event: payload.encrypted_content,
            encoded_message_event_signature: payload.encoded_event_signature,
            conversation_token: None,
        })
    }

    // -- Group management -----------------------------------------------------

    /// Prepare a group creation: fresh key + the two required signatures.
    pub fn prepare_group_create(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: &str,
        member_ids: &[String],
        admin_ids: &[String],
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_create(GroupCreateParams::new(
            public_keys.to_vec(),
            conversation_id,
            member_ids.to_vec(),
            admin_ids.to_vec(),
        ))
    }

    /// Prepare a member add: rotated key + the two required signatures.
    pub fn prepare_group_members_change(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: &str,
        new_member_ids: &[String],
        current_member_ids: &[String],
        current_admin_ids: &[String],
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner
            .prepare_group_members_change(GroupMembersChangeParams::new(
                public_keys.to_vec(),
                conversation_id,
                new_member_ids.to_vec(),
                current_member_ids.to_vec(),
                current_admin_ids.to_vec(),
                vec![],
            ))
    }

    // -- Media streaming -----------------------------------------------------

    /// Chunk size fed through the incremental stream encryptor/decryptor.
    pub const MEDIA_CHUNK: usize = 1024 * 1024;

    /// Encrypt a media blob with the incremental stream API.
    ///
    /// Feeding fixed-size chunks through `push` keeps memory bounded no
    /// matter how large the file is; `finish` emits the final frame that
    /// seals the stream (decryption fails without it).
    pub fn encrypt_media(
        &self,
        plaintext: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        let mut enc = self.inner.stream_encryptor(conversation_key)?;
        let mut out = Vec::new();
        for chunk in plaintext.chunks(Self::MEDIA_CHUNK) {
            out.extend(enc.push(chunk)?);
        }
        out.extend(enc.finish()?);
        Ok(out)
    }

    /// Decrypt a media blob with the incremental stream API.
    ///
    /// `finish` errors if the stream was truncated, so plaintext from `push`
    /// must not be treated as complete until it succeeds.
    pub fn decrypt_media(
        &self,
        ciphertext: &[u8],
        conversation_key: &XChatConversationKey,
    ) -> Result<Vec<u8>, SdkError> {
        let mut dec = self.inner.stream_decryptor(conversation_key)?;
        let mut out = Vec::new();
        for chunk in ciphertext.chunks(Self::MEDIA_CHUNK) {
            out.extend(dec.push(chunk)?);
        }
        out.extend(dec.finish()?);
        Ok(out)
    }

    // -- Generic helpers (handy for metadata + tests) -----------------------

    pub fn encrypt(
        &self,
        plaintext: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        self.inner.encrypt(plaintext, conversation_key)
    }

    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        self.inner.decrypt(ciphertext_b64, conversation_key)
    }
}

impl Default for ChatCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Pull the plain text out of a decrypted Message event, or `None`.
pub fn message_text(event: &Event) -> Option<&str> {
    match event {
        Event::Message(msg) => msg.text(),
        _ => None,
    }
}

/// Map a prepared conversation change into the X API request shape.
///
/// Works for 1:1 key changes (one signature) and group create / member add
/// (two signatures). `signing_public_key` is the sender's own signing key,
/// which the API expects alongside each signature.
pub fn prep_to_request(prep: &PreparedConversationChange, signing_public_key: &str) -> Value {
    let participant_keys: Vec<Value> = prep
        .participant_keys
        .iter()
        .map(|pk| {
            json!({
                "user_id": pk.user_id,
                "encrypted_conversation_key": pk.encrypted_key,
                "public_key_version": pk.public_key_version,
            })
        })
        .collect();
    let action_signatures: Vec<Value> = prep
        .action_signatures
        .iter()
        .map(|sig| {
            let mut entry = json!({
                "message_id": sig.message_id,
                "encoded_message_event_detail": sig.encoded_message_event_detail,
                "message_event_signature": {
                    "signature": sig.signature,
                    "signature_version": sig.signature_version,
                    "public_key_version": sig.public_key_version,
                    "signing_public_key": signing_public_key,
                },
            });
            // Conversation-key-change payloads are withheld by the SDK (they
            // embed the plaintext key); only forward one when it is present.
            if !sig.signature_payload.is_empty() {
                entry["signature_payload"] = json!(sig.signature_payload);
            }
            entry
        })
        .collect();
    json!({
        "conversation_key_version": prep.conversation_key_version,
        "conversation_participant_keys": participant_keys,
        "action_signatures": action_signatures,
    })
}
