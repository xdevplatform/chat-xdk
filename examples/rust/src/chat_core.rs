//! Crypto core for the Rust chat-xdk example bot.
//!
//! A thin, network-free wrapper around the `chat_xdk_core` binding.
//! Everything that touches the SDK lives here so it can be unit-tested directly
//! (see `tests/chat_core.rs`). The four core feature touchpoints are all here:
//!
//! - key management     -> [`ChatCore::load_keys`] / [`ChatCore::generate_and_register`]
//! - conversation keys  -> [`ChatCore::prepare_conversation_key_change`] / [`ChatCore::decrypt_conversation_key`]
//! - message encryption -> [`ChatCore::encrypt_reply`], then
//!   [`ChatCore::encrypt_media`] for its files
//! - event decryption   -> [`ChatCore::decrypt_batch`] (decrypt_events) and
//!   [`ChatCore::decrypt_one`] (decrypt_event)

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::error::SdkError;
use chat_xdk_core::{
    AttachmentDescriptor, ChatCore as SdkCore, ConversationKeyChangeParams, DecryptEventParams,
    DecryptEventsParams, DecryptEventsResult, EncryptMessageParams, EncryptReactionParams,
    EncryptReplyParams, EntityDescriptor, Event, FileDecryptorParams, FileEncryptorParams,
    GroupCreateParams, GroupMembersChangeParams, PreparedConversationChange, PublicKeyInput,
    PublicKeyRegistrationPayload, PublicKeys, QuickReply, SigningKeyEntry,
};
use chat_xdk_core::{ImportKeysParams, SetIdentityParams};
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
    /// Attachment descriptors to embed. Each file names the media hash key
    /// its upload started with; encrypt the files afterwards with
    /// [`ChatCore::encrypt_media`] and the returned body's `event_b64`.
    pub attachments: Option<Vec<AttachmentDescriptor>>,
    /// Quick reply offering selectable options, or answering them.
    pub quick_reply: Option<QuickReply>,
    /// Disappearing-message lifetime in milliseconds.
    pub ttl_msec: Option<i64>,
}

/// Fields the X API expects for an encrypted message send, plus the
/// message's `event_b64`, which stays local.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendBody {
    pub message_id: String,
    pub encoded_message_create_event: String,
    pub encoded_message_event_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_token: Option<String>,
    /// The message as recipients receive it; encrypt the message's files
    /// from it with [`ChatCore::encrypt_media`].
    #[serde(skip)]
    pub event_b64: String,
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
            signing_key_version: String::new(),
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
        self.inner.import_keys(
            &ImportKeysParams::new(bytes).with_signing_key_version(signing_key_version),
        )?;
        self.signing_key_version = signing_key_version.to_string();
        Ok(())
    }

    /// Like [`ChatCore::load_keys`], for keys whose registered version is not
    /// known yet; [`ChatCore::set_registered_version`] records it once the X
    /// API reports it.
    pub fn load_keys_without_version(&mut self, private_keys_b64: &str) -> Result<(), SdkError> {
        let bytes = B64
            .decode(private_keys_b64)
            .map_err(|e| SdkError::Parse(format!("invalid base64 private keys: {e}")))?;
        self.inner.import_keys(&ImportKeysParams::new(bytes))
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
    pub fn set_identity(&self, user_id: &str) -> Result<(), SdkError> {
        if self.signing_key_version.is_empty() {
            return Err(SdkError::InvalidState(
                "signing key version unknown: pass load_keys or set_registered_version the \
                 public_key_version the X API returned when the keys were registered"
                    .into(),
            ));
        }
        self.inner.set_identity(&SetIdentityParams::new(
            user_id,
            self.signing_key_version.as_str(),
        ))
    }

    // -- Conversation keys --------------------------------------------------

    pub fn prepare_conversation_key_change(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: Option<&str>,
    ) -> Result<PreparedConversationChange, SdkError> {
        let mut params = ConversationKeyChangeParams::new(public_keys.to_vec());
        params.conversation_id = conversation_id.map(String::from);
        self.inner.prepare_conversation_key_change(&params)
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
        self.inner.decrypt_events(
            DecryptEventsParams::new(events.iter().map(|e| e.to_string()).collect())
                .with_signing_keys(signing_keys.to_vec()),
        )
    }

    /// Single-event path — used for each new event after the initial load.
    pub fn decrypt_one(
        &self,
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        self.inner.decrypt_event(
            DecryptEventParams::new(event_b64, conversation_keys.clone())
                .with_signing_keys(signing_keys.to_vec()),
        )
    }

    // -- Message encryption -------------------------------------------------

    /// Encrypt + sign a message, returning fields ready for the X API send.
    ///
    /// Without `reply_to_event` this sends a fresh message via
    /// `encrypt_message`; with it, the SDK's `encrypt_reply` builds a
    /// *threaded* reply whose preview is derived from that raw event.
    /// `entities` are byte ranges into the text; `attachments` are attachment
    /// descriptors (e.g. a media reference); `quick_reply` offers selectable
    /// options or answers them; `ttl_msec` makes the message disappear after
    /// the given lifetime. The sender identity comes from
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
                params.quick_reply = options.quick_reply;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_message(&params)?
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
                params.quick_reply = options.quick_reply;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_reply(&params)?
            }
        };
        Ok(SendBody {
            // The SDK generates the message id and returns it in the payload.
            message_id: payload.message_id,
            encoded_message_create_event: payload.encrypted_content,
            encoded_message_event_signature: payload.encoded_event_signature,
            conversation_token: None,
            event_b64: payload.event_b64,
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
            event_b64: payload.event_b64,
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
        self.inner.prepare_group_create(&GroupCreateParams::new(
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
            .prepare_group_members_change(&GroupMembersChangeParams::new(
                public_keys.to_vec(),
                conversation_id,
                new_member_ids.to_vec(),
                current_member_ids.to_vec(),
                current_admin_ids.to_vec(),
                vec![],
            ))
    }

    // -- Media files -----------------------------------------------------------

    /// Chunk size fed through the incremental file encryptor/decryptor.
    pub const MEDIA_CHUNK: usize = 1024 * 1024;

    /// Encrypt a media file of an outgoing message with the incremental file
    /// API.
    ///
    /// `event_b64` is the `event_b64` of the body [`ChatCore::encrypt_reply`]
    /// returned for the message, `conversation_key` and
    /// `conversation_key_version` the key the message was encrypted under,
    /// and `media_hash_key` the hash key the file's upload started with, as
    /// listed in the message's attachments; the SDK encrypts the file under
    /// that attachment's key. Feeding fixed-size chunks through `push` keeps
    /// memory bounded no matter how large the file is; `finish` emits the
    /// final frame that seals the file (decryption fails without it).
    pub fn encrypt_media(
        &self,
        plaintext: &[u8],
        event_b64: &str,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
        media_hash_key: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let mut enc = self.inner.file_encryptor(
            &FileEncryptorParams::new(event_b64, media_hash_key)
                .with_conversation_key(conversation_key.to_bytes(), conversation_key_version),
        )?;
        let mut out = Vec::new();
        for chunk in plaintext.chunks(Self::MEDIA_CHUNK) {
            out.extend(enc.push(chunk)?);
        }
        out.extend(enc.finish()?);
        Ok(out)
    }

    /// Decrypt a downloaded media file with the incremental file API.
    ///
    /// `event_b64` is the raw event of the message that carries the media and
    /// `conversation_keys` its conversation's key map, as passed to
    /// `decrypt_one`; the SDK finds `media_hash_key` in the event and derives
    /// that file's key. `finish` errors if the file was truncated, so
    /// plaintext from `push` must not be treated as complete until it
    /// succeeds.
    pub fn decrypt_media(
        &self,
        ciphertext: &[u8],
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        media_hash_key: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let mut dec = self.inner.file_decryptor(FileDecryptorParams::new(
            event_b64,
            conversation_keys.clone(),
            media_hash_key,
        ))?;
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
/// (two signatures). The action signatures already have the request's shape;
/// the participant keys take the request's field names.
pub fn prep_to_request(prep: &PreparedConversationChange) -> Value {
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
    json!({
        "conversation_key_version": prep.conversation_key_version,
        "conversation_participant_keys": participant_keys,
        "action_signatures": prep.action_signatures,
    })
}
