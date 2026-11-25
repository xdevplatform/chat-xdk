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
//!
//! Other users' public keys reach the SDK through one hook,
//! [`ChatCore::fetch_public_keys_with`]: the SDK calls it for the keys a
//! decrypt or a key change lacks, and stores what it returns.

use std::collections::HashMap;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::error::SdkError;
use chat_xdk_core::{
    AttachmentDescriptor, ChatCore as SdkCore, ConversationArchiveParams,
    ConversationKeyChangeParams, ConversationMuteParams, DecryptEventParams, DecryptEventsParams,
    DecryptEventsResult, EncryptMessageParams, EncryptReactionParams, EncryptReplyParams,
    EntityDescriptor, Event, FileDecryptorParams, FileEncryptorParams, GroupCreateParams,
    GroupMembersChangeParams, GroupMembersRemoveParams, GroupTitleChangeParams, PreparedAction,
    PreparedConversationChange, PreparedGroupMetadataChange, PublicKeyInput, PublicKeyRecord,
    PublicKeyRegistrationPayload, PublicKeys, QuickReply, ResolvePublicKeys,
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
    /// `attachment_id` of the one attachment of `reply_to_event` to reply
    /// to, such as one photo of an album; the preview quotes only that
    /// attachment. `None` replies to the whole message.
    pub reply_to_attachment_id: Option<String>,
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
    /// The conversation key and its version to encrypt under, overriding
    /// the SDK's cached key: the newest one a verified key change carried.
    pub conversation_key: Option<(XChatConversationKey, String)>,
}

impl ReplyOptions {
    /// Encrypt under `key` at `version` rather than the SDK's cached key.
    pub fn with_conversation_key(mut self, key: &XChatConversationKey, version: &str) -> Self {
        self.conversation_key = Some((key.clone(), version.to_string()));
        self
    }
}

/// Fields the X API expects for an encrypted message send, plus the
/// message's `event_b64`, which stays local.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendBody {
    pub message_id: String,
    pub encoded_message_create_event: String,
    pub encoded_message_event_signature: String,
    pub xdk_version: String,
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
    /// A chat whose conversation-key cache is on: `decrypt_batch` fills it
    /// from verified key changes, and the encrypt calls take the newest key
    /// from it.
    pub fn new() -> Self {
        let inner = SdkCore::new();
        inner.set_cache_keys(true);
        Self {
            inner,
            signing_key_version: String::new(),
        }
    }

    /// The URL of the X API's feature switches: with the bucket of this
    /// bot's sender once [`ChatCore::set_identity`] has run, the bare
    /// endpoint before.
    pub fn feature_switches_url(&self) -> String {
        self.inner.feature_switches_url()
    }

    /// Take the answer to `GET` [`ChatCore::feature_switches_url`]: its status
    /// and body. The switches decide whether sends are v0 or v1; each answer
    /// replaces the one before.
    pub fn set_feature_switches(&self, status: u16, body: &[u8]) {
        self.inner.set_feature_switches(status, body);
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

    /// Like [`ChatCore::load_keys`], without the registered version;
    /// [`ChatCore::set_registered_version`] records the `public_key_version`
    /// the registration returns.
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

    // -- Other users' public keys -------------------------------------------

    /// Have the SDK fetch the public keys it lacks with `fetch`, which
    /// returns one user's records from `GET /2/users/{id}/public_keys`.
    ///
    /// This sets the SDK's public-key hook. [`ChatCore::decrypt_batch`] then
    /// fetches the signing keys a page's events name and the SDK does not
    /// hold, those of the members who made its key changes as well as those
    /// of the senders of its messages, and decrypts the page once more. The
    /// prepare calls that make a conversation key fetch their members'
    /// identity keys when they are passed no public keys. The SDK stores
    /// what arrives, and waits a minute before it asks again for a key a
    /// lookup did not bring.
    ///
    /// A user whose fetch fails is logged and left out, so the keys of the
    /// other users still arrive.
    pub fn fetch_public_keys_with<F>(&self, fetch: F)
    where
        F: Fn(&str) -> Result<Vec<PublicKeyRecord>, String> + Send + Sync + 'static,
    {
        let resolve: ResolvePublicKeys = Arc::new(
            move |user_ids: &[String]| -> HashMap<String, Vec<PublicKeyRecord>> {
                let mut records = HashMap::new();
                for user_id in user_ids {
                    match fetch(user_id.as_str()) {
                        Ok(found) => {
                            records.insert(user_id.clone(), found);
                        }
                        Err(err) => eprintln!("public_keys_fetch_failed user={user_id} err={err}"),
                    }
                }
                records
            },
        );
        self.inner.set_resolve_public_keys(Some(resolve));
    }

    /// Set the SDK's public-key hook to `resolve` as it is: a function that
    /// takes user ids and returns each user's records, by user id. A process
    /// with several signed-in users gives every chat the same function, so
    /// they share its lookups (see [`crate::multi_user`]).
    pub fn resolve_public_keys_with(&self, resolve: ResolvePublicKeys) {
        self.inner.set_resolve_public_keys(Some(resolve));
    }

    // -- Conversation keys --------------------------------------------------

    /// Prepare a conversation-key change: a fresh key encrypted to every
    /// participant, and the signature the X API takes with it.
    ///
    /// `public_keys` are the participants' identity keys. Pass none for a
    /// one-to-one that `conversation_id` names, by its id or by the other
    /// user's id alone: the SDK reads both users' keys from the public keys
    /// it holds, fetching the ones it lacks through
    /// [`ChatCore::fetch_public_keys_with`].
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

    /// Batch path — every page of events goes through it, the key changes
    /// and the data events together: it extracts the conversation keys from
    /// the KeyChange events, caches those of the key changes that verify,
    /// then decrypts every event.
    ///
    /// Signatures verify with the public keys the SDK holds. The ones the
    /// page lacks are fetched through [`ChatCore::fetch_public_keys_with`];
    /// the result's `missing_signing_keys` lists those that did not arrive.
    pub fn decrypt_batch(&self, events: &[&str]) -> DecryptEventsResult {
        self.inner.decrypt_events(&DecryptEventsParams::new(
            events.iter().map(|e| e.to_string()).collect(),
        ))
    }

    /// Single-event path — decrypt one event. An empty `conversation_keys`
    /// takes the keys from the SDK's cache, and the signature verifies with
    /// the public keys the SDK holds. This path fetches none: an event whose
    /// sender's keys the SDK may lack goes through
    /// [`ChatCore::decrypt_batch`].
    pub fn decrypt_one(
        &self,
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
    ) -> Result<Event, SdkError> {
        self.inner.decrypt_event(&DecryptEventParams::new(
            event_b64,
            conversation_keys.clone(),
        ))
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
    /// [`ChatCore::set_identity`], and the conversation key from the SDK's
    /// cache unless `options` sets one.
    pub fn encrypt_reply(
        &self,
        conversation_id: &str,
        text: &str,
        options: ReplyOptions,
    ) -> Result<SendBody, SdkError> {
        let (conversation_key, conversation_key_version) = match options.conversation_key {
            Some((key, version)) => (Some(key.to_bytes()), Some(version)),
            None => (None, None),
        };
        let payload =
            if options.reply_to_event.is_none() && options.reply_to_attachment_id.is_none() {
                let mut params = EncryptMessageParams::new(conversation_id, text);
                params.conversation_key = conversation_key;
                params.conversation_key_version = conversation_key_version;
                params.entities = options.entities;
                params.attachments = options.attachments;
                params.quick_reply = options.quick_reply;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_message(&params)?
            } else {
                let mut params = EncryptReplyParams::new(
                    conversation_id,
                    text,
                    options.reply_to_event.unwrap_or_default(),
                );
                params.conversation_key = conversation_key;
                params.conversation_key_version = conversation_key_version;
                params.reply_to_ckces = options.reply_to_ckces;
                params.reply_to_attachment_id = options.reply_to_attachment_id;
                params.entities = options.entities;
                params.attachments = options.attachments;
                params.quick_reply = options.quick_reply;
                params.ttl_msec = options.ttl_msec;
                self.inner.encrypt_reply(&params)?
            };
        Ok(SendBody {
            // The SDK generates the message id and returns it in the payload.
            message_id: payload.message_id,
            encoded_message_create_event: payload.encoded_message_create_event,
            encoded_message_event_signature: payload.encoded_message_event_signature,
            xdk_version: payload.xdk_version,
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
        self.send_reaction(add, &params)
    }

    /// Like [`ChatCore::encrypt_reaction`], for one attachment of the target:
    /// `target_attachment_id` is the `attachment_id` of an attachment
    /// `target_event` carries, such as one photo of an album. The SDK
    /// decrypts `target_event` to check the attachment is in it. Remove the
    /// reaction with the same `target_attachment_id`.
    pub fn encrypt_reaction_to_attachment(
        &self,
        add: bool,
        target_event: &str,
        target_attachment_id: &str,
        emoji: &str,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
    ) -> Result<SendBody, SdkError> {
        let params = EncryptReactionParams::new(target_event, emoji)
            .with_conversation_key(conversation_key.to_bytes(), conversation_key_version)
            .with_target_attachment_id(target_attachment_id);
        self.send_reaction(add, &params)
    }

    fn send_reaction(
        &self,
        add: bool,
        params: &EncryptReactionParams,
    ) -> Result<SendBody, SdkError> {
        let payload = if add {
            self.inner.encrypt_add_reaction(params)?
        } else {
            self.inner.encrypt_remove_reaction(params)?
        };
        Ok(SendBody {
            // The SDK generates the message id and returns it in the payload.
            message_id: payload.message_id,
            encoded_message_create_event: payload.encoded_message_create_event,
            encoded_message_event_signature: payload.encoded_message_event_signature,
            xdk_version: payload.xdk_version,
            conversation_token: None,
            event_b64: payload.event_b64,
        })
    }

    // -- Group management -----------------------------------------------------

    /// Prepare a group creation: fresh key + the two required signatures.
    /// A plaintext `title` is encrypted under the new key; send the result's
    /// `encrypted_title` as the request's `group_name`.
    ///
    /// Pass no `public_keys` to have the SDK read the identity keys of
    /// `member_ids` and `admin_ids` from the public keys it holds, fetching
    /// the ones it lacks through [`ChatCore::fetch_public_keys_with`].
    pub fn prepare_group_create(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: &str,
        member_ids: &[String],
        admin_ids: &[String],
        title: Option<&str>,
    ) -> Result<PreparedConversationChange, SdkError> {
        let mut params = GroupCreateParams::new(
            public_keys.to_vec(),
            conversation_id,
            member_ids.to_vec(),
            admin_ids.to_vec(),
        );
        if let Some(title) = title {
            params = params.with_title(title);
        }
        self.inner.prepare_group_create(&params)
    }

    /// Prepare a member add: rotated key + the two required signatures.
    ///
    /// Pass no `public_keys` to have the SDK read the identity keys of
    /// `current_member_ids` and `new_member_ids` from the public keys it
    /// holds, fetching the ones it lacks.
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

    /// Prepare a member removal that rotates the key for who stays.
    ///
    /// `public_keys` are the identity keys of the members who remain. Pass
    /// none, and name those members in `remaining_member_ids`, to have the
    /// SDK read their keys from the public keys it holds, fetching the ones
    /// it lacks; with `public_keys` passed, `remaining_member_ids` is not
    /// read.
    pub fn prepare_group_members_remove(
        &self,
        public_keys: &[PublicKeyInput],
        conversation_id: &str,
        user_ids: &[String],
        remaining_member_ids: &[String],
    ) -> Result<PreparedConversationChange, SdkError> {
        self.inner.prepare_group_members_remove(
            &GroupMembersRemoveParams::new(
                public_keys.to_vec(),
                conversation_id,
                user_ids.to_vec(),
            )
            .with_remaining_member_ids(remaining_member_ids.to_vec()),
        )
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
        let mut dec = self.inner.file_decryptor(&FileDecryptorParams::new(
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

    // -- Group metadata -----------------------------------------------------

    /// Prepare a group title change: the SDK encrypts the plaintext title
    /// under the conversation key and signs it. Send `encrypted_value` as the
    /// group's name and `action_signatures` on the request.
    pub fn prepare_group_title_change(
        &self,
        conversation_id: &str,
        title: &str,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.inner.prepare_group_title_change(
            &GroupTitleChangeParams::new(conversation_id, title)
                .with_conversation_key(conversation_key.to_bytes(), conversation_key_version),
        )
    }

    /// Decrypt a group title or description the X API returns for a
    /// conversation.
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        self.inner.decrypt(ciphertext_b64, conversation_key)
    }

    // -- Conversation archive -----------------------------------------------

    /// Sign archiving (`archived` true) or unarchiving (false) a
    /// conversation, group or one-to-one. Send `action_signatures` on
    /// `POST /2/chat/conversations/{id}/archive` to archive, or on `DELETE`
    /// of the same path to unarchive. Signed with the session identity.
    pub fn prepare_conversation_archive(
        &self,
        conversation_id: &str,
        archived: bool,
    ) -> Result<PreparedAction, SdkError> {
        let params = ConversationArchiveParams::new(conversation_id, archived);
        self.inner.prepare_conversation_archive(&params)
    }

    // -- Conversation mute --------------------------------------------------

    /// Sign muting (`muted` true) or unmuting (false) a conversation, group
    /// or one-to-one, for this bot alone. The event is signed in the bot's
    /// own `{user_id}:{user_id}` conversation and names `conversation_id` in
    /// canonical colon form; send `action_signatures` with a mute or unmute
    /// request that names the conversation in that same form. Signed with
    /// the session identity.
    pub fn prepare_conversation_mute(
        &self,
        conversation_id: &str,
        muted: bool,
    ) -> Result<PreparedAction, SdkError> {
        self.inner
            .prepare_conversation_mute(&ConversationMuteParams::new(conversation_id, muted))
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
/// (two signatures). The participant keys and action signatures already have
/// the request's shape.
pub fn prep_to_request(prep: &PreparedConversationChange) -> Value {
    json!({
        "conversation_key_version": prep.conversation_key_version,
        "conversation_participant_keys": prep.conversation_participant_keys,
        "action_signatures": prep.action_signatures,
    })
}

/// Map a rotating member removal into the members/remove request.
///
/// Both signatures go in `action_signatures`. The new key version and the
/// participant keys for the members who stay go in `group_key_rotation_data`.
pub fn removal_to_request(user_ids: &[String], prep: &PreparedConversationChange) -> Value {
    json!({
        "user_ids": user_ids,
        "action_signatures": prep.action_signatures,
        "group_key_rotation_data": {
            "conversation_key_version": prep.conversation_key_version,
            "conversation_participant_keys": prep.conversation_participant_keys,
        },
    })
}
