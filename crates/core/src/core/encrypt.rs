//! Message encryption: messages, replies, reactions, edits and their signatures.

use super::*;

impl ChatCore {
    // Message Encryption

    /// Parse a raw conversation key supplied in a params struct.
    pub(crate) fn conversation_key_from_bytes(
        bytes: &[u8],
    ) -> Result<XChatConversationKey, SdkError> {
        XChatConversationKey::from_bytes(bytes.to_vec()).ok_or_else(|| {
            SdkError::InvalidInput("Invalid conversation key (expected 32 bytes)".into())
        })
    }

    /// Encrypt a text message.
    pub fn encrypt_message(&self, params: &EncryptMessageParams) -> Result<SendPayload, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &params.conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let thrift_entities = params
            .entities
            .as_deref()
            .map(crate::pipeline::build_thrift_entities);
        if let Some(a) = params.attachments.as_deref() {
            crate::pipeline::validate_attachment_descriptors(a)?;
            crate::pipeline::validate_file_media_hash_keys(a)?;
        }
        let send_version = self.send_version();
        let message_id = Self::outgoing_message_id(
            send_version,
            &ckey,
            &conversation_key_version,
            &sender_id,
            &params.conversation_id,
            params.attachments.as_deref(),
        )?;
        let thrift_attachments = params
            .attachments
            .as_deref()
            .map(|a| crate::pipeline::build_outgoing_attachments(a, &message_id, send_version));
        let thrift_quick_reply = params
            .quick_reply
            .as_ref()
            .map(crate::pipeline::build_thrift_quick_reply);
        let content_bytes = crate::pipeline::build_message_content(
            &params.text,
            thrift_entities,
            thrift_attachments,
            thrift_quick_reply,
        )?;

        let mut api_params = crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &params.conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        )
        .send_version(send_version);
        api_params.should_notify = params.should_notify;
        api_params.ttl_msec = params.ttl_msec;
        crate::pipeline::encrypt_and_sign(api_params)
    }

    /// Encrypt a reply.
    ///
    /// When `reply_to_event` is set, the reply preview (sequence id, sender,
    /// text, entities, attachments) is derived from that raw signed event and
    /// the event itself is embedded so recipients can validate the preview.
    /// Explicit `reply_to_*` fields override the derived values.
    pub fn encrypt_reply(&self, params: &EncryptReplyParams) -> Result<SendPayload, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &params.conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let thrift_entities = params
            .entities
            .as_deref()
            .map(crate::pipeline::build_thrift_entities);
        if let Some(a) = params.attachments.as_deref() {
            crate::pipeline::validate_attachment_descriptors(a)?;
            crate::pipeline::validate_file_media_hash_keys(a)?;
        }
        let send_version = self.send_version();
        let message_id = Self::outgoing_message_id(
            send_version,
            &ckey,
            &conversation_key_version,
            &sender_id,
            &params.conversation_id,
            params.attachments.as_deref(),
        )?;
        let thrift_attachments = params
            .attachments
            .as_deref()
            .map(|a| crate::pipeline::build_outgoing_attachments(a, &message_id, send_version));

        let thrift_quick_reply = params
            .quick_reply
            .as_ref()
            .map(crate::pipeline::build_thrift_quick_reply);

        let preview = self.build_reply_preview(params, &ckey, &conversation_key_version)?;

        let content_bytes = crate::pipeline::build_message_content_with_preview(
            &params.text,
            preview,
            thrift_entities,
            thrift_attachments,
            thrift_quick_reply,
        )?;

        let mut api_params = crate::pipeline::EncryptAndSignParams::new(
            &ckey,
            &signing_kp.private,
            &message_id,
            &sender_id,
            &params.conversation_id,
            &content_bytes,
            &conversation_key_version,
            &signing_key_version,
        )
        .send_version(send_version);
        api_params.should_notify = params.should_notify;
        api_params.ttl_msec = params.ttl_msec;
        crate::pipeline::encrypt_and_sign(api_params)
    }

    /// Encrypt a reaction-add.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_add_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_reaction_target(params)?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let content_bytes =
            crate::pipeline::build_reaction_add_content(&target_sequence_id, &params.emoji)?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(
            crate::pipeline::EncryptAndSignParams::new(
                &ckey,
                &signing_kp.private,
                &message_id,
                &sender_id,
                &conversation_id,
                &content_bytes,
                &conversation_key_version,
                &signing_key_version,
            )
            .send_version(self.send_version()),
        )
    }

    /// Encrypt a reaction-remove.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_remove_reaction(
        &self,
        params: &EncryptReactionParams,
    ) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_reaction_target(params)?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        let content_bytes =
            crate::pipeline::build_reaction_remove_content(&target_sequence_id, &params.emoji)?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(
            crate::pipeline::EncryptAndSignParams::new(
                &ckey,
                &signing_kp.private,
                &message_id,
                &sender_id,
                &conversation_id,
                &content_bytes,
                &conversation_key_version,
                &signing_key_version,
            )
            .send_version(self.send_version()),
        )
    }

    /// Encrypt a message edit.
    ///
    /// The edit replaces the target message's text (and entities) for every
    /// recipient; it is sent through the same message-create channel as a
    /// regular message and carries its own fresh message id.
    ///
    /// When `target_event` is set, the conversation id and target sequence id
    /// are derived from that raw event; explicit fields override them.
    pub fn encrypt_edit(&self, params: &EncryptEditParams) -> Result<SendPayload, SdkError> {
        let (conversation_id, target_sequence_id) = Self::resolve_event_target(
            params.target_event.as_deref(),
            params.conversation_id.as_deref(),
            params.target_message_sequence_id.as_deref(),
        )?;
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let (ckey, conversation_key_version) = self.resolve_conversation_key(
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
            &conversation_id,
            &sender_id,
        )?;
        let signing_kp = self.get_signing_keypair_arc()?;
        // Only v1 edits name the message they edit; v0 edits are built as
        // 0.5.x built them. Read leniently: an unparsable target event already
        // fails above unless explicit fields made it unnecessary, and then
        // only the message id is lost.
        let send_version = self.send_version();
        let target_message_id = params
            .target_event
            .as_deref()
            .filter(|_| send_version == crate::pipeline::SendVersion::V1)
            .filter(|v| !v.is_empty())
            .and_then(|b64| Self::parse_event_b64(b64).ok())
            .and_then(|event| event.message_id);
        let content_bytes = crate::pipeline::build_message_edit_content(
            &target_sequence_id,
            &params.updated_text,
            params.entities.as_deref(),
            target_message_id.as_deref(),
        )?;
        let message_id = Self::generate_message_id();
        crate::pipeline::encrypt_and_sign(
            crate::pipeline::EncryptAndSignParams::new(
                &ckey,
                &signing_kp.private,
                &message_id,
                &sender_id,
                &conversation_id,
                &content_bytes,
                &conversation_key_version,
                &signing_key_version,
            )
            .send_version(send_version),
        )
    }

    /// Build the signed action for deleting messages from a conversation.
    ///
    /// A delete is a plaintext `MessageDeleteEvent`, not an encrypted
    /// message: the result's one `action_signatures` entry carries the
    /// encoded event detail and its signature, nested as the request nests
    /// it. The SDK generates the action's message id; read it back from the
    /// entry.
    pub fn prepare_message_delete(
        &self,
        params: &MessageDeleteParams,
    ) -> Result<PreparedAction, SdkError> {
        if params.sequence_ids.is_empty() {
            return Err(SdkError::InvalidInput(
                "sequence_ids is empty: pass at least one message to delete".into(),
            ));
        }
        if params.sequence_ids.iter().any(String::is_empty) {
            return Err(SdkError::InvalidInput(
                "sequence_ids contains an empty id: every entry must name a message".into(),
            ));
        }
        if params.conversation_id.is_empty() {
            return Err(SdkError::InvalidInput(
                "conversation_id is empty: pass the conversation the messages belong to".into(),
            ));
        }
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let conversation_id =
            crate::pipeline::canonical_conversation_id(&params.conversation_id, &sender_id);
        let signing_key = self.get_signing_private_key()?;

        let delete_action = if params.delete_for_all {
            crate::thrift::event::DeleteMessageAction::DELETE_FOR_ALL
        } else {
            crate::thrift::event::DeleteMessageAction::DELETE_FOR_SELF
        };
        let message_id = Self::generate_message_id();
        let mut signature = crate::signatures::build_message_delete_signature(
            &signing_key,
            &signing_key_version,
            &message_id,
            &sender_id,
            &conversation_id,
            &params.sequence_ids,
            delete_action.0,
        )?;
        signature.encoded_message_event_detail =
            Self::encode_message_delete_detail(&params.sequence_ids, delete_action)?;
        Ok(PreparedAction {
            action_signatures: vec![signature],
        })
    }

    /// Serialize the `MessageDeleteEvent` the API validates and relays.
    ///
    /// Encoded as a base64 `MessageEventDetail` carrying the sequence ids and
    /// the delete action.
    pub(super) fn encode_message_delete_detail(
        sequence_ids: &[String],
        delete_action: crate::thrift::event::DeleteMessageAction,
    ) -> Result<String, SdkError> {
        let detail = crate::thrift::event::MessageEventDetail::MessageDeleteEvent(
            crate::thrift::event::MessageDeleteEvent {
                sequence_ids: Some(sequence_ids.to_vec()),
                delete_message_action: Some(delete_action),
                pme_sequence_ids: None,
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Build the signed action for marking a conversation read.
    ///
    /// A read receipt is a plaintext `MarkConversationReadEvent`, not an
    /// encrypted message: the result's one `action_signatures` entry carries
    /// the encoded event detail and its signature, nested as the
    /// conversation-change requests nest theirs, for the mark-read request
    /// (`POST /2/chat/conversations/{id}/read`). The SDK generates the
    /// action's message id; read it back from the entry. An unset
    /// `seen_at_msec` reads the system clock.
    pub fn prepare_mark_conversation_read(
        &self,
        params: &MarkConversationReadParams,
    ) -> Result<PreparedAction, SdkError> {
        if params.conversation_id.is_empty() {
            return Err(SdkError::InvalidInput(
                "conversation_id is empty: pass the conversation being marked read".into(),
            ));
        }
        if params.seen_until_sequence_id.is_empty() {
            return Err(SdkError::InvalidInput(
                "seen_until_sequence_id is empty: pass the sequence_id of the newest event read"
                    .into(),
            ));
        }
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        let conversation_id =
            crate::pipeline::canonical_conversation_id(&params.conversation_id, &sender_id);
        let signing_key = self.get_signing_private_key()?;
        let seen_at_msec = params.seen_at_msec.unwrap_or_else(now_msec);

        let message_id = Self::generate_message_id();
        let mut signature = crate::signatures::build_mark_conversation_read_signature(
            &signing_key,
            &signing_key_version,
            &message_id,
            &sender_id,
            &conversation_id,
            &params.seen_until_sequence_id,
            seen_at_msec,
        )?;
        signature.encoded_message_event_detail = Self::encode_mark_conversation_read_detail(
            &params.seen_until_sequence_id,
            seen_at_msec,
        )?;
        Ok(PreparedAction {
            action_signatures: vec![signature],
        })
    }

    /// Serialize the `MarkConversationReadEvent` as a base64
    /// `MessageEventDetail` carrying the read point and its time.
    pub(super) fn encode_mark_conversation_read_detail(
        seen_until_sequence_id: &str,
        seen_at_msec: i64,
    ) -> Result<String, SdkError> {
        let detail = crate::thrift::event::MessageEventDetail::MarkConversationReadEvent(
            crate::thrift::event::MarkConversationReadEvent {
                seen_until_sequence_id: Some(seen_until_sequence_id.to_string()),
                seen_at_millis: Some(seen_at_msec),
                is_grok: None,
            },
        );
        Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
    }

    /// Resolve a reaction's conversation id and target sequence id from the
    /// explicit fields or, when unset, from the parsed `target_event`.
    pub(super) fn resolve_reaction_target(
        params: &EncryptReactionParams,
    ) -> Result<(String, String), SdkError> {
        Self::resolve_event_target(
            params.target_event.as_deref(),
            params.conversation_id.as_deref(),
            params.target_message_sequence_id.as_deref(),
        )
    }

    /// Resolve a target message's conversation id and sequence id from the
    /// explicit fields or, when unset, from the parsed `target_event`.
    pub(super) fn resolve_event_target(
        target_event: Option<&str>,
        conversation_id: Option<&str>,
        target_message_sequence_id: Option<&str>,
    ) -> Result<(String, String), SdkError> {
        let explicit_conv = conversation_id.filter(|v| !v.is_empty());
        let explicit_seq = target_message_sequence_id.filter(|v| !v.is_empty());
        if let (Some(conv), Some(seq)) = (explicit_conv, explicit_seq) {
            return Ok((conv.to_string(), seq.to_string()));
        }

        let parsed = match target_event.filter(|v| !v.is_empty()) {
            Some(event_b64) => Some(Self::parse_event_b64(event_b64)?),
            None => None,
        };
        let conversation_id = match explicit_conv {
            Some(v) => v.to_string(),
            None => parsed
                .as_ref()
                .and_then(|p| p.conversation_id.clone())
                .ok_or_else(|| {
                    SdkError::InvalidInput(
                        "conversation_id is not set: pass target_event or conversation_id".into(),
                    )
                })?,
        };
        let target_sequence_id = match explicit_seq {
            Some(v) => v.to_string(),
            None => parsed
                .as_ref()
                .and_then(|p| p.sequence_id.clone())
                .ok_or_else(|| {
                    SdkError::InvalidInput(
                        "target_message_sequence_id is not set: pass target_event or \
                         target_message_sequence_id"
                            .into(),
                    )
                })?,
        };
        Ok((conversation_id, target_sequence_id))
    }

    /// Parse decrypted content bytes into the wire-level entry contents.
    pub(super) fn parse_thrift_entry_contents(
        data: &[u8],
    ) -> Result<MessageEntryContents, SdkError> {
        let cursor = Cursor::new(data);
        let mut raw = TBinaryInputProtocol::new(cursor, true);
        let mut protocol = BoundedProtocol::new(&mut raw);
        let holder = MessageEntryHolder::read_from_in_protocol(&mut protocol)
            .map_err(|e| SdkError::Parse(format!("Content parse error: {}", e)))?;
        holder
            .contents
            .map(|c| *c)
            .ok_or_else(|| SdkError::Parse("content carries no entry".into()))
    }

    /// Parse decrypted content bytes into the wire-level `MessageContents`.
    ///
    /// Errors when the content is not a text message (reactions, edits, and
    /// markers cannot anchor a reply preview).
    pub(super) fn parse_thrift_message_contents(
        data: &[u8],
    ) -> Result<crate::thrift::product::MessageContents, SdkError> {
        match Self::parse_thrift_entry_contents(data)? {
            MessageEntryContents::Message(msg) => Ok(*msg),
            _ => Err(SdkError::Parse("reply target is not a text message".into())),
        }
    }

    /// Parse decrypted content bytes into the wire-level `MessageEdit`.
    pub(super) fn parse_thrift_message_edit(
        data: &[u8],
    ) -> Result<crate::thrift::product::MessageEdit, SdkError> {
        match Self::parse_thrift_entry_contents(data)? {
            MessageEntryContents::MessageEdit(edit) => Ok(*edit),
            _ => Err(SdkError::Parse("edit event is not a message edit".into())),
        }
    }

    /// The message key of a `MessageCreateEvent` that uses one, derived from
    /// its conversation key and the event's own sender and message id;
    /// `None` when the event uses the conversation key directly.
    pub(super) fn message_key_for(
        event: &MessageEvent,
        conversation_key: &XChatConversationKey,
    ) -> Result<Option<XChatConversationKey>, SdkError> {
        let Some(MessageEventDetail::MessageCreateEvent(mce)) = &event.detail else {
            return Ok(None);
        };
        if !message_keys::uses_message_key(mce.contents_encryption_version) {
            return Ok(None);
        }
        let (Some(sender_id), Some(message_id)) =
            (event.sender_id.as_deref(), event.message_id.as_deref())
        else {
            return Err(SdkError::Crypto(CryptoError::DecryptionFailed(
                "message key needs the event's sender id and message id".into(),
            )));
        };
        Ok(Some(message_keys::derive_message_key(
            conversation_key,
            sender_id,
            message_id,
        )?))
    }

    /// Whether a raw event is a `MessageCreateEvent` encrypted under a
    /// message key.
    pub(super) fn uses_message_key(raw: &MessageEvent) -> bool {
        matches!(
            &raw.detail,
            Some(MessageEventDetail::MessageCreateEvent(mce))
                if message_keys::uses_message_key(mce.contents_encryption_version)
        )
    }

    /// The key that opens a raw `MessageCreateEvent`'s contents: its message
    /// key when it uses one, otherwise the conversation key for its key
    /// version, from `extra_keys`, the outer message's key, the key cache, or
    /// the supplied key-change events, in that order. `None` when the
    /// contents are plaintext.
    ///
    /// A wrong key cannot yield wrong plaintext — the cipher authenticates —
    /// so key-change events are usable here without their own verification.
    pub(super) fn raw_event_contents_key(
        &self,
        raw: &MessageEvent,
        outer_key: Option<&XChatConversationKey>,
        outer_version: Option<&str>,
        key_changes: &[MessageEvent],
        extra_keys: &HashMap<String, XChatConversationKey>,
    ) -> Result<Option<XChatConversationKey>, SdkError> {
        let Some(MessageEventDetail::MessageCreateEvent(mce)) = &raw.detail else {
            return Err(SdkError::Parse(
                "raw event is not a MessageCreateEvent".into(),
            ));
        };
        let Some(version) = mce.conversation_key_version.as_deref() else {
            return Ok(None);
        };

        let conversation_key = extra_keys
            .get(version)
            .cloned()
            .or_else(|| {
                outer_key
                    .filter(|_| outer_version == Some(version))
                    .cloned()
            })
            .or_else(|| {
                raw.conversation_id
                    .as_deref()
                    .and_then(|conv_id| self.cached_key_for(conv_id, version))
            })
            .or_else(|| {
                key_changes
                    .iter()
                    .find_map(|kce_event| match &kce_event.detail {
                        Some(MessageEventDetail::ConversationKeyChangeEvent(kce))
                            if kce.conversation_key_version.as_deref() == Some(version) =>
                        {
                            self.decrypt_key_change_ckey(kce)
                        }
                        _ => None,
                    })
            })
            .ok_or_else(|| {
                SdkError::Crypto(CryptoError::DecryptionFailed(format!(
                    "no conversation key for version '{}' of the replied-to message; \
                     pass reply_to_ckces with its key-change event",
                    version
                )))
            })?;
        Ok(Some(
            Self::message_key_for(raw, &conversation_key)?.unwrap_or(conversation_key),
        ))
    }

    /// Decrypt a raw `MessageCreateEvent`'s contents with `key`, or return
    /// them as is when the event carries plaintext (`key` is `None`).
    pub(super) fn open_raw_event(
        raw: &MessageEvent,
        key: Option<&XChatConversationKey>,
    ) -> Result<Vec<u8>, SdkError> {
        let Some(MessageEventDetail::MessageCreateEvent(mce)) = &raw.detail else {
            return Err(SdkError::Parse(
                "raw event is not a MessageCreateEvent".into(),
            ));
        };
        let contents = mce
            .contents
            .as_ref()
            .ok_or_else(|| SdkError::Parse("raw event has no contents".into()))?;
        match key {
            Some(key) => Ok(decrypt_message_bytes(key, contents)?),
            None => Ok(contents.clone()),
        }
    }

    /// Decrypt an event quoted by a received reply. A message-key event
    /// opens with the key the reply carries for it when there is one, which
    /// must be a 32-byte key; otherwise its key is resolved like any raw
    /// event's. Returns the plaintext and, for a message-key event, the
    /// message key that opened it.
    pub(super) fn open_quoted_event(
        &self,
        raw: &MessageEvent,
        carried_key: Option<&[u8]>,
        key_changes: &[MessageEvent],
        conversation_keys: &HashMap<String, XChatConversationKey>,
    ) -> Result<(Vec<u8>, Option<XChatConversationKey>), SdkError> {
        let uses_message_key = Self::uses_message_key(raw);
        let key = match carried_key.filter(|_| uses_message_key) {
            Some(bytes) => Some(
                XChatConversationKey::from_bytes(bytes.to_vec()).ok_or_else(|| {
                    SdkError::Parse("carried message key must be 32 bytes".into())
                })?,
            ),
            None => self.raw_event_contents_key(raw, None, None, key_changes, conversation_keys)?,
        };
        let plaintext = Self::open_raw_event(raw, key.as_ref())?;
        Ok((plaintext, key.filter(|_| uses_message_key)))
    }

    /// Build the wire `ReplyingToPreview` for an outgoing reply.
    ///
    /// When `reply_to_event` is set, the preview fields are derived from the
    /// decrypted original and the raw signed event is embedded so recipients
    /// can validate the preview; explicit `reply_to_*` fields override the
    /// derived values. Without it, the preview is built from the explicit
    /// fields alone.
    pub(super) fn build_reply_preview(
        &self,
        params: &EncryptReplyParams,
        outer_key: &XChatConversationKey,
        outer_version: &str,
    ) -> Result<crate::thrift::product::ReplyingToPreview, SdkError> {
        let thrift_reply_entities = params
            .reply_to_entities
            .as_deref()
            .map(crate::pipeline::build_thrift_entities)
            .map(|v| v.into_iter().map(|b| *b).collect::<Vec<_>>());
        // The attachment-combination guard deliberately does not apply here:
        // a reply preview mirrors an already-sent original (which receivers
        // validate against the embedded raw event), so rejecting it would
        // block replying to messages from clients that sent such lists.
        let thrift_reply_attachments = params
            .reply_to_attachments
            .as_deref()
            .map(crate::pipeline::build_thrift_attachments);
        let explicit_sequence_id = params
            .reply_to_sequence_id
            .clone()
            .filter(|v| !v.is_empty());
        let explicit_sender_id = match params
            .reply_to_sender_id
            .as_deref()
            .filter(|v| !v.is_empty())
        {
            Some(id) => {
                crate::pipeline::validate_user_id("reply_to_sender_id", id)?;
                id.parse::<i64>().ok()
            }
            None => None,
        };

        let Some(raw_b64) = params.reply_to_event.as_deref().filter(|v| !v.is_empty()) else {
            let sequence_id = explicit_sequence_id.ok_or_else(|| {
                SdkError::InvalidInput(
                    "reply target is not set: pass reply_to_event or reply_to_sequence_id".into(),
                )
            })?;
            return Ok(crate::thrift::product::ReplyingToPreview::new(
                explicit_sender_id,
                params.reply_to_text.clone(),
                thrift_reply_entities,
                thrift_reply_attachments,
                None::<String>,
                Some(sequence_id),
                None::<String>,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ));
        };

        let raw = Self::parse_event_b64(raw_b64)?;
        let edit_event = match params
            .reply_to_edit_event
            .as_deref()
            .filter(|v| !v.is_empty())
        {
            Some(b64) => Some(Self::parse_event_b64(b64)?),
            None => None,
        };
        let key_changes: Vec<MessageEvent> = params
            .reply_to_ckces
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|b64| !b64.is_empty())
            .map(|b64| Self::parse_event_b64(b64))
            .collect::<Result<_, _>>()?;

        // Each override stands on its own: the original is decrypted whenever
        // any preview field is left unset, and skipped only when the
        // overrides cover every derived field.
        let need_original = params.reply_to_text.is_none()
            || thrift_reply_entities.is_none()
            || thrift_reply_attachments.is_none();
        // When the original was edited, the preview quotes what the message
        // says now, so text and entities derive from the edit's contents;
        // attachments stay with the original (edits do not carry them).
        let need_edit = edit_event.is_some()
            && (params.reply_to_text.is_none() || thrift_reply_entities.is_none());

        // A quoted message-key event's key is resolved even when its
        // contents are not needed, so the reply can carry it; failing to
        // resolve it then only means the reply carries no key.
        let original_key = if need_original || Self::uses_message_key(&raw) {
            match self.raw_event_contents_key(
                &raw,
                Some(outer_key),
                Some(outer_version),
                &key_changes,
                &HashMap::new(),
            ) {
                Ok(key) => key,
                Err(e) if need_original => return Err(e),
                Err(_) => None,
            }
        } else {
            None
        };
        let edit_key = match &edit_event {
            Some(edit) if need_edit || Self::uses_message_key(edit) => {
                match self.raw_event_contents_key(
                    edit,
                    Some(outer_key),
                    Some(outer_version),
                    &key_changes,
                    &HashMap::new(),
                ) {
                    Ok(key) => key,
                    Err(e) if need_edit => return Err(e),
                    Err(_) => None,
                }
            }
            _ => None,
        };

        let original = if need_original {
            let plaintext = Self::open_raw_event(&raw, original_key.as_ref())?;
            Some(Self::parse_thrift_message_contents(&plaintext)?)
        } else {
            None
        };
        let edited = match &edit_event {
            Some(edit) if need_edit => {
                let plaintext = Self::open_raw_event(edit, edit_key.as_ref())?;
                Some(Self::parse_thrift_message_edit(&plaintext)?)
            }
            _ => None,
        };

        // Only per-message keys are carried; a conversation key never is.
        let raw_event_message_key = original_key
            .filter(|_| Self::uses_message_key(&raw))
            .map(|k| k.to_bytes());
        let raw_event_edit_message_key = match &edit_event {
            Some(edit) if Self::uses_message_key(edit) => edit_key.map(|k| k.to_bytes()),
            _ => None,
        };

        let sequence_id = explicit_sequence_id
            .or_else(|| raw.sequence_id.clone())
            .ok_or_else(|| {
                SdkError::InvalidInput("reply_to_event carries no sequence_id".into())
            })?;
        let sender_id = explicit_sender_id
            .or_else(|| raw.sender_id.as_deref().and_then(|s| s.parse::<i64>().ok()));
        let message_text = params.reply_to_text.clone().or_else(|| match &edited {
            Some(edit) => edit.updated_text.clone(),
            None => original.as_ref().and_then(|m| m.message_text.clone()),
        });
        let entities = thrift_reply_entities.or_else(|| match &edited {
            Some(edit) => edit.entities.clone(),
            None => original
                .as_ref()
                .and_then(|m| m.entities.as_ref())
                .map(|e| e.iter().map(|b| (**b).clone()).collect()),
        });
        let attachments = thrift_reply_attachments
            .or_else(|| original.as_ref().and_then(|m| m.attachments.clone()));

        // A key-change event is only useful to a recipient when it carries a
        // key version this reply's own version does not already imply.
        let embedded_ckces: Vec<MessageEvent> = key_changes
            .into_iter()
            .filter(|e| match &e.detail {
                Some(MessageEventDetail::ConversationKeyChangeEvent(kce)) => {
                    kce.conversation_key_version.as_deref() != Some(outer_version)
                }
                _ => false,
            })
            .collect();

        Ok(crate::thrift::product::ReplyingToPreview::new(
            sender_id,
            message_text,
            entities,
            attachments,
            None::<String>,
            Some(sequence_id),
            raw.message_id.clone(),
            raw,
            edit_event,
            (!embedded_ckces.is_empty()).then_some(embedded_ckces),
            None,
            None,
            raw_event_message_key,
            raw_event_edit_message_key,
        ))
    }

    /// Validate a received reply preview against the raw signed original
    /// event embedded in it: verify the raw event's signature, decrypt its
    /// contents, and check every claim the preview makes against the
    /// decrypted original.
    pub(super) fn validate_reply_preview(
        &self,
        outer: &MessageEvent,
        preview: &crate::thrift::product::ReplyingToPreview,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        all_signing_keys: &[SigningKeyEntry],
    ) -> ReplyPreviewValidation {
        let Some(raw) = preview.raw_event_message_create.as_ref() else {
            return ReplyPreviewValidation::Invalid;
        };
        // The original must belong to the same conversation as the reply;
        // otherwise a participant could attribute words from elsewhere.
        if raw.conversation_id.is_none() || raw.conversation_id != outer.conversation_id {
            return ReplyPreviewValidation::Invalid;
        }
        let Some(raw_detail) = raw.detail.as_ref() else {
            return ReplyPreviewValidation::Invalid;
        };
        if !matches!(raw_detail, MessageEventDetail::MessageCreateEvent(_)) {
            return ReplyPreviewValidation::Invalid;
        }
        // Same key selection as top-level events: filter to the raw event's
        // sender, then match the version embedded in its signature.
        let sender_keys: Vec<SigningKeyEntry> = match raw.sender_id.as_deref() {
            Some(sid) => all_signing_keys
                .iter()
                .filter(|k| k.user_id == sid)
                .cloned()
                .collect(),
            None => return ReplyPreviewValidation::Invalid,
        };
        if !matches!(
            self.verify_event_signature(raw, raw_detail, &sender_keys, None),
            Ok(true)
        ) {
            return ReplyPreviewValidation::Invalid;
        }

        let embedded_ckces: Vec<MessageEvent> = preview.raw_event_ckces.clone().unwrap_or_default();
        let Ok((plaintext, original_message_key)) = self.open_quoted_event(
            raw,
            preview.raw_event_message_key.as_deref(),
            &embedded_ckces,
            conversation_keys,
        ) else {
            return ReplyPreviewValidation::Invalid;
        };
        let Ok(original) = Self::parse_thrift_message_contents(&plaintext) else {
            return ReplyPreviewValidation::Invalid;
        };

        if let Some(claimed_sender) = preview.sender_id {
            if raw.sender_id.as_deref() != Some(claimed_sender.to_string().as_str()) {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_seq) = preview.replying_to_message_sequence_id.as_deref() {
            if raw.sequence_id.as_deref() != Some(claimed_seq) {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_id) = preview.replying_to_message_id.as_deref() {
            if raw.message_id.as_deref() != Some(claimed_id) {
                return ReplyPreviewValidation::Invalid;
            }
        }

        // When an edit event is embedded, the preview quotes the edited
        // contents, so the text and entity claims are checked against the
        // edit; the edit itself must verify like the original and come from
        // the original's author. Attachment claims always check against the
        // original (edits do not carry attachments).
        let edited = match preview.raw_event_edit_message.as_ref() {
            None => None,
            Some(edit) => {
                if edit.conversation_id.is_none()
                    || edit.conversation_id != outer.conversation_id
                    || edit.sender_id.is_none()
                    || edit.sender_id != raw.sender_id
                {
                    return ReplyPreviewValidation::Invalid;
                }
                let Some(edit_detail) = edit.detail.as_ref() else {
                    return ReplyPreviewValidation::Invalid;
                };
                if !matches!(edit_detail, MessageEventDetail::MessageCreateEvent(_)) {
                    return ReplyPreviewValidation::Invalid;
                }
                if !matches!(
                    self.verify_event_signature(edit, edit_detail, &sender_keys, None),
                    Ok(true)
                ) {
                    return ReplyPreviewValidation::Invalid;
                }
                let Ok((edit_plaintext, _)) = self.open_quoted_event(
                    edit,
                    preview.raw_event_edit_message_key.as_deref(),
                    &embedded_ckces,
                    conversation_keys,
                ) else {
                    return ReplyPreviewValidation::Invalid;
                };
                let Ok(edit_contents) = Self::parse_thrift_message_edit(&edit_plaintext) else {
                    return ReplyPreviewValidation::Invalid;
                };
                // An edit quoted with a message-key original must name that
                // original by its signed message id; an edit without one
                // cannot be tied to it.
                if original_message_key.is_some()
                    && (edit_contents.message_id.is_none()
                        || edit_contents.message_id != raw.message_id)
                {
                    return ReplyPreviewValidation::Invalid;
                }
                Some(edit_contents)
            }
        };
        let quoted_text = match &edited {
            Some(edit) => edit.updated_text.as_deref(),
            None => original.message_text.as_deref(),
        };
        let quoted_entities: Vec<&crate::thrift::product::RichTextEntity> = match &edited {
            Some(edit) => edit.entities.iter().flatten().collect(),
            None => original
                .entities
                .iter()
                .flatten()
                .map(|b| b.as_ref())
                .collect(),
        };

        if let Some(claimed_text) = preview.message_text.as_deref() {
            let quoted_text = quoted_text.unwrap_or("");
            // Previews may be truncated on the wire, so a claim is valid when
            // it matches the quoted contents up to the preview's own length
            // (on a character boundary).
            if !quoted_text.is_char_boundary(claimed_text.len())
                || !quoted_text.starts_with(claimed_text)
            {
                return ReplyPreviewValidation::Invalid;
            }
        }
        if let Some(claimed_entities) = preview.entities.as_ref() {
            for entity in claimed_entities {
                if !quoted_entities.contains(&entity) {
                    return ReplyPreviewValidation::Invalid;
                }
            }
        }
        if let Some(claimed_attachments) = preview.attachments.as_ref() {
            let original_attachments: Vec<ThriftMessageAttachment> = original
                .attachments
                .iter()
                .flatten()
                .filter_map(|a| claim_comparable(a))
                .collect();
            for attachment in claimed_attachments
                .iter()
                .filter_map(|a| claim_comparable(a))
            {
                if !original_attachments.contains(&attachment) {
                    return ReplyPreviewValidation::Invalid;
                }
            }
        }
        ReplyPreviewValidation::Valid
    }
}
