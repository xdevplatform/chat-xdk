//! The params classes the calls take.

use super::*;

/// Parameters for ``Chat.encrypt_message``.
///
/// The constructor takes the required fields; the optional fields are
/// keyword-only and default to ``None``. Every field is a read-write
/// attribute. Identity and key fields resolve from the session identity
/// (``Chat.set_identity``) and the opt-in key cache (``Chat.set_cache_keys``)
/// when ``None``.
#[pyclass(get_all, set_all)]
pub struct EncryptMessageParams {
    /// ID of the conversation the message belongs to.
    pub(crate) conversation_id: String,
    /// Plaintext message body.
    pub(crate) text: String,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Raw 32-byte conversation key (``bytes``). Set it together with
    /// ``conversation_key_version``, or leave both ``None`` to resolve from
    /// the key cache.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key, as its key-change event carries it.
    pub(crate) conversation_key_version: Option<String>,
    /// ``(start, end, entity_type)`` tuples for rich text. ``start`` and
    /// ``end`` count bytes of the text's UTF-8 encoding, not ``str`` indices
    /// (``len(text[:i].encode())`` converts index ``i``), so
    /// ``0 <= start <= end <=`` the text's UTF-8 length; other offsets raise
    /// ``InvalidInputError``.
    pub(crate) entities: Option<Py<PyAny>>,
    /// Attachment dicts, each with an ``"attachment_type"`` key. Each file
    /// (a ``"media"`` attachment, or a ``"url"`` card's ``banner_image`` or
    /// ``favicon_image``) names the media hash key its upload started with;
    /// encrypt the files afterwards with ``Chat.encrypt_file`` or
    /// ``Chat.file_encryptor``. Upload each file for one message only:
    /// reusing another message's uploads can give this message that
    /// message's id. A file with an empty ``filename``, a ``filesize_bytes``
    /// of 0 or less, or a negative ``width`` or ``height``, a ``"url"`` card
    /// with an empty ``url``, and a ``"post"`` with neither ``rest_id`` nor
    /// ``post_url`` raise ``InvalidInputError``.
    pub(crate) attachments: Option<Py<PyAny>>,
    /// ``QuickReply`` dict: a request offering options, or a response
    /// selecting one.
    pub(crate) quick_reply: Option<Py<PyAny>>,
    /// Whether to send a push notification (default ``True``).
    pub(crate) should_notify: Option<bool>,
    /// TTL in milliseconds for disappearing messages.
    pub(crate) ttl_msec: Option<i64>,
}

#[pymethods]
impl EncryptMessageParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (conversation_id, text, *, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None, entities=None, attachments=None, quick_reply=None, should_notify=None, ttl_msec=None))]
    pub(crate) fn new(
        conversation_id: String,
        text: String,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
        entities: Option<Py<PyAny>>,
        attachments: Option<Py<PyAny>>,
        quick_reply: Option<Py<PyAny>>,
        should_notify: Option<bool>,
        ttl_msec: Option<i64>,
    ) -> Self {
        Self {
            conversation_id,
            text,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
            entities,
            attachments,
            quick_reply,
            should_notify,
            ttl_msec,
        }
    }
}

impl EncryptMessageParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::EncryptMessageParams> {
        let mut params = chat_xdk_core::EncryptMessageParams::new(
            self.conversation_id.as_str(),
            self.text.as_str(),
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params.entities = entities_field(py, &self.entities, "entities")?;
        params.attachments = attachments_field(py, &self.attachments, "attachments")?;
        params.quick_reply = quick_reply_field(py, &self.quick_reply)?;
        params.should_notify = self.should_notify;
        params.ttl_msec = self.ttl_msec;
        Ok(params)
    }
}

/// Parameters for ``Chat.encrypt_reply``.
///
/// The preferred form passes ``reply_to_event`` — the base64 raw signed event
/// being replied to — so the preview (sequence id, sender, text, entities,
/// attachments) is derived from it and the raw event is embedded for
/// recipients to validate. Pass ``None`` only when setting
/// ``reply_to_sequence_id`` and the other ``reply_to_*`` fields directly.
/// Identity and key fields resolve like ``EncryptMessageParams``.
#[pyclass(get_all, set_all)]
pub struct EncryptReplyParams {
    /// ID of the conversation the reply belongs to.
    pub(crate) conversation_id: String,
    /// Plaintext reply body.
    pub(crate) text: String,
    /// Base64 raw signed event being replied to.
    pub(crate) reply_to_event: Option<String>,
    /// Base64 raw signed edit event, when the original was edited.
    pub(crate) reply_to_edit_event: Option<String>,
    /// Base64 raw key-change events needed to decrypt the original when it
    /// used a different key version than this reply.
    pub(crate) reply_to_ckces: Option<Py<PyAny>>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Raw 32-byte conversation key (``bytes``). Set it together with
    /// ``conversation_key_version``, or leave both ``None`` to resolve from
    /// the key cache.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key, as its key-change event carries it.
    pub(crate) conversation_key_version: Option<String>,
    /// Sequence id of the message being replied to; derived from
    /// ``reply_to_event`` when ``None``.
    pub(crate) reply_to_sequence_id: Option<String>,
    /// User ID of the message's sender, as digits; derived from
    /// ``reply_to_event`` when ``None``.
    pub(crate) reply_to_sender_id: Option<String>,
    /// Text of the message being replied to (for the preview); derived from
    /// ``reply_to_event`` when ``None``.
    pub(crate) reply_to_text: Option<String>,
    /// ``(start, end, entity_type)`` tuples for rich text in the reply.
    pub(crate) entities: Option<Py<PyAny>>,
    /// Attachment dicts for the reply, as in
    /// ``EncryptMessageParams.attachments``.
    pub(crate) attachments: Option<Py<PyAny>>,
    /// ``(start, end, entity_type)`` tuples of the quoted message (for the
    /// preview); derived from ``reply_to_event`` when ``None``.
    pub(crate) reply_to_entities: Option<Py<PyAny>>,
    /// Attachment dicts of the quoted message (for the preview); derived
    /// from ``reply_to_event`` when ``None``.
    pub(crate) reply_to_attachments: Option<Py<PyAny>>,
    /// ``QuickReply`` dict: a request offering options, or a response
    /// selecting one.
    pub(crate) quick_reply: Option<Py<PyAny>>,
    /// Whether to send a push notification (default ``True``).
    pub(crate) should_notify: Option<bool>,
    /// TTL in milliseconds for disappearing messages.
    pub(crate) ttl_msec: Option<i64>,
}

#[pymethods]
impl EncryptReplyParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (conversation_id, text, reply_to_event=None, *, reply_to_edit_event=None, reply_to_ckces=None, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None, reply_to_sequence_id=None, reply_to_sender_id=None, reply_to_text=None, entities=None, attachments=None, reply_to_entities=None, reply_to_attachments=None, quick_reply=None, should_notify=None, ttl_msec=None))]
    pub(crate) fn new(
        conversation_id: String,
        text: String,
        reply_to_event: Option<String>,
        reply_to_edit_event: Option<String>,
        reply_to_ckces: Option<Py<PyAny>>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
        reply_to_sequence_id: Option<String>,
        reply_to_sender_id: Option<String>,
        reply_to_text: Option<String>,
        entities: Option<Py<PyAny>>,
        attachments: Option<Py<PyAny>>,
        reply_to_entities: Option<Py<PyAny>>,
        reply_to_attachments: Option<Py<PyAny>>,
        quick_reply: Option<Py<PyAny>>,
        should_notify: Option<bool>,
        ttl_msec: Option<i64>,
    ) -> Self {
        Self {
            conversation_id,
            text,
            reply_to_event,
            reply_to_edit_event,
            reply_to_ckces,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
            reply_to_sequence_id,
            reply_to_sender_id,
            reply_to_text,
            entities,
            attachments,
            reply_to_entities,
            reply_to_attachments,
            quick_reply,
            should_notify,
            ttl_msec,
        }
    }
}

impl EncryptReplyParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::EncryptReplyParams> {
        let mut params = chat_xdk_core::EncryptReplyParams::new(
            self.conversation_id.as_str(),
            self.text.as_str(),
            self.reply_to_event.clone().unwrap_or_default(),
        );
        params.reply_to_edit_event = self.reply_to_edit_event.clone();
        params.reply_to_ckces =
            extract_optional_field::<Vec<String>>(py, &self.reply_to_ckces, "reply_to_ckces")?;
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params.reply_to_sequence_id = self.reply_to_sequence_id.clone();
        params.reply_to_sender_id = self.reply_to_sender_id.clone();
        params.reply_to_text = self.reply_to_text.clone();
        params.entities = entities_field(py, &self.entities, "entities")?;
        params.attachments = attachments_field(py, &self.attachments, "attachments")?;
        params.reply_to_entities =
            entities_field(py, &self.reply_to_entities, "reply_to_entities")?;
        params.reply_to_attachments =
            attachments_field(py, &self.reply_to_attachments, "reply_to_attachments")?;
        params.quick_reply = quick_reply_field(py, &self.quick_reply)?;
        params.should_notify = self.should_notify;
        params.ttl_msec = self.ttl_msec;
        Ok(params)
    }
}

/// Parameters for ``Chat.encrypt_add_reaction`` and
/// ``Chat.encrypt_remove_reaction``.
///
/// The preferred form passes ``target_event`` — the base64 raw event being
/// reacted to — so the conversation id and target sequence id are derived
/// from it. Pass ``None`` only when setting ``conversation_id`` and
/// ``target_message_sequence_id`` directly. The same params can be passed to
/// both methods to add and later remove the same reaction.
#[pyclass(get_all, set_all)]
pub struct EncryptReactionParams {
    /// Base64 raw event being reacted to.
    pub(crate) target_event: Option<String>,
    /// The reaction emoji.
    pub(crate) emoji: String,
    /// ID of the conversation; derived from ``target_event`` when ``None``.
    pub(crate) conversation_id: Option<String>,
    /// Sequence id of the message being reacted to; derived from
    /// ``target_event`` when ``None``.
    pub(crate) target_message_sequence_id: Option<String>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Raw 32-byte conversation key (``bytes``). Set it together with
    /// ``conversation_key_version``, or leave both ``None`` to resolve from
    /// the key cache.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key, as its key-change event carries it.
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl EncryptReactionParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (target_event=None, emoji=None, *, conversation_id=None, target_message_sequence_id=None, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        target_event: Option<String>,
        emoji: Option<String>,
        conversation_id: Option<String>,
        target_message_sequence_id: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            target_event,
            emoji: required(emoji, "emoji")?,
            conversation_id,
            target_message_sequence_id,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
        })
    }
}

impl EncryptReactionParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::EncryptReactionParams {
        let mut params = chat_xdk_core::EncryptReactionParams::new(
            self.target_event.clone().unwrap_or_default(),
            self.emoji.as_str(),
        );
        params.conversation_id = self.conversation_id.clone();
        params.target_message_sequence_id = self.target_message_sequence_id.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.encrypt_edit``.
///
/// The preferred form passes ``target_event`` — the base64 raw event of the
/// message being edited — so the conversation id and target sequence id are
/// derived from it. Pass ``None`` only when setting ``conversation_id`` and
/// ``target_message_sequence_id`` directly.
#[pyclass(get_all, set_all)]
pub struct EncryptEditParams {
    /// Base64 raw event of the message being edited.
    pub(crate) target_event: Option<String>,
    /// The replacement message text.
    pub(crate) updated_text: String,
    /// ``(start, end, entity_type)`` tuples for rich text in the replacement
    /// text; ``None`` clears any entities the original carried.
    pub(crate) entities: Option<Py<PyAny>>,
    /// ID of the conversation; derived from ``target_event`` when ``None``.
    pub(crate) conversation_id: Option<String>,
    /// Sequence id of the message being edited; derived from
    /// ``target_event`` when ``None``.
    pub(crate) target_message_sequence_id: Option<String>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Raw 32-byte conversation key (``bytes``). Set it together with
    /// ``conversation_key_version``, or leave both ``None`` to resolve from
    /// the key cache.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// Version of the conversation key, as its key-change event carries it.
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl EncryptEditParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (target_event=None, updated_text=None, *, entities=None, conversation_id=None, target_message_sequence_id=None, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        target_event: Option<String>,
        updated_text: Option<String>,
        entities: Option<Py<PyAny>>,
        conversation_id: Option<String>,
        target_message_sequence_id: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            target_event,
            updated_text: required(updated_text, "updated_text")?,
            entities,
            conversation_id,
            target_message_sequence_id,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
        })
    }
}

impl EncryptEditParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::EncryptEditParams> {
        let mut params = chat_xdk_core::EncryptEditParams::new(
            self.target_event.clone().unwrap_or_default(),
            self.updated_text.as_str(),
        );
        params.entities = entities_field(py, &self.entities, "entities")?;
        params.conversation_id = self.conversation_id.clone();
        params.target_message_sequence_id = self.target_message_sequence_id.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_conversation_key_change``.
#[pyclass(get_all, set_all)]
pub struct ConversationKeyChangeParams {
    /// ``{"user_id", "identity_public_key", "public_key_version"}`` dicts for every
    /// participant the new key is encrypted for.
    pub(crate) public_keys: Py<PyAny>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Conversation the change applies to; ``None`` derives the one-to-one
    /// id from the two participants.
    pub(crate) conversation_id: Option<String>,
}

#[pymethods]
impl ConversationKeyChangeParams {
    #[new]
    #[pyo3(signature = (public_keys, *, sender_id=None, signing_key_version=None, conversation_id=None))]
    pub(crate) fn new(
        public_keys: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_id: Option<String>,
    ) -> Self {
        Self {
            public_keys,
            sender_id,
            signing_key_version,
            conversation_id,
        }
    }
}

impl ConversationKeyChangeParams {
    pub(crate) fn to_core(
        &self,
        py: Python<'_>,
    ) -> PyResult<chat_xdk_core::ConversationKeyChangeParams> {
        let mut params = chat_xdk_core::ConversationKeyChangeParams::new(public_keys_field(
            py,
            &self.public_keys,
        )?);
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_id = self.conversation_id.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_group_members_change``.
///
/// ``current_title`` and ``current_description`` are plaintext: the call
/// encrypts each under the new conversation key it generates.
/// ``current_avatar_url`` is the avatar's media URL, signed as is.
#[pyclass(get_all, set_all)]
pub struct GroupMembersChangeParams {
    /// ``{"user_id", "identity_public_key", "public_key_version"}`` dicts for the updated
    /// roster.
    pub(crate) public_keys: Py<PyAny>,
    /// ID of the group conversation.
    pub(crate) conversation_id: String,
    /// IDs of the members being added.
    pub(crate) new_member_ids: Py<PyAny>,
    /// IDs of the current members.
    pub(crate) current_member_ids: Py<PyAny>,
    /// IDs of the current admins.
    pub(crate) current_admin_ids: Py<PyAny>,
    /// IDs of the current pending members.
    pub(crate) current_pending_member_ids: Py<PyAny>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Current group title, as plaintext, if set; the call encrypts it.
    pub(crate) current_title: Option<String>,
    /// Current group avatar media URL, if set.
    pub(crate) current_avatar_url: Option<String>,
    /// Current group description, as plaintext, if set; the call encrypts
    /// it.
    pub(crate) current_description: Option<String>,
    /// Current disappearing-message TTL in milliseconds, if set.
    pub(crate) current_ttl_msec: Option<i64>,
    /// Current screen-capture-blocking state; ``None`` when unset.
    pub(crate) current_screen_capture_blocking_enabled: Option<bool>,
}

#[pymethods]
impl GroupMembersChangeParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (public_keys, conversation_id, new_member_ids, current_member_ids, current_admin_ids, current_pending_member_ids, *, sender_id=None, signing_key_version=None, current_title=None, current_avatar_url=None, current_description=None, current_ttl_msec=None, current_screen_capture_blocking_enabled=None))]
    pub(crate) fn new(
        public_keys: Py<PyAny>,
        conversation_id: String,
        new_member_ids: Py<PyAny>,
        current_member_ids: Py<PyAny>,
        current_admin_ids: Py<PyAny>,
        current_pending_member_ids: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        current_title: Option<String>,
        current_avatar_url: Option<String>,
        current_description: Option<String>,
        current_ttl_msec: Option<i64>,
        current_screen_capture_blocking_enabled: Option<bool>,
    ) -> Self {
        Self {
            public_keys,
            conversation_id,
            new_member_ids,
            current_member_ids,
            current_admin_ids,
            current_pending_member_ids,
            sender_id,
            signing_key_version,
            current_title,
            current_avatar_url,
            current_description,
            current_ttl_msec,
            current_screen_capture_blocking_enabled,
        }
    }
}

impl GroupMembersChangeParams {
    pub(crate) fn to_core(
        &self,
        py: Python<'_>,
    ) -> PyResult<chat_xdk_core::GroupMembersChangeParams> {
        let mut params = chat_xdk_core::GroupMembersChangeParams::new(
            public_keys_field(py, &self.public_keys)?,
            self.conversation_id.as_str(),
            extract_field(py, &self.new_member_ids, "new_member_ids")?,
            extract_field(py, &self.current_member_ids, "current_member_ids")?,
            extract_field(py, &self.current_admin_ids, "current_admin_ids")?,
            extract_field(
                py,
                &self.current_pending_member_ids,
                "current_pending_member_ids",
            )?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.current_title = self.current_title.clone();
        params.current_avatar_url = self.current_avatar_url.clone();
        params.current_description = self.current_description.clone();
        params.current_ttl_msec = self.current_ttl_msec;
        params.current_screen_capture_blocking_enabled =
            self.current_screen_capture_blocking_enabled;
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_group_create``.
#[pyclass(get_all, set_all)]
pub struct GroupCreateParams {
    /// ``{"user_id", "identity_public_key", "public_key_version"}`` dicts for the new roster.
    pub(crate) public_keys: Py<PyAny>,
    /// ID of the group conversation, as the initialize endpoint minted it.
    pub(crate) conversation_id: String,
    /// IDs of the initial members.
    pub(crate) member_ids: Py<PyAny>,
    /// IDs of the initial admins.
    pub(crate) admin_ids: Py<PyAny>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
    /// Group title, as plaintext, if set; the create encrypts it.
    pub(crate) title: Option<String>,
    /// Disappearing-message TTL in milliseconds, if set.
    pub(crate) ttl_msec: Option<i64>,
}

#[pymethods]
impl GroupCreateParams {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (public_keys, conversation_id, member_ids, admin_ids, *, sender_id=None, signing_key_version=None, title=None, ttl_msec=None))]
    pub(crate) fn new(
        public_keys: Py<PyAny>,
        conversation_id: String,
        member_ids: Py<PyAny>,
        admin_ids: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        title: Option<String>,
        ttl_msec: Option<i64>,
    ) -> Self {
        Self {
            public_keys,
            conversation_id,
            member_ids,
            admin_ids,
            sender_id,
            signing_key_version,
            title,
            ttl_msec,
        }
    }
}

impl GroupCreateParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::GroupCreateParams> {
        let mut params = chat_xdk_core::GroupCreateParams::new(
            public_keys_field(py, &self.public_keys)?,
            self.conversation_id.as_str(),
            extract_field(py, &self.member_ids, "member_ids")?,
            extract_field(py, &self.admin_ids, "admin_ids")?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.title = self.title.clone();
        params.ttl_msec = self.ttl_msec;
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_message_delete``.
///
/// A delete is a signed plaintext event, not an encrypted message, so no
/// conversation key is involved.
#[pyclass(get_all, set_all)]
pub struct MessageDeleteParams {
    /// ID of the conversation the messages belong to.
    pub(crate) conversation_id: String,
    /// The ``sequence_id``s of the messages to delete.
    pub(crate) sequence_ids: Py<PyAny>,
    /// Delete for every participant (``True``, own messages only) or only
    /// from the caller's view (``False``).
    pub(crate) delete_for_all: bool,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl MessageDeleteParams {
    #[new]
    #[pyo3(signature = (conversation_id, sequence_ids, delete_for_all, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        sequence_ids: Py<PyAny>,
        delete_for_all: bool,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            sequence_ids,
            delete_for_all,
            sender_id,
            signing_key_version,
        }
    }
}

impl MessageDeleteParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::MessageDeleteParams> {
        let mut params = chat_xdk_core::MessageDeleteParams::new(
            self.conversation_id.as_str(),
            extract_field(py, &self.sequence_ids, "sequence_ids")?,
            self.delete_for_all,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        Ok(params)
    }
}

pub(crate) fn apply_identity(
    sender_id: &mut Option<String>,
    signing_key_version: &mut Option<String>,
    sender: Option<String>,
    version: Option<String>,
) {
    *sender_id = sender;
    *signing_key_version = version;
}

/// Parameters for ``Chat.prepare_group_members_remove``.
///
/// ``public_keys`` are the identity keys of the members who stay, yours
/// included: the call rotates the conversation key for them, and a member
/// left out can't read what the group sends under the new key. ``title`` and
/// ``description`` are the group's current plaintext metadata; pass each one
/// the group has. Each one set is encrypted under the new key and signed with
/// the removal as a key-rotation re-encryption, which recipients' decrypt
/// drops rather than show as a change.
#[pyclass(get_all, set_all)]
pub struct GroupMembersRemoveParams {
    pub(crate) public_keys: Py<PyAny>,
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Py<PyAny>,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupMembersRemoveParams {
    #[new]
    #[pyo3(signature = (public_keys, conversation_id, user_ids, *, title=None, description=None, sender_id=None, signing_key_version=None))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        public_keys: Py<PyAny>,
        conversation_id: String,
        user_ids: Py<PyAny>,
        title: Option<String>,
        description: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            public_keys,
            conversation_id,
            user_ids,
            title,
            description,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupMembersRemoveParams {
    pub(crate) fn to_core(
        &self,
        py: Python<'_>,
    ) -> PyResult<chat_xdk_core::GroupMembersRemoveParams> {
        let mut params = chat_xdk_core::GroupMembersRemoveParams::new(
            public_keys_field(py, &self.public_keys)?,
            self.conversation_id.as_str(),
            extract_field(py, &self.user_ids, "user_ids")?,
        );
        params.title = self.title.clone();
        params.description = self.description.clone();
        apply_identity(
            &mut params.sender_id,
            &mut params.signing_key_version,
            self.sender_id.clone(),
            self.signing_key_version.clone(),
        );
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_group_leave``.
///
/// Leave removes the sender and does not rotate the conversation key.
/// ``promote_admin_id`` adds an admin-promotion signature.
#[pyclass(get_all, set_all)]
pub struct GroupLeaveParams {
    pub(crate) conversation_id: String,
    pub(crate) promote_admin_id: Option<String>,
    pub(crate) conversation_key_version: Option<String>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupLeaveParams {
    #[new]
    #[pyo3(signature = (conversation_id, *, promote_admin_id=None, conversation_key_version=None, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        promote_admin_id: Option<String>,
        conversation_key_version: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            promote_admin_id,
            conversation_key_version,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupLeaveParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupLeaveParams {
        let mut params = chat_xdk_core::GroupLeaveParams::new(self.conversation_id.as_str());
        params.promote_admin_id = self.promote_admin_id.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_title_change``.
///
/// ``new_title`` is plaintext: the call encrypts it under the conversation
/// key, the explicit ``conversation_key`` / ``conversation_key_version``
/// pair or, both ``None``, the opt-in key cache.
#[pyclass(get_all, set_all)]
pub struct GroupTitleChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_title: String,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
    pub(crate) conversation_key: Option<Vec<u8>>,
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl GroupTitleChangeParams {
    #[new]
    #[pyo3(signature = (conversation_id, new_title, *, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        new_title: String,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            new_title,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
        }
    }
}

impl GroupTitleChangeParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupTitleChangeParams {
        let mut params = chat_xdk_core::GroupTitleChangeParams::new(
            self.conversation_id.as_str(),
            self.new_title.as_str(),
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_avatar_change``.
///
/// A group's avatar URL is not encrypted. ``new_avatar_url`` is the media
/// URL of the avatar image, which the app encrypts under the conversation
/// key and uploads first; ``conversation_key_version`` is the version of the
/// key the image is encrypted under.
#[pyclass(get_all, set_all)]
pub struct GroupAvatarChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_avatar_url: String,
    pub(crate) conversation_key_version: String,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupAvatarChangeParams {
    #[new]
    #[pyo3(signature = (conversation_id, new_avatar_url, conversation_key_version, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        new_avatar_url: String,
        conversation_key_version: String,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            new_avatar_url,
            conversation_key_version,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupAvatarChangeParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupAvatarChangeParams {
        let mut params = chat_xdk_core::GroupAvatarChangeParams::new(
            self.conversation_id.as_str(),
            self.new_avatar_url.as_str(),
            self.conversation_key_version.as_str(),
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_description_change``.
///
/// ``new_description`` is plaintext: the call encrypts it under the conversation
/// key, the explicit ``conversation_key`` / ``conversation_key_version``
/// pair or, both ``None``, the opt-in key cache.
#[pyclass(get_all, set_all)]
pub struct GroupDescriptionChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_description: String,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
    pub(crate) conversation_key: Option<Vec<u8>>,
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl GroupDescriptionChangeParams {
    #[new]
    #[pyo3(signature = (conversation_id, new_description, *, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        new_description: String,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            new_description,
            sender_id,
            signing_key_version,
            conversation_key,
            conversation_key_version,
        }
    }
}

impl GroupDescriptionChangeParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupDescriptionChangeParams {
        let mut params = chat_xdk_core::GroupDescriptionChangeParams::new(
            self.conversation_id.as_str(),
            self.new_description.as_str(),
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_admins_add``.
#[pyclass(get_all, set_all)]
pub struct GroupAdminsAddParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Py<PyAny>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupAdminsAddParams {
    #[new]
    #[pyo3(signature = (conversation_id, user_ids, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        user_ids: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            user_ids,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupAdminsAddParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::GroupAdminsAddParams> {
        let mut params = chat_xdk_core::GroupAdminsAddParams::new(
            self.conversation_id.as_str(),
            extract_field(py, &self.user_ids, "user_ids")?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_group_admins_remove``.
#[pyclass(get_all, set_all)]
pub struct GroupAdminsRemoveParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Py<PyAny>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupAdminsRemoveParams {
    #[new]
    #[pyo3(signature = (conversation_id, user_ids, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        user_ids: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            user_ids,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupAdminsRemoveParams {
    pub(crate) fn to_core(
        &self,
        py: Python<'_>,
    ) -> PyResult<chat_xdk_core::GroupAdminsRemoveParams> {
        let mut params = chat_xdk_core::GroupAdminsRemoveParams::new(
            self.conversation_id.as_str(),
            extract_field(py, &self.user_ids, "user_ids")?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_group_invite_enable``.
///
/// An empty ``affiliate_id`` and a negative ``expires_at_msec`` sign ``null``.
#[pyclass(get_all, set_all)]
pub struct GroupInviteEnableParams {
    pub(crate) conversation_id: String,
    pub(crate) invite_url: String,
    pub(crate) expires_at_msec: Option<i64>,
    pub(crate) affiliate_id: Option<String>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupInviteEnableParams {
    #[new]
    #[pyo3(signature = (conversation_id, invite_url, *, expires_at_msec=None, affiliate_id=None, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        invite_url: String,
        expires_at_msec: Option<i64>,
        affiliate_id: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            invite_url,
            expires_at_msec,
            affiliate_id,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupInviteEnableParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupInviteEnableParams {
        let mut params = chat_xdk_core::GroupInviteEnableParams::new(
            self.conversation_id.as_str(),
            self.invite_url.as_str(),
        );
        params.expires_at_msec = self.expires_at_msec;
        params.affiliate_id = self.affiliate_id.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_invite_disable``.
///
/// ``disabled_by`` defaults to the sender.
#[pyclass(get_all, set_all)]
pub struct GroupInviteDisableParams {
    pub(crate) conversation_id: String,
    pub(crate) disabled_by: Option<String>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupInviteDisableParams {
    #[new]
    #[pyo3(signature = (conversation_id, *, disabled_by=None, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        disabled_by: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            disabled_by,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupInviteDisableParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupInviteDisableParams {
        let mut params =
            chat_xdk_core::GroupInviteDisableParams::new(self.conversation_id.as_str());
        params.disabled_by = self.disabled_by.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_join_request``.
///
/// ``requesting_user_id`` defaults to the sender. An invite token is not signed.
#[pyclass(get_all, set_all)]
pub struct GroupJoinRequestParams {
    pub(crate) conversation_id: String,
    pub(crate) requesting_user_id: Option<String>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupJoinRequestParams {
    #[new]
    #[pyo3(signature = (conversation_id, *, requesting_user_id=None, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        requesting_user_id: Option<String>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            requesting_user_id,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupJoinRequestParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::GroupJoinRequestParams {
        let mut params = chat_xdk_core::GroupJoinRequestParams::new(self.conversation_id.as_str());
        params.requesting_user_id = self.requesting_user_id.clone();
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_group_join_reject``.
#[pyclass(get_all, set_all)]
pub struct GroupJoinRejectParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Py<PyAny>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl GroupJoinRejectParams {
    #[new]
    #[pyo3(signature = (conversation_id, user_ids, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        user_ids: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            user_ids,
            sender_id,
            signing_key_version,
        }
    }
}

impl GroupJoinRejectParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::GroupJoinRejectParams> {
        let mut params = chat_xdk_core::GroupJoinRejectParams::new(
            self.conversation_id.as_str(),
            extract_field(py, &self.user_ids, "user_ids")?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.prepare_message_ttl_change``.
#[pyclass(get_all, set_all)]
pub struct MessageTtlChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) ttl_msec: i64,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl MessageTtlChangeParams {
    #[new]
    #[pyo3(signature = (conversation_id, ttl_msec, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        ttl_msec: i64,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            ttl_msec,
            sender_id,
            signing_key_version,
        }
    }
}

impl MessageTtlChangeParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::MessageTtlChangeParams {
        let mut params = chat_xdk_core::MessageTtlChangeParams::new(
            self.conversation_id.as_str(),
            self.ttl_msec,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_message_ttl_remove``.
#[pyclass(get_all, set_all)]
pub struct MessageTtlRemoveParams {
    pub(crate) conversation_id: String,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl MessageTtlRemoveParams {
    #[new]
    #[pyo3(signature = (conversation_id, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            sender_id,
            signing_key_version,
        }
    }
}

impl MessageTtlRemoveParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::MessageTtlRemoveParams {
        let mut params = chat_xdk_core::MessageTtlRemoveParams::new(self.conversation_id.as_str());
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.prepare_screen_capture``.
///
/// ``change`` is a :class:`ScreenCaptureChange` value.
#[pyclass(get_all, set_all)]
pub struct ScreenCaptureParams {
    pub(crate) conversation_id: String,
    pub(crate) change: Py<PyAny>,
    pub(crate) sender_id: Option<String>,
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl ScreenCaptureParams {
    #[new]
    #[pyo3(signature = (conversation_id, change, *, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        change: Py<PyAny>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            change,
            sender_id,
            signing_key_version,
        }
    }
}

impl ScreenCaptureParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::ScreenCaptureParams> {
        let bound = self.change.bind(py);
        // A str enum's str() is its qualified name; the value is the str it is.
        let change = bound.extract::<String>().or_else(|_| {
            bound
                .str()
                .and_then(|text| text.to_cow().map(|cow| cow.into_owned()))
        })?;
        let mut params = chat_xdk_core::ScreenCaptureParams::new(
            self.conversation_id.as_str(),
            chat_xdk_core::ScreenCaptureChange::parse(&change).map_err(to_py_err)?,
        );
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        Ok(params)
    }
}

/// Parameters for ``Chat.set_identity``.
#[pyclass(get_all, set_all)]
pub struct SetIdentityParams {
    /// Your user ID: the sender of everything this chat signs.
    pub(crate) user_id: String,
    /// The ``public_key_version`` the X API returned when your keys were
    /// registered.
    pub(crate) signing_key_version: String,
}

#[pymethods]
impl SetIdentityParams {
    #[new]
    #[pyo3(signature = (user_id, signing_key_version))]
    pub(crate) fn new(user_id: String, signing_key_version: String) -> Self {
        Self {
            user_id,
            signing_key_version,
        }
    }
}

/// Parameters for ``Chat.import_keys``.
#[pyclass(get_all, set_all)]
pub struct ImportKeysParams {
    /// Key bytes from ``export_keys()``: 32 (the identity key) or 64 (the
    /// identity and signing keys).
    pub(crate) keys: Vec<u8>,
    /// The ``public_key_version`` the X API returned when the keys were
    /// registered. When given, it becomes the signing-key version, as with
    /// ``set_identity``.
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl ImportKeysParams {
    #[new]
    #[pyo3(signature = (keys, *, signing_key_version=None))]
    pub(crate) fn new(keys: Vec<u8>, signing_key_version: Option<String>) -> Self {
        Self {
            keys,
            signing_key_version,
        }
    }
}

/// Parameters for ``Chat.prepare_mark_conversation_read``.
///
/// A read receipt is a signed plaintext event, not an encrypted message, so
/// no conversation key is involved.
#[pyclass(get_all, set_all)]
pub struct MarkConversationReadParams {
    /// ID of the conversation being marked read.
    pub(crate) conversation_id: String,
    /// The ``sequence_id`` of the newest event read.
    pub(crate) seen_until_sequence_id: String,
    /// When the conversation was read, in milliseconds since the Unix epoch;
    /// defaults to the current time.
    pub(crate) seen_at_msec: Option<i64>,
    /// Your user ID; defaults to the ``set_identity`` value.
    pub(crate) sender_id: Option<String>,
    /// Your registered signing public key version; defaults to the
    /// ``set_identity`` value.
    pub(crate) signing_key_version: Option<String>,
}

#[pymethods]
impl MarkConversationReadParams {
    #[new]
    #[pyo3(signature = (conversation_id, seen_until_sequence_id, *, seen_at_msec=None, sender_id=None, signing_key_version=None))]
    pub(crate) fn new(
        conversation_id: String,
        seen_until_sequence_id: String,
        seen_at_msec: Option<i64>,
        sender_id: Option<String>,
        signing_key_version: Option<String>,
    ) -> Self {
        Self {
            conversation_id,
            seen_until_sequence_id,
            seen_at_msec,
            sender_id,
            signing_key_version,
        }
    }
}

impl MarkConversationReadParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::MarkConversationReadParams {
        let mut params = chat_xdk_core::MarkConversationReadParams::new(
            self.conversation_id.as_str(),
            self.seen_until_sequence_id.as_str(),
        );
        params.seen_at_msec = self.seen_at_msec;
        params.sender_id = self.sender_id.clone();
        params.signing_key_version = self.signing_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.decrypt_event``.
#[pyclass(get_all, set_all)]
pub struct DecryptEventParams {
    /// The base64 event, as delivered.
    pub(crate) event_b64: String,
    /// The conversation's key map: key version to raw 32-byte key
    /// (``bytes``), from ``decrypt_events`` or ``extract_conversation_keys``.
    /// Leave it ``None``, or pass ``{}``, for events without message
    /// contents, or to take the keys from the opt-in key cache.
    pub(crate) conversation_keys: Option<Py<PyAny>>,
    /// Signing-key dicts ``{"user_id", "public_key_version", "public_key",
    /// "identity_public_key", "identity_public_key_signature"}``, straight
    /// from the X API public keys response. ``None`` or empty uses the keys
    /// stored via ``Chat.set_signing_keys``.
    pub(crate) signing_keys: Option<Py<PyAny>>,
}

#[pymethods]
impl DecryptEventParams {
    #[new]
    #[pyo3(signature = (event_b64, conversation_keys=None, *, signing_keys=None))]
    pub(crate) fn new(
        event_b64: String,
        conversation_keys: Option<Py<PyAny>>,
        signing_keys: Option<Py<PyAny>>,
    ) -> Self {
        Self {
            event_b64,
            conversation_keys,
            signing_keys,
        }
    }
}

impl DecryptEventParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::DecryptEventParams> {
        let conversation_keys = match &self.conversation_keys {
            Some(keys) => conversation_keys_field(py, keys)?,
            None => HashMap::new(),
        };
        let mut params =
            chat_xdk_core::DecryptEventParams::new(self.event_b64.as_str(), conversation_keys);
        params.signing_keys = signing_keys_field(py, &self.signing_keys)?;
        Ok(params)
    }
}

/// Parameters for ``Chat.decrypt_events``.
#[pyclass(get_all, set_all)]
pub struct DecryptEventsParams {
    /// The base64 events, as delivered. Their key changes supply the
    /// conversation keys the messages among them are decrypted with.
    pub(crate) events: Py<PyAny>,
    /// Signing-key dicts for all participants, as in
    /// ``DecryptEventParams.signing_keys``. ``None`` or empty uses the keys
    /// stored via ``Chat.set_signing_keys``.
    pub(crate) signing_keys: Option<Py<PyAny>>,
}

#[pymethods]
impl DecryptEventsParams {
    #[new]
    #[pyo3(signature = (events, *, signing_keys=None))]
    pub(crate) fn new(events: Py<PyAny>, signing_keys: Option<Py<PyAny>>) -> Self {
        Self {
            events,
            signing_keys,
        }
    }
}

impl DecryptEventsParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::DecryptEventsParams> {
        let mut params =
            chat_xdk_core::DecryptEventsParams::new(extract_field(py, &self.events, "events")?);
        params.signing_keys = signing_keys_field(py, &self.signing_keys)?;
        Ok(params)
    }
}

/// Parameters for ``Chat.encrypt_file``.
#[pyclass(get_all, set_all)]
pub struct EncryptFileParams {
    /// The file to encrypt (``bytes``).
    pub(crate) file: Vec<u8>,
    /// The ``event_b64`` of the payload that ``encrypt_message`` or
    /// ``encrypt_reply`` returned for the message carrying the file.
    pub(crate) event_b64: String,
    /// The media hash key the file's upload started with, as listed in the
    /// message's attachments.
    pub(crate) media_hash_key: String,
    /// The raw 32-byte conversation key the message was encrypted under;
    /// with ``conversation_key_version`` left ``None`` too, it resolves from
    /// the key cache, as for ``EncryptMessageParams``.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// The version of ``conversation_key``: the message's key version.
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl EncryptFileParams {
    #[new]
    #[pyo3(signature = (file, event_b64, media_hash_key, *, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        file: Vec<u8>,
        event_b64: String,
        media_hash_key: String,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> Self {
        Self {
            file,
            event_b64,
            media_hash_key,
            conversation_key,
            conversation_key_version,
        }
    }
}

impl EncryptFileParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::EncryptFileParams {
        let mut params = chat_xdk_core::EncryptFileParams::new(
            self.file.clone(),
            self.event_b64.as_str(),
            self.media_hash_key.as_str(),
        );
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.file_encryptor``: those of ``EncryptFileParams``
/// apart from the file, which is fed to the encryptor.
#[pyclass(get_all, set_all)]
pub struct FileEncryptorParams {
    /// The ``event_b64`` of the payload that ``encrypt_message`` or
    /// ``encrypt_reply`` returned for the message carrying the file.
    pub(crate) event_b64: String,
    /// The media hash key the file's upload started with, as listed in the
    /// message's attachments.
    pub(crate) media_hash_key: String,
    /// The raw 32-byte conversation key the message was encrypted under;
    /// resolves from the key cache when left ``None``.
    pub(crate) conversation_key: Option<Vec<u8>>,
    /// The version of ``conversation_key``: the message's key version.
    pub(crate) conversation_key_version: Option<String>,
}

#[pymethods]
impl FileEncryptorParams {
    #[new]
    #[pyo3(signature = (event_b64, media_hash_key, *, conversation_key=None, conversation_key_version=None))]
    pub(crate) fn new(
        event_b64: String,
        media_hash_key: String,
        conversation_key: Option<Vec<u8>>,
        conversation_key_version: Option<String>,
    ) -> Self {
        Self {
            event_b64,
            media_hash_key,
            conversation_key,
            conversation_key_version,
        }
    }
}

impl FileEncryptorParams {
    pub(crate) fn to_core(&self) -> chat_xdk_core::FileEncryptorParams {
        let mut params = chat_xdk_core::FileEncryptorParams::new(
            self.event_b64.as_str(),
            self.media_hash_key.as_str(),
        );
        params.conversation_key = self.conversation_key.clone();
        params.conversation_key_version = self.conversation_key_version.clone();
        params
    }
}

/// Parameters for ``Chat.decrypt_file``.
#[pyclass(get_all, set_all)]
pub struct DecryptFileParams {
    /// The encrypted file, as downloaded (``bytes``).
    pub(crate) encrypted: Vec<u8>,
    /// The base64 event of the message that carries the file, as passed to
    /// ``decrypt_event``.
    pub(crate) event_b64: String,
    /// The conversation's key map, as passed to ``decrypt_event``. It must
    /// hold the key for the message's version.
    pub(crate) conversation_keys: Py<PyAny>,
    /// The file's media hash key from the decrypted message: a media
    /// attachment, a link card's banner or favicon, or media quoted in its
    /// reply preview.
    pub(crate) media_hash_key: String,
}

#[pymethods]
impl DecryptFileParams {
    #[new]
    pub(crate) fn new(
        encrypted: Vec<u8>,
        event_b64: String,
        conversation_keys: Py<PyAny>,
        media_hash_key: String,
    ) -> Self {
        Self {
            encrypted,
            event_b64,
            conversation_keys,
            media_hash_key,
        }
    }
}

impl DecryptFileParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::DecryptFileParams> {
        Ok(chat_xdk_core::DecryptFileParams::new(
            self.encrypted.clone(),
            self.event_b64.as_str(),
            conversation_keys_field(py, &self.conversation_keys)?,
            self.media_hash_key.as_str(),
        ))
    }
}

/// Parameters for ``Chat.file_decryptor``: those of ``DecryptFileParams``
/// apart from the encrypted file, which is fed to the decryptor.
#[pyclass(get_all, set_all)]
pub struct FileDecryptorParams {
    /// The base64 event of the message that carries the file, as passed to
    /// ``decrypt_event``.
    pub(crate) event_b64: String,
    /// The conversation's key map, as passed to ``decrypt_event``. It must
    /// hold the key for the message's version.
    pub(crate) conversation_keys: Py<PyAny>,
    /// The file's media hash key from the decrypted message: a media
    /// attachment, a link card's banner or favicon, or media quoted in its
    /// reply preview.
    pub(crate) media_hash_key: String,
}

#[pymethods]
impl FileDecryptorParams {
    #[new]
    pub(crate) fn new(
        event_b64: String,
        conversation_keys: Py<PyAny>,
        media_hash_key: String,
    ) -> Self {
        Self {
            event_b64,
            conversation_keys,
            media_hash_key,
        }
    }
}

impl FileDecryptorParams {
    pub(crate) fn to_core(&self, py: Python<'_>) -> PyResult<chat_xdk_core::FileDecryptorParams> {
        Ok(chat_xdk_core::FileDecryptorParams::new(
            self.event_b64.as_str(),
            conversation_keys_field(py, &self.conversation_keys)?,
            self.media_hash_key.as_str(),
        ))
    }
}
