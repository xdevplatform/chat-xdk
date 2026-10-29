//! Conversation keys: decrypting, extracting and preparing key changes.

use super::*;

impl ChatCore {
    // Conversation Keys

    /// Decrypt an encrypted conversation key (ECIES).
    pub fn decrypt_conversation_key(
        &self,
        encrypted_key_b64: &str,
    ) -> Result<XChatConversationKey, SdkError> {
        let encrypted_bytes = base64_decode(encrypted_key_b64)?;
        let identity = self.keypair_manager.get_identity_keypair()?;
        let ckey =
            conversation_keys::decrypt_conversation_key(&encrypted_bytes, &identity.private)?;
        Ok(ckey)
    }

    /// Generate a new conversation key.
    pub(crate) fn generate_conversation_key(&self) -> Result<XChatConversationKey, SdkError> {
        Ok(KeyFactory::generate_conversation_key()?)
    }

    /// Encrypt a conversation key for one or more recipients.
    ///
    /// Public keys may be SEC1 uncompressed (65 bytes), SEC1 compressed (33 bytes),
    /// or SPKI/DER encoded (91 bytes). SPKI keys are automatically unwrapped.
    pub(crate) fn encrypt_conversation_key_for_recipients(
        &self,
        ckey: &XChatConversationKey,
        recipients: &[RecipientInput],
    ) -> Result<Vec<ConversationParticipantKey>, SdkError> {
        let recipients_parsed: Vec<(String, crate::crypto::keys::XChatPublicKey, String)> =
            recipients
                .iter()
                .map(|r| {
                    let pk_bytes = base64_decode(&r.public_key)?;
                    // Strip 26-byte SPKI header if present (91-byte DER-encoded key)
                    let raw = if pk_bytes.len() == 91 {
                        &pk_bytes[26..]
                    } else {
                        &pk_bytes
                    };
                    let pk = KeyFactory::reconstruct_public_key(raw, KeypairPurpose::Identity)?;
                    Ok((r.user_id.clone(), pk, r.key_version.clone()))
                })
                .collect::<Result<Vec<_>, SdkError>>()?;

        let encrypted =
            conversation_keys::encrypt_conversation_key_for_recipients(ckey, &recipients_parsed)?;

        Ok(encrypted
            .into_iter()
            .map(|e| ConversationParticipantKey {
                user_id: e.user_id,
                encrypted_conversation_key: base64_encode(&e.encrypted_key),
                public_key_version: e.public_key_version,
            })
            .collect())
    }

    /// Generate a conversation key and encrypt it for every participant.
    ///
    /// Groups `public_keys` by user, keeps the highest version per user, then
    /// returns the raw key (to store locally) and one encrypted copy per user.
    pub(super) fn build_participant_keys(
        &self,
        public_keys: &[PublicKeyInput],
    ) -> Result<(XChatConversationKey, Vec<ConversationParticipantKey>), SdkError> {
        if public_keys.is_empty() {
            return Err(SdkError::InvalidInput(
                "public_keys must not be empty".to_string(),
            ));
        }
        for pk in public_keys {
            crate::pipeline::validate_user_id("public_keys user_id", &pk.user_id)?;
            crate::pipeline::validate_key_version(
                "public_keys public_key_version",
                &pk.public_key_version,
            )?;
        }

        let mut best_by_user: HashMap<String, &PublicKeyInput> = HashMap::new();
        for pk in public_keys {
            let is_newer = match best_by_user.get(&pk.user_id) {
                None => true,
                Some(current) => match (
                    pk.public_key_version.parse::<u64>(),
                    current.public_key_version.parse::<u64>(),
                ) {
                    (Ok(new_ver), Ok(cur_ver)) => new_ver > cur_ver,
                    _ => pk.public_key_version > current.public_key_version,
                },
            };
            if is_newer {
                best_by_user.insert(pk.user_id.clone(), pk);
            }
        }

        let recipients: Vec<RecipientInput> = best_by_user
            .values()
            .map(|pk| RecipientInput {
                user_id: pk.user_id.clone(),
                public_key: pk.identity_public_key.clone(),
                key_version: pk.public_key_version.clone(),
            })
            .collect();

        let ckey = self.generate_conversation_key()?;
        let participant_keys = self.encrypt_conversation_key_for_recipients(&ckey, &recipients)?;
        Ok((ckey, participant_keys))
    }

    /// Derive the canonical id for a one-to-one conversation.
    ///
    /// The id is the two distinct user ids ordered by
    /// [`crate::pipeline::join_sorted_pair`] — length then lexically, which
    /// equals numeric order for decimal ids — and joined with a colon.
    /// Signer and verifier derive the same string from the same pair, so the
    /// signed payload only matches when this exact form is used. Requires
    /// exactly two distinct users; a group must pass its id explicitly.
    pub(super) fn derive_one_to_one_conversation_id(
        public_keys: &[PublicKeyInput],
    ) -> Result<String, SdkError> {
        let mut ids: Vec<&str> = Vec::new();
        for pk in public_keys {
            if !ids.contains(&pk.user_id.as_str()) {
                ids.push(pk.user_id.as_str());
            }
        }
        if ids.len() != 2 {
            return Err(SdkError::InvalidInput(format!(
                "cannot derive a one-to-one conversation id from {} distinct user(s); \
                 pass conversation_id explicitly for group conversations",
                ids.len()
            )));
        }
        Ok(crate::pipeline::join_sorted_pair(ids[0], ids[1]))
    }

    /// Generate a random message id for a signed action.
    pub(super) fn generate_message_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes)
            .into_uuid()
            .to_string()
    }

    /// The id of an outgoing message or reply. In v1 its files are encrypted
    /// after the message is built and uploaded under keys derived from this
    /// id, so a message with files takes an id derived from what identifies it
    /// (see [`message_keys::derive_media_message_id`]): building the same
    /// message again keeps its uploaded files valid. v0 files use the
    /// conversation key, so v0 messages, like messages without files, take a
    /// random id, as 0.5.x did.
    pub(super) fn outgoing_message_id(
        send_version: crate::pipeline::SendVersion,
        conversation_key: &XChatConversationKey,
        conversation_key_version: &str,
        sender_id: &str,
        conversation_id: &str,
        attachments: Option<&[AttachmentDescriptor]>,
    ) -> Result<String, SdkError> {
        let media_hash_keys = attachments
            .map(crate::pipeline::file_media_hash_keys)
            .unwrap_or_default();
        if send_version == crate::pipeline::SendVersion::V0 || media_hash_keys.is_empty() {
            return Ok(Self::generate_message_id());
        }
        let conversation_id =
            crate::pipeline::canonical_conversation_id(conversation_id, sender_id);
        Ok(message_keys::derive_media_message_id(
            conversation_key,
            conversation_key_version,
            sender_id,
            &conversation_id,
            &media_hash_keys,
        )?)
    }

    /// Prepare a signed conversation-key change, ready to send to the X API.
    ///
    /// Use this to start a one-to-one or rotate an existing conversation's key
    /// (one-to-one or group). Creating a group or adding members requires a
    /// paired group signature as well — use [`Self::prepare_group_create`] or
    /// [`Self::prepare_group_members_change`] for those.
    ///
    /// Generates a fresh conversation key, encrypts it for every participant,
    /// and signs the change so recipients can verify it came from the sender.
    /// Omit `conversation_id` for a one-to-one and it is derived from the two
    /// participants; pass the existing id for a group key rotation.
    ///
    /// The returned `conversation_key` is the raw key to store locally for
    /// encrypting messages.
    pub fn prepare_conversation_key_change(
        &self,
        params: &ConversationKeyChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_conversation_key_change_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_conversation_key_change`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_conversation_key_change_with_version(
        &self,
        params: &ConversationKeyChangeParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        crate::pipeline::validate_key_version(
            "conversation_key_version",
            conversation_key_version,
        )?;
        // An empty id means "derive": FFI layers cannot express Option and
        // send "" for "not set".
        let conversation_id = match params
            .conversation_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            // Canonicalize caller-supplied forms (hyphen pair, unsorted pair,
            // bare recipient id) so the signature covers the id the backend
            // fans out.
            Some(id) => crate::pipeline::canonical_conversation_id(id, &sender_id).into_owned(),
            None => Self::derive_one_to_one_conversation_id(&params.public_keys)?,
        };
        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;
        let signature = self.sign_key_change(
            &signing_key_version,
            &sender_id,
            &conversation_id,
            conversation_key_version,
            &ckey,
            &participant_keys,
        )?;
        Ok(PreparedConversationChange {
            conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            conversation_participant_keys: participant_keys,
            action_signatures: vec![signature],
            encrypted_title: None,
            encrypted_description: None,
        })
    }

    /// Sign the change to the conversation key `ckey` at
    /// `conversation_key_version`: a `ConversationKeyChangeEvent` carrying
    /// the per-participant encrypted keys, the event the API persists and
    /// relays. Its signed payload covers the plaintext key, which recipients
    /// decrypt from their participant key.
    pub(crate) fn sign_key_change(
        &self,
        public_key_version: &str,
        sender_id: &str,
        conversation_id: &str,
        conversation_key_version: &str,
        ckey: &XChatConversationKey,
        participant_keys: &[ConversationParticipantKey],
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let participant_keys = participant_keys
            .iter()
            .map(|pk| crate::thrift::event::ConversationParticipantKey {
                user_id: Some(pk.user_id.clone()),
                encrypted_conversation_key: Some(pk.encrypted_conversation_key.clone()),
                public_key_version: Some(pk.public_key_version.clone()),
            })
            .collect();
        let detail = crate::thrift::event::MessageEventDetail::ConversationKeyChangeEvent(
            crate::thrift::event::ConversationKeyChangeEvent {
                conversation_key_version: Some(conversation_key_version.to_string()),
                conversation_participant_keys: Some(participant_keys),
                ratchet_tree_change: None,
                for_key_rotation: Some(false),
            },
        );
        self.sign_action_event(
            public_key_version,
            sender_id,
            conversation_id,
            crate::signatures::CURRENT_SIGNATURE_VERSION,
            detail,
            Some(ckey.encoded()),
        )
    }

    /// The `GroupCreate` event the API persists and relays: the full group
    /// roster, the encrypted title, and the conversation-key version. The
    /// backend matches on `member_ids`, `admin_ids`, `title`, `avatar_url`
    /// and `conversation_key_version`; a create sets no avatar.
    pub(super) fn group_create_detail(
        member_ids: &[String],
        admin_ids: &[String],
        title: Option<&str>,
        conversation_key_version: &str,
        ttl_msec: Option<i64>,
        is_legacy_group_upgrade: Option<bool>,
    ) -> crate::thrift::event::MessageEventDetail {
        let group_create = crate::thrift::event::GroupCreate {
            member_ids: Some(member_ids.to_vec()),
            admin_ids: Some(admin_ids.to_vec()),
            title: title.map(|s| s.to_string()),
            avatar_url: None,
            conversation_key_version: Some(conversation_key_version.to_string()),
            is_legacy_group_upgrade,
            ttl_msec,
            group_type: None,
        };
        crate::thrift::event::MessageEventDetail::GroupChangeEvent(
            crate::thrift::event::GroupChangeEvent {
                group_change: Some(crate::thrift::event::GroupChange::GroupCreate(group_create)),
                for_key_rotation: Some(false),
            },
        )
    }

    /// The `GroupMemberAddChange` event the API persists and relays: the new
    /// members plus the current roster snapshot the backend matches against,
    /// its title and description encrypted under the new key.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn group_member_add_detail(
        new_member_ids: &[String],
        current_member_ids: &[String],
        current_admin_ids: &[String],
        current_pending_member_ids: &[String],
        current_title: Option<&str>,
        current_avatar_url: Option<&str>,
        current_description: Option<&str>,
        current_ttl_msec: Option<i64>,
        current_screen_capture_blocking_enabled: Option<bool>,
        conversation_key_version: &str,
    ) -> crate::thrift::event::MessageEventDetail {
        let change = crate::thrift::event::GroupMemberAddChange {
            member_ids: Some(new_member_ids.to_vec()),
            current_member_ids: Some(current_member_ids.to_vec()),
            current_admin_ids: Some(current_admin_ids.to_vec()),
            current_title: current_title.map(|s| s.to_string()),
            current_avatar_url: current_avatar_url.map(|s| s.to_string()),
            conversation_key_version: Some(conversation_key_version.to_string()),
            current_ttl_msec,
            current_pending_member_ids: Some(current_pending_member_ids.to_vec()),
            screen_capture_blocking_enabled: current_screen_capture_blocking_enabled,
            group_invite_enable: None,
            admin_settings: None,
            current_pmk_bundle: None,
            group_created_by_user_id: None,
            rotated_pmk_bundle: None,
            current_description: current_description.map(str::to_string),
        };
        crate::thrift::event::MessageEventDetail::GroupChangeEvent(
            crate::thrift::event::GroupChangeEvent {
                group_change: Some(crate::thrift::event::GroupChange::GroupMemberAdd(change)),
                for_key_rotation: Some(false),
            },
        )
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Use this once, when creating a group (`conversation_id` is the `g…` id
    /// minted by the initialize endpoint). Later key rotations use
    /// [`Self::prepare_conversation_key_change`]; roster additions use
    /// [`Self::prepare_group_members_change`].
    ///
    /// Generates a fresh conversation key for the new group, encrypts it for
    /// every participant, and emits the two action signatures the backend
    /// requires: a conversation-key change and the group-create itself. The
    /// returned `conversation_key` is the raw key to store locally.
    ///
    /// `title` is plaintext. The call encrypts it under the new conversation
    /// key, as [`Self::prepare_group_title_change`] encrypts a title, signs
    /// the ciphertext, and returns it as `encrypted_title`: the `group_name`
    /// the create request sends. A create sets no avatar; set it afterwards
    /// with [`Self::prepare_group_avatar_change`].
    pub fn prepare_group_create(
        &self,
        params: &GroupCreateParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_group_create_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_group_create`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_group_create_with_version(
        &self,
        params: &GroupCreateParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        crate::pipeline::validate_key_version(
            "conversation_key_version",
            conversation_key_version,
        )?;
        // Normalize absent-value encodings so every binding signs identical
        // bytes: FFI layers cannot express Option and pass "" / a negative
        // TTL for "not set".
        let title = params.title.as_deref().filter(|t| !t.is_empty());
        let ttl_msec = params.ttl_msec.filter(|t| *t >= 0);

        crate::pipeline::validate_user_ids("member_ids", &params.member_ids)?;
        crate::pipeline::validate_user_ids("admin_ids", &params.admin_ids)?;
        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;
        let encrypted_title = title
            .map(|title| group_actions::encrypt_group_metadata(&ckey, title))
            .transpose()?;

        // A group create needs two signed actions: the conversation-key change
        // that seeds the group's key, and the group-create action itself.
        let ckce_sig = self.sign_key_change(
            &signing_key_version,
            &sender_id,
            &params.conversation_id,
            conversation_key_version,
            &ckey,
            &participant_keys,
        )?;
        let create_sig = self.sign_action_event(
            &signing_key_version,
            &sender_id,
            &params.conversation_id,
            crate::signatures::CURRENT_SIGNATURE_VERSION,
            Self::group_create_detail(
                &params.member_ids,
                &params.admin_ids,
                encrypted_title.as_deref(),
                conversation_key_version,
                ttl_msec,
                None,
            ),
            None,
        )?;

        Ok(PreparedConversationChange {
            conversation_id: params.conversation_id.clone(),
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            conversation_participant_keys: participant_keys,
            action_signatures: vec![ckce_sig, create_sig],
            encrypted_title,
            encrypted_description: None,
        })
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Use this when adding members to an existing group. Creating the group is
    /// [`Self::prepare_group_create`]; a key rotation without a roster change is
    /// [`Self::prepare_conversation_key_change`].
    ///
    /// Generates a fresh conversation key for the updated roster, encrypts it
    /// for every participant in `public_keys`, and emits the two action
    /// signatures the backend requires: a conversation-key change and the
    /// member add itself. The returned `conversation_key` is the raw key to
    /// store locally.
    ///
    /// `current_title` and `current_description` are plaintext. The call
    /// encrypts each under the new key, signs the ciphertext, and returns it
    /// as `encrypted_title` and `encrypted_description`. While sends are v0,
    /// a member add that carries a description signs at version 8, the first
    /// that covers it, and any other at 7; while they are v1, every add signs
    /// at 10. `current_avatar_url` is the avatar's media URL, signed as is.
    pub fn prepare_group_members_change(
        &self,
        params: &GroupMembersChangeParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_group_members_change_with_version(params, &now_millis())
    }

    /// Like [`Self::prepare_group_members_change`] but uses the caller-supplied
    /// conversation-key version instead of the system clock.
    pub fn prepare_group_members_change_with_version(
        &self,
        params: &GroupMembersChangeParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let sender_id = self.resolve_sender_id(params.sender_id.as_deref())?;
        let signing_key_version =
            self.resolve_signing_key_version(params.signing_key_version.as_deref())?;
        crate::pipeline::validate_key_version(
            "conversation_key_version",
            conversation_key_version,
        )?;
        // Normalize absent-value encodings so every binding signs identical
        // bytes: FFI layers cannot express Option and pass "" / a negative
        // TTL for "not set".
        let current_title = params.current_title.as_deref().filter(|t| !t.is_empty());
        let current_avatar_url = params
            .current_avatar_url
            .as_deref()
            .filter(|a| !a.is_empty());
        let current_description = params
            .current_description
            .as_deref()
            .filter(|d| !d.is_empty());
        let current_ttl_msec = params.current_ttl_msec.filter(|t| *t >= 0);

        crate::pipeline::validate_user_ids("new_member_ids", &params.new_member_ids)?;
        crate::pipeline::validate_user_ids("current_member_ids", &params.current_member_ids)?;
        crate::pipeline::validate_user_ids("current_admin_ids", &params.current_admin_ids)?;
        crate::pipeline::validate_user_ids(
            "current_pending_member_ids",
            &params.current_pending_member_ids,
        )?;
        let (ckey, participant_keys) = self.build_participant_keys(&params.public_keys)?;
        let encrypted_title = current_title
            .map(|title| group_actions::encrypt_group_metadata(&ckey, title))
            .transpose()?;
        let encrypted_description = current_description
            .map(|description| group_actions::encrypt_group_metadata(&ckey, description))
            .transpose()?;

        // A member add needs two signed actions: the conversation-key change
        // that rotates the group's key, and the member-add action itself.
        let ckce_sig = self.sign_key_change(
            &signing_key_version,
            &sender_id,
            &params.conversation_id,
            conversation_key_version,
            &ckey,
            &participant_keys,
        )?;
        // A description is first part of the member-add payload at version
        // 8, so a v0 add that carries one signs at 8.
        let legacy_version = if encrypted_description.is_some() {
            crate::signatures::MEMBER_ADD_DESCRIPTION_SIGNATURE_VERSION
        } else {
            crate::signatures::CURRENT_SIGNATURE_VERSION
        };
        let member_add_sig = self.sign_action_event(
            &signing_key_version,
            &sender_id,
            &params.conversation_id,
            legacy_version,
            Self::group_member_add_detail(
                &params.new_member_ids,
                &params.current_member_ids,
                &params.current_admin_ids,
                &params.current_pending_member_ids,
                encrypted_title.as_deref(),
                current_avatar_url,
                encrypted_description.as_deref(),
                current_ttl_msec,
                params.current_screen_capture_blocking_enabled,
                conversation_key_version,
            ),
            None,
        )?;

        Ok(PreparedConversationChange {
            conversation_id: params.conversation_id.clone(),
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            conversation_participant_keys: participant_keys,
            action_signatures: vec![ckce_sig, member_add_sig],
            encrypted_title,
            encrypted_description,
        })
    }
}
