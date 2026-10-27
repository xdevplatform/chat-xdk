//! Removing members, which rotates the conversation key for the members
//! who stay; leaving; and adding and removing admins.

use crate::core::ChatCore;
use crate::error::SdkError;
use crate::params::{
    GroupAdminsAddParams, GroupAdminsRemoveParams, GroupLeaveParams, GroupMembersRemoveParams,
};
use crate::signatures::{
    ActionSignature, CURRENT_SIGNATURE_VERSION, MEMBER_REMOVE_SIGNATURE_VERSION,
};
use crate::thrift::event::{
    ConversationDeleteEvent, GroupAdminAddChange, GroupAdminRemoveChange, GroupChange,
    GroupMemberRemoveChange, MessageEventDetail,
};
use crate::types::{PreparedAction, PreparedConversationChange};

use super::{
    encode_detail, group_detail, nullable_str, require_user_ids, sign_metadata, sign_named,
    ActionCtx, GroupMetadata,
};

impl ChatCore {
    /// Sign a group member removal and rotate the conversation key for the
    /// members who stay.
    ///
    /// `public_keys` are the identity keys of the members who stay. The
    /// result is a [`PreparedConversationChange`]: the new conversation key,
    /// its participant keys, and `action_signatures` in request order — the
    /// removal (bound to the new key version); a title and a description
    /// change for each of `title` and `description` that is set, encrypted
    /// under the new key and marked as key-rotation re-encryptions; then the
    /// conversation-key change.
    ///
    /// The removal is signed at signature version 11 so the key version is
    /// part of the payload. The key change is signed at the version every
    /// other key change uses.
    ///
    /// The result does not include a ratchet tree (`base64_encoded_key_rotation`)
    /// or a rewrapped pin-key bundle (`rotated_pmk_bundle`).
    pub fn prepare_group_members_remove(
        &self,
        params: &GroupMembersRemoveParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        self.prepare_group_members_remove_with_version(params, &crate::core::now_millis())
    }

    /// Like [`Self::prepare_group_members_remove`], using
    /// `conversation_key_version` as the new key version instead of the
    /// system clock.
    ///
    /// WASM calls this with a JavaScript timestamp so the core never reads
    /// the system clock.
    pub fn prepare_group_members_remove_with_version(
        &self,
        params: &GroupMembersRemoveParams,
        conversation_key_version: &str,
    ) -> Result<PreparedConversationChange, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        require_user_ids("user_ids", &params.user_ids)?;
        crate::pipeline::validate_key_version(
            "conversation_key_version",
            conversation_key_version,
        )?;
        let public_keys = &params.public_keys;
        if public_keys.is_empty() {
            return Err(SdkError::InvalidInput(
                "public_keys is empty: pass the public keys of the remaining members".into(),
            ));
        }
        if public_keys
            .iter()
            .any(|key| params.user_ids.iter().any(|id| id == &key.user_id))
        {
            return Err(SdkError::InvalidInput(
                "public_keys includes a user being removed: pass the public keys of the remaining members"
                    .into(),
            ));
        }
        let (ckey, participant_keys) = self.build_participant_keys(public_keys)?;
        let mut action_signatures = vec![sign_member_remove(
            &ctx,
            &params.user_ids,
            Some(conversation_key_version),
        )?];
        for (field, value) in [
            (GroupMetadata::Title, &params.title),
            (GroupMetadata::Description, &params.description),
        ] {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                let (_, signature) =
                    sign_metadata(&ctx, field, value, &ckey, conversation_key_version, true)?;
                action_signatures.push(signature);
            }
        }
        let key_change_id = Self::generate_message_id();
        let mut key_change = self.sign_key_change(
            &ctx.signing_key_version,
            &key_change_id,
            &ctx.sender_id,
            &ctx.conversation_id,
            conversation_key_version,
            ckey.encoded(),
        )?;
        key_change.encoded_message_event_detail =
            Self::encode_ckey_change_detail(conversation_key_version, &participant_keys)?;
        action_signatures.push(key_change);

        Ok(PreparedConversationChange {
            conversation_id: ctx.conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            conversation_participant_keys: participant_keys,
            action_signatures,
            encrypted_title: None,
            encrypted_description: None,
        })
    }

    /// Sign leaving a group.
    ///
    /// Leave is a member removal of the sender and does not rotate the
    /// conversation key. The result's `action_signatures` are that removal,
    /// then a `GroupAdminAddChange` when `promote_admin_id` is set, then a
    /// `ConversationDeleteEvent` with no further fields.
    pub fn prepare_group_leave(
        &self,
        params: &GroupLeaveParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let bound = bound_key_version(&params.conversation_key_version)?;
        let promote = match params
            .promote_admin_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            Some(id) => {
                crate::pipeline::validate_user_id("promote_admin_id", id)?;
                Some(id.to_string())
            }
            None => None,
        };

        let self_ids = vec![ctx.sender_id.clone()];
        let mut signatures = vec![sign_member_remove(&ctx, &self_ids, bound.as_deref())?];
        if let Some(admin_id) = promote {
            let detail = group_detail(GroupChange::GroupAdminAdd(GroupAdminAddChange {
                admin_ids: Some(vec![admin_id.clone()]),
            }))?;
            signatures.push(sign_named(
                &ctx,
                "GroupChangeEvent.GroupAdminAddChange",
                &[&admin_id],
                CURRENT_SIGNATURE_VERSION,
                detail,
            )?);
        }
        signatures.push(sign_named(
            &ctx,
            "ConversationDeleteEvent",
            &[],
            CURRENT_SIGNATURE_VERSION,
            encode_detail(MessageEventDetail::ConversationDeleteEvent(
                ConversationDeleteEvent {
                    conversation_id: Some(ctx.conversation_id.clone()),
                    clear_conversation_options: None,
                },
            ))?,
        )?);
        Ok(PreparedAction {
            action_signatures: signatures,
        })
    }

    /// Sign adding group admins.
    pub fn prepare_group_admins_add(
        &self,
        params: &GroupAdminsAddParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_id_list(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            "user_ids",
            &params.user_ids,
            "GroupChangeEvent.GroupAdminAddChange",
            |ids| {
                group_detail(GroupChange::GroupAdminAdd(GroupAdminAddChange {
                    admin_ids: Some(ids.to_vec()),
                }))
            },
        )
    }

    /// Sign removing group admins.
    pub fn prepare_group_admins_remove(
        &self,
        params: &GroupAdminsRemoveParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_id_list(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            "user_ids",
            &params.user_ids,
            "GroupChangeEvent.GroupAdminRemoveChange",
            |ids| {
                group_detail(GroupChange::GroupAdminRemove(GroupAdminRemoveChange {
                    admin_ids: Some(ids.to_vec()),
                }))
            },
        )
    }
}

fn bound_key_version(version: &Option<String>) -> Result<Option<String>, SdkError> {
    match version.as_deref().filter(|value| !value.is_empty()) {
        Some(value) => {
            crate::pipeline::validate_key_version("conversation_key_version", value)?;
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

fn sign_member_remove(
    ctx: &ActionCtx,
    user_ids: &[String],
    key_version: Option<&str>,
) -> Result<ActionSignature, SdkError> {
    let version = nullable_str(key_version);
    let mut extras: Vec<&str> = user_ids.iter().map(String::as_str).collect();
    extras.push(version.as_str());
    sign_named(
        ctx,
        "GroupChangeEvent.GroupMemberRemoveChange",
        &extras,
        MEMBER_REMOVE_SIGNATURE_VERSION,
        group_detail(GroupChange::GroupMemberRemove(GroupMemberRemoveChange {
            member_ids: Some(user_ids.to_vec()),
            conversation_key_version: key_version.map(str::to_string),
        }))?,
    )
}
