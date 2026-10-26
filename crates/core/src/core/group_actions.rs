//! Signed group and conversation-metadata actions.
//!
//! Each prepare builds one request's `action_signatures`. A member remove
//! also rotates the conversation key for the members who stay, reusing the
//! key-change signer, and returns that key. The title, avatar and
//! description changes encrypt their plaintext under the conversation key
//! before signing it. The other prepares do not rotate.

use crate::crypto::keys::XChatConversationKey;
use crate::error::SdkError;
use crate::params::{
    GroupAdminsAddParams, GroupAdminsRemoveParams, GroupAvatarChangeParams,
    GroupDescriptionChangeParams, GroupInviteDisableParams, GroupInviteEnableParams,
    GroupJoinRejectParams, GroupJoinRequestParams, GroupLeaveParams, GroupMembersRemoveParams,
    GroupTitleChangeParams, MessageTtlChangeParams, MessageTtlRemoveParams, ScreenCaptureParams,
};
use crate::protocol::serialization::base64_encode;
use crate::signatures::{
    sign_action, ActionSignature, CURRENT_SIGNATURE_VERSION, MEMBER_REMOVE_SIGNATURE_VERSION,
};
use crate::thrift::event::{
    ConversationDeleteEvent, ConversationMetadataChange, ConversationMetadataChangeEvent,
    DisableScreenCaptureBlocking, DisableScreenCaptureDetection, EnableScreenCaptureBlocking,
    EnableScreenCaptureDetection, GroupAdminAddChange, GroupAdminRemoveChange,
    GroupAvatarUrlChange, GroupChange, GroupChangeEvent, GroupDescriptionChange,
    GroupInviteDisable, GroupInviteEnable, GroupJoinReject, GroupJoinRequest,
    GroupMemberRemoveChange, GroupTitleChange, MessageDurationChange, MessageDurationRemove,
    MessageEventDetail,
};
use crate::types::{PreparedAction, PreparedConversationChange, PreparedGroupMetadataChange};

use super::ChatCore;

struct ActionCtx {
    sender_id: String,
    signing_key_version: String,
    conversation_id: String,
    signing_key: crate::crypto::keys::XChatPrivateKey,
}

/// The inputs of a title, avatar or description change.
struct MetadataChange<'a> {
    conversation_id: &'a str,
    sender_id: Option<&'a str>,
    signing_key_version: Option<&'a str>,
    conversation_key: Option<&'a [u8]>,
    conversation_key_version: Option<&'a str>,
    /// The params field `value` comes from, named in errors.
    param: &'a str,
    value: &'a str,
}

/// A group field the SDK encrypts under the conversation key before signing.
#[derive(Clone, Copy)]
enum GroupMetadata {
    Title,
    AvatarUrl,
    Description,
}

impl GroupMetadata {
    fn event_name(self) -> &'static str {
        match self {
            Self::Title => "GroupChangeEvent.GroupTitleChange",
            Self::AvatarUrl => "GroupChangeEvent.GroupAvatarUrlChange",
            Self::Description => "GroupChangeEvent.GroupDescriptionChange",
        }
    }

    fn detail(self, encrypted: &str, key_version: &str) -> Result<String, SdkError> {
        let encrypted = Some(encrypted.to_string());
        let conversation_key_version = Some(key_version.to_string());
        group_detail(match self {
            Self::Title => GroupChange::GroupTitleChange(GroupTitleChange {
                custom_title: encrypted,
                conversation_key_version,
            }),
            Self::AvatarUrl => GroupChange::GroupAvatarChange(GroupAvatarUrlChange {
                custom_avatar_url: encrypted,
                conversation_key_version,
            }),
            Self::Description => GroupChange::GroupDescriptionChange(GroupDescriptionChange {
                custom_description: encrypted,
                conversation_key_version,
            }),
        })
    }
}

impl ChatCore {
    /// Sign a group member removal and rotate the conversation key for the
    /// members who stay.
    ///
    /// `public_keys` are the identity keys of the members who stay. The
    /// result is a [`PreparedConversationChange`]: the new conversation key,
    /// its participant keys, and `action_signatures` in request order — the
    /// removal (bound to the new key version); a title, avatar and
    /// description change for each of `title`, `avatar_url` and
    /// `description` that is set, encrypted under the new key; then the
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
        self.prepare_group_members_remove_with_version(params, &super::now_millis())
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
            (GroupMetadata::AvatarUrl, &params.avatar_url),
            (GroupMetadata::Description, &params.description),
        ] {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                let (_, signature) =
                    sign_metadata(&ctx, field, value, &ckey, conversation_key_version)?;
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

    /// Encrypt a new group title under the conversation key and sign the
    /// change.
    ///
    /// `new_title` is plaintext. The conversation key resolves as
    /// [`Self::encrypt_message`] resolves it: the explicit key and version
    /// pair, or the key cache. The signature covers the key version and the
    /// encrypted title, under `GroupChangeEvent.GroupTitleChange`.
    pub fn prepare_group_title_change(
        &self,
        params: &GroupTitleChangeParams,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.prepare_metadata_change(
            MetadataChange {
                conversation_id: &params.conversation_id,
                sender_id: params.sender_id.as_deref(),
                signing_key_version: params.signing_key_version.as_deref(),
                conversation_key: params.conversation_key.as_deref(),
                conversation_key_version: params.conversation_key_version.as_deref(),
                param: "new_title",
                value: &params.new_title,
            },
            GroupMetadata::Title,
        )
    }

    /// Encrypt a new group avatar URL under the conversation key and sign
    /// the change, under `GroupChangeEvent.GroupAvatarUrlChange`. The key
    /// resolves as in [`Self::prepare_group_title_change`].
    pub fn prepare_group_avatar_change(
        &self,
        params: &GroupAvatarChangeParams,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.prepare_metadata_change(
            MetadataChange {
                conversation_id: &params.conversation_id,
                sender_id: params.sender_id.as_deref(),
                signing_key_version: params.signing_key_version.as_deref(),
                conversation_key: params.conversation_key.as_deref(),
                conversation_key_version: params.conversation_key_version.as_deref(),
                param: "new_avatar_url",
                value: &params.new_avatar_url,
            },
            GroupMetadata::AvatarUrl,
        )
    }

    /// Encrypt a new group description under the conversation key and sign
    /// the change, under `GroupChangeEvent.GroupDescriptionChange`. The key
    /// resolves as in [`Self::prepare_group_title_change`].
    pub fn prepare_group_description_change(
        &self,
        params: &GroupDescriptionChangeParams,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        self.prepare_metadata_change(
            MetadataChange {
                conversation_id: &params.conversation_id,
                sender_id: params.sender_id.as_deref(),
                signing_key_version: params.signing_key_version.as_deref(),
                conversation_key: params.conversation_key.as_deref(),
                conversation_key_version: params.conversation_key_version.as_deref(),
                param: "new_description",
                value: &params.new_description,
            },
            GroupMetadata::Description,
        )
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

    /// Sign enabling a group invite.
    ///
    /// An empty `affiliate_id` and a negative `expires_at_msec` are unset and
    /// sign the literal `null`.
    pub fn prepare_group_invite_enable(
        &self,
        params: &GroupInviteEnableParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let invite_url = require_text("invite_url", &params.invite_url)?;
        let expires = params.expires_at_msec.filter(|msec| *msec >= 0);
        let affiliate = params.affiliate_id.as_deref().filter(|id| !id.is_empty());
        let expires_text = nullable_i64(expires);
        let affiliate_text = nullable_str(affiliate);
        let signature = sign_named(
            &ctx,
            "GroupChangeEvent.GroupInviteEnable",
            &[invite_url, &expires_text, &affiliate_text],
            CURRENT_SIGNATURE_VERSION,
            group_detail(GroupChange::GroupInviteEnable(GroupInviteEnable {
                expires_at_msec: expires,
                invite_url: Some(invite_url.to_string()),
                affiliate_id: affiliate.map(str::to_string),
            }))?,
        )?;
        Ok(one_action(signature))
    }

    /// Sign disabling a group invite.
    ///
    /// `disabled_by` defaults to the sender.
    pub fn prepare_group_invite_disable(
        &self,
        params: &GroupInviteDisableParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let disabled_by = match params.disabled_by.as_deref().filter(|id| !id.is_empty()) {
            Some(id) => {
                crate::pipeline::validate_user_id("disabled_by", id)?;
                id.to_string()
            }
            None => ctx.sender_id.clone(),
        };
        let detail = group_detail(GroupChange::GroupInviteDisable(GroupInviteDisable {
            disabled_by_member_id: Some(disabled_by.clone()),
        }))?;
        let signature = sign_named(
            &ctx,
            "GroupChangeEvent.GroupInviteDisable",
            &[&disabled_by],
            CURRENT_SIGNATURE_VERSION,
            detail,
        )?;
        Ok(one_action(signature))
    }

    /// Sign a request to join a group.
    ///
    /// `requesting_user_id` defaults to the sender. An invite token is not
    /// part of the signature.
    pub fn prepare_group_join_request(
        &self,
        params: &GroupJoinRequestParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let requesting = match params
            .requesting_user_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            Some(id) => {
                crate::pipeline::validate_user_id("requesting_user_id", id)?;
                id.to_string()
            }
            None => ctx.sender_id.clone(),
        };
        let detail = group_detail(GroupChange::GroupJoinRequest(GroupJoinRequest {
            requesting_user_id: Some(requesting.clone()),
        }))?;
        let signature = sign_named(
            &ctx,
            "GroupChangeEvent.GroupJoinRequest",
            &[&requesting],
            CURRENT_SIGNATURE_VERSION,
            detail,
        )?;
        Ok(one_action(signature))
    }

    /// Sign rejecting group join requests.
    pub fn prepare_group_join_reject(
        &self,
        params: &GroupJoinRejectParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_id_list(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            "user_ids",
            &params.user_ids,
            "GroupChangeEvent.GroupJoinReject",
            |ids| {
                group_detail(GroupChange::GroupJoinReject(GroupJoinReject {
                    rejected_user_ids: Some(ids.to_vec()),
                }))
            },
        )
    }

    /// Sign a message-TTL change. The signature covers `ttl_msec` only.
    pub fn prepare_message_ttl_change(
        &self,
        params: &MessageTtlChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        if params.ttl_msec < 0 {
            return Err(SdkError::InvalidInput(
                "ttl_msec is negative: pass the message TTL in milliseconds".into(),
            ));
        }
        let ttl = params.ttl_msec.to_string();
        let signature = sign_named(
            &ctx,
            "ConversationMetadataChangeEvent.MessageDurationChange",
            &[&ttl],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(ConversationMetadataChange::MessageDurationChange(
                MessageDurationChange {
                    ttl_msec: Some(params.ttl_msec),
                    apply_to_all_messages: None,
                },
            ))?,
        )?;
        Ok(one_action(signature))
    }

    /// Sign clearing a conversation's message TTL.
    pub fn prepare_message_ttl_remove(
        &self,
        params: &MessageTtlRemoveParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let signature = sign_named(
            &ctx,
            "ConversationMetadataChangeEvent.MessageDurationRemove",
            &[],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(ConversationMetadataChange::MessageDurationRemove(
                MessageDurationRemove {
                    current_ttl_msec: None,
                },
            ))?,
        )?;
        Ok(one_action(signature))
    }

    /// Sign one screen-capture setting change.
    ///
    /// Blocking and detection each have an enable and a disable event. The
    /// signed payload has no fields after the conversation id. Detection
    /// event names are the ones this SDK's verifier reconstructs.
    pub fn prepare_screen_capture(
        &self,
        params: &ScreenCaptureParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let signature = sign_named(
            &ctx,
            params.change.event_name(),
            &[],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(screen_capture_detail(params.change))?,
        )?;
        Ok(one_action(signature))
    }

    fn action_ctx(
        &self,
        conversation_id: &str,
        sender_id: Option<&str>,
        signing_key_version: Option<&str>,
    ) -> Result<ActionCtx, SdkError> {
        if conversation_id.is_empty() {
            return Err(SdkError::InvalidInput(
                "conversation_id is empty: pass the conversation this action belongs to".into(),
            ));
        }
        let sender_id = self.resolve_sender_id(sender_id)?;
        let signing_key_version = self.resolve_signing_key_version(signing_key_version)?;
        let conversation_id =
            crate::pipeline::canonical_conversation_id(conversation_id, &sender_id).into_owned();
        let signing_key = self.get_signing_private_key()?;
        Ok(ActionCtx {
            sender_id,
            signing_key_version,
            conversation_id,
            signing_key,
        })
    }

    fn prepare_metadata_change(
        &self,
        change: MetadataChange<'_>,
        field: GroupMetadata,
    ) -> Result<PreparedGroupMetadataChange, SdkError> {
        let ctx = self.action_ctx(
            change.conversation_id,
            change.sender_id,
            change.signing_key_version,
        )?;
        let value = require_text(change.param, change.value)?;
        let (key, key_version) = self.resolve_conversation_key(
            change.conversation_key,
            change.conversation_key_version,
            &ctx.conversation_id,
            &ctx.sender_id,
        )?;
        crate::pipeline::validate_key_version("conversation_key_version", &key_version)?;
        let (encrypted_value, signature) = sign_metadata(&ctx, field, value, &key, &key_version)?;
        Ok(PreparedGroupMetadataChange {
            encrypted_value,
            conversation_key_version: key_version,
            action_signatures: vec![signature],
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_id_list(
        &self,
        conversation_id: &str,
        sender_id: Option<&str>,
        signing_key_version: Option<&str>,
        field: &str,
        user_ids: &[String],
        event_name: &str,
        encode: impl FnOnce(&[String]) -> Result<String, SdkError>,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(conversation_id, sender_id, signing_key_version)?;
        require_user_ids(field, user_ids)?;
        let refs: Vec<&str> = user_ids.iter().map(String::as_str).collect();
        let signature = sign_named(
            &ctx,
            event_name,
            &refs,
            CURRENT_SIGNATURE_VERSION,
            encode(user_ids)?,
        )?;
        Ok(one_action(signature))
    }
}

fn one_action(signature: ActionSignature) -> PreparedAction {
    PreparedAction {
        action_signatures: vec![signature],
    }
}

fn require_text<'a>(field: &str, value: &'a str) -> Result<&'a str, SdkError> {
    if value.is_empty() {
        Err(SdkError::InvalidInput(format!(
            "{field} is empty: pass the value this action signs"
        )))
    } else {
        Ok(value)
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

fn require_user_ids(field: &str, user_ids: &[String]) -> Result<(), SdkError> {
    if user_ids.is_empty() {
        return Err(SdkError::InvalidInput(format!(
            "{field} is empty: pass at least one user id"
        )));
    }
    crate::pipeline::validate_user_ids(field, user_ids)
}

fn nullable_str(value: Option<&str>) -> String {
    value
        .map(str::to_string)
        .unwrap_or_else(|| "null".to_string())
}

fn nullable_i64(value: Option<i64>) -> String {
    value
        .map(|n| n.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Encrypt `value` under `key` and sign it as a `field` change bound to
/// `key_version`. Returns the base64 ciphertext and the signature.
fn sign_metadata(
    ctx: &ActionCtx,
    field: GroupMetadata,
    value: &str,
    key: &XChatConversationKey,
    key_version: &str,
) -> Result<(String, ActionSignature), SdkError> {
    let encrypted = base64_encode(&crate::crypto::encryption::encrypt_message(
        key,
        value.as_bytes(),
    )?);
    let signature = sign_named(
        ctx,
        field.event_name(),
        &[key_version, &encrypted],
        CURRENT_SIGNATURE_VERSION,
        field.detail(&encrypted, key_version)?,
    )?;
    Ok((encrypted, signature))
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

fn sign_named(
    ctx: &ActionCtx,
    event_name: &str,
    extras: &[&str],
    signature_version: i32,
    detail: String,
) -> Result<ActionSignature, SdkError> {
    let message_id = ChatCore::generate_message_id();
    let mut components = Vec::with_capacity(4 + extras.len());
    components.push(event_name);
    components.push(message_id.as_str());
    components.push(ctx.sender_id.as_str());
    components.push(ctx.conversation_id.as_str());
    components.extend_from_slice(extras);
    let mut signature = sign_action(
        &ctx.signing_key,
        &ctx.signing_key_version,
        &message_id,
        signature_version,
        &components,
    )?;
    signature.encoded_message_event_detail = detail;
    Ok(signature)
}

fn group_detail(change: GroupChange) -> Result<String, SdkError> {
    encode_detail(MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
        group_change: Some(change),
        for_key_rotation: Some(false),
    }))
}

fn metadata_detail(change: ConversationMetadataChange) -> Result<String, SdkError> {
    encode_detail(MessageEventDetail::ConversationMetadataChangeEvent(
        ConversationMetadataChangeEvent {
            conversation_metadata_change: Some(change),
        },
    ))
}

fn screen_capture_detail(change: crate::types::ScreenCaptureChange) -> ConversationMetadataChange {
    use crate::types::ScreenCaptureChange as Change;
    match change {
        Change::BlockingEnabled => {
            ConversationMetadataChange::EnableScreenCaptureBlocking(EnableScreenCaptureBlocking {
                placeholder: None,
            })
        }
        Change::BlockingDisabled => {
            ConversationMetadataChange::DisableScreenCaptureBlocking(DisableScreenCaptureBlocking {
                placeholder: None,
            })
        }
        Change::DetectionEnabled => {
            ConversationMetadataChange::EnableScreenCaptureDetection(EnableScreenCaptureDetection {
                placeholder: None,
            })
        }
        Change::DetectionDisabled => ConversationMetadataChange::DisableScreenCaptureDetection(
            DisableScreenCaptureDetection { placeholder: None },
        ),
    }
}

fn encode_detail(detail: MessageEventDetail) -> Result<String, SdkError> {
    Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::build_event_signature_payload;
    use crate::crypto::key_factory::KeyFactory;
    use crate::params::{ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams};
    use crate::protocol::safe_reader::BoundedProtocol;
    use crate::protocol::serialization::base64_decode;
    use crate::types::{
        Event, GroupChange as Change, PublicKeyInput, ScreenCaptureChange, SigningKeyEntry,
    };
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use std::collections::HashMap;
    use std::io::Cursor;
    use thrift::protocol::{TBinaryInputProtocol, TSerializable};

    fn ready_core() -> ChatCore {
        ready_core_and_signing_keys().0
    }

    /// An unlocked core and the signing key that verifies what it signs as
    /// [`identity`].
    fn ready_core_and_signing_keys() -> (ChatCore, Vec<SigningKeyEntry>) {
        let core = ChatCore::new();
        let registration = core.generate_keypairs().unwrap().public_key;
        let (sender, version) = identity();
        let signing_keys = vec![SigningKeyEntry::new(
            sender,
            version,
            registration.signing_public_key,
            registration.public_key,
            registration.identity_public_key_signature,
        )];
        (core, signing_keys)
    }

    fn identity() -> (String, String) {
        ("910004".to_string(), "1".to_string())
    }

    fn decode_detail(b64: &str) -> MessageEventDetail {
        let bytes = base64_decode(b64).unwrap();
        let mut cursor = Cursor::new(bytes);
        let mut raw = TBinaryInputProtocol::new(&mut cursor, true);
        let mut proto = BoundedProtocol::new(&mut raw);
        MessageEventDetail::read_from_in_protocol(&mut proto).unwrap()
    }

    /// The event recipients receive for a signed action.
    fn signed_event(
        signature: &ActionSignature,
        sender_id: &str,
        conversation_id: &str,
    ) -> crate::thrift::event::MessageEvent {
        let signed = &signature.message_event_signature;
        let event_sig = crate::thrift::event::MessageEventSignature::new(
            Some(signed.signature.clone()),
            Some(signed.public_key_version.clone()),
            Some(signed.signature_version.clone()),
            None::<String>,
            None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
        );
        crate::thrift::event::MessageEvent::new(
            Some("seq-1".to_string()),
            Some(signature.message_id.clone()),
            Some(sender_id.to_string()),
            Some(conversation_id.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(decode_detail(&signature.encoded_message_event_detail)),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(event_sig),
            None::<String>,
            None::<bool>,
            None,
        )
    }

    /// [`signed_event`] as the base64 a webhook delivers.
    fn signed_event_b64(
        signature: &ActionSignature,
        sender_id: &str,
        conversation_id: &str,
    ) -> String {
        base64_encode(
            &crate::pipeline::serialize_thrift(&signed_event(
                signature,
                sender_id,
                conversation_id,
            ))
            .unwrap(),
        )
    }

    fn decrypted_change(event: Event) -> Change {
        match event {
            Event::GroupChange(change) => {
                assert!(change.verified, "the group change must verify");
                change.change
            }
            other => panic!("expected a group change, got {other:?}"),
        }
    }

    fn assert_round_trip(
        core: &ChatCore,
        signature: &ActionSignature,
        sender_id: &str,
        conversation_id: &str,
        plaintext_ckey_b64: Option<&str>,
    ) {
        let event = signed_event(signature, sender_id, conversation_id);
        let detail = event.detail.clone().unwrap();
        let signed = &signature.message_event_signature;
        let reconstructed = build_event_signature_payload(&event, &detail, plaintext_ckey_b64)
            .expect("verifier could not reconstruct the signed payload");
        if !signature.signature_payload.is_empty() {
            assert_eq!(
                reconstructed.as_slice(),
                signature.signature_payload.as_bytes(),
                "signer payload and verifier reconstruction diverge"
            );
        }
        let signing_pubkey = core.get_public_keys().unwrap().signing;
        let sig_bytes = base64_decode(&signed.signature).unwrap();
        assert!(
            core.verify(&signing_pubkey, &sig_bytes, &reconstructed)
                .unwrap(),
            "signature did not verify against the reconstructed payload"
        );
    }

    fn assert_actions(
        core: &ChatCore,
        signatures: &[ActionSignature],
        sender_id: &str,
        conversation_id: &str,
        plaintext_ckey_b64: Option<&str>,
    ) {
        for signature in signatures {
            assert_round_trip(
                core,
                signature,
                sender_id,
                conversation_id,
                plaintext_ckey_b64,
            );
        }
    }

    fn remaining_keys(core: &ChatCore, user_id: &str) -> Vec<PublicKeyInput> {
        vec![PublicKeyInput::new(
            user_id,
            core.get_public_keys().unwrap().identity,
            "1",
        )]
    }

    #[test]
    fn member_remove_signs_the_new_key_then_the_key_change() {
        let core = ready_core();
        let (sender, version) = identity();
        let params = GroupMembersRemoveParams::new(
            remaining_keys(&core, &sender),
            "222-111",
            vec!["910007".into()],
        )
        .with_identity(&sender, &version);
        let prepared = core
            .prepare_group_members_remove_with_version(&params, "42")
            .unwrap();
        assert_eq!(prepared.conversation_id, "111:222");
        assert_eq!(prepared.conversation_key_version, "42");
        assert!(prepared.conversation_key.is_some());
        assert_eq!(prepared.conversation_participant_keys.len(), 1);
        assert_eq!(prepared.action_signatures.len(), 2);
        let removal = &prepared.action_signatures[0];
        assert_eq!(
            removal.message_event_signature.signature_version,
            MEMBER_REMOVE_SIGNATURE_VERSION.to_string()
        );
        assert!(removal
            .signature_payload
            .contains(",910007,42,signature_version=11"));
        assert!(prepared.action_signatures[1].signature_payload.is_empty());
        assert_eq!(
            prepared.action_signatures[1]
                .message_event_signature
                .signature_version,
            CURRENT_SIGNATURE_VERSION.to_string()
        );
        let ckey_b64 =
            STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
        assert_actions(
            &core,
            &prepared.action_signatures,
            &sender,
            "111:222",
            Some(&ckey_b64),
        );
    }

    #[test]
    fn member_remove_rotates_with_the_clock_version() {
        let core = ready_core();
        let (sender, version) = identity();
        let prepared = core
            .prepare_group_members_remove(
                &GroupMembersRemoveParams::new(
                    remaining_keys(&core, &sender),
                    "g100",
                    vec!["910007".into()],
                )
                .with_identity(&sender, &version),
            )
            .unwrap();
        let key_version = &prepared.conversation_key_version;
        assert!(key_version.parse::<u64>().unwrap() > 0, "{key_version}");
        assert!(prepared.action_signatures[0]
            .signature_payload
            .ends_with(&format!(",910007,{key_version},signature_version=11")));
        assert_eq!(prepared.action_signatures.len(), 2);
    }

    #[test]
    fn member_remove_rejects_a_removed_member_in_the_new_key() {
        let core = ready_core();
        let (sender, version) = identity();
        let params = GroupMembersRemoveParams::new(
            remaining_keys(&core, "910007"),
            "g100",
            vec!["910007".into()],
        )
        .with_identity(&sender, &version);
        let err = core
            .prepare_group_members_remove_with_version(&params, "42")
            .unwrap_err();
        assert!(err.to_string().contains("remaining members"), "got: {err}");
    }

    #[test]
    fn member_remove_requires_the_remaining_members_keys() {
        let core = ready_core();
        let (sender, version) = identity();
        let err = core
            .prepare_group_members_remove(
                &GroupMembersRemoveParams::new(vec![], "g100", vec!["910007".into()])
                    .with_identity(&sender, &version),
            )
            .unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)), "got: {err:?}");
        assert_eq!(
            err.to_string(),
            "public_keys is empty: pass the public keys of the remaining members"
        );
    }

    #[test]
    fn leave_appends_a_conversation_delete_and_optional_admin_add() {
        let core = ready_core();
        let (sender, version) = identity();
        let params = GroupLeaveParams::new("g100")
            .with_identity(&sender, &version)
            .with_conversation_key_version("7")
            .with_promote_admin_id("910008");
        let prepared = core.prepare_group_leave(&params).unwrap();
        assert_eq!(prepared.action_signatures.len(), 3);
        assert!(prepared.action_signatures[0]
            .signature_payload
            .starts_with("GroupChangeEvent.GroupMemberRemoveChange,"));
        assert!(prepared.action_signatures[0]
            .signature_payload
            .contains(&format!(",{sender},g100,{sender},7,signature_version=11")));
        assert!(prepared.action_signatures[1]
            .signature_payload
            .ends_with(",910008"));
        assert_eq!(
            prepared.action_signatures[1]
                .message_event_signature
                .signature_version,
            "7"
        );
        let delete = &prepared.action_signatures[2];
        assert_eq!(
            delete.signature_payload,
            format!(
                "ConversationDeleteEvent,{},{sender},g100",
                delete.message_id
            )
        );
        assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);

        let plain = core
            .prepare_group_leave(&GroupLeaveParams::new("g100").with_identity(&sender, &version))
            .unwrap();
        assert_eq!(plain.action_signatures.len(), 2);
        assert!(plain.action_signatures[0]
            .signature_payload
            .ends_with(",null,signature_version=11"));
    }

    #[test]
    fn group_metadata_actions_round_trip_through_the_verifier() {
        let core = ready_core();
        let (sender, version) = identity();
        let cases: Vec<PreparedAction> = vec![
            core.prepare_group_admins_add(
                &GroupAdminsAddParams::new("g100", vec!["910008".into(), "910009".into()])
                    .with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_group_admins_remove(
                &GroupAdminsRemoveParams::new("g100", vec!["910008".into()])
                    .with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_group_join_reject(
                &GroupJoinRejectParams::new("g100", vec!["910010".into()])
                    .with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_message_ttl_change(
                &MessageTtlChangeParams::new("g100", 86_400_000).with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_message_ttl_remove(
                &MessageTtlRemoveParams::new("g100").with_identity(&sender, &version),
            )
            .unwrap(),
        ];
        let expected_prefixes = [
            "GroupChangeEvent.GroupAdminAddChange,",
            "GroupChangeEvent.GroupAdminRemoveChange,",
            "GroupChangeEvent.GroupJoinReject,",
            "ConversationMetadataChangeEvent.MessageDurationChange,",
            "ConversationMetadataChangeEvent.MessageDurationRemove,",
        ];
        for (prepared, prefix) in cases.iter().zip(expected_prefixes) {
            assert_eq!(prepared.action_signatures.len(), 1);
            let payload = &prepared.action_signatures[0].signature_payload;
            assert!(payload.starts_with(prefix), "{payload}");
            assert_eq!(
                prepared.action_signatures[0]
                    .message_event_signature
                    .signature_version,
                "7"
            );
            assert!(!payload.contains("signature_version="));
            assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);
        }
        let ttl = &cases[3].action_signatures[0].signature_payload;
        assert!(ttl.ends_with(",86400000"), "{ttl}");
    }

    #[test]
    fn metadata_changes_sign_ciphertext_that_decrypts_on_receive() {
        let (core, signing_keys) = ready_core_and_signing_keys();
        let (sender, version) = identity();
        let key = KeyFactory::generate_conversation_key().unwrap();
        let keys = HashMap::from([("7".to_string(), key.clone())]);
        let title = core
            .prepare_group_title_change(
                &GroupTitleChangeParams::new("g100", "Board: layoffs, Q3")
                    .with_identity(&sender, &version)
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        let avatar = core
            .prepare_group_avatar_change(
                &GroupAvatarChangeParams::new("g100", "https://img/a.png")
                    .with_identity(&sender, &version)
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        let description = core
            .prepare_group_description_change(
                &GroupDescriptionChangeParams::new("g100", "Rules: be kind")
                    .with_identity(&sender, &version)
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        let cases = [
            (
                title,
                "GroupChangeEvent.GroupTitleChange,",
                "Board: layoffs, Q3",
            ),
            (
                avatar,
                "GroupChangeEvent.GroupAvatarUrlChange,",
                "https://img/a.png",
            ),
            (
                description,
                "GroupChangeEvent.GroupDescriptionChange,",
                "Rules: be kind",
            ),
        ];
        for (prepared, prefix, plaintext) in cases {
            assert_eq!(prepared.conversation_key_version, "7");
            assert_eq!(prepared.action_signatures.len(), 1);
            let signature = &prepared.action_signatures[0];
            let payload = &signature.signature_payload;
            assert!(payload.starts_with(prefix), "{payload}");
            assert!(
                payload.ends_with(&format!(",7,{}", prepared.encrypted_value)),
                "{payload}"
            );
            assert!(!payload.contains(plaintext), "{payload}");
            assert_eq!(signature.message_event_signature.signature_version, "7");
            let detail = base64_decode(&signature.encoded_message_event_detail).unwrap();
            assert!(!String::from_utf8_lossy(&detail).contains(plaintext));
            assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);

            let change = decrypted_change(
                core.decrypt_event(
                    DecryptEventParams::new(
                        signed_event_b64(signature, &sender, "g100"),
                        keys.clone(),
                    )
                    .with_signing_keys(signing_keys.clone()),
                )
                .unwrap(),
            );
            let decrypted = match change {
                Change::TitleChanged { new_title } => new_title,
                Change::AvatarChanged { new_avatar_url } => new_avatar_url,
                Change::DescriptionChanged { new_description } => new_description,
                other => panic!("expected a metadata change, got {other:?}"),
            };
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn metadata_change_resolves_the_cached_key_like_encrypt_message() {
        let (core, signing_keys) = ready_core_and_signing_keys();
        let (sender, version) = identity();
        let params = GroupTitleChangeParams::new("g100", "Cached").with_identity(&sender, &version);
        let err = core.prepare_group_title_change(&params).unwrap_err();
        assert!(matches!(err, SdkError::InvalidState(_)), "got: {err:?}");
        assert!(err
            .to_string()
            .contains("no cached conversation key for 'g100'"));

        core.set_cache_keys(true);
        let mut key_change = ConversationKeyChangeParams::new(remaining_keys(&core, &sender))
            .with_identity(&sender, &version);
        key_change.conversation_id = Some("g100".into());
        let rotated = core
            .prepare_conversation_key_change_with_version(&key_change, "42")
            .unwrap();
        let batch = core.decrypt_events(
            DecryptEventsParams::new(vec![signed_event_b64(
                &rotated.action_signatures[0],
                &sender,
                "g100",
            )])
            .with_signing_keys(signing_keys.clone()),
        );
        assert!(batch.errors.is_empty(), "{:?}", batch.errors);

        let title = core.prepare_group_title_change(&params).unwrap();
        assert_eq!(title.conversation_key_version, "42");
        let change = decrypted_change(
            core.decrypt_event(
                DecryptEventParams::new(
                    signed_event_b64(&title.action_signatures[0], &sender, "g100"),
                    HashMap::new(),
                )
                .with_signing_keys(signing_keys),
            )
            .unwrap(),
        );
        assert!(matches!(change, Change::TitleChanged { ref new_title } if new_title == "Cached"));
    }

    #[test]
    fn metadata_change_without_its_key_fails_on_receive() {
        let (core, signing_keys) = ready_core_and_signing_keys();
        let (sender, version) = identity();
        let key = KeyFactory::generate_conversation_key().unwrap();
        let description = core
            .prepare_group_description_change(
                &GroupDescriptionChangeParams::new("g100", "Rules")
                    .with_identity(&sender, &version)
                    .with_conversation_key(key.to_bytes(), "7"),
            )
            .unwrap();
        let err = core
            .decrypt_event(
                DecryptEventParams::new(
                    signed_event_b64(&description.action_signatures[0], &sender, "g100"),
                    HashMap::new(),
                )
                .with_signing_keys(signing_keys),
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Group description encrypted with key version '7' but no matching key"),
            "got: {err}"
        );
    }

    #[test]
    fn member_remove_reencrypts_the_metadata_under_the_new_key() {
        let (core, signing_keys) = ready_core_and_signing_keys();
        let (sender, version) = identity();
        let params = GroupMembersRemoveParams::new(
            remaining_keys(&core, &sender),
            "g100",
            vec!["910007".into()],
        )
        .with_identity(&sender, &version)
        .with_title("Board")
        .with_avatar_url("")
        .with_description("Rules: be kind");
        let prepared = core
            .prepare_group_members_remove_with_version(&params, "42")
            .unwrap();
        let payloads: Vec<&str> = prepared
            .action_signatures
            .iter()
            .map(|signature| signature.signature_payload.as_str())
            .collect();
        assert_eq!(payloads.len(), 4, "{payloads:?}");
        assert!(payloads[0].starts_with("GroupChangeEvent.GroupMemberRemoveChange,"));
        assert!(payloads[1].starts_with("GroupChangeEvent.GroupTitleChange,"));
        assert!(payloads[2].starts_with("GroupChangeEvent.GroupDescriptionChange,"));
        assert!(
            payloads[3].is_empty(),
            "the key change withholds its payload"
        );
        assert!(payloads[1].contains(",42,"), "{}", payloads[1]);

        let keys = HashMap::from([("42".to_string(), prepared.conversation_key.clone().unwrap())]);
        let decrypt = |index: usize| {
            decrypted_change(
                core.decrypt_event(
                    DecryptEventParams::new(
                        signed_event_b64(&prepared.action_signatures[index], &sender, "g100"),
                        keys.clone(),
                    )
                    .with_signing_keys(signing_keys.clone()),
                )
                .unwrap(),
            )
        };
        assert!(
            matches!(decrypt(1), Change::TitleChanged { ref new_title } if new_title == "Board")
        );
        assert!(matches!(
            decrypt(2),
            Change::DescriptionChanged { ref new_description } if new_description == "Rules: be kind"
        ));
        let ckey_b64 =
            STANDARD_NO_PAD.encode(prepared.conversation_key.as_ref().unwrap().encoded());
        assert_actions(
            &core,
            &prepared.action_signatures,
            &sender,
            "g100",
            Some(&ckey_b64),
        );
    }

    #[test]
    fn invite_and_join_sign_null_sentinels_and_sender_defaults() {
        let core = ready_core();
        let (sender, version) = identity();
        let mut enable = GroupInviteEnableParams::new("g100", "https://x.com/i/invite/abc")
            .with_identity(&sender, &version);
        enable.expires_at_msec = Some(-1);
        enable.affiliate_id = Some(String::new());
        let enabled = core.prepare_group_invite_enable(&enable).unwrap();
        assert!(enabled.action_signatures[0]
            .signature_payload
            .ends_with(",https://x.com/i/invite/abc,null,null"));
        assert_actions(&core, &enabled.action_signatures, &sender, "g100", None);

        let mut timed = GroupInviteEnableParams::new("g100", "https://x.com/i/invite/abc")
            .with_identity(&sender, &version);
        timed.expires_at_msec = Some(1_700_000_000_000);
        timed.affiliate_id = Some("aff-1".into());
        let timed = core.prepare_group_invite_enable(&timed).unwrap();
        assert!(timed.action_signatures[0]
            .signature_payload
            .ends_with(",https://x.com/i/invite/abc,1700000000000,aff-1"));

        let disabled = core
            .prepare_group_invite_disable(
                &GroupInviteDisableParams::new("g100").with_identity(&sender, &version),
            )
            .unwrap();
        assert!(disabled.action_signatures[0]
            .signature_payload
            .ends_with(&format!(",{sender}")));
        assert_actions(&core, &disabled.action_signatures, &sender, "g100", None);

        let request = core
            .prepare_group_join_request(
                &GroupJoinRequestParams::new("g100").with_identity(&sender, &version),
            )
            .unwrap();
        assert!(request.action_signatures[0]
            .signature_payload
            .starts_with("GroupChangeEvent.GroupJoinRequest,"));
        assert!(request.action_signatures[0]
            .signature_payload
            .ends_with(&format!(",{sender}")));
        assert_actions(&core, &request.action_signatures, &sender, "g100", None);
    }

    #[test]
    fn screen_capture_signs_each_verifier_event_name() {
        let core = ready_core();
        let (sender, version) = identity();
        let expected = [
            (
                ScreenCaptureChange::BlockingEnabled,
                "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,",
            ),
            (
                ScreenCaptureChange::BlockingDisabled,
                "ConversationMetadataChangeEvent.DisableScreenCaptureBlocking,",
            ),
            (
                ScreenCaptureChange::DetectionEnabled,
                "ConversationMetadataChangeEvent.EnableScreenCaptureDetection,",
            ),
            (
                ScreenCaptureChange::DetectionDisabled,
                "ConversationMetadataChangeEvent.DisableScreenCaptureDetection,",
            ),
        ];
        for (change, prefix) in expected {
            let prepared = core
                .prepare_screen_capture(
                    &ScreenCaptureParams::new("g100", change).with_identity(&sender, &version),
                )
                .unwrap();
            let payload = &prepared.action_signatures[0].signature_payload;
            let message_id = &prepared.action_signatures[0].message_id;
            assert_eq!(payload, &format!("{prefix}{message_id},{sender},g100"));
            assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);
        }
    }

    #[test]
    fn invalid_group_action_inputs_name_the_value() {
        let core = ready_core();
        let (sender, version) = identity();
        let err = core
            .prepare_group_members_remove(
                &GroupMembersRemoveParams::new(remaining_keys(&core, &sender), "g100", vec![])
                    .with_identity(&sender, &version),
            )
            .unwrap_err();
        assert!(err.to_string().contains("user_ids"), "got: {err}");

        let key = KeyFactory::generate_conversation_key().unwrap();
        let err = core
            .prepare_group_title_change(
                &GroupTitleChangeParams::new("g100", "")
                    .with_identity(&sender, &version)
                    .with_conversation_key(key.to_bytes(), "4"),
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "new_title is empty: pass the value this action signs"
        );

        let mut half_key = GroupAvatarChangeParams::new("g100", "https://img/a.png")
            .with_identity(&sender, &version);
        half_key.conversation_key = Some(key.to_bytes());
        let err = core.prepare_group_avatar_change(&half_key).unwrap_err();
        assert!(
            err.to_string().contains("must be passed together"),
            "got: {err}"
        );

        let err = ScreenCaptureChange::parse("nope").unwrap_err();
        assert_eq!(err.to_string(), "Invalid screen capture change: 'nope'");
    }
}
