//! Signed group and conversation-metadata actions.
//!
//! Each prepare builds one request's `action_signatures`. A member remove
//! that is given the remaining members' public keys also rotates the
//! conversation key, reusing the key-change signer, and returns that key.
//! The other prepares sign a single event and do not rotate.

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
use crate::types::{PreparedAction, PreparedConversationChange};

use super::ChatCore;

struct ActionCtx {
    sender_id: String,
    signing_key_version: String,
    conversation_id: String,
    signing_key: crate::crypto::keys::XChatPrivateKey,
}

impl ChatCore {
    /// Sign a group member removal.
    ///
    /// Pass `public_keys` for the members who remain to rotate the
    /// conversation key in this call: the result is a
    /// [`PreparedConversationChange`] whose `action_signatures` are the
    /// removal (bound to the new key version) and then the key change.
    /// Without `public_keys` the same type comes back with no new key, empty
    /// participant keys, and only the removal signature. `conversation_key`
    /// is unset in that case, and `conversation_key_version` is the version
    /// bound into the removal, or empty when that field signs `null`.
    ///
    /// The removal is signed at signature version 11 so the key version is
    /// part of the payload. The key change is signed at the version every
    /// other key change uses.
    ///
    /// The result does not include a ratchet tree (`base64_encoded_key_rotation`)
    /// or a rewrapped pin-key bundle (`rotated_pmk_bundle`). It also does not
    /// re-encrypt a group title, avatar, or description; sign those with
    /// [`Self::prepare_group_title_change`], [`Self::prepare_group_avatar_change`],
    /// and [`Self::prepare_group_description_change`] under the new key and
    /// place them between the removal signature and the key-change signature.
    pub fn prepare_group_members_remove(
        &self,
        params: &GroupMembersRemoveParams,
    ) -> Result<PreparedConversationChange, SdkError> {
        let version = if rotates(params) {
            super::now_millis()
        } else {
            String::new()
        };
        self.prepare_group_members_remove_with_version(params, &version)
    }

    /// Like [`Self::prepare_group_members_remove`], using `conversation_key_version`
    /// as the new key version when the call rotates.
    ///
    /// The version is ignored when `public_keys` is absent. WASM calls this
    /// with a JavaScript timestamp so the core never reads the system clock.
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
        let bound = bound_key_version(&params.conversation_key_version)?;

        let Some(public_keys) = params
            .public_keys
            .as_deref()
            .filter(|keys| !keys.is_empty())
        else {
            let removal = sign_member_remove(&ctx, &params.user_ids, bound.as_deref())?;
            return Ok(PreparedConversationChange {
                conversation_id: ctx.conversation_id,
                conversation_key: None,
                conversation_key_version: bound.unwrap_or_default(),
                conversation_participant_keys: Vec::new(),
                action_signatures: vec![removal],
            });
        };

        crate::pipeline::validate_key_version(
            "conversation_key_version",
            conversation_key_version,
        )?;
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
        let removal = sign_member_remove(&ctx, &params.user_ids, Some(conversation_key_version))?;
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

        Ok(PreparedConversationChange {
            conversation_id: ctx.conversation_id,
            conversation_key: Some(ckey),
            conversation_key_version: conversation_key_version.to_string(),
            conversation_participant_keys: participant_keys,
            action_signatures: vec![removal, key_change],
        })
    }

    /// Sign leaving a group.
    ///
    /// Leave is a member removal of the sender and does not rotate the
    /// conversation key. The result's `action_signatures` are that removal,
    /// then a `ConversationDeleteEvent` with no further fields, then a
    /// `GroupAdminAddChange` when `promote_admin_id` is set.
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
        let mut signatures = vec![
            sign_member_remove(&ctx, &self_ids, bound.as_deref())?,
            sign_named(
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
            )?,
        ];
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
        Ok(PreparedAction {
            action_signatures: signatures,
        })
    }

    /// Sign a group title change. `custom_title` is the ciphertext the
    /// request sends.
    pub fn prepare_group_title_change(
        &self,
        params: &GroupTitleChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_text_change(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            &params.conversation_key_version,
            "custom_title",
            &params.custom_title,
            "GroupChangeEvent.GroupTitleChange",
            |title, version| {
                group_detail(GroupChange::GroupTitleChange(GroupTitleChange {
                    custom_title: Some(title.to_string()),
                    conversation_key_version: Some(version.to_string()),
                }))
            },
        )
    }

    /// Sign a group avatar change. `custom_avatar_url` is the value the
    /// request sends.
    pub fn prepare_group_avatar_change(
        &self,
        params: &GroupAvatarChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_text_change(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            &params.conversation_key_version,
            "custom_avatar_url",
            &params.custom_avatar_url,
            "GroupChangeEvent.GroupAvatarUrlChange",
            |avatar, version| {
                group_detail(GroupChange::GroupAvatarChange(GroupAvatarUrlChange {
                    custom_avatar_url: Some(avatar.to_string()),
                    conversation_key_version: Some(version.to_string()),
                }))
            },
        )
    }

    /// Sign a group description change. `custom_description` is the
    /// ciphertext the request sends.
    ///
    /// The signed fields are the key version and the description, under
    /// `GroupChangeEvent.GroupDescriptionChange`.
    pub fn prepare_group_description_change(
        &self,
        params: &GroupDescriptionChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        self.prepare_text_change(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
            &params.conversation_key_version,
            "custom_description",
            &params.custom_description,
            "GroupChangeEvent.GroupDescriptionChange",
            |description, version| {
                group_detail(GroupChange::GroupDescriptionChange(
                    GroupDescriptionChange {
                        custom_description: Some(description.to_string()),
                        conversation_key_version: Some(version.to_string()),
                    },
                ))
            },
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

    fn prepare_text_change(
        &self,
        conversation_id: &str,
        sender_id: Option<&str>,
        signing_key_version: Option<&str>,
        conversation_key_version: &str,
        field: &str,
        value: &str,
        event_name: &str,
        encode: impl FnOnce(&str, &str) -> Result<String, SdkError>,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(conversation_id, sender_id, signing_key_version)?;
        require_key_version(conversation_key_version)?;
        let value = require_text(field, value)?;
        let signature = sign_named(
            &ctx,
            event_name,
            &[conversation_key_version, value],
            CURRENT_SIGNATURE_VERSION,
            encode(value, conversation_key_version)?,
        )?;
        Ok(one_action(signature))
    }

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

fn rotates(params: &GroupMembersRemoveParams) -> bool {
    params
        .public_keys
        .as_ref()
        .is_some_and(|keys| !keys.is_empty())
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

fn require_key_version(version: &str) -> Result<(), SdkError> {
    if version.is_empty() {
        return Err(SdkError::InvalidInput(
            "conversation_key_version is empty: pass the group's current key version".into(),
        ));
    }
    crate::pipeline::validate_key_version("conversation_key_version", version)
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
    use crate::protocol::safe_reader::BoundedProtocol;
    use crate::protocol::serialization::base64_decode;
    use crate::types::{PublicKeyInput, ScreenCaptureChange};
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use std::io::Cursor;
    use thrift::protocol::{TBinaryInputProtocol, TSerializable};

    fn ready_core() -> ChatCore {
        let core = ChatCore::new();
        core.generate_keypairs().unwrap();
        core
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

    fn assert_round_trip(
        core: &ChatCore,
        signature: &ActionSignature,
        sender_id: &str,
        conversation_id: &str,
        plaintext_ckey_b64: Option<&str>,
    ) {
        let detail = decode_detail(&signature.encoded_message_event_detail);
        let signed = &signature.message_event_signature;
        let event_sig = crate::thrift::event::MessageEventSignature::new(
            Some(signed.signature.clone()),
            Some(signed.public_key_version.clone()),
            Some(signed.signature_version.clone()),
            None::<String>,
            None::<Vec<crate::thrift::event::MessageSigningKeyInfo>>,
        );
        let event = crate::thrift::event::MessageEvent::new(
            Some("seq-1".to_string()),
            Some(signature.message_id.clone()),
            Some(sender_id.to_string()),
            Some(conversation_id.to_string()),
            None::<String>,
            Some("1700000000000".to_string()),
            Some(detail.clone()),
            None::<crate::thrift::event::MessageEventRelaySource>,
            Some(event_sig),
            None::<String>,
            None::<bool>,
            None,
        );
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

    #[test]
    fn member_remove_without_rotation_signs_null_key_version_at_v11() {
        let core = ready_core();
        let (sender, version) = identity();
        let prepared = core
            .prepare_group_members_remove(
                &GroupMembersRemoveParams::new("g100", vec!["910007".into()])
                    .with_identity(&sender, &version),
            )
            .unwrap();
        assert!(prepared.conversation_key.is_none());
        assert!(prepared.conversation_participant_keys.is_empty());
        assert!(prepared.conversation_key_version.is_empty());
        assert_eq!(prepared.action_signatures.len(), 1);
        let removal = &prepared.action_signatures[0];
        assert_eq!(
            removal.message_event_signature.signature_version,
            MEMBER_REMOVE_SIGNATURE_VERSION.to_string()
        );
        assert!(removal
            .signature_payload
            .ends_with(",910007,null,signature_version=11"));
        assert!(removal.signature_payload.contains(",g100,"));
        assert_actions(&core, &prepared.action_signatures, &sender, "g100", None);
    }

    #[test]
    fn member_remove_with_rotation_signs_the_new_key_then_the_key_change() {
        let core = ready_core();
        let (sender, version) = identity();
        let pk = core.get_public_keys().unwrap();
        let mut params = GroupMembersRemoveParams::new("222-111", vec!["910007".into()])
            .with_identity(&sender, &version);
        params.public_keys = Some(vec![PublicKeyInput {
            user_id: sender.clone(),
            public_key: pk.identity,
            key_version: "1".into(),
        }]);
        params.conversation_key_version = Some("9".into());
        let prepared = core
            .prepare_group_members_remove_with_version(&params, "42")
            .unwrap();
        assert_eq!(prepared.conversation_id, "111:222");
        assert_eq!(prepared.conversation_key_version, "42");
        assert!(prepared.conversation_key.is_some());
        assert_eq!(prepared.conversation_participant_keys.len(), 1);
        assert_eq!(prepared.action_signatures.len(), 2);
        let removal = &prepared.action_signatures[0];
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
    fn member_remove_rejects_a_removed_member_in_the_new_key() {
        let core = ready_core();
        let (sender, version) = identity();
        let pk = core.get_public_keys().unwrap();
        let mut params = GroupMembersRemoveParams::new("g100", vec!["910007".into()])
            .with_identity(&sender, &version);
        params.public_keys = Some(vec![PublicKeyInput {
            user_id: "910007".into(),
            public_key: pk.identity,
            key_version: "1".into(),
        }]);
        let err = core
            .prepare_group_members_remove_with_version(&params, "42")
            .unwrap_err();
        assert!(err.to_string().contains("remaining members"), "got: {err}");
    }

    #[test]
    fn leave_appends_a_conversation_delete_and_optional_admin_add() {
        let core = ready_core();
        let (sender, version) = identity();
        let mut params = GroupLeaveParams::new("g100").with_identity(&sender, &version);
        params.conversation_key_version = Some("7".into());
        params.promote_admin_id = Some("910008".into());
        let prepared = core.prepare_group_leave(&params).unwrap();
        assert_eq!(prepared.action_signatures.len(), 3);
        assert!(prepared.action_signatures[0]
            .signature_payload
            .starts_with("GroupChangeEvent.GroupMemberRemoveChange,"));
        assert!(prepared.action_signatures[0]
            .signature_payload
            .contains(&format!(",{sender},g100,{sender},7,signature_version=11")));
        let delete = &prepared.action_signatures[1];
        assert_eq!(
            delete.signature_payload,
            format!(
                "ConversationDeleteEvent,{},{sender},g100",
                delete.message_id
            )
        );
        assert!(prepared.action_signatures[2]
            .signature_payload
            .ends_with(",910008"));
        assert_eq!(
            prepared.action_signatures[2]
                .message_event_signature
                .signature_version,
            "7"
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
            core.prepare_group_title_change(
                &GroupTitleChangeParams::new("g100", "4", "enc-title")
                    .with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_group_avatar_change(
                &GroupAvatarChangeParams::new("g100", "4", "https://img/a.png")
                    .with_identity(&sender, &version),
            )
            .unwrap(),
            core.prepare_group_description_change(
                &GroupDescriptionChangeParams::new("g100", "4", "enc-desc")
                    .with_identity(&sender, &version),
            )
            .unwrap(),
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
            "GroupChangeEvent.GroupTitleChange,",
            "GroupChangeEvent.GroupAvatarUrlChange,",
            "GroupChangeEvent.GroupDescriptionChange,",
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
        let title = &cases[0].action_signatures[0].signature_payload;
        assert!(title.ends_with(",4,enc-title"), "{title}");
        let description = &cases[2].action_signatures[0].signature_payload;
        assert!(description.ends_with(",4,enc-desc"), "{description}");
        let ttl = &cases[6].action_signatures[0].signature_payload;
        assert!(ttl.ends_with(",86400000"), "{ttl}");
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
                &GroupMembersRemoveParams::new("g100", vec![]).with_identity(&sender, &version),
            )
            .unwrap_err();
        assert!(err.to_string().contains("user_ids"), "got: {err}");

        let err = core
            .prepare_group_title_change(
                &GroupTitleChangeParams::new("g100", "4", "a,b").with_identity(&sender, &version),
            )
            .unwrap_err();
        assert!(err.to_string().contains("comma"), "got: {err}");

        let err = ScreenCaptureChange::parse("nope").unwrap_err();
        assert_eq!(err.to_string(), "Invalid screen capture change: 'nope'");
    }
}
