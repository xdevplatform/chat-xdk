//! Group invites and requests to join.

use crate::core::ChatCore;
use crate::error::SdkError;
use crate::params::{
    GroupInviteDisableParams, GroupInviteEnableParams, GroupJoinRejectParams,
    GroupJoinRequestParams,
};
use crate::signatures::CURRENT_SIGNATURE_VERSION;
use crate::thrift::event::{
    GroupChange, GroupInviteDisable, GroupInviteEnable, GroupJoinReject, GroupJoinRequest,
};
use crate::types::PreparedAction;

use super::{group_detail, nullable_str, one_action, require_text, sign_named};

impl ChatCore {
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
}

fn nullable_i64(value: Option<i64>) -> String {
    value
        .map(|n| n.to_string())
        .unwrap_or_else(|| "null".to_string())
}
