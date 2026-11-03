//! The group title and description, encrypted under the conversation key
//! before they are signed, and the avatar.

use crate::core::ChatCore;
use crate::error::SdkError;
use crate::params::{
    GroupAvatarChangeParams, GroupDescriptionChangeParams, GroupTitleChangeParams,
};
use crate::thrift::event::{GroupAvatarUrlChange, GroupChange};
use crate::types::{PreparedAction, PreparedGroupMetadataChange};

use super::{group_detail, one_action, require_text, sign_change, sign_metadata, GroupMetadata};

/// The inputs of a title or description change.
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

impl ChatCore {
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

    /// Sign a group avatar change, under
    /// `GroupChangeEvent.GroupAvatarUrlChange`.
    ///
    /// The avatar URL is not encrypted: it is the media URL of the image,
    /// which the app encrypts under the conversation key and uploads to the
    /// group's media first. The signature covers the version of the key the
    /// image is encrypted under and the URL as is.
    pub fn prepare_group_avatar_change(
        &self,
        params: &GroupAvatarChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let avatar_url = require_text("new_avatar_url", &params.new_avatar_url)?;
        let key_version = params.conversation_key_version.as_str();
        crate::pipeline::validate_key_version("conversation_key_version", key_version)?;
        let signature = sign_change(
            &ctx,
            group_detail(GroupChange::GroupAvatarChange(GroupAvatarUrlChange {
                custom_avatar_url: Some(avatar_url.to_string()),
                conversation_key_version: Some(key_version.to_string()),
            })),
        )?;
        Ok(one_action(signature))
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
        let (encrypted_value, signature) =
            sign_metadata(&ctx, field, value, &key, &key_version, false)?;
        Ok(PreparedGroupMetadataChange {
            encrypted_value,
            conversation_key_version: key_version,
            action_signatures: vec![signature],
        })
    }
}
