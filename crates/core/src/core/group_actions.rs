//! Signed group and conversation-metadata actions.
//!
//! Each prepare builds one request's `action_signatures`. A member remove
//! also rotates the conversation key for the members who stay, reusing the
//! key-change signer, and returns that key. The title and description
//! changes encrypt their plaintext under the conversation key before
//! signing it; the avatar change signs the avatar's media URL as is. The
//! other prepares do not rotate.

use crate::crypto::keys::XChatConversationKey;
use crate::error::SdkError;
use crate::protocol::serialization::base64_encode;
use crate::signatures::{sign_action, ActionSignature, CURRENT_SIGNATURE_VERSION};
use crate::thrift::event::{
    GroupChange, GroupChangeEvent, GroupDescriptionChange, GroupTitleChange, MessageEventDetail,
};
use crate::types::PreparedAction;

use super::ChatCore;

struct ActionCtx {
    sender_id: String,
    signing_key_version: String,
    conversation_id: String,
    signing_key: crate::crypto::keys::XChatPrivateKey,
}

/// A group field the SDK encrypts under the conversation key before signing.
#[derive(Clone, Copy)]
enum GroupMetadata {
    Title,
    Description,
}

impl GroupMetadata {
    fn event_name(self) -> &'static str {
        match self {
            Self::Title => "GroupChangeEvent.GroupTitleChange",
            Self::Description => "GroupChangeEvent.GroupDescriptionChange",
        }
    }

    /// The change event for `encrypted` under `key_version`. A change that
    /// only re-encrypts the value for a key rotation is marked
    /// `for_key_rotation`, so X clients don't show it as a change and the
    /// SDK's decrypt drops it.
    fn detail(
        self,
        encrypted: &str,
        key_version: &str,
        for_key_rotation: bool,
    ) -> Result<String, SdkError> {
        let encrypted = Some(encrypted.to_string());
        let conversation_key_version = Some(key_version.to_string());
        group_event_detail(
            match self {
                Self::Title => GroupChange::GroupTitleChange(GroupTitleChange {
                    custom_title: encrypted,
                    conversation_key_version,
                }),
                Self::Description => GroupChange::GroupDescriptionChange(GroupDescriptionChange {
                    custom_description: encrypted,
                    conversation_key_version,
                }),
            },
            for_key_rotation,
        )
    }
}

impl ChatCore {
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

/// Encrypt a group title or description under `key`: the base64
/// XSalsa20-Poly1305 ciphertext a group event carries and its signature
/// covers.
pub(super) fn encrypt_group_metadata(
    key: &XChatConversationKey,
    value: &str,
) -> Result<String, SdkError> {
    Ok(base64_encode(&crate::crypto::encryption::encrypt_message(
        key,
        value.as_bytes(),
    )?))
}

/// Encrypt `value` under `key` and sign it as a `field` change bound to
/// `key_version`. Returns the base64 ciphertext and the signature.
fn sign_metadata(
    ctx: &ActionCtx,
    field: GroupMetadata,
    value: &str,
    key: &XChatConversationKey,
    key_version: &str,
    for_key_rotation: bool,
) -> Result<(String, ActionSignature), SdkError> {
    let encrypted = encrypt_group_metadata(key, value)?;
    let signature = sign_named(
        ctx,
        field.event_name(),
        &[key_version, &encrypted],
        CURRENT_SIGNATURE_VERSION,
        field.detail(&encrypted, key_version, for_key_rotation)?,
    )?;
    Ok((encrypted, signature))
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
    group_event_detail(change, false)
}

fn group_event_detail(change: GroupChange, for_key_rotation: bool) -> Result<String, SdkError> {
    encode_detail(MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
        group_change: Some(change),
        for_key_rotation: Some(for_key_rotation),
    }))
}

fn encode_detail(detail: MessageEventDetail) -> Result<String, SdkError> {
    Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
}

mod invites;
mod members;
mod metadata;
mod settings;

#[cfg(test)]
mod tests;
