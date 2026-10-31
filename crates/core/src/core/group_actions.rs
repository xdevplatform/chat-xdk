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
use crate::signatures::{sign_event, ActionSignature, CURRENT_SIGNATURE_VERSION};
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
    /// The send format this call's signatures follow, read once.
    send_version: crate::pipeline::SendVersion,
    /// The version this call's group and conversation actions sign at; a key
    /// change it carries signs at `ChatCore::key_change_signature_version`.
    signature_version: i32,
}

/// A group field the SDK encrypts under the conversation key before signing.
#[derive(Clone, Copy)]
enum GroupMetadata {
    Title,
    Description,
}

impl GroupMetadata {
    /// The change event for `encrypted` under `key_version`. A change that
    /// only re-encrypts the value for a key rotation is marked
    /// `for_key_rotation`, so recipients don't show it as a change; this
    /// SDK's decrypt drops it.
    fn detail(
        self,
        encrypted: &str,
        key_version: &str,
        for_key_rotation: bool,
    ) -> MessageEventDetail {
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
        let send_version = self.send_version();
        Ok(ActionCtx {
            sender_id,
            signing_key_version,
            conversation_id,
            signing_key,
            send_version,
            signature_version: super::signing::action_signature_version(
                send_version,
                CURRENT_SIGNATURE_VERSION,
            ),
        })
    }

    fn prepare_id_list(
        &self,
        conversation_id: &str,
        sender_id: Option<&str>,
        signing_key_version: Option<&str>,
        field: &str,
        user_ids: &[String],
        change: impl FnOnce(&[String]) -> GroupChange,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(conversation_id, sender_id, signing_key_version)?;
        require_user_ids(field, user_ids)?;
        let signature = sign_change(&ctx, group_detail(change(user_ids)))?;
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
    let signature = sign_change(ctx, field.detail(&encrypted, key_version, for_key_rotation))?;
    Ok((encrypted, signature))
}

/// Sign `detail` as a new action of `ctx`, at `ctx`'s signature version.
fn sign_change(ctx: &ActionCtx, detail: MessageEventDetail) -> Result<ActionSignature, SdkError> {
    sign_event(
        &ctx.signing_key,
        &ctx.signing_key_version,
        &ChatCore::generate_message_id(),
        &ctx.sender_id,
        &ctx.conversation_id,
        ctx.signature_version,
        detail,
        None,
    )
}

fn group_detail(change: GroupChange) -> MessageEventDetail {
    group_event_detail(change, false)
}

fn group_event_detail(change: GroupChange, for_key_rotation: bool) -> MessageEventDetail {
    MessageEventDetail::GroupChangeEvent(GroupChangeEvent {
        group_change: Some(change),
        for_key_rotation: Some(for_key_rotation),
    })
}

#[cfg(test)]
fn encode_detail(detail: MessageEventDetail) -> Result<String, SdkError> {
    Ok(base64_encode(&crate::pipeline::serialize_thrift(&detail)?))
}

mod invites;
mod members;
mod metadata;
mod settings;

#[cfg(test)]
mod tests;
