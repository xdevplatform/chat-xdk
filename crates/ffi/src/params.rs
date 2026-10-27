//! The params documents the calls take, one JSON document per call.

use super::*;

// FFI params mirrors — one JSON document per method, snake_case keys matching
// the core param structs. Consolidating every argument into a single JSON
// document keeps the C ABI stable: a future optional field is an additive
// JSON key, not a new C argument. An absent or null key deserializes to
// `None`; `conversation_key` crosses the boundary as base64. Identity
// (`sender_id`, `signing_key_version`) and key
// (`conversation_key`, `conversation_key_version`) fields are optional
// overrides resolved by core from the session identity and the opt-in key
// cache when unset; core also treats an empty string as unset, so no
// filtering happens here. Entities are `[start, end, "type"]` tuples;
// attachment objects use the wire-format keys of `AttachmentDescriptor` and
// are parsed strictly (a missing required media field is an error — see
// `parse_attachments`).

#[derive(serde::Deserialize)]
pub(crate) struct FfiEncryptMessageParams {
    pub(crate) conversation_id: String,
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
    pub(crate) entities: Option<Vec<(i32, i32, String)>>,
    pub(crate) attachments: Option<serde_json::Value>,
    pub(crate) quick_reply: Option<serde_json::Value>,
    pub(crate) should_notify: Option<bool>,
    pub(crate) ttl_msec: Option<i64>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiEncryptReplyParams {
    pub(crate) conversation_id: String,
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) reply_to_event: Option<String>,
    #[serde(default)]
    pub(crate) reply_to_edit_event: Option<String>,
    #[serde(default)]
    pub(crate) reply_to_ckces: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
    #[serde(default)]
    pub(crate) reply_to_sequence_id: Option<String>,
    pub(crate) reply_to_sender_id: Option<String>,
    pub(crate) reply_to_text: Option<String>,
    pub(crate) entities: Option<Vec<(i32, i32, String)>>,
    pub(crate) attachments: Option<serde_json::Value>,
    pub(crate) quick_reply: Option<serde_json::Value>,
    pub(crate) reply_to_entities: Option<Vec<(i32, i32, String)>>,
    pub(crate) reply_to_attachments: Option<serde_json::Value>,
    pub(crate) should_notify: Option<bool>,
    pub(crate) ttl_msec: Option<i64>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiEncryptReactionParams {
    pub(crate) emoji: String,
    #[serde(default)]
    pub(crate) target_event: Option<String>,
    #[serde(default)]
    pub(crate) conversation_id: Option<String>,
    #[serde(default)]
    pub(crate) target_message_sequence_id: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiEncryptEditParams {
    pub(crate) updated_text: String,
    #[serde(default)]
    pub(crate) target_event: Option<String>,
    #[serde(default)]
    pub(crate) entities: Option<Vec<(i32, i32, String)>>,
    #[serde(default)]
    pub(crate) conversation_id: Option<String>,
    #[serde(default)]
    pub(crate) target_message_sequence_id: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiMessageDeleteParams {
    pub(crate) conversation_id: String,
    pub(crate) sequence_ids: Vec<String>,
    pub(crate) delete_for_all: bool,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupMembersRemoveParams {
    pub(crate) public_keys: Vec<PublicKeyInput>,
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Vec<String>,
    #[serde(default)]
    pub(crate) title: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupLeaveParams {
    pub(crate) conversation_id: String,
    #[serde(default)]
    pub(crate) promote_admin_id: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupTitleChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_title: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupAvatarChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_avatar_url: String,
    pub(crate) conversation_key_version: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupDescriptionChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) new_description: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupAdminsAddParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Vec<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupAdminsRemoveParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Vec<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupInviteEnableParams {
    pub(crate) conversation_id: String,
    pub(crate) invite_url: String,
    #[serde(default)]
    pub(crate) expires_at_msec: Option<i64>,
    #[serde(default)]
    pub(crate) affiliate_id: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupInviteDisableParams {
    pub(crate) conversation_id: String,
    #[serde(default)]
    pub(crate) disabled_by: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupJoinRequestParams {
    pub(crate) conversation_id: String,
    #[serde(default)]
    pub(crate) requesting_user_id: Option<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupJoinRejectParams {
    pub(crate) conversation_id: String,
    pub(crate) user_ids: Vec<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiMessageTtlChangeParams {
    pub(crate) conversation_id: String,
    pub(crate) ttl_msec: i64,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiMessageTtlRemoveParams {
    pub(crate) conversation_id: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiScreenCaptureParams {
    pub(crate) conversation_id: String,
    pub(crate) change: String,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiMarkConversationReadParams {
    pub(crate) conversation_id: String,
    pub(crate) seen_until_sequence_id: String,
    #[serde(default)]
    pub(crate) seen_at_msec: Option<i64>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiConversationKeyChangeParams {
    pub(crate) public_keys: Vec<PublicKeyInput>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    pub(crate) conversation_id: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupMembersChangeParams {
    pub(crate) public_keys: Vec<PublicKeyInput>,
    pub(crate) conversation_id: String,
    pub(crate) new_member_ids: Vec<String>,
    pub(crate) current_member_ids: Vec<String>,
    pub(crate) current_admin_ids: Vec<String>,
    pub(crate) current_pending_member_ids: Vec<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    pub(crate) current_title: Option<String>,
    pub(crate) current_avatar_url: Option<String>,
    pub(crate) current_description: Option<String>,
    pub(crate) current_ttl_msec: Option<i64>,
    pub(crate) current_screen_capture_blocking_enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiGroupCreateParams {
    pub(crate) public_keys: Vec<PublicKeyInput>,
    pub(crate) conversation_id: String,
    pub(crate) member_ids: Vec<String>,
    pub(crate) admin_ids: Vec<String>,
    #[serde(default)]
    pub(crate) sender_id: Option<String>,
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) ttl_msec: Option<i64>,
}

// The receive and file params carry `conversation_keys` as
// `{"version": "base64 raw 32-byte key"}` and byte fields as base64.

#[derive(serde::Deserialize)]
pub(crate) struct FfiSetIdentityParams {
    pub(crate) user_id: String,
    pub(crate) signing_key_version: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiImportKeysParams {
    #[serde(default)]
    pub(crate) signing_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiDecryptEventParams {
    pub(crate) event_b64: String,
    #[serde(default)]
    pub(crate) conversation_keys: HashMap<String, String>,
    #[serde(default)]
    pub(crate) signing_keys: Option<Vec<SigningKeyEntry>>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiDecryptEventsParams {
    pub(crate) events: Vec<String>,
    #[serde(default)]
    pub(crate) signing_keys: Option<Vec<SigningKeyEntry>>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiEncryptFileParams {
    pub(crate) file: String,
    pub(crate) event_b64: String,
    pub(crate) media_hash_key: String,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiFileEncryptorParams {
    pub(crate) event_b64: String,
    pub(crate) media_hash_key: String,
    #[serde(default)]
    pub(crate) conversation_key: Option<String>,
    #[serde(default)]
    pub(crate) conversation_key_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FfiDecryptFileParams {
    pub(crate) encrypted: String,
    pub(crate) event_b64: String,
    pub(crate) conversation_keys: HashMap<String, String>,
    pub(crate) media_hash_key: String,
}

/// The params of the file encryptor and decryptor.
#[derive(serde::Deserialize)]
pub(crate) struct FfiFileParams {
    pub(crate) event_b64: String,
    pub(crate) conversation_keys: HashMap<String, String>,
    pub(crate) media_hash_key: String,
}

/// Deserialize a single-JSON params document into its FFI mirror struct.
///
/// Parsing is strict: a missing required field or a type mismatch returns an
/// error result rather than being silently dropped or defaulted.
pub(crate) fn parse_params<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, FfiResult> {
    serde_json::from_str(json).map_err(|e| err_result(&format!("Invalid params JSON: {}", e)))
}

/// Convert entity tuples `[start, end, "type"]` into core descriptors.
pub(crate) fn entity_tuples_to_descs(tuples: Vec<(i32, i32, String)>) -> Vec<EntityDescriptor> {
    tuples
        .into_iter()
        .map(|(start, end, entity_type)| EntityDescriptor::new(start, end, entity_type))
        .collect()
}
