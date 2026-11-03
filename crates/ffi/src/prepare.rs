//! The prepare calls: conversation-key changes and signed actions.

use super::*;

/// Prepare a signed conversation-key change.
///
/// `params_json` — single JSON document: `public_keys`
/// (`[{"user_id","identity_public_key","public_key_version"},...]`), plus optional
/// `sender_id` / `signing_key_version` (unset resolves from the session
/// identity) and `conversation_id` (absent or empty derives the one-to-one
/// id).
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_conversation_key_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiConversationKeyChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params = ConversationKeyChangeParams::new(p.public_keys);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        // Core treats an absent or empty id as "derive the one-to-one id".
        params.conversation_id = p.conversation_id;

        match h.inner.prepare_conversation_key_change(&params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Prepare a signed group member-add change.
///
/// `params_json` — single JSON document: `public_keys` (for the updated
/// roster), `conversation_id`, `new_member_ids`, `current_member_ids`,
/// `current_admin_ids`, `current_pending_member_ids`, plus optional
/// `sender_id` / `signing_key_version` (unset resolves from the session
/// identity), `current_title` and `current_description` (plaintext,
/// encrypted under the new conversation key), `current_avatar_url` (the
/// avatar's media URL, signed as is), `current_ttl_msec`, and
/// `current_screen_capture_blocking_enabled` (an absent key means unset,
/// never false). Emits two action signatures; the result carries the
/// encrypted title and description as `encrypted_title` and
/// `encrypted_description`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_members_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupMembersChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params = GroupMembersChangeParams::new(
            p.public_keys,
            p.conversation_id,
            p.new_member_ids,
            p.current_member_ids,
            p.current_admin_ids,
            p.current_pending_member_ids,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.current_title = p.current_title;
        params.current_avatar_url = p.current_avatar_url;
        params.current_description = p.current_description;
        params.current_ttl_msec = p.current_ttl_msec;
        params.current_screen_capture_blocking_enabled = p.current_screen_capture_blocking_enabled;

        match h.inner.prepare_group_members_change(&params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Prepare a signed group create.
///
/// `params_json` — single JSON document: `public_keys` (for the roster),
/// `conversation_id`, `member_ids`, `admin_ids`, plus optional `sender_id` /
/// `signing_key_version` (unset resolves from the session identity),
/// `title` (plaintext, encrypted under the new conversation key), and
/// `ttl_msec`. Emits two action signatures; the result carries the
/// encrypted title as `encrypted_title`. A create sets no avatar; set it
/// afterwards with `chat_xdk_prepare_group_avatar_change`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_create(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupCreateParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            GroupCreateParams::new(p.public_keys, p.conversation_id, p.member_ids, p.admin_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.title = p.title;
        params.ttl_msec = p.ttl_msec;

        match h.inner.prepare_group_create(&params) {
            Ok(res) => match json_prepared_change(&res) {
                Ok(s) => ok_data(&s),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

/// Build the signed action for deleting messages from a conversation.
///
/// `params_json` — single JSON document: `conversation_id`, `sequence_ids`
/// (the messages to delete), `delete_for_all` (every participant vs only the
/// caller's view), plus optional `sender_id` / `signing_key_version` (unset
/// resolves from the session identity).
///
/// Returns JSON `PreparedAction`: `action_signatures`, one entry with its
/// signature nested under `message_event_signature`. The SDK-generated
/// `message_id` is a field on the entry.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_delete(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageDeleteParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            MessageDeleteParams::new(p.conversation_id, p.sequence_ids, p.delete_for_all);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;

        match h.inner.prepare_message_delete(&params) {
            Ok(prepared) => match serde_json::to_string(&prepared) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}

pub(crate) fn ffi_prepared_action(
    prepared: Result<chat_xdk_core::PreparedAction, chat_xdk_core::error::SdkError>,
) -> FfiResult {
    match prepared {
        Ok(prepared) => match serde_json::to_string(&prepared) {
            Ok(json) => ok_data(&json),
            Err(e) => internal_error(e),
        },
        Err(e) => err_from(e),
    }
}

pub(crate) fn ffi_prepared_metadata_change(
    prepared: Result<chat_xdk_core::PreparedGroupMetadataChange, chat_xdk_core::error::SdkError>,
) -> FfiResult {
    match prepared {
        Ok(prepared) => match serde_json::to_string(&prepared) {
            Ok(json) => ok_data(&json),
            Err(e) => internal_error(e),
        },
        Err(e) => err_from(e),
    }
}

pub(crate) fn ffi_prepared_change(
    prepared: Result<chat_xdk_core::PreparedConversationChange, chat_xdk_core::error::SdkError>,
) -> FfiResult {
    match prepared {
        Ok(res) => match json_prepared_change(&res) {
            Ok(s) => ok_data(&s),
            Err(e) => internal_error(e),
        },
        Err(e) => err_from(e),
    }
}

/// Sign a group member removal and rotate the conversation key for the
/// members who stay.
///
/// `params_json` — `public_keys` (the identity keys of the members who
/// stay, yours included: a member left out can't read what the group sends
/// under the new key), `conversation_id`, `user_ids`, plus optional `title`
/// and `description` (the group's current plaintext metadata, re-encrypted
/// under the new key; pass each one the group has) and `sender_id` /
/// `signing_key_version`.
///
/// Returns JSON `PreparedConversationChange`: `conversation_key` is the new
/// raw key base64, and `action_signatures` is the removal, a title and a
/// description change for each one set, marked as key-rotation
/// re-encryptions, which recipients' decrypt drops, then the key change.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_members_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupMembersRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params =
            GroupMembersRemoveParams::new(p.public_keys, p.conversation_id, p.user_ids);
        params.title = p.title;
        params.description = p.description;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_change(h.inner.prepare_group_members_remove(&params))
    })
}

/// Sign leaving a group.
///
/// `params_json` — `conversation_id`, plus optional `promote_admin_id`,
/// `conversation_key_version` (named on the removal when set), and
/// `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`: the removal of the sender, an admin add
/// when `promote_admin_id` is set, and a conversation delete. Leave does not
/// rotate the conversation key.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_leave(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupLeaveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupLeaveParams::new(p.conversation_id);
        params.promote_admin_id = p.promote_admin_id;
        params.conversation_key_version = p.conversation_key_version;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_leave(&params))
    })
}

/// Encrypt a new group title under the conversation key and sign the
/// change.
///
/// `params_json` — `conversation_id`, `new_title` (plaintext), plus
/// optional `sender_id` / `signing_key_version` (unset resolves from the
/// session identity) and `conversation_key` (base64 raw 32-byte key) /
/// `conversation_key_version` (unset resolves from the opt-in key cache).
///
/// Returns JSON `PreparedGroupMetadataChange`: `encrypted_value` (the base64
/// ciphertext the request sends), `conversation_key_version`, and
/// `action_signatures`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_title_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupTitleChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut params = GroupTitleChangeParams::new(p.conversation_id, p.new_title);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;
        ffi_prepared_metadata_change(h.inner.prepare_group_title_change(&params))
    })
}

/// Sign a group avatar change.
///
/// `params_json` — `conversation_id`, `new_avatar_url` (the media URL of
/// the avatar image, signed and sent as is), `conversation_key_version`
/// (the version of the key the image is encrypted under), plus optional
/// `sender_id` / `signing_key_version` (unset resolves from the session
/// identity).
///
/// Returns JSON `PreparedAction`: `action_signatures`, one entry.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_avatar_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAvatarChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAvatarChangeParams::new(
            p.conversation_id,
            p.new_avatar_url,
            p.conversation_key_version,
        );
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_avatar_change(&params))
    })
}

/// Encrypt a new group description under the conversation key and sign the
/// change.
///
/// `params_json` — `conversation_id`, `new_description` (plaintext), plus
/// optional `sender_id` / `signing_key_version` (unset resolves from the
/// session identity) and `conversation_key` (base64 raw 32-byte key) /
/// `conversation_key_version` (unset resolves from the opt-in key cache).
///
/// Returns JSON `PreparedGroupMetadataChange`: `encrypted_value` (the base64
/// ciphertext the request sends), `conversation_key_version`, and
/// `action_signatures`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_description_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupDescriptionChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ckey_bytes = match decode_ckey_bytes(p.conversation_key.as_deref()) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut params = GroupDescriptionChangeParams::new(p.conversation_id, p.new_description);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        params.conversation_key = ckey_bytes;
        params.conversation_key_version = p.conversation_key_version;
        ffi_prepared_metadata_change(h.inner.prepare_group_description_change(&params))
    })
}

/// Sign adding group admins.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_admins_add(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAdminsAddParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAdminsAddParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_admins_add(&params))
    })
}

/// Sign removing group admins.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_admins_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupAdminsRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupAdminsRemoveParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_admins_remove(&params))
    })
}

/// Sign enabling a group invite.
///
/// `params_json` — `conversation_id`, `invite_url`, plus optional
/// `expires_at_msec` and `affiliate_id` (absent or a negative expiry signs
/// `null`) and `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_invite_enable(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupInviteEnableParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupInviteEnableParams::new(p.conversation_id, p.invite_url);
        params.expires_at_msec = p.expires_at_msec;
        params.affiliate_id = p.affiliate_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_invite_enable(&params))
    })
}

/// Sign disabling a group invite.
///
/// `params_json` — `conversation_id`, plus optional `disabled_by` (the sender
/// when absent) and `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_invite_disable(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupInviteDisableParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupInviteDisableParams::new(p.conversation_id);
        params.disabled_by = p.disabled_by;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_invite_disable(&params))
    })
}

/// Sign a request to join a group.
///
/// `params_json` — `conversation_id`, plus optional `requesting_user_id` (the
/// sender when absent) and `sender_id` / `signing_key_version`. An invite
/// token is not part of the signature.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_join_request(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupJoinRequestParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupJoinRequestParams::new(p.conversation_id);
        params.requesting_user_id = p.requesting_user_id;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_join_request(&params))
    })
}

/// Sign rejecting group join requests.
///
/// `params_json` — `conversation_id`, `user_ids`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_group_join_reject(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiGroupJoinRejectParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = GroupJoinRejectParams::new(p.conversation_id, p.user_ids);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_group_join_reject(&params))
    })
}

/// Sign a message-TTL change.
///
/// `params_json` — `conversation_id`, `ttl_msec`, plus optional `sender_id` /
/// `signing_key_version`. The signature covers `ttl_msec` only.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_ttl_change(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageTtlChangeParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = MessageTtlChangeParams::new(p.conversation_id, p.ttl_msec);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_message_ttl_change(&params))
    })
}

/// Sign clearing a conversation's message TTL.
///
/// `params_json` — `conversation_id`, plus optional `sender_id` /
/// `signing_key_version`. Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_message_ttl_remove(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMessageTtlRemoveParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut params = MessageTtlRemoveParams::new(p.conversation_id);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_message_ttl_remove(&params))
    })
}

/// Sign one screen-capture setting change.
///
/// `params_json` — `conversation_id`, `change` (`BlockingEnabled`,
/// `BlockingDisabled`, `DetectionEnabled`, or `DetectionDisabled`; camelCase
/// spellings are accepted), plus optional `sender_id` / `signing_key_version`.
///
/// Returns JSON `PreparedAction`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_screen_capture(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiScreenCaptureParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let change = match ScreenCaptureChange::parse(&p.change) {
            Ok(change) => change,
            Err(e) => return err_from(e),
        };
        let mut params = ScreenCaptureParams::new(p.conversation_id, change);
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;
        ffi_prepared_action(h.inner.prepare_screen_capture(&params))
    })
}

/// Build the signed action for marking a conversation read.
///
/// `params_json` — single JSON document: `conversation_id`,
/// `seen_until_sequence_id` (the sequence id of the newest event read), plus
/// optional `seen_at_msec` (when it was read, in milliseconds since the Unix
/// epoch; unset takes the current time) and `sender_id` /
/// `signing_key_version` (unset resolves from the session identity).
///
/// Returns JSON `PreparedAction`, shaped as `chat_xdk_prepare_message_delete`
/// returns it: the mark-read request's `action_signatures`.
#[no_mangle]
pub extern "C" fn chat_xdk_prepare_mark_conversation_read(
    handle: *const ChatHandle,
    params_json: *const c_char,
) -> FfiResult {
    catch_ffi(|| {
        if handle.is_null() {
            return err_result("Null handle");
        }
        let h = unsafe { &*handle };
        let p: FfiMarkConversationReadParams = match parse_params(try_str!(params_json)) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let mut params =
            MarkConversationReadParams::new(p.conversation_id, p.seen_until_sequence_id);
        params.seen_at_msec = p.seen_at_msec;
        params.sender_id = p.sender_id;
        params.signing_key_version = p.signing_key_version;

        match h.inner.prepare_mark_conversation_read(&params) {
            Ok(prepared) => match serde_json::to_string(&prepared) {
                Ok(json) => ok_data(&json),
                Err(e) => internal_error(e),
            },
            Err(e) => err_from(e),
        }
    })
}
