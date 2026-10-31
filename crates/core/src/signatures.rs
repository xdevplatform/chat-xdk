//! Action signature builders for X Chat group operations.
//!
//! Builds comma-separated signature payloads, signs them with
//! ECDSA P-256, and packages them as [`ActionSignature`] structs.

use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{KeypairPurpose, XChatPrivateKey};
use crate::error::SdkError;
use crate::protocol::serialization::base64_encode;
use crate::thrift::event::{MessageEvent, MessageEventDetail};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

/// [`SIGNATURE_VERSION`] as the integer used in verification.
pub const CURRENT_SIGNATURE_VERSION: i32 = 7;

/// Signature version of v0 sends, and of every signed action while sends
/// are v0 (conversation-key changes, group and conversation changes,
/// deletes and read receipts), apart from a member add that carries a
/// description, which signs at version 8. While sends are v1, sends and
/// signed actions sign at version 10. Either way, a key change in a
/// conversation where the chat signed or verified one at a higher version
/// signs at that version.
pub const SIGNATURE_VERSION: &str = "7";

/// Signature version of a group member add that carries a description while
/// sends are v0: the first version whose member-add payload covers
/// `current_description`.
pub(crate) const MEMBER_ADD_DESCRIPTION_SIGNATURE_VERSION: i32 = 8;

/// Signature version of v1 sends, and of every signed action while sends are
/// v1 apart from a key change raised above it (see [`SIGNATURE_VERSION`]):
/// the first version whose payload signs `contents_encryption_version`,
/// so the choice of key for the contents is covered by the signature. v0
/// sends sign at [`SIGNATURE_VERSION`].
pub(crate) const MESSAGE_SIGNATURE_VERSION: i32 = 10;

/// Minimum signature version accepted on verification. v1 payloads omit
/// the event-type discriminant and conversation-key version, so accepting
/// them would let a forger downgrade to the weaker payload via the
/// attacker-visible version field.
pub const MIN_SIGNATURE_VERSION: i32 = 2;

/// Highest signature version accepted on verification. A higher version may
/// sign fields this SDK does not know how to reproduce.
pub(crate) const MAX_SIGNATURE_VERSION: i32 = 11;

/// First signature version whose conversation-key-change payload signs the
/// plaintext conversation key. From this version on a recipient can
/// reconstruct the signed bytes and verify the change; earlier versions
/// sign the full per-participant key list, which the recipient never
/// receives in full and therefore cannot reproduce.
pub const CKEY_PLAINTEXT_SIGNATURE_VERSION: i32 = 6;

/// A signed action (conversation-key change, group change, message delete
/// or read receipt), shaped as an entry of a request's `action_signatures`:
/// the signature is nested under `message_event_signature`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct ActionSignature {
    /// Unique message ID (UUID).
    pub message_id: String,
    /// Base64-encoded Thrift-serialized MessageEventDetail.
    pub encoded_message_event_detail: String,
    /// The signature over the action, with its versions and the signer's
    /// signing public key.
    #[cfg_attr(feature = "js", js_camel(wrap))]
    pub message_event_signature: MessageEventSignature,
    /// The comma-separated payload that was signed, for this crate's tests:
    /// never serialized, so it stays off the wire. Empty for
    /// conversation-key changes, whose payload embeds the plaintext
    /// conversation key.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) signature_payload: String,
}

/// The signature of an [`ActionSignature`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "js", derive(chat_xdk_macros::JsCamelCase))]
#[non_exhaustive]
pub struct MessageEventSignature {
    /// Base64 ECDSA signature of the payload.
    pub signature: String,
    /// Signature protocol version.
    pub signature_version: String,
    /// Version of the signing public key.
    pub public_key_version: String,
    /// The signer's base64 signing public key, as `get_public_keys` returns
    /// it.
    pub signing_public_key: String,
}

impl MessageEventSignature {
    /// Sign `payload` at [`SIGNATURE_VERSION`].
    fn sign(
        signing_key: &XChatPrivateKey,
        public_key_version: &str,
        payload: &[u8],
    ) -> Result<Self, SdkError> {
        Self::sign_at(signing_key, public_key_version, payload, SIGNATURE_VERSION)
    }

    /// Sign `payload` at `signature_version`.
    fn sign_at(
        signing_key: &XChatPrivateKey,
        public_key_version: &str,
        payload: &[u8],
        signature_version: &str,
    ) -> Result<Self, SdkError> {
        let signature = KeyFactory::sign(signing_key, payload).map_err(SdkError::Crypto)?;
        let signing_keypair = KeyFactory::get_keypair_from_private_key_bytes(
            signing_key.encoded(),
            KeypairPurpose::Signing,
        )
        .map_err(SdkError::Crypto)?;
        Ok(Self {
            signature: STANDARD_NO_PAD.encode(&signature),
            signature_version: signature_version.to_string(),
            public_key_version: public_key_version.to_string(),
            signing_public_key: base64_encode(signing_keypair.public.encoded()),
        })
    }
}

/// Build and sign a GroupMemberAdd action signature (signed at v7).
///
/// Payload format (v7 field layout):
/// ```text
/// GroupChangeEvent.GroupMemberAddChange,{msg_id},{sender_id},{conv_id},
///   {new_member_ids...},{current_member_ids...},{current_admin_ids...},
///   {title|null},{avatar_url|null},{ttl_msec|null},{ckey_version},
///   {screen_capture_blocking|null}
/// ```
///
/// Pending member ids are not part of the v7 payload. The screen-capture slot
/// carries the group's current screen-capture-blocking state
/// (`current_screen_capture_blocking_enabled`), rendered as the `null` sentinel
/// when unset; the verifier reconstructs it from the same field in the event
/// detail, so the SDK can verify its own signatures.
///
/// The payload is comma-joined with no escaping, so signing fails with a
/// parse error if any component (e.g. `current_title`) contains a comma.
#[allow(clippy::too_many_arguments)]
pub fn build_group_member_add_signature(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    new_member_ids: &[String],
    current_member_ids: &[String],
    current_admin_ids: &[String],
    current_title: Option<&str>,
    current_avatar_url: Option<&str>,
    current_ttl_msec: Option<i64>,
    current_screen_capture_blocking_enabled: Option<bool>,
    conversation_key_version: &str,
) -> Result<ActionSignature, SdkError> {
    let mut components: Vec<&str> = vec![
        "GroupChangeEvent.GroupMemberAddChange",
        message_id,
        sender_id,
        conversation_id,
    ];
    components.extend(new_member_ids.iter().map(String::as_str));
    components.extend(current_member_ids.iter().map(String::as_str));
    components.extend(current_admin_ids.iter().map(String::as_str));

    let title_str = nullable_str(current_title);
    let avatar_str = nullable_str(current_avatar_url);
    let ttl_str = nullable_i64(current_ttl_msec);
    let screen_capture_str = nullable_bool(current_screen_capture_blocking_enabled);
    components.push(&title_str);
    components.push(&avatar_str);
    components.push(&ttl_str);
    components.push(conversation_key_version);
    components.push(&screen_capture_str);
    sign_payload(signing_key, public_key_version, message_id, &components)
}

/// Build and sign a GroupCreate action signature.
///
/// Signed at signature version 7; the legacy/title/avatar trailer is part of the
/// field layout from v4 onward.
///
/// Payload format:
/// ```text
/// GroupChangeEvent.GroupCreate,{msg_id},{sender_id},{ckey_version},
///   {member_ids...},{is_legacy_group_upgrade},{title},{avatar_url}
/// ```
///
/// The conversation id, admin ids, and ttl are carried in the encoded event
/// detail but are not part of the signed payload; `None` renders as `"null"`.
///
/// The payload is comma-joined with no escaping, so signing fails with a
/// parse error if any component (e.g. `title`) contains a comma.
#[allow(clippy::too_many_arguments)]
pub fn build_group_create_signature(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    sender_id: &str,
    member_ids: &[String],
    title: Option<&str>,
    avatar_url: Option<&str>,
    conversation_key_version: &str,
    is_legacy_group_upgrade: Option<bool>,
) -> Result<ActionSignature, SdkError> {
    let mut components: Vec<&str> = vec![
        "GroupChangeEvent.GroupCreate",
        message_id,
        sender_id,
        conversation_key_version,
    ];

    let member_id_refs: Vec<&str> = member_ids.iter().map(|s| s.as_str()).collect();
    components.extend_from_slice(&member_id_refs);

    let legacy_str = nullable_bool(is_legacy_group_upgrade);
    let title_str = nullable_str(title);
    let avatar_str = nullable_str(avatar_url);
    components.push(&legacy_str);
    components.push(&title_str);
    components.push(&avatar_str);

    sign_payload(signing_key, public_key_version, message_id, &components)
}

/// Render a nullable string into a signature payload: the value or `"null"`.
fn nullable_str(v: Option<&str>) -> String {
    v.map(|s| s.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Render a nullable i64 into a signature payload: the digits or `"null"`.
fn nullable_i64(v: Option<i64>) -> String {
    v.map(|n| n.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Render a nullable bool into a signature payload: `"true"`, `"false"`, or `"null"`.
fn nullable_bool(v: Option<bool>) -> String {
    v.map(|b| b.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Build and sign a ConversationKeyChange action signature (v7).
///
/// Signs the plaintext conversation key bytes (base64 no-padding) rather
/// than per-participant encrypted keys. Because the signed payload embeds
/// the plaintext conversation key, it must never leave the SDK: the
/// intermediate strings are zeroized and not kept. Verifiers reconstruct
/// the payload from the event and their decrypted copy of the key.
pub fn build_ckey_change_signature(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    conversation_key_version: &str,
    conversation_key: &[u8],
) -> Result<ActionSignature, SdkError> {
    use zeroize::Zeroizing;

    // Same no-escaping rule as sign_payload; the base64 key itself can never
    // contain a comma.
    if [
        message_id,
        sender_id,
        conversation_id,
        conversation_key_version,
    ]
    .iter()
    .any(|c| c.contains(','))
    {
        return Err(SdkError::InvalidInput(
            "Signature payload contains comma-separated component".into(),
        ));
    }

    let ckey_b64 = Zeroizing::new(STANDARD_NO_PAD.encode(conversation_key));
    let payload = Zeroizing::new(
        [
            "ConversationKeyChangeEvent",
            message_id,
            sender_id,
            conversation_id,
            conversation_key_version,
            &ckey_b64,
        ]
        .join(","),
    );

    Ok(ActionSignature {
        message_id: message_id.to_string(),
        encoded_message_event_detail: String::new(),
        message_event_signature: MessageEventSignature::sign(
            signing_key,
            public_key_version,
            payload.as_bytes(),
        )?,
        signature_payload: String::new(),
    })
}

/// Build and sign a MessageDelete action signature.
///
/// Payload format:
/// ```text
/// MessageDeleteEvent,{msg_id},{sender_id},{conv_id},{delete_action},{sequence_ids...}
/// ```
///
/// `delete_action` is the wire integer: `1` delete-for-self, `2`
/// delete-for-all.
///
/// The payload is comma-joined with no escaping, so signing fails with a
/// parse error if any component contains a comma.
pub fn build_message_delete_signature(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    sequence_ids: &[String],
    delete_action: i32,
) -> Result<ActionSignature, SdkError> {
    let action_str = delete_action.to_string();
    let mut components: Vec<&str> = vec![
        "MessageDeleteEvent",
        message_id,
        sender_id,
        conversation_id,
        &action_str,
    ];
    components.extend(sequence_ids.iter().map(|s| s.as_str()));
    sign_payload(signing_key, public_key_version, message_id, &components)
}

/// Sign a comma-joined payload at [`CURRENT_SIGNATURE_VERSION`] and return an
/// [`ActionSignature`].
///
/// Rejects any component containing `,`: the payload has no escaping, so an
/// embedded comma would both make the signature unverifiable and let one
/// signed byte string decode as two different component sequences.
fn sign_payload(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    components: &[&str],
) -> Result<ActionSignature, SdkError> {
    if components.iter().any(|c| c.contains(',')) {
        return Err(SdkError::InvalidInput(
            "Signature payload contains comma-separated component".into(),
        ));
    }
    let payload = components.join(",");
    Ok(ActionSignature {
        message_id: message_id.to_string(),
        encoded_message_event_detail: String::new(),
        message_event_signature: MessageEventSignature::sign(
            signing_key,
            public_key_version,
            payload.as_bytes(),
        )?,
        signature_payload: payload,
    })
}

/// Sign `detail`, the event of the action `message_id` that `sender_id`
/// sends in `conversation_id`, at `signature_version`, and return it as an
/// [`ActionSignature`] carrying the encoded event.
///
/// The signed bytes are the payload recipients rebuild from the event
/// (`crate::core::build_event_signature_payload`), in the layout of
/// `signature_version`, so what is signed is what they verify.
/// `plaintext_ckey_b64` is the conversation key a key change carries, which
/// its payload embeds; that payload is never kept. The comma rule of
/// [`sign_payload`] applies to every component.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_event(
    signing_key: &XChatPrivateKey,
    public_key_version: &str,
    message_id: &str,
    sender_id: &str,
    conversation_id: &str,
    signature_version: i32,
    detail: MessageEventDetail,
    plaintext_ckey_b64: Option<&str>,
) -> Result<ActionSignature, SdkError> {
    let event = MessageEvent {
        message_id: Some(message_id.to_string()),
        sender_id: Some(sender_id.to_string()),
        conversation_id: Some(conversation_id.to_string()),
        message_event_signature: Some(crate::thrift::event::MessageEventSignature {
            signature_version: Some(signature_version.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let payload = crate::core::build_event_signature_payload(&event, &detail, plaintext_ckey_b64)
        .ok_or_else(|| {
        SdkError::InvalidInput("Signature payload contains comma-separated component".into())
    })?;
    Ok(ActionSignature {
        message_id: message_id.to_string(),
        encoded_message_event_detail: base64_encode(&crate::pipeline::serialize_thrift(&detail)?),
        message_event_signature: MessageEventSignature::sign_at(
            signing_key,
            public_key_version,
            &payload,
            &signature_version.to_string(),
        )?,
        signature_payload: match plaintext_ckey_b64 {
            Some(_) => String::new(),
            None => String::from_utf8_lossy(&payload).into_owned(),
        },
    })
}

/// Events whose signed payload a recipient rebuilds and verifies, each
/// payload starting with the name followed by a comma (see
/// `build_event_signature_payload`).
const SIGNED_EVENT_NAMES: &[&str] = &[
    "MessageCreateEvent",
    "ConversationKeyChangeEvent",
    "MessageDeleteEvent",
    "ConversationDeleteEvent",
    "MarkConversationReadEvent",
    "MarkConversationUnreadEvent",
];

/// Event families whose payloads start with the family, a dot and the change
/// name: every group change and conversation-metadata change.
const SIGNED_EVENT_FAMILIES: &[&str] = &["GroupChangeEvent.", "ConversationMetadataChangeEvent."];

/// Whether `data` is something only the SDK signs with the signing key.
///
/// That is a payload a recipient verifies as a signed event, or a P-256
/// public key: the signing key's signature over an identity public key is
/// the binding recipients check before trusting the pair. A verifier rebuilds
/// a payload byte for byte from the event and checks the signature over those
/// bytes only, and every rebuilt payload starts with an event name above, so
/// the prefix match covers every payload whose signature would verify; data
/// that differs in its first bytes (case, spacing, another encoding) yields a
/// signature no event verifies with. The key check covers every encoding the
/// SDK reads an identity key from: a SEC1 point, compressed or not, and SPKI
/// DER.
pub(crate) fn is_sdk_signed_data(data: &[u8]) -> bool {
    let names = SIGNED_EVENT_NAMES
        .iter()
        .any(|name| data.starts_with(name.as_bytes()) && data.get(name.len()) == Some(&b','));
    let families = SIGNED_EVENT_FAMILIES
        .iter()
        .any(|family| data.starts_with(family.as_bytes()));
    names || families || is_public_key_encoding(data)
}

fn is_public_key_encoding(data: &[u8]) -> bool {
    use p256::pkcs8::DecodePublicKey;
    // The SDK reads a 91-byte key as SPKI by dropping its 26-byte header.
    let point = if data.len() == 91 { &data[26..] } else { data };
    p256::PublicKey::from_sec1_bytes(point).is_ok()
        || p256::PublicKey::from_public_key_der(data).is_ok()
}

#[cfg(test)]
mod round_trip_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_signatures_nest_the_signature_as_requests_do() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let delete = build_message_delete_signature(
            &kp.private,
            "3",
            "msg-1",
            "1",
            "1:2",
            &["5".to_string()],
            2,
        )
        .unwrap();
        let key_change =
            build_ckey_change_signature(&kp.private, "3", "msg-2", "1", "1:2", "9", &[7u8; 32])
                .unwrap();

        for sig in [&delete, &key_change] {
            let inner = &sig.message_event_signature;
            assert_eq!(inner.signing_public_key, base64_encode(kp.public.encoded()));
            let json = serde_json::to_value(sig).unwrap();
            assert_eq!(
                json["message_event_signature"],
                serde_json::json!({
                    "signature": inner.signature,
                    "signature_version": "7",
                    "public_key_version": "3",
                    "signing_public_key": inner.signing_public_key,
                })
            );
            for flat in ["signature", "signature_version", "public_key_version"] {
                assert!(json.get(flat).is_none(), "{flat} is nested, not flat");
            }
        }
        assert!(!delete.signature_payload.is_empty());
        for sig in [&delete, &key_change] {
            let json = serde_json::to_value(sig).unwrap();
            assert!(json.get("signature_payload").is_none());
        }
    }

    #[test]
    fn test_group_member_add_payload_format() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-1",
            "sender-1",
            "conv-1",
            &["new-user-1".to_string()],
            &["existing-1".to_string(), "existing-2".to_string()],
            &["existing-1".to_string()],
            None,
            None,
            None,
            None,
            "42",
        )
        .unwrap();

        // v7 layout: no pending ids; None title/avatar/ttl render as "null";
        // the trailing "null" is the (unset) screen-capture slot.
        assert_eq!(
            sig.signature_payload,
            "GroupChangeEvent.GroupMemberAddChange,msg-1,sender-1,conv-1,\
             new-user-1,existing-1,existing-2,existing-1,null,null,null,42,null"
        );
        assert!(!sig.message_event_signature.signature.is_empty());
        assert_eq!(sig.message_event_signature.signature_version, "7");
    }

    #[test]
    fn test_group_create_payload_format() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_create_signature(
            &kp.private,
            "1",
            "msg-gc",
            "sender-1",
            &["member-1".to_string(), "member-2".to_string()],
            None,
            None,
            "42",
            None,
        )
        .unwrap();

        // conversation_key_version leads the extras, then member ids, then the
        // legacy/title/avatar trailer (all "null" here). conv_id is absent.
        assert_eq!(
            sig.signature_payload,
            "GroupChangeEvent.GroupCreate,msg-gc,sender-1,42,member-1,member-2,null,null,null"
        );
        assert!(!sig.message_event_signature.signature.is_empty());
        assert_eq!(sig.message_event_signature.signature_version, "7");

        let verified = KeyFactory::verify(
            &kp.public,
            &base64_decode_sig(&sig.message_event_signature.signature),
            sig.signature_payload.as_bytes(),
        )
        .unwrap();
        assert!(verified);
    }

    #[test]
    fn test_group_create_payload_with_optional_fields() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_create_signature(
            &kp.private,
            "3",
            "msg-gc2",
            "admin-1",
            &["a".to_string()],
            Some("My Group"),
            Some("https://img.com/a.png"),
            "7",
            Some(true),
        )
        .unwrap();

        assert_eq!(
            sig.signature_payload,
            "GroupChangeEvent.GroupCreate,msg-gc2,admin-1,7,a,true,My Group,https://img.com/a.png"
        );
        assert_eq!(sig.message_event_signature.public_key_version, "3");
    }

    #[test]
    fn test_ckey_change_payload_format() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        // 32-byte key: 0x00..0x1f
        let ckey: Vec<u8> = (0u8..32).collect();
        let sig = build_ckey_change_signature(
            &kp.private,
            "1",
            "msg-2",
            "sender-1",
            "conv-1",
            "42",
            &ckey,
        )
        .unwrap();

        // The payload embeds the plaintext conversation key and is withheld;
        // pin the signed-bytes format by reconstructing it and verifying.
        assert!(sig.signature_payload.is_empty());
        // base64-no-pad of bytes 0x00..0x1f
        let expected_ckey_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let expected_payload = format!(
            "ConversationKeyChangeEvent,msg-2,sender-1,conv-1,42,{}",
            expected_ckey_b64
        );
        assert!(!sig.message_event_signature.signature.is_empty());
        let verified = KeyFactory::verify(
            &kp.public,
            &base64_decode_sig(&sig.message_event_signature.signature),
            expected_payload.as_bytes(),
        )
        .unwrap();
        assert!(verified);
    }

    // build_group_member_add_signature — optional fields filled

    #[test]
    fn test_group_member_add_with_all_optional_fields() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "2",
            "msg-full",
            "admin-1",
            "conv-full",
            &["new-a".to_string(), "new-b".to_string()],
            &[
                "member-1".to_string(),
                "member-2".to_string(),
                "member-3".to_string(),
            ],
            &["admin-1".to_string()],
            Some("Team Chat"),         // title
            Some("https://img.com/a"), // avatar URL
            Some(604800000),           // TTL (7 days)
            None,                      // screen-capture blocking unset
            "99",
        )
        .unwrap();

        // Verify payload structure
        let parts: Vec<&str> = sig.signature_payload.split(',').collect();
        assert_eq!(parts[0], "GroupChangeEvent.GroupMemberAddChange");
        assert_eq!(parts[1], "msg-full");
        assert_eq!(parts[2], "admin-1");
        assert_eq!(parts[3], "conv-full");
        // new members
        assert!(sig.signature_payload.contains("new-a"));
        assert!(sig.signature_payload.contains("new-b"));
        // current members
        assert!(sig.signature_payload.contains("member-1"));
        assert!(sig.signature_payload.contains("member-2"));
        assert!(sig.signature_payload.contains("member-3"));
        // admin
        assert!(sig.signature_payload.contains("admin-1"));
        // optional fields
        assert!(sig.signature_payload.contains("Team Chat"));
        assert!(sig.signature_payload.contains("https://img.com/a"));
        assert!(sig.signature_payload.contains("604800000"));
        // ckey version followed by the null screen-capture slot
        assert!(sig.signature_payload.ends_with(",99,null"));
        assert_eq!(sig.message_event_signature.public_key_version, "2");
        assert_eq!(sig.message_id, "msg-full");
    }

    #[test]
    fn test_group_member_add_with_title_only() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-t",
            "sender-1",
            "conv-1",
            &["new-1".to_string()],
            &["existing-1".to_string()],
            &[],
            Some("My Group"),
            None, // no avatar
            None, // no ttl
            None, // no screen-capture blocking
            "1",
        )
        .unwrap();
        assert!(sig.signature_payload.contains("My Group"));
        // absent avatar and ttl render as the "null" sentinel
        assert!(sig.signature_payload.contains("My Group,null,null"));
    }

    #[test]
    fn test_group_member_add_with_avatar_only() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-a",
            "sender-1",
            "conv-1",
            &["new-1".to_string()],
            &[],
            &[],
            None,
            Some("https://avatar.com/pic.png"),
            None,
            None,
            "1",
        )
        .unwrap();
        assert!(sig.signature_payload.contains("https://avatar.com/pic.png"));
    }

    #[test]
    fn test_group_member_add_with_ttl_only() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-ttl",
            "sender-1",
            "conv-1",
            &["new-1".to_string()],
            &[],
            &[],
            None,
            None,
            Some(30000),
            None,
            "1",
        )
        .unwrap();
        assert!(sig.signature_payload.contains("30000"));
    }

    #[test]
    fn test_group_member_add_with_screen_capture_blocking_enabled() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-scb",
            "sender-1",
            "conv-1",
            &["new-1".to_string()],
            &["existing-1".to_string()],
            &["existing-1".to_string()],
            None,
            None,
            None,
            Some(true),
            "42",
        )
        .unwrap();

        // The trailing screen-capture slot signs the caller-supplied state.
        assert_eq!(
            sig.signature_payload,
            "GroupChangeEvent.GroupMemberAddChange,msg-scb,sender-1,conv-1,\
             new-1,existing-1,existing-1,null,null,null,42,true"
        );

        let verified = KeyFactory::verify(
            &kp.public,
            &base64_decode_sig(&sig.message_event_signature.signature),
            sig.signature_payload.as_bytes(),
        )
        .unwrap();
        assert!(verified);
    }

    // build_ckey_change_signature — multiple participants

    #[test]
    fn test_ckey_change_signs_plaintext_key() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let ckey: Vec<u8> = (0u8..32).collect();
        let sig = build_ckey_change_signature(
            &kp.private,
            "1",
            "msg-multi",
            "sender-1",
            "conv-1",
            "50",
            &ckey,
        )
        .unwrap();

        // Payload embeds the plaintext conversation key and is withheld.
        assert!(sig.signature_payload.is_empty());
        assert_eq!(sig.message_event_signature.signature_version, "7");
        assert_eq!(sig.message_id, "msg-multi");

        // Verify the signature against the reconstructed signed bytes to pin
        // the wire format.
        let expected_payload = format!(
            "ConversationKeyChangeEvent,msg-multi,sender-1,conv-1,50,{}",
            STANDARD_NO_PAD.encode(&ckey)
        );
        let verified = KeyFactory::verify(
            &kp.public,
            &base64_decode_sig(&sig.message_event_signature.signature),
            expected_payload.as_bytes(),
        )
        .unwrap();
        assert!(verified);
    }

    #[test]
    fn test_ckey_change_different_keys_sign_different_bytes() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let ckey1: Vec<u8> = vec![1u8; 32];
        let ckey2: Vec<u8> = vec![2u8; 32];
        let sig1 =
            build_ckey_change_signature(&kp.private, "1", "m", "s", "c", "1", &ckey1).unwrap();
        let sig2 =
            build_ckey_change_signature(&kp.private, "1", "m", "s", "c", "1", &ckey2).unwrap();

        // The payload embeds the plaintext conversation key and is withheld;
        // reconstruct the signed bytes per key and check each signature only
        // verifies against its own key's payload.
        let payload = |ckey: &[u8]| {
            format!(
                "ConversationKeyChangeEvent,m,s,c,1,{}",
                STANDARD_NO_PAD.encode(ckey)
            )
        };
        let sig1_bytes = base64_decode_sig(&sig1.message_event_signature.signature);
        let sig2_bytes = base64_decode_sig(&sig2.message_event_signature.signature);
        assert!(KeyFactory::verify(&kp.public, &sig1_bytes, payload(&ckey1).as_bytes()).unwrap());
        assert!(KeyFactory::verify(&kp.public, &sig2_bytes, payload(&ckey2).as_bytes()).unwrap());
        assert!(!KeyFactory::verify(&kp.public, &sig1_bytes, payload(&ckey2).as_bytes()).unwrap());

        let sig_empty =
            build_ckey_change_signature(&kp.private, "1", "m", "s", "c", "1", &[]).unwrap();
        // Empty key → just the base64 of empty bytes
        assert!(KeyFactory::verify(
            &kp.public,
            &base64_decode_sig(&sig_empty.message_event_signature.signature),
            payload(&[]).as_bytes()
        )
        .unwrap());
    }

    fn base64_decode_sig(b64: &str) -> Vec<u8> {
        STANDARD_NO_PAD.decode(b64).unwrap()
    }

    // Signature payload format validation

    #[test]
    fn test_group_member_add_payload_component_count() {
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        // 1 new, 2 current, 1 admin = 4 id components
        // + 4 header (event type, msg_id, sender_id, conv_id)
        // + 5 trailer (title, avatar, ttl, ckey_version, screen_capture)
        // = 13 total
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-1",
            "sender-1",
            "conv-1",
            &["new-1".to_string()],
            &["m-1".to_string(), "m-2".to_string()],
            &["a-1".to_string()],
            None,
            None,
            None,
            None,
            "1",
        )
        .unwrap();

        let parts: Vec<&str> = sig.signature_payload.split(',').collect();
        // 4 header + 1 new + 2 current + 1 admin + 5 trailer = 13
        assert_eq!(parts.len(), 13);
    }

    #[test]
    fn test_action_signature_encoded_message_event_detail_is_empty() {
        // The signer leaves encoded_message_event_detail empty; the prepare
        // methods populate it.
        let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
        let sig = build_group_member_add_signature(
            &kp.private,
            "1",
            "msg-1",
            "s-1",
            "c-1",
            &["n-1".to_string()],
            &[],
            &[],
            None,
            None,
            None,
            None,
            "1",
        )
        .unwrap();
        assert!(sig.encoded_message_event_detail.is_empty());
    }

    #[test]
    fn test_signature_version_is_constant() {
        assert_eq!(SIGNATURE_VERSION, "7");
    }
}
