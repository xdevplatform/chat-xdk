//! Signing, verification and key-binding checks.

use super::*;

impl ChatCore {
    // Signing

    /// Sign arbitrary data.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SdkError> {
        let signing = self.keypair_manager.get_signing_keypair()?;
        let signature = KeyFactory::sign(&signing.private, data)?;
        Ok(signature)
    }

    /// Verify a raw r||s signature over `data` with a base64 P-256 public
    /// key (SEC1 or SPKI). Needs no loaded keys.
    pub fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, SdkError> {
        let invalid_key = || {
            SdkError::InvalidInput(
                "Invalid public key: pass a base64 P-256 public key (SEC1 or SPKI)".into(),
            )
        };
        let pk_bytes = base64_decode(public_key_b64).map_err(|_| invalid_key())?;
        let raw_pk = if pk_bytes.len() == 91 {
            &pk_bytes[26..]
        } else {
            &pk_bytes
        };
        let public_key = KeyFactory::reconstruct_public_key(raw_pk, KeypairPurpose::Signing)
            .map_err(|_| invalid_key())?;
        if signature.len() != 64 {
            return Err(SdkError::InvalidInput(format!(
                "Invalid signature: expected the 64-byte raw r||s signature, got {} bytes",
                signature.len()
            )));
        }
        Ok(KeyFactory::verify(&public_key, signature, data)?)
    }

    /// Build and sign a GroupMemberAdd action signature.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_add_members(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        conversation_id: &str,
        new_member_ids: &[String],
        current_member_ids: &[String],
        current_admin_ids: &[String],
        conversation_key_version: &str,
        current_title: Option<&str>,
        current_avatar_url: Option<&str>,
        current_description: Option<&str>,
        current_ttl_msec: Option<i64>,
        current_screen_capture_blocking_enabled: Option<bool>,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::sign_group_member_add(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            conversation_id,
            new_member_ids,
            current_member_ids,
            current_admin_ids,
            current_title,
            current_avatar_url,
            current_ttl_msec,
            current_screen_capture_blocking_enabled,
            conversation_key_version,
            current_description,
        )
    }

    /// Build and sign a GroupCreate action signature, which sets no avatar.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_group_create(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        member_ids: &[String],
        title: Option<&str>,
        conversation_key_version: &str,
        is_legacy_group_upgrade: Option<bool>,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::build_group_create_signature(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            member_ids,
            title,
            None,
            conversation_key_version,
            is_legacy_group_upgrade,
        )
    }

    /// Build and sign a ConversationKeyChange action signature (v7).
    ///
    /// `conversation_key` is the raw 32-byte conversation key.
    pub(crate) fn sign_key_change(
        &self,
        public_key_version: &str,
        message_id: &str,
        sender_id: &str,
        conversation_id: &str,
        conversation_key_version: &str,
        conversation_key: &[u8],
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        crate::signatures::build_ckey_change_signature(
            &signing_key,
            public_key_version,
            message_id,
            sender_id,
            conversation_id,
            conversation_key_version,
            conversation_key,
        )
    }
}
