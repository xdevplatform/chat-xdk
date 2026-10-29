//! Signing, verification and key-binding checks.

use super::*;

impl ChatCore {
    // Signing

    /// Sign application data with the signing key.
    ///
    /// Refuses data that only the SDK signs: a payload recipients verify as a
    /// signed event (a message, key change, group or conversation change,
    /// delete or read receipt) and a P-256 public key, whose signature by
    /// the signing key binds it as an identity key. The SDK signs those on
    /// its own path, so a signature from this method never stands in for
    /// one.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SdkError> {
        if crate::signatures::is_sdk_signed_data(data) {
            return Err(SdkError::InvalidInput(
                "data is an event signature payload or a public key, which only the SDK \
                 signs: pass your application's own data"
                    .into(),
            ));
        }
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

    /// The signature version of a signed action: `legacy` while sends are
    /// v0, and the version v1 sends sign at while they are v1, so every
    /// event a chat signs takes one version at a time.
    pub(crate) fn action_signature_version(&self, legacy: i32) -> i32 {
        match self.send_version() {
            crate::pipeline::SendVersion::V0 => legacy,
            crate::pipeline::SendVersion::V1 => crate::signatures::MESSAGE_SIGNATURE_VERSION,
        }
    }

    /// Sign `detail`, the event of a new action from `sender_id` in
    /// `conversation_id`, at [`Self::action_signature_version`] of `legacy`.
    /// `conversation_key` is the raw key a key change carries.
    pub(crate) fn sign_action_event(
        &self,
        public_key_version: &str,
        sender_id: &str,
        conversation_id: &str,
        legacy: i32,
        detail: crate::thrift::event::MessageEventDetail,
        conversation_key: Option<&[u8]>,
    ) -> Result<crate::signatures::ActionSignature, SdkError> {
        let signing_key = self.get_signing_private_key()?;
        let ckey_b64 =
            conversation_key.map(|key| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(key)));
        crate::signatures::sign_event(
            &signing_key,
            public_key_version,
            &Self::generate_message_id(),
            sender_id,
            conversation_id,
            self.action_signature_version(legacy),
            detail,
            ckey_b64.as_deref().map(String::as_str),
        )
    }
}
