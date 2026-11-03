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

    /// The signature version of a signed action under the current send
    /// format; see [`action_signature_version`].
    pub(crate) fn action_signature_version(&self, legacy: i32) -> i32 {
        action_signature_version(self.send_version(), legacy)
    }

    /// The signature version of a new key change in `conversation_id` signed
    /// under `send_version`: [`action_signature_version`], raised to the
    /// highest version of a key change this instance signed or verified in
    /// that conversation.
    pub(crate) fn key_change_signature_version(
        &self,
        conversation_id: &str,
        send_version: crate::pipeline::SendVersion,
    ) -> i32 {
        let version =
            action_signature_version(send_version, crate::signatures::CURRENT_SIGNATURE_VERSION);
        let floors = self
            .key_change_signature_floor
            .read()
            .unwrap_or_else(|e| e.into_inner());
        floors
            .get(conversation_id)
            .map_or(version, |floor| version.max(*floor))
    }

    /// Record a key change in `conversation_id` signed or verified at
    /// `version`, so no later one this instance signs there goes below it.
    pub(crate) fn raise_key_change_signature_floor(&self, conversation_id: &str, version: i32) {
        let mut floors = self
            .key_change_signature_floor
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let floor = floors.entry(conversation_id.to_string()).or_insert(version);
        *floor = (*floor).max(version);
    }

    /// Record `key_change`, a key change whose signature verified, in its
    /// conversation's floor.
    pub(crate) fn raise_key_change_signature_floor_for(&self, key_change: &MessageEvent) {
        if let (Some(conversation_id), Some(version)) = (
            key_change.conversation_id.as_deref(),
            signature_version(key_change),
        ) {
            self.raise_key_change_signature_floor(conversation_id, version);
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
        self.sign_action_event_at(
            public_key_version,
            sender_id,
            conversation_id,
            self.action_signature_version(legacy),
            detail,
            conversation_key,
        )
    }

    /// Sign `detail` as [`Self::sign_action_event`] does, at
    /// `signature_version`.
    pub(crate) fn sign_action_event_at(
        &self,
        public_key_version: &str,
        sender_id: &str,
        conversation_id: &str,
        signature_version: i32,
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
            signature_version,
            detail,
            ckey_b64.as_deref().map(String::as_str),
        )
    }
}

/// The signature version of a signed action under `send_version`: `legacy`,
/// the action's own version, while sends are v0, and
/// [`crate::signatures::MESSAGE_SIGNATURE_VERSION`] while they are v1. A
/// call that signs several actions reads the send format once, so a feature
/// refresh between its signatures can't split them across formats.
pub(crate) fn action_signature_version(
    send_version: crate::pipeline::SendVersion,
    legacy: i32,
) -> i32 {
    match send_version {
        crate::pipeline::SendVersion::V0 => legacy,
        crate::pipeline::SendVersion::V1 => crate::signatures::MESSAGE_SIGNATURE_VERSION,
    }
}
