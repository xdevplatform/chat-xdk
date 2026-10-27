//! File encryption and decryption from the message that carries the file.

use super::*;

impl ChatCore {
    // Files

    /// Encrypt a file for an outgoing message.
    ///
    /// Build the message first: its attachments name each file by the media
    /// hash key the file's upload started with. Then pass the returned
    /// payload's `event_b64`, the file's media hash key, and the conversation
    /// key and version the message was encrypted under (or neither, to
    /// resolve them from the key cache). The SDK finds the file's attachment
    /// in the message and derives its key, so files can be encrypted in any
    /// order, and a file that is not in the message, or a key that does not
    /// decrypt the message, is an error.
    pub fn encrypt_file(&self, params: &EncryptFileParams) -> Result<Vec<u8>, SdkError> {
        let conversation_key = self.outgoing_file_conversation_key(
            &params.event_b64,
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
        )?;
        let key = media::outgoing_media_key(
            &params.event_b64,
            conversation_key
                .as_ref()
                .map(|(key, version)| (key, version.as_str())),
            &params.media_hash_key,
        )?;
        let mut reader = Cursor::new(params.file.as_slice());
        let mut output: Vec<u8> = Vec::new();
        crate::crypto::encryption::encrypt_file(&key, &mut reader, &mut output)?;
        Ok(output)
    }

    /// Create an incremental encryptor for a file too large to hold in
    /// memory. Takes the params of [`Self::encrypt_file`] apart from the
    /// file, which is fed to the encryptor.
    pub fn file_encryptor(&self, params: &FileEncryptorParams) -> Result<FileEncryptor, SdkError> {
        let conversation_key = self.outgoing_file_conversation_key(
            &params.event_b64,
            params.conversation_key.as_deref(),
            params.conversation_key_version.as_deref(),
        )?;
        let key = media::outgoing_media_key(
            &params.event_b64,
            conversation_key
                .as_ref()
                .map(|(key, version)| (key, version.as_str())),
            &params.media_hash_key,
        )?;
        Ok(FileEncryptor::new(&key)?)
    }

    /// The conversation key a file of the message in `event_b64` is
    /// encrypted under, with its version: the explicit pair, or, both unset,
    /// the cached key for the message's conversation, as `encrypt_message`
    /// resolves it. The version must be the message's.
    pub(super) fn outgoing_file_conversation_key(
        &self,
        event_b64: &str,
        conversation_key: Option<&[u8]>,
        conversation_key_version: Option<&str>,
    ) -> Result<Option<(XChatConversationKey, String)>, SdkError> {
        let event = Self::parse_event_b64(event_b64)?;
        let Some(MessageEventDetail::MessageCreateEvent(create)) = &event.detail else {
            // Not a message: the file lookup reports what to pass.
            return Ok(None);
        };
        if let Some(version) = conversation_key_version.filter(|v| !v.is_empty()) {
            crate::pipeline::validate_key_version("conversation_key_version", version)?;
        }
        let (key, version) = self.resolve_conversation_key(
            conversation_key,
            conversation_key_version,
            event.conversation_id.as_deref().unwrap_or_default(),
            event.sender_id.as_deref().unwrap_or_default(),
        )?;
        if let Some(message_version) = create.conversation_key_version.as_deref() {
            if message_version != version {
                return Err(SdkError::InvalidInput(format!(
                    "conversation_key_version '{version}' is not the message's key version \
                     '{message_version}': pass the conversation key the message was \
                     encrypted under"
                )));
            }
        }
        Ok(Some((key, version)))
    }

    /// Decrypt a file.
    ///
    /// `params.event_b64` is the event of the message that carries the file
    /// and `params.conversation_keys` its conversation's key map, as passed
    /// to [`Self::decrypt_event`]. `params.media_hash_key` names the file: a
    /// media attachment, a link card's banner or favicon, or media the
    /// message quotes from another message in its reply preview. The SDK
    /// finds that attachment in the event and derives its key from the key
    /// for the message's version.
    ///
    /// Errors say what to pass instead when the key map lacks the message's
    /// key version, the event is not an encrypted message with files, the
    /// media hash key is not in it, or `params.encrypted` is not the
    /// complete encrypted file. Signatures are not checked here; use the
    /// `verified` flag from [`Self::decrypt_event`].
    pub fn decrypt_file(&self, params: &DecryptFileParams) -> Result<Vec<u8>, SdkError> {
        let key = media::media_key(
            &params.event_b64,
            &params.conversation_keys,
            &params.media_hash_key,
        )?;
        Ok(crate::crypto::encryption::decrypt_media(
            &key,
            &params.media_hash_key,
            &params.encrypted,
        )?)
    }

    /// Create an incremental decryptor for a file too large to hold in
    /// memory. Takes the params of [`Self::decrypt_file`] apart from the
    /// encrypted file, which is fed to the decryptor; its errors say which
    /// file failed and what to pass.
    pub fn file_decryptor(&self, params: &FileDecryptorParams) -> Result<FileDecryptor, SdkError> {
        let key = media::media_key(
            &params.event_b64,
            &params.conversation_keys,
            &params.media_hash_key,
        )?;
        Ok(FileDecryptor::for_media(&key, &params.media_hash_key)?)
    }

    /// Decrypt a group title or description the X API returns for a
    /// conversation: base64 XSalsa20-Poly1305 ciphertext under the
    /// conversation key, decrypted to its UTF-8 plaintext.
    ///
    /// Group changes in events need no call of their own:
    /// [`Self::decrypt_event`] returns them decrypted. The input is base64
    /// rather than raw bytes because it is an API-edge value consumed
    /// verbatim.
    pub fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &XChatConversationKey,
    ) -> Result<String, SdkError> {
        let ciphertext = crate::protocol::serialization::base64_decode(ciphertext_b64)?;
        let plaintext = crate::crypto::encryption::decrypt_message(conversation_key, &ciphertext)?;
        String::from_utf8(plaintext)
            .map_err(|e| SdkError::Parse(format!("Decrypted data is not valid UTF-8: {}", e)))
    }
}
