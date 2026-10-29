//! The key of an encrypted media file, found from the message that carries
//! it: an incoming message for decryption, or an outgoing message for
//! encryption.
//!
//! A message names each media file by its media hash key: a media attachment,
//! a link card's banner or favicon, or media quoted from another message in a
//! reply preview. A message without a message key encrypts its media under
//! the conversation key; a message with one encrypts each attachment under a
//! key derived from the message key and the attachment's id, and a link
//! card's banner and favicon share the card's key. The key comes from the
//! caller's arguments alone.

use std::collections::HashMap;

use super::ChatCore;
use crate::crypto::encryption::decrypt_message as decrypt_message_bytes;
use crate::crypto::keys::XChatConversationKey;
use crate::crypto::message_keys;
use crate::error::{CryptoError, SdkError};
use crate::thrift::event::{MessageCreateEvent, MessageEvent, MessageEventDetail};
use crate::thrift::product::{
    MessageAttachment, MessageContents, MessageEntryContents, ReplyingToPreview, UrlAttachment,
};

/// The key of the media file `media_hash_key` names in the message event
/// `event_b64`, using the key for the message's version from
/// `conversation_keys`.
pub(super) fn media_key(
    event_b64: &str,
    conversation_keys: &HashMap<String, XChatConversationKey>,
    media_hash_key: &str,
) -> Result<XChatConversationKey, SdkError> {
    if media_hash_key.is_empty() {
        return Err(invalid_input(
            "media_hash_key is empty: pass the media hash key of the attachment, from the \
             message decrypt_event returned",
        ));
    }
    let event = ChatCore::parse_event_b64(event_b64)?;
    let Some(MessageEventDetail::MessageCreateEvent(create)) = &event.detail else {
        return Err(invalid_input(
            "the event is not a message, so it has no media: pass the event of the message \
             that carries the media",
        ));
    };
    let message = open_message(
        &event,
        create,
        conversation_keys,
        None,
        "the message",
        KeySource::Map,
    )?;
    if let Some(key) = message.attachment_key(media_hash_key)? {
        return Ok(key);
    }

    let mut known = media_hash_keys(message.contents.attachments.as_deref());
    if let Some(preview) = message.contents.replying_to_preview.as_deref() {
        let shown = media_hash_keys(preview.attachments.as_deref());
        match open_quoted(&event, preview, conversation_keys) {
            Ok(quoted) => {
                if let Some(key) = quoted.attachment_key(media_hash_key)? {
                    return Ok(key);
                }
                known.extend(media_hash_keys(quoted.contents.attachments.as_deref()));
            }
            // When the preview shows this media, why its message cannot be
            // opened is the answer; otherwise the media is not quoted here.
            Err(error) if shown.iter().any(|shown| shown == media_hash_key) => return Err(error),
            Err(_) => known.extend(shown),
        }
    }

    if known.is_empty() {
        return Err(invalid_input(
            "the message has no media: pass the event of the message that carries the media",
        ));
    }
    Err(invalid_input(format!(
        "media_hash_key '{}' is not in the message, whose media hash keys are {}: pass one of \
         those, or the event of the message that carries this media",
        media_hash_key,
        known.join(", ")
    )))
}

/// The key a file is encrypted under for the outgoing message `event_b64`:
/// the key of the message's own attachment that `media_hash_key` names.
/// Media a reply quotes belongs to the quoted message, whose sender uploaded
/// it, so it is never encrypted again.
pub(super) fn outgoing_media_key(
    event_b64: &str,
    conversation_key: Option<(&XChatConversationKey, &str)>,
    media_hash_key: &str,
) -> Result<XChatConversationKey, SdkError> {
    if media_hash_key.is_empty() {
        return Err(invalid_input(
            "media_hash_key is empty: pass the media hash key the file's upload started with, \
             as listed in the message's attachments",
        ));
    }
    let event = ChatCore::parse_event_b64(event_b64)?;
    let Some(MessageEventDetail::MessageCreateEvent(create)) = &event.detail else {
        return Err(invalid_input(
            "the event is not a message: pass the event_b64 of the payload that encrypt_message \
             or encrypt_reply returned",
        ));
    };
    let conversation_keys: HashMap<String, XChatConversationKey> = conversation_key
        .map(|(key, version)| (version.to_string(), key.clone()))
        .into_iter()
        .collect();
    let message = open_message(
        &event,
        create,
        &conversation_keys,
        None,
        "the message",
        KeySource::Single,
    )?;
    if let Some(key) = message.attachment_key(media_hash_key)? {
        return Ok(key);
    }

    let quoted = message
        .contents
        .replying_to_preview
        .as_deref()
        .map(|preview| media_hash_keys(preview.attachments.as_deref()))
        .unwrap_or_default();
    if quoted.iter().any(|quoted| quoted == media_hash_key) {
        return Err(invalid_input(format!(
            "media_hash_key '{media_hash_key}' is media the reply quotes: its file belongs to the \
             quoted message and was uploaded with it, so there is nothing to encrypt"
        )));
    }
    let own = media_hash_keys(message.contents.attachments.as_deref());
    if own.is_empty() {
        return Err(invalid_input(
            "the message has no files: list each file's media hash key in the message's \
             attachments, then encrypt the file with the payload that returns",
        ));
    }
    Err(invalid_input(format!(
        "media_hash_key '{}' is not one of the message's files, whose media hash keys are {}: \
         pass one of those, or list this file in the message's attachments",
        media_hash_key,
        own.join(", ")
    )))
}

/// A decrypted message and what its attachments' keys come from.
struct OpenedMessage {
    contents: MessageContents,
    keys: AttachmentKeys,
}

/// What a message's contents and attachments are encrypted under.
enum AttachmentKeys {
    /// Every attachment is under the conversation key.
    Conversation(XChatConversationKey),
    /// Each attachment has a key derived from the message key and the
    /// attachment's id.
    Message {
        message_key: XChatConversationKey,
        message_id: String,
    },
}

impl OpenedMessage {
    /// The key of the attachment carrying `media_hash_key`, when the message
    /// has one.
    fn attachment_key(
        &self,
        media_hash_key: &str,
    ) -> Result<Option<XChatConversationKey>, SdkError> {
        let attachments = self.contents.attachments.as_deref().unwrap_or_default();
        let Some((position, own_id)) = find_attachment(attachments, media_hash_key) else {
            return Ok(None);
        };
        let key = match &self.keys {
            AttachmentKeys::Conversation(conversation_key) => conversation_key.clone(),
            AttachmentKeys::Message {
                message_key,
                message_id,
            } => message_keys::derive_attachment_key(
                message_key,
                &message_keys::resolve_attachment_id(own_id, message_id, position),
            )?,
        };
        Ok(Some(key))
    }
}

/// How the caller passed the conversation key, so errors name that input.
#[derive(Clone, Copy)]
enum KeySource {
    /// A key map (`conversation_keys`), as the decrypt calls take.
    Map,
    /// One key and its version (`conversation_key`), as the encrypt calls take.
    Single,
}

/// Decrypt the message `event`, whose detail is `create`. Its key is the
/// conversation key for its version from `conversation_keys`, or, when the
/// map lacks that version, `carried_message_key` for a message that uses a
/// message key. `which` names the message in errors and `key_source` how
/// the key was passed.
fn open_message(
    event: &MessageEvent,
    create: &MessageCreateEvent,
    conversation_keys: &HashMap<String, XChatConversationKey>,
    carried_message_key: Option<&[u8]>,
    which: &str,
    key_source: KeySource,
) -> Result<OpenedMessage, SdkError> {
    let Some(version) = create.conversation_key_version.as_deref() else {
        return Err(invalid_input(format!(
            "{which} is not encrypted, so neither is its media: use the downloaded bytes as they \
             are"
        )));
    };
    let carried_message_key = carried_message_key
        .filter(|_| message_keys::uses_message_key(create.contents_encryption_version));
    let (keys, key_source) = match (conversation_keys.get(version), carried_message_key) {
        (Some(conversation_key), _) => {
            let keys = match ChatCore::message_key_for(event, conversation_key)? {
                Some(message_key) => AttachmentKeys::Message {
                    message_key,
                    message_id: message_id(event, which)?,
                },
                None => AttachmentKeys::Conversation(conversation_key.clone()),
            };
            let source = match key_source {
                KeySource::Map => format!("the key for version '{version}' in conversation_keys"),
                KeySource::Single => format!("conversation_key (version '{version}')"),
            };
            (keys, source)
        }
        (None, Some(bytes)) => {
            let message_key =
                XChatConversationKey::from_bytes(bytes.to_vec()).ok_or_else(|| {
                    invalid_input(format!(
                    "the key the reply carries for {which} is not 32 bytes: pass {which}'s own \
                     event"
                ))
                })?;
            let keys = AttachmentKeys::Message {
                message_key,
                message_id: message_id(event, which)?,
            };
            (keys, format!("the key the reply carries for {which}"))
        }
        (None, None) => {
            let mut versions: Vec<&str> = conversation_keys.keys().map(String::as_str).collect();
            versions.sort_unstable();
            return Err(SdkError::Crypto(CryptoError::DecryptionFailed(format!(
                "conversation_keys has no key for version '{version}', which {which} is \
                 encrypted under (it has versions [{}]): pass the conversation's key map from \
                 decrypt_events or extract_conversation_keys, including version '{version}'",
                versions.join(", ")
            ))));
        }
    };

    let encrypted = create
        .contents
        .as_ref()
        .ok_or_else(|| invalid_input(format!("{which} has no contents")))?;
    let contents_key = match &keys {
        AttachmentKeys::Conversation(conversation_key) => conversation_key,
        AttachmentKeys::Message { message_key, .. } => message_key,
    };
    let plaintext = decrypt_message_bytes(contents_key, encrypted).map_err(|_| {
        SdkError::Crypto(CryptoError::DecryptionFailed(format!(
            "{key_source} does not decrypt {which}: pass the conversation key for version \
             '{version}'"
        )))
    })?;
    let contents = match ChatCore::parse_thrift_entry_contents(&plaintext)? {
        MessageEntryContents::Message(contents) => *contents,
        MessageEntryContents::MessageEdit(_) => {
            return Err(invalid_input(format!(
                "{which} is an edit, and edits carry no media: pass the event of the message \
                 that was edited"
            )))
        }
        _ => {
            return Err(invalid_input(format!(
                "{which} is a reaction, read marker, or other entry without media: pass the \
                 event of the message that carries the media"
            )))
        }
    };
    Ok(OpenedMessage { contents, keys })
}

/// Decrypt the message a reply quotes, embedded in the reply's preview.
fn open_quoted(
    reply: &MessageEvent,
    preview: &ReplyingToPreview,
    conversation_keys: &HashMap<String, XChatConversationKey>,
) -> Result<OpenedMessage, SdkError> {
    let Some(quoted) = preview.raw_event_message_create.as_ref() else {
        return Err(invalid_input(
            "the reply does not embed the message it quotes, so that message's media can't be \
             opened through the reply: pass the quoted message's own event",
        ));
    };
    if quoted.conversation_id.is_none() || quoted.conversation_id != reply.conversation_id {
        return Err(invalid_input(
            "the reply quotes a message from another conversation: pass the quoted message's \
             own event",
        ));
    }
    let Some(MessageEventDetail::MessageCreateEvent(create)) = &quoted.detail else {
        return Err(invalid_input(
            "the reply's quoted event is not a message: pass the event of the message that \
             carries the media",
        ));
    };
    open_message(
        quoted,
        create,
        conversation_keys,
        preview.raw_event_message_key.as_deref(),
        "the quoted message",
        KeySource::Map,
    )
}

fn message_id(event: &MessageEvent, which: &str) -> Result<String, SdkError> {
    event
        .message_id
        .clone()
        .ok_or_else(|| invalid_input(format!("{which} has no message id")))
}

/// The position and own id of the attachment carrying `media_hash_key`: a
/// media attachment, or a link card whose banner or favicon it is. Payment
/// receipts take no position, as the native clients leave them out of a
/// message's attachments before numbering them.
fn find_attachment<'a>(
    attachments: &'a [Box<MessageAttachment>],
    media_hash_key: &str,
) -> Option<(usize, Option<&'a str>)> {
    attachments
        .iter()
        .filter(|attachment| !matches!(***attachment, MessageAttachment::PaymentReceipt(_)))
        .enumerate()
        .find_map(|(position, attachment)| {
            let own_id = match &**attachment {
                MessageAttachment::Media(media)
                    if media.media_hash_key.as_deref() == Some(media_hash_key) =>
                {
                    media.attachment_id.as_deref()
                }
                MessageAttachment::Url(card)
                    if card_images(card).any(|image| image == media_hash_key) =>
                {
                    card.attachment_id.as_deref()
                }
                _ => return None,
            };
            Some((position, own_id))
        })
}

fn card_images(card: &UrlAttachment) -> impl Iterator<Item = &str> {
    [
        &card.banner_image_media_hash_key,
        &card.favicon_image_media_hash_key,
    ]
    .into_iter()
    .filter_map(|image| image.as_ref()?.media_hash_key.as_deref())
}

fn media_hash_keys(attachments: Option<&[Box<MessageAttachment>]>) -> Vec<String> {
    attachments
        .unwrap_or_default()
        .iter()
        .flat_map(|attachment| match &**attachment {
            MessageAttachment::Media(media) => media.media_hash_key.iter().cloned().collect(),
            MessageAttachment::Url(card) => card_images(card).map(str::to_string).collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn invalid_input(message: impl Into<String>) -> SdkError {
    SdkError::Crypto(CryptoError::InvalidInput(message.into()))
}
