//! Decrypting media with the message event that carries it.

use super::test_support::{
    envelope, frame, hex_key, holder, key, keys, known_answer_media_message, media, message_event,
    message_key, Party, KAT_CONVERSATION_KEY, KAT_FIRST_ATTACHMENT_KEY, KAT_KEY_SENDER,
    KAT_SECOND_ATTACHMENT_KEY,
};
use super::*;
use crate::crypto::encryption::encrypt_file;
use crate::pipeline::serialize_thrift;
use crate::thrift::event::{
    MessageCreateEvent, MessageEvent as ThriftEvent, MessageEventDetail as Detail,
    MessageEventSignature,
};
use crate::thrift::product::{
    MessageAttachment as ThriftAttachment, MessageContents, MessageEdit,
    MessageEntryContents as Contents, MessageReactionAdd, PaymentReceiptAttachment,
    ReplyingToPreview as ThriftPreview, UrlAttachment as ThriftUrl,
    UrlAttachmentImage as ThriftUrlImage,
};

fn encrypt_media(key: &XChatConversationKey, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_file(key, Cursor::new(plaintext), &mut out).unwrap();
    out
}

/// Decrypt `encrypted` as the media `media_hash_key` names in `event`, on an
/// instance that has decrypted nothing before.
fn open(
    event: &ThriftEvent,
    conversation_keys: &HashMap<String, XChatConversationKey>,
    media_hash_key: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, SdkError> {
    ChatCore::new().decrypt_file(DecryptFileParams::new(
        encrypted.to_vec(),
        frame(event),
        conversation_keys.clone(),
        media_hash_key,
    ))
}

fn open_incrementally(
    event: &ThriftEvent,
    conversation_keys: &HashMap<String, XChatConversationKey>,
    media_hash_key: &str,
    encrypted: &[u8],
    step: usize,
) -> Result<Vec<u8>, SdkError> {
    let mut decryptor = ChatCore::new().file_decryptor(FileDecryptorParams::new(
        frame(event),
        conversation_keys.clone(),
        media_hash_key,
    ))?;
    let mut plaintext = Vec::new();
    for chunk in encrypted.chunks(step) {
        plaintext.extend(decryptor.push(chunk)?);
    }
    plaintext.extend(decryptor.finish()?);
    Ok(plaintext)
}

fn error_text(result: Result<Vec<u8>, SdkError>) -> String {
    result.unwrap_err().to_string()
}

/// A v10 message from `author` under key version "7" that uses a message
/// key, carrying `attachments`.
#[allow(clippy::vec_box)]
fn message_with(
    author: &Party,
    message_id: &str,
    conversation_key: &XChatConversationKey,
    attachments: Vec<Box<ThriftAttachment>>,
) -> ThriftEvent {
    message_event(
        author,
        message_id,
        "100",
        "7",
        Some(1),
        10,
        &message_key(conversation_key, &author.user_id, message_id),
        &holder(MessageContents {
            message_text: Some("media".to_string()),
            attachments: Some(attachments),
            ..Default::default()
        }),
    )
}

fn link_card(banner: &str, favicon: &str) -> Box<ThriftAttachment> {
    let image = |hash: &str| {
        Some(Box::new(ThriftUrlImage {
            media_hash_key: Some(hash.to_string()),
            ..Default::default()
        }))
    };
    Box::new(ThriftAttachment::Url(Box::new(ThriftUrl {
        url: Some("https://example.com".to_string()),
        banner_image_media_hash_key: image(banner),
        favicon_image_media_hash_key: image(favicon),
        display_title: Some("Example".to_string()),
        ..Default::default()
    })))
}

fn attachment_key(message_key: &XChatConversationKey, attachment_id: &str) -> XChatConversationKey {
    message_keys::derive_attachment_key(message_key, attachment_id).unwrap()
}

// The message's own media.

#[test]
fn one_file_opens_with_its_attachment_key() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_with(&author, "m-1", &ckey, vec![media("photo", None)]);
    let plaintext: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let encrypted = encrypt_media(
        &attachment_key(&message_key(&ckey, "1001", "m-1"), "m-1"),
        &plaintext,
    );
    let map = keys("7", &ckey);

    assert_eq!(open(&event, &map, "photo", &encrypted).unwrap(), plaintext);
    for step in [1, 24, 1041, 4096] {
        assert_eq!(
            open_incrementally(&event, &map, "photo", &encrypted, step).unwrap(),
            plaintext,
            "step={step}"
        );
    }
}

#[test]
fn several_files_open_with_the_known_attachment_keys() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    let map = keys("7", &hex_key(KAT_CONVERSATION_KEY));
    let first = encrypt_media(&hex_key(KAT_FIRST_ATTACHMENT_KEY), &[1u8; 3000]);
    let second = encrypt_media(&hex_key(KAT_SECOND_ATTACHMENT_KEY), &[2u8; 10]);

    assert_eq!(
        open(&event, &map, "photo-a", &first).unwrap(),
        vec![1u8; 3000]
    );
    assert_eq!(
        open(&event, &map, "photo-b", &second).unwrap(),
        vec![2u8; 10]
    );
    assert_eq!(
        open_incrementally(&event, &map, "photo-b", &second, 7).unwrap(),
        vec![2u8; 10]
    );
}

#[test]
fn a_set_attachment_id_names_the_key_even_when_empty() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_with(
        &author,
        "m-ids",
        &ckey,
        vec![
            media("a", Some("att-9")),
            media("b", Some("")),
            media("c", None),
        ],
    );
    let msg_key = message_key(&ckey, "1001", "m-ids");
    for (hash, attachment_id) in [("a", "att-9"), ("b", ""), ("c", "m-ids#2")] {
        let encrypted = encrypt_media(&attachment_key(&msg_key, attachment_id), hash.as_bytes());
        assert_eq!(
            open(&event, &keys("7", &ckey), hash, &encrypted).unwrap(),
            hash.as_bytes(),
            "{hash}"
        );
    }
}

#[test]
fn positions_count_attachments_the_sdk_does_not_surface() {
    let author = Party::new("1001");
    let ckey = key(6);
    let receipt = Box::new(ThriftAttachment::PaymentReceipt(Box::new(
        PaymentReceiptAttachment {
            receipt_token: Some("token".to_string()),
        },
    )));
    let event = message_with(&author, "m-2", &ckey, vec![receipt, media("photo", None)]);
    let encrypted = encrypt_media(
        &attachment_key(&message_key(&ckey, "1001", "m-2"), "m-2#1"),
        b"photo",
    );
    assert_eq!(
        open(&event, &keys("7", &ckey), "photo", &encrypted).unwrap(),
        b"photo"
    );
}

#[test]
fn a_link_cards_banner_and_favicon_share_the_cards_key() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_with(
        &author,
        "m-card",
        &ckey,
        vec![media("photo", None), link_card("banner", "favicon")],
    );
    let msg_key = message_key(&ckey, "1001", "m-card");
    let map = keys("7", &ckey);

    let card_key = attachment_key(&msg_key, "m-card#1");
    for hash in ["banner", "favicon"] {
        let encrypted = encrypt_media(&card_key, hash.as_bytes());
        assert_eq!(
            open(&event, &map, hash, &encrypted).unwrap(),
            hash.as_bytes()
        );
    }
    let photo = encrypt_media(&attachment_key(&msg_key, "m-card"), b"photo");
    assert_eq!(open(&event, &map, "photo", &photo).unwrap(), b"photo");
}

#[test]
fn old_format_media_opens_with_the_conversation_key() {
    let author = Party::new("1001");
    let ckey = key(6);
    let contents = holder(MessageContents {
        attachments: Some(vec![media("photo", None), link_card("banner", "favicon")]),
        ..Default::default()
    });
    let encrypted = encrypt_media(&ckey, b"old format");
    for (contents_encryption_version, signature_version) in [(None, 7), (Some(0), 10)] {
        let event = message_event(
            &author,
            "m-old",
            "100",
            "7",
            contents_encryption_version,
            signature_version,
            &ckey,
            &contents,
        );
        for hash in ["photo", "banner", "favicon"] {
            assert_eq!(
                open(&event, &keys("7", &ckey), hash, &encrypted).unwrap(),
                b"old format",
                "{hash} at v{signature_version}"
            );
        }
    }
}

#[test]
fn the_key_comes_from_the_version_the_message_names() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_with(&author, "m-3", &ckey, vec![media("photo", None)]);
    let encrypted = encrypt_media(
        &attachment_key(&message_key(&ckey, "1001", "m-3"), "m-3"),
        b"photo",
    );
    let map: HashMap<String, XChatConversationKey> = [
        ("6".to_string(), key(1)),
        ("7".to_string(), ckey.clone()),
        ("8".to_string(), key(2)),
    ]
    .into_iter()
    .collect();
    assert_eq!(open(&event, &map, "photo", &encrypted).unwrap(), b"photo");
}

// Media quoted from another message.

const AUTHOR: &str = "1001";
const REPLIER: &str = "1002";

/// An original message from the author under key version "7" with a photo,
/// and what a reply to it under version "8" needs.
struct Quote {
    replier: Party,
    original_ckey: XChatConversationKey,
    reply_ckey: XChatConversationKey,
    original: ThriftEvent,
    /// The original's message key, when it uses one.
    original_message_key: Option<XChatConversationKey>,
}

impl Quote {
    fn new(uses_message_key: bool) -> Self {
        let author = Party::new(AUTHOR);
        let original_ckey = key(7);
        let original_message_key =
            uses_message_key.then(|| message_key(&original_ckey, AUTHOR, "orig-1"));
        let (cev, version) = if uses_message_key {
            (Some(1), 10)
        } else {
            (None, 7)
        };
        let original = message_event(
            &author,
            "orig-1",
            "200",
            "7",
            cev,
            version,
            original_message_key.as_ref().unwrap_or(&original_ckey),
            &holder(MessageContents {
                message_text: Some("Hello there".to_string()),
                attachments: Some(vec![media("photo", None)]),
                ..Default::default()
            }),
        );
        Self {
            replier: Party::new(REPLIER),
            original_ckey,
            reply_ckey: key(8),
            original,
            original_message_key,
        }
    }

    /// A preview that embeds the original, shows its photo, and carries the
    /// original's message key when it has one.
    fn preview(&self) -> ThriftPreview {
        ThriftPreview {
            sender_id: Some(AUTHOR.parse().unwrap()),
            message_text: Some("Hello there".to_string()),
            attachments: Some(vec![media("photo", None)]),
            replying_to_message_sequence_id: Some("200".to_string()),
            replying_to_message_id: Some("orig-1".to_string()),
            raw_event_message_create: Some(self.original.clone()),
            raw_event_message_key: self.original_message_key.as_ref().map(|k| k.to_bytes()),
            ..Default::default()
        }
    }

    /// The replier's reply under version "8", with its own `attachments`.
    #[allow(clippy::vec_box)]
    fn reply(
        &self,
        preview: ThriftPreview,
        attachments: Vec<Box<ThriftAttachment>>,
    ) -> ThriftEvent {
        message_event(
            &self.replier,
            "reply-1",
            "300",
            "8",
            None,
            7,
            &self.reply_ckey,
            &holder(MessageContents {
                message_text: Some("a reply".to_string()),
                attachments: Some(attachments),
                replying_to_preview: Some(Box::new(preview)),
                ..Default::default()
            }),
        )
    }

    fn photo_key(&self) -> XChatConversationKey {
        match &self.original_message_key {
            Some(message_key) => attachment_key(message_key, "orig-1"),
            None => self.original_ckey.clone(),
        }
    }

    fn reply_keys(&self) -> HashMap<String, XChatConversationKey> {
        keys("8", &self.reply_ckey)
    }

    fn both_keys(&self) -> HashMap<String, XChatConversationKey> {
        let mut map = self.reply_keys();
        map.insert("7".to_string(), self.original_ckey.clone());
        map
    }
}

#[test]
fn quoted_media_opens_with_the_key_the_reply_carries() {
    let quote = Quote::new(true);
    let reply = quote.reply(quote.preview(), Vec::new());
    let encrypted = encrypt_media(&quote.photo_key(), b"quoted photo");
    assert_eq!(
        open(&reply, &quote.reply_keys(), "photo", &encrypted).unwrap(),
        b"quoted photo"
    );
    assert_eq!(
        open_incrementally(&reply, &quote.reply_keys(), "photo", &encrypted, 5).unwrap(),
        b"quoted photo"
    );
}

#[test]
fn quoted_media_opens_with_the_quoted_messages_version_from_the_map() {
    let quote = Quote::new(true);
    let mut preview = quote.preview();
    preview.raw_event_message_key = None;
    let reply = quote.reply(preview, Vec::new());
    let encrypted = encrypt_media(&quote.photo_key(), b"quoted photo");
    assert_eq!(
        open(&reply, &quote.both_keys(), "photo", &encrypted).unwrap(),
        b"quoted photo"
    );
}

#[test]
fn the_key_map_is_used_before_a_carried_key() {
    let quote = Quote::new(true);
    let mut preview = quote.preview();
    preview.raw_event_message_key = Some(vec![0u8; 32]);
    let reply = quote.reply(preview, Vec::new());
    let encrypted = encrypt_media(&quote.photo_key(), b"quoted photo");
    assert_eq!(
        open(&reply, &quote.both_keys(), "photo", &encrypted).unwrap(),
        b"quoted photo"
    );
}

#[test]
fn quoted_old_format_media_opens_with_the_quoted_messages_conversation_key() {
    let quote = Quote::new(false);
    let reply = quote.reply(quote.preview(), Vec::new());
    let encrypted = encrypt_media(&quote.photo_key(), b"quoted photo");
    assert_eq!(
        open(&reply, &quote.both_keys(), "photo", &encrypted).unwrap(),
        b"quoted photo"
    );
}

#[test]
fn a_replys_own_media_and_its_quoted_media_each_use_their_own_key() {
    let quote = Quote::new(true);
    let reply = quote.reply(quote.preview(), vec![media("reply-photo", None)]);
    let own = encrypt_media(&quote.reply_ckey, b"own photo");
    let quoted = encrypt_media(&quote.photo_key(), b"quoted photo");
    let map = quote.reply_keys();
    assert_eq!(
        open(&reply, &map, "reply-photo", &own).unwrap(),
        b"own photo"
    );
    assert_eq!(
        open(&reply, &map, "photo", &quoted).unwrap(),
        b"quoted photo"
    );
}

#[test]
fn a_quoted_message_whose_key_version_is_missing_names_that_version() {
    let quote = Quote::new(false);
    let reply = quote.reply(quote.preview(), Vec::new());
    let encrypted = encrypt_media(&quote.photo_key(), b"quoted photo");
    let err = error_text(open(&reply, &quote.reply_keys(), "photo", &encrypted));
    assert!(err.contains("no key for version '7'"), "{err}");
    assert!(err.contains("the quoted message"), "{err}");
    assert!(err.contains("including version '7'"), "{err}");
}

#[test]
fn a_reply_that_does_not_embed_the_quoted_message_says_to_pass_that_message() {
    let quote = Quote::new(true);
    let mut preview = quote.preview();
    preview.raw_event_message_create = None;
    let reply = quote.reply(preview, Vec::new());
    let err = error_text(open(&reply, &quote.reply_keys(), "photo", b"bytes"));
    assert!(
        err.contains("does not embed the message it quotes"),
        "{err}"
    );
    assert!(err.contains("pass the quoted message's own event"), "{err}");
}

#[test]
fn a_quoted_message_from_another_conversation_is_refused() {
    let quote = Quote::new(true);
    let mut preview = quote.preview();
    if let Some(original) = preview.raw_event_message_create.as_mut() {
        original.conversation_id = Some("2:99".to_string());
    }
    let reply = quote.reply(preview, Vec::new());
    let err = error_text(open(&reply, &quote.reply_keys(), "photo", b"bytes"));
    assert!(err.contains("another conversation"), "{err}");
}

#[test]
fn a_wrong_carried_key_says_which_version_to_pass() {
    let quote = Quote::new(true);
    let mut preview = quote.preview();
    preview.raw_event_message_key = Some(vec![0u8; 32]);
    let reply = quote.reply(preview, Vec::new());
    let err = error_text(open(&reply, &quote.reply_keys(), "photo", b"bytes"));
    assert!(err.contains("the key the reply carries"), "{err}");
    assert!(
        err.contains("pass the conversation key for version '7'"),
        "{err}"
    );
}

// Errors.

#[test]
fn a_missing_key_version_names_the_version_to_pass() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    for map in [HashMap::new(), keys("9", &key(1))] {
        let err = error_text(open(&event, &map, "photo-a", b"bytes"));
        assert!(
            err.contains("conversation_keys has no key for version '7'"),
            "{err}"
        );
        assert!(err.contains("including version '7'"), "{err}");
    }
    let err = error_text(open(&event, &keys("9", &key(1)), "photo-a", b"bytes"));
    assert!(err.contains("[9]"), "{err}");
}

#[test]
fn a_wrong_key_for_the_version_says_so() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    let err = error_text(open(&event, &keys("7", &key(9)), "photo-a", b"bytes"));
    assert!(
        err.contains("the key for version '7' in conversation_keys does not decrypt the message"),
        "{err}"
    );
}

#[test]
fn a_media_hash_key_that_is_not_in_the_message_lists_the_ones_that_are() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    let map = keys("7", &hex_key(KAT_CONVERSATION_KEY));
    let err = error_text(open(&event, &map, "photo-z", b"bytes"));
    assert!(
        err.contains("media_hash_key 'photo-z' is not in the message"),
        "{err}"
    );
    assert!(err.contains("photo-a, photo-b"), "{err}");

    let err = error_text(open(&event, &map, "", b"bytes"));
    assert!(err.contains("media_hash_key is empty"), "{err}");
}

#[test]
fn quoted_media_hash_keys_are_listed_too() {
    let quote = Quote::new(true);
    let reply = quote.reply(quote.preview(), vec![media("reply-photo", None)]);
    let err = error_text(open(&reply, &quote.reply_keys(), "photo-z", b"bytes"));
    assert!(err.contains("reply-photo, photo"), "{err}");
}

#[test]
fn a_message_without_media_says_so() {
    let author = Party::new("1001");
    let ckey = key(6);
    let event = message_event(
        &author,
        "m-text",
        "100",
        "7",
        Some(1),
        10,
        &message_key(&ckey, "1001", "m-text"),
        &holder(MessageContents {
            message_text: Some("just text".to_string()),
            ..Default::default()
        }),
    );
    let err = error_text(open(&event, &keys("7", &ckey), "photo", b"bytes"));
    assert!(err.contains("the message has no media"), "{err}");
}

#[test]
fn an_event_that_is_not_a_message_says_so() {
    let author = Party::new("1001");
    let typing = envelope(
        "t-1",
        &author,
        "100",
        Detail::MessageTypingEvent(Default::default()),
        MessageEventSignature::default(),
    );
    let err = error_text(open(&typing, &keys("7", &key(6)), "photo", b"bytes"));
    assert!(err.contains("the event is not a message"), "{err}");
}

#[test]
fn edits_and_reactions_say_they_carry_no_media() {
    let author = Party::new("1001");
    let ckey = key(6);
    let entry = |contents: Contents| {
        serialize_thrift(&MessageEntryHolder::new(Some(Box::new(contents)))).unwrap()
    };
    let edit = entry(Contents::MessageEdit(Box::new(MessageEdit::new(
        Some("100".to_string()),
        Some("edited".to_string()),
        None,
        None,
    ))));
    let reaction = entry(Contents::ReactionAdd(Box::new(MessageReactionAdd {
        message_sequence_id: Some("100".to_string()),
        emoji: Some("+1".to_string()),
        ..Default::default()
    })));
    for (plaintext, expected) in [(edit, "is an edit"), (reaction, "is a reaction")] {
        let event = message_event(&author, "m-4", "101", "7", None, 7, &ckey, &plaintext);
        let err = error_text(open(&event, &keys("7", &ckey), "photo", b"bytes"));
        assert!(err.contains(expected), "{err}");
    }
}

#[test]
fn an_unencrypted_message_says_its_media_is_not_encrypted() {
    let author = Party::new("1001");
    let plain = envelope(
        "m-plain",
        &author,
        "100",
        Detail::MessageCreateEvent(MessageCreateEvent {
            contents: Some(holder(MessageContents {
                attachments: Some(vec![media("photo", None)]),
                ..Default::default()
            })),
            ..Default::default()
        }),
        MessageEventSignature::default(),
    );
    let err = error_text(open(&plain, &keys("7", &key(6)), "photo", b"bytes"));
    assert!(err.contains("the message is not encrypted"), "{err}");
    assert!(
        err.contains("use the downloaded bytes as they are"),
        "{err}"
    );
}

#[test]
fn wrong_bytes_name_the_media_and_what_to_pass() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    let map = keys("7", &hex_key(KAT_CONVERSATION_KEY));
    let second = encrypt_media(&hex_key(KAT_SECOND_ATTACHMENT_KEY), &[2u8; 3000]);

    for err in [
        error_text(open(&event, &map, "photo-a", &second)),
        error_text(open_incrementally(&event, &map, "photo-a", &second, 100)),
    ] {
        assert!(
            err.contains("not the encrypted file of media_hash_key 'photo-a'"),
            "{err}"
        );
        assert!(
            err.contains("pass the bytes downloaded for that media hash key"),
            "{err}"
        );
    }
}

#[test]
fn truncated_bytes_say_to_pass_the_complete_download() {
    let author = Party::new(KAT_KEY_SENDER);
    let event = known_answer_media_message(&author);
    let map = keys("7", &hex_key(KAT_CONVERSATION_KEY));
    let first = encrypt_media(&hex_key(KAT_FIRST_ATTACHMENT_KEY), &[1u8; 3000]);

    for cut in [&first[..10], &first[..24 + 2 * 1041]] {
        for err in [
            error_text(open(&event, &map, "photo-a", cut)),
            error_text(open_incrementally(&event, &map, "photo-a", cut, 300)),
        ] {
            assert!(
                err.contains("media_hash_key 'photo-a' are truncated"),
                "{err}"
            );
            assert!(err.contains("pass the complete bytes"), "{err}");
        }
    }
    let err = error_text(open(&event, &map, "photo-a", &first[..first.len() - 1]));
    assert!(
        err.contains("truncated, corrupted, or another file"),
        "{err}"
    );
}

#[test]
fn an_event_that_is_not_base64_is_rejected() {
    let err = ChatCore::new()
        .decrypt_file(DecryptFileParams::new(
            b"bytes".to_vec(),
            "not base64!",
            HashMap::new(),
            "photo",
        ))
        .unwrap_err();
    assert!(!err.to_string().is_empty());
}
