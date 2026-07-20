namespace java com.x.dmv2.thriftjava
#@namespace scala com.x.dmv2.thriftscala
#@namespace strato com.x.dmv2
#@namespace py com.x.dmv2.thriftpython

include "event.thrift"

# For now this is just a single field, but I want to keep the flexibility of adding more later
struct MessageEntryHolder {
    1: optional MessageEntryContents contents
}

union MessageEntryContents {
    1: MessageContents message
    2: MessageReactionAdd reaction_add
    3: MessageReactionRemove reaction_remove
    4: MessageEdit message_edit
    5: MarkConversationRead mark_conversation_read
    6: MarkConversationUnread mark_conversation_unread
    7: PinConversation pin_conversation
    8: UnpinConversation unpin_conversation
    9: ScreenCaptureDetected screen_capture_detected
    10: AVCallEnded av_call_ended
    11: AVCallMissed av_call_missed
    12: DraftMessage draft_message
    13: AcceptMessageRequest accept_message_request
    14: NicknameMessage nickname_message
    15: SetVerifiedStatus set_verified_status
    16: AVCallStarted av_call_started
}

struct MarkConversationRead {
    1: optional string seen_until_sequence_id
    2: optional i64 seen_at_millis
}

struct MarkConversationUnread {
    1: optional string seen_until_sequence_id
}

struct PinConversation {
    1: optional string conversation_id
}

struct UnpinConversation {
    1: optional string conversation_id
}

struct AVCallEnded {
    1: optional i64 sent_at_millis
    2: optional i64 duration_seconds
    3: optional bool is_audio_only
    // 4: deprecated
    5: optional string broadcast_id
}

struct AVCallMissed {
    1: optional i64 sent_at_millis
    2: optional bool is_audio_only
}

struct AVCallStarted {
    1: optional bool is_audio_only
    // 2: deprecated
    3: optional string broadcast_id
}

enum ScreenCaptureType {
    SCREENSHOT = 1
    RECORDING = 2
}

struct ScreenCaptureDetected {
    1: optional ScreenCaptureType type
}

struct DraftMessage {
    1: optional string conversation_id
    2: optional string draft_text
}

struct AcceptMessageRequest {}

struct NicknameMessage {
    1: optional i64 user_id
    2: optional string nickname_text
}

struct SetVerifiedStatus {
    1: optional i64 user_id
    2: optional bool verified_status
}

struct MessageContents {
    1: optional string message_text
    2: optional list<RichTextEntity> entities
    // Note: we currently only ever send one attachment, this is just a list for possible future improvements
    3: optional list<MessageAttachment> attachments
    4: optional ReplyingToPreview replying_to_preview
    // 5 was editEventIds but wasn't actually used and had a serialization bug, DO NOT REUSE
    6: optional ForwardedMessage forwarded_message
    7: optional SentFromSurface sent_from
    8: optional QuickReply quick_reply
    9: optional list<CallToAction> ctas
    10: optional map<string, string> additional_fields
}

enum SentFromSurface {
    CONVERSATION_SCREEN_COMPOSER = 1
    NOTIFICATION_REPLY = 2
    SHARE_SHEET = 3
    PAYMENTS_SUPPORT_COMPOSER = 4
    MESSAGE_FORWARD_SHEET = 5
}

struct RichTextEntity {
    1: optional i32 start_index
    2: optional i32 end_index
    3: optional RichTextContent content
}

union RichTextContent {
    1: HashtagRichTextContent hashtag
    2: CashtagRichTextContent cashtag
    3: MentionRichTextContent mention
    4: UrlRichTextContent url
    5: EmailRichTextContent email
    6: AddressRichTextContent address
    7: PhoneNumberRichTextContent phoneNumber
}

struct HashtagRichTextContent {
}

struct CashtagRichTextContent {
}

struct MentionRichTextContent {
}

struct UrlRichTextContent {
}

struct EmailRichTextContent {
}

struct AddressRichTextContent {
}

struct PhoneNumberRichTextContent {
}

struct ReplyingToPreview {
    1: optional i64 sender_id
    2: optional string message_text
    3: optional list<RichTextEntity> entities
    // Note: we currently only ever send one attachment, this is just a list for possible future improvements
    4: optional list<MessageAttachment> attachments
    5: optional string sender_display_name
    6: optional string replying_to_message_sequence_id
    7: optional string replying_to_message_id
    8: optional event.MessageEvent raw_event_message_create
    9: optional event.MessageEvent raw_event_edit_message
    10: optional list<event.MessageEvent> raw_event_ckces
    11: optional ReplyAVCallCard av_call_card
    12: optional string replying_to_attachment_id
}

union ReplyAVCallCard {
    1: AVCallEnded ended
    2: AVCallMissed missed
    3: AVCallStarted started
}

struct ForwardedMessage {
    1: optional string message_text
    2: optional list<RichTextEntity> entities
}

union MessageAttachment {
    1: MediaAttachment media
    2: PostAttachment post
    3: UrlAttachment url
    4: UnifiedCardAttachment unified_card
    5: MoneyAttachment money
    6: JetfuelAttachment jetfuel
}

struct JetfuelAttachment {
    // We used to include the payload but this would allow attackers to craft malicious jetfuel messages.
    // DEPRECATED 1: optional string payload
    2: optional i32 height
    3: optional string url
    4: optional string attachment_id
}

struct MoneyAttachment {
    1: optional string fallbackText
    2: optional binary payload
}

// Posts are hydrated on the receiver side
struct PostAttachment {
    1: optional string rest_id
    2: optional string post_url
    3: optional string attachment_id
}

// Urls are hydrated on the sender side so we have to include metadata here
struct UrlAttachment {
    1: optional string url
    2: optional UrlAttachmentImage banner_image_media_hash_key
    3: optional UrlAttachmentImage favicon_image_media_hash_key
    4: optional string display_title
    5: optional string attachment_id
}

// Unified cards are hydrated on the receiver side
struct UnifiedCardAttachment {
    1: optional string url
    2: optional string attachment_id
}

struct UrlAttachmentImage {
    // This will point to an encrypted image if there's a ckey_version on the containing MCE
    1: optional string media_hash_key
    2: optional i64 filesize_bytes
    3: optional string filename
    4: optional MediaDimensions dimensions
}

struct MediaAttachment {
    1: optional string media_hash_key
    2: optional MediaDimensions dimensions
    3: optional MediaType type
    4: optional i64 duration_millis
    5: optional i64 filesize_bytes
    6: optional string filename
    7: optional string attachment_id
    8: optional string legacy_media_url_https
    9: optional string legacy_media_preview_url
    10: optional string grok_tag
}

struct MediaDimensions {
    1: optional i64 width
    2: optional i64 height
}

enum MediaType {
    IMAGE = 1
    GIF = 2
    VIDEO = 3
    AUDIO = 4
    FILE = 5
    SVG = 6
}

struct MessageReactionAdd {
    1: optional string message_sequence_id
    2: optional string emoji
    3: optional string message_attachment_id
}

struct MessageReactionRemove {
    1: optional string message_sequence_id
    2: optional string emoji
    3: optional string message_attachment_id
}

struct MessageEdit {
    1: optional string message_sequence_id
    2: optional string updated_text
    3: optional list<RichTextEntity> entities
}

struct QuickReplyOption {
    1: optional string id
    2: optional string label
    3: optional string metadata
    4: optional string description
}

struct QuickReplyOptionsRequest {
    1: optional string id
    2: optional list<QuickReplyOption> options
}

struct QuickReplyOptionsResponse {
    1: optional string request_id
    2: optional string metadata
    3: optional string selected_option_id
}

union QuickReplyRequest {
    1: QuickReplyOptionsRequest options
}

union QuickReplyResponse {
    1: QuickReplyOptionsResponse options
}

union QuickReply {
    1: QuickReplyRequest request
    2: QuickReplyResponse response
}

struct CallToAction {
    1: optional string label
    2: optional string url
}
