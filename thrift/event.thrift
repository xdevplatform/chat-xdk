namespace java com.x.dmv2.thriftjava
#@namespace scala com.x.dmv2.thriftscala
#@namespace strato com.x.dmv2
#@namespace py com.x.dmv2.thriftpython

include "trees.thrift"

// Higher the number, lower the priority. everyting assumed A = 1 if not set
enum EventQueuePriority {
    A = 1
    B = 2
    C = 3
    D = 4
    E = 5
} (persisted='true', strato.graphql.typename='XChatEventQueuePriority')

// Additional actions client will need to perform when processing an MCE
enum AdditionalAction {
    // fetch the latest page of a conversation if the ckey is missing
    FETCH_CONV_IF_MISSING_CKEY
} (persisted='true', strato.graphql.typename='XChatAdditionalAction')

struct PinConversations {
    1: optional list<string> conversation_ids_to_pin
} (persisted='true', strato.graphql.typename='XChatPinConversations')

struct SetNicknames {
    1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatSetNicknames')

struct SetVerifiedUsers {
    1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatSetVerifiedUsers')

// Full snapshot of per-user settings synced across devices via an encrypted MCE in the
// self conversation (Encrypted Metadata Sync). Serialized + encrypted into MCE `contents`
struct UserMetadata {
    1: optional list<string> pinned_conversation_ids
    2: optional map<i64, string> user_id_to_nickname
    3: optional list<i64> safety_number_verified_user_ids
} (persisted='true', strato.graphql.typename='XChatUserMetadata')

struct MessageRequestInboxSummary {
    1: optional list<string> member_ids
    2: optional i32 unread_count_priority
    3: optional i32 unread_count_hidden
    4: optional bool has_unseen
    5: optional i64 latest_seen_seq_id
    6: optional i64 max_priority_seq
} (persisted='true', strato.graphql.typename='XChatMessageRequestInboxSummary')

struct SenderPrivilege {
    1: optional bool is_admin
    2: optional bool is_restricted_chat
} (persisted='true', strato.graphql.typename='XChatSenderPrivilege')

// Signed token from XMoney backend ratifying a transaction. Backend validates
// the JWT (signature, participants, expiry) on send before accepting the MCE.
struct ValidatePaymentToken {
    1: optional string receipt_token
} (persisted='true', strato.graphql.typename='XChatValidatePaymentToken')

struct FrankingData {
    1: optional binary franking_tag
    2: optional binary encrypted_nonce
    // deprecated
    // 3: optional binary encrypted_media_hash
    4: optional list<binary> encrypted_media_hashes   // multiple media, in attachment order
} (persisted='true', strato.graphql.typename='XChatFrankingData')

struct TargetedNotify {
    1: optional list<string> user_ids
    2: optional bool respect_mutes
} (persisted='true', strato.graphql.typename='XChatTargetedNotify')

struct MessageCreateEvent {
    100: optional binary contents
    101: optional string conversation_key_version
    102: optional bool should_notify
    103: optional i64 ttl_msec (GraphQlEncoding="NumericString")
    104: optional i64 delivered_at_msec (GraphQlEncoding="NumericString")
    105: optional bool is_pending_public_key
    106: optional EventQueuePriority priority
    107: optional list<AdditionalAction> additional_action_list
    108: optional FrankingData franking_data
    109: optional bool is_message_request
    // replaces additional-actions with something more extensible
    111: optional list<SideEffect> side_effects
    112: optional i16 contents_encryption_version
} (persisted='true', strato.graphql.typename='XChatMessageCreateEvent')

// Declared after MessageCreateEvent: the Rust generator boxes the elements of
// a list of unions only when the union is declared after the list's struct.
// This will replace AdditionalAction idea. Side-effect is something the client or backend will need to do
// when set by the client
union SideEffect {
    1: AdditionalAction additional_action
    2: TargetedNotify targeted_notify
    3: PinConversations pin_conversations
    4: SetNicknames set_nicknames
    5: SetVerifiedUsers set_verified_users
    6: SenderPrivilege sender_privilege
    7: ValidatePaymentToken validate_payment_token
} (persisted='true', strato.graphql.typename='XChatSideEffect')

enum GroupType {
    NORMAL = 0
    SUBSCRIBER_CHAT = 1
} (strato.graphql.typename='XChatGroupType', strato.case.format='preserve')

struct GroupCreate {
    1: optional list<string> member_ids
    2: optional list<string> admin_ids
    3: optional string title
    4: optional string avatar_url
    5: optional string conversation_key_version
    6: optional bool is_legacy_group_upgrade
    7: optional i64 ttl_msec (GraphQlEncoding="NumericString")
    8: optional GroupType group_type
} (persisted='true', strato.graphql.typename='XChatGroupCreate')

struct GroupTitleChange {
    1: optional string custom_title
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupTitleChange')

struct GroupAvatarUrlChange {
    1: optional string custom_avatar_url
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupAvatarUrlChange')

// Encrypted group description / "rules" change (see GroupMetadata.description in the backend).
struct GroupDescriptionChange {
    1: optional string custom_description
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupDescriptionChange')

struct GroupAdminAddChange {
    1: optional list<string> admin_ids
} (persisted='true', strato.graphql.typename='XChatGroupAdminAddChange')

struct GroupMemberAddChange {
    1: optional list<string> member_ids
    2: optional list<string> current_member_ids
    3: optional list<string> current_admin_ids
    4: optional string current_title
    5: optional string current_avatar_url
    6: optional string conversation_key_version
    7: optional i64 current_ttl_msec (GraphQlEncoding="NumericString")
    8: optional list<string> current_pending_member_ids
    9: optional bool screen_capture_blocking_enabled
   // deprecated
   // 10: optional bool invite_enabled
   11: optional GroupInviteEnable group_invite_enable
   12: optional GroupMemberAdminSettings admin_settings
   // Legacy join handoff. Retained for GraphQL/thrift schema compatibility; unset by server.
   13: optional map<string, binary> current_pmk_bundle (strato.graphql.typename='XChatCurrentPmkBundleEntry')
   14: optional string group_created_by_user_id
   // Rich join handoff (same shape as inbox pmk_bundle): message seq id -> PinnedMessageKey.
   15: optional map<string, PinnedMessageKey> rotated_pmk_bundle (strato.graphql.typename='XChatRotatedPmkBundleEntry')
   // Current encrypted group description, so members added later receive it.
   // 16 to stay in lockstep with the backend dm.thrift.
   16: optional string current_description
} (persisted='true', strato.graphql.typename='XChatGroupMemberAddChange')

struct GroupAdminRemoveChange {
    1: optional list<string> admin_ids
} (persisted='true', strato.graphql.typename='XChatGroupAdminRemoveChange')

struct GroupMemberRemoveChange {
    1: optional list<string> member_ids
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupMemberRemoveChange')

struct GroupInviteEnable {
    1: optional i64 expires_at_msec (GraphQlEncoding="NumericString")
    2: optional string invite_url
    3: optional string affiliate_id
} (persisted='true', strato.graphql.typename='XChatGroupInviteEnable')

struct GroupInviteDisable {
    1: optional string disabled_by_member_id
} (persisted='true', strato.graphql.typename='XChatGroupInviteDisable')

struct GroupJoinRequest {
    1: optional string requesting_user_id
} (persisted='true', strato.graphql.typename='XChatGroupJoinRequest')

struct GroupJoinReject {
    1: optional list<string> rejected_user_ids
} (persisted='true', strato.graphql.typename='XChatGroupJoinReject')

struct GroupAdminSettingsChange {
    1: optional bool edit_group_info
    2: optional bool edit_message_ttl
    3: optional bool block_screen_capture
    4: optional bool add_member
    5: optional bool send_message
    6: optional bool start_call
    // 7 was grok_settings but was never supported. Do not reuse.
} (persisted = 'true', strato.graphql.typename = 'XChatGroupAdminSettingsChange')

struct GroupMemberAdminSettings {
    1: optional bool edit_group_info
    2: optional bool edit_message_ttl
    3: optional bool block_screen_capture
    4: optional bool add_member
    5: optional bool send_message
    6: optional bool start_call
    // 7 was grok_settings but was never supported. Do not reuse.
} (persisted = 'true', strato.graphql.typename = 'XChatGroupMemberAdminSettings')

union GroupChange {
    1: GroupCreate group_create
    2: GroupTitleChange group_title_change
    3: GroupAvatarUrlChange group_avatar_change
    4: GroupAdminAddChange group_admin_add
    5: GroupMemberAddChange group_member_add
    6: GroupAdminRemoveChange group_admin_remove
    7: GroupMemberRemoveChange group_member_remove
    8: GroupInviteEnable group_invite_enable
    9: GroupInviteDisable group_invite_disable
    10: GroupJoinRequest group_join_request
    11: GroupJoinReject group_join_reject
    12: GroupAdminSettingsChange group_admin_settings_change
    14: GroupDescriptionChange group_description_change
} (persisted='true', strato.graphql.typename='XChatGroupChange')

struct GroupChangeEvent {
    1: optional GroupChange group_change
    2: optional bool for_key_rotation
} (persisted='true', strato.graphql.typename='XChatGroupChangeEvent')

struct ConversationParticipantKey {
    1: optional string user_id
    2: optional string encrypted_conversation_key
    3: optional string public_key_version
} (persisted='true', strato.graphql.typename='XChatConversationParticipantKey')

struct ConversationKeyChangeEvent {
    1: optional string conversation_key_version
    2: optional list<ConversationParticipantKey> conversation_participant_keys
    // 3: old ratchet tree impl
    4: optional trees.GroupOpData ratchet_tree_change
    5: optional bool for_key_rotation
} (persisted='true', strato.graphql.typename='XChatConversationKeyChangeEvent')

enum MessageActivityType {
    TYPING = 1
    RECORDING_VOICE_MESSAGE = 2
} (persisted='true', strato.graphql.typename='XChatMessageActivityType')

struct GrokBotMetadata {
    1: optional string agent_id
    2: optional string name
    3: optional string avatar_color
    4: optional string avatar_shape
} (persisted='true', strato.graphql.typename='XChatGrokBotMetadata')

struct MessageTypingEvent {
    1: optional string conversation_id
    2: optional MessageActivityType activity_type
    3: optional bool is_grok
    4: optional string created_at_msec
    5: optional GrokBotMetadata grok_bot
} (persisted='true', strato.graphql.typename='XChatMessageTypingEvent')

enum FailureType {
    EMPTY_DETAIL = 1
    INTERNAL_ERROR = 2
    CONTENTS_TOO_LARGE = 3
    TOO_MANY_MESSAGES = 4
    INVALID_SENDER_SIGNATURE = 5
    NON_LATEST_CKEY_VERSION = 6
    RECIPIENT_HAS_NOT_TRUSTED_CONVERSATION = 7
    RECIPIENT_KEY_HAS_CHANGED = 8
    ONLY_ENCRYPTED_MESSAGES_ALLOWED = 9
    REQUESTER_NOT_ADMIN = 10
    FLAGGED_AS_SPAM = 11
    // Sender hit their per-tier daily message-request limit (BotMaker rule RateLimitUntrustedDm).
    // The client decodes this into the Premium upsell prompt.
    RATE_LIMIT_UPSELL = 12
    // Sender's ECDSA signature failed send-side verification; client should route to keypair recovery.
    SIGNATURE_FAILED_TO_VERIFY_AGAINST_PUBLIC_KEY = 13
    // Catch-all for send failures without a more specific code.
    GENERIC_ERROR = 14
    // Sender is not a member of the group they're trying to send to.
    SENDER_NOT_GROUP_MEMBER = 15
    // Client signed with a signature_version below the minimum required protocol version.
    INVALID_SIGNATURE_VERSION = 16
    // Pin rejected: source message not found, already expired, or malformed PME.
    INVALID_PIN_REQUEST = 17
    // Pin rejected: the conversation already has the maximum number of pinned messages.
    TOO_MANY_PINS = 18
    // Could not validate the X Money receipt token (bad signature, expired, wrong participants, etc.).
    INVALID_X_MONEY_TOKEN = 19
} (persisted='false', strato.graphql.typename='XChatFailureType')

// Which tier's daily message-request cap a RATE_LIMIT_UPSELL refusal was enforced at (the
// BotMaker RateLimitUntrustedDm rule's RateLimitTier output feature). Lets clients tailor
// the Premium upsell copy to the limit the sender actually hit.
enum RateLimitTier {
    FREE = 1
    VERIFIED_PHONE = 2
    PREMIUM = 3
    PREMIUM_PLUS = 4
    PREMIUM_BUSINESS = 5
} (persisted='false', strato.graphql.typename='XChatRateLimitTier')

struct MessageFailureEvent {
    1: optional FailureType failure_type
    // Only set when failure_type is RATE_LIMIT_UPSELL.
    2: optional RateLimitTier rate_limit_tier
} (persisted='true', strato.graphql.typename='XChatMessageFailureEvent')

enum DeleteMessageAction {
    DELETE_FOR_SELF = 1
    DELETE_FOR_ALL = 2
} (persisted='true', strato.graphql.typename='XChatDeleteMessageAction')

struct MessageDeleteEvent {
    1: optional list<string> sequence_ids
    2: optional DeleteMessageAction delete_message_action
    // MCE seq id -> PME seq id for deleted messages that are pinned (unpin runs before delete)
    3: optional map<string, string> pme_sequence_ids (strato.graphql.typename='XChatPmeSequenceIdEntry')
} (persisted='true', strato.graphql.typename='XChatMessageDeleteEvent')

struct MessageKeyPinInfo {
    // Both keys are under the ckey named by the pin's conversation_key_version
    1: optional binary encrypted_message_key
    2: optional i64 edit_sequence_id (GraphQlEncoding="NumericString")
    3: optional binary encrypted_edit_message_key
    // Server-filled: the stored events, serialized
    4: optional binary message_event
    5: optional binary edit_message_event
} (persisted='true', strato.graphql.typename='XChatMessageKeyPinInfo')

// Pin Message Event (PME). Only `contents` is E2E encrypted; the rest is server-readable.
struct PinMessageEvent {
    // Source MessageEvent (with decrypted MCE contents) re-encrypted under this pin's PMK,
    // so the pin renders standalone (sender, timestamp, body, media reference)
    1: optional binary contents
    // This pin's PMK under the ckey named by conversation_key_version. Readers without
    // that ckey use the conversation's PMK bundle (PinnedMessageKey rows) instead.
    2: optional binary encrypted_pmk
    3: optional string conversation_key_version
    // Seq id of the pinned MCE; also the side-table and bundle key
    4: optional i64 message_sequence_id (GraphQlEncoding="NumericString")
    // This PME's own seq id
    5: optional i64 sequence_id (GraphQlEncoding="NumericString")
    // Inherited from the source MCE so a pinned disappearing message expires with it
    6: optional i64 ttl_msec (GraphQlEncoding="NumericString")
    7: optional i64 delivered_at_msec (GraphQlEncoding="NumericString")
    // Replaces contents and encrypted_pmk for messages with a per-message key
    8: optional MessageKeyPinInfo message_key_pin_info
} (persisted='true', strato.graphql.typename='XChatPinMessageEvent')

// One pin removed by an UnpinMessageEvent.
struct UnpinMessageEntry {
    1: optional i64 pme_sequence_id (GraphQlEncoding="NumericString")
    // Source message of the removed pin, so consumers can un-mark it without the deleted PME.
    // Client-supplied it is only a lookup hint; the server stamps it from the stored PME.
    2: optional i64 message_sequence_id (GraphQlEncoding="NumericString")
} (persisted='true', strato.graphql.typename='XChatUnpinMessageEntry')

// Unpin tombstone; persisted so offline clients catch the removal via the bottom cursor.
struct UnpinMessageEvent {
    // DEPRECATED: use `entries` (a single unpin is a one-entry list, like
    // MessageDeleteEvent.sequence_ids). Senders may still use these fields (read as a
    // one-entry batch); persisted tombstones always carry `entries`, with these fields
    // mirroring `entries.head`. Never reuse field ids 1-2.
    1: optional i64 pme_sequence_id (GraphQlEncoding="NumericString")
    // Source message of the removed pin, so consumers can un-mark it without the deleted PME
    2: optional i64 message_sequence_id (GraphQlEncoding="NumericString")
    // Every pin this event removes (the canonical form). When set, fields 1-2 are ignored
    // on the way in. Validation is all-or-nothing: one bad entry rejects the event.
    3: optional list<UnpinMessageEntry> entries
} (persisted='true', strato.graphql.typename='XChatUnpinMessageEvent')

struct PinnedMessageKey {
    1: optional i64 pme_sequence_id (GraphQlEncoding="NumericString")
    2: optional string conversation_key_version
    3: optional binary encrypted_pmk
    4: optional binary encrypted_message_key
    5: optional binary encrypted_edit_message_key
} (persisted='true', strato.graphql.typename='XChatPinnedMessageKey')

// Server-generated after a PMK bundle upload is accepted.
// Fans the bundle as stored to all members so their clients
// can detect entries still wrapped under older ckey versions and schedule a repair.
struct PmkBundleUpdateEvent {
    // Full bundle as stored: pinned message seq id -> PinnedMessageKey. Each entry
    // carries the ckey version it is wrapped under; entries on an older version than
    // the latest ckey are the client's signal to schedule a bundle repair.
    1: optional map<string, PinnedMessageKey> pmk_bundle (strato.graphql.typename='XChatPmkBundleUpdateEntry')
} (persisted='true', strato.graphql.typename='XChatPmkBundleUpdateEvent')

struct ClearConversationOptions {
    1: optional bool clear_all_messages
    2: optional i64 sort_order_msec
} (persisted='true', strato.graphql.typename='XChatClearConversationOptions')

struct ConversationDeleteEvent {
    1: optional string conversation_id
    2: optional ClearConversationOptions clear_conversation_options
} (persisted='true', strato.graphql.typename='XChatConversationDeleteEvent')

struct MessageDurationChange {
    1: optional i64 ttl_msec (GraphQlEncoding="NumericString")
    2: optional bool apply_to_all_messages
} (persisted='true', strato.graphql.typename='XChatMessageDurationChange')

struct MessageDurationRemove {
  1: optional i64 current_ttl_msec (GraphQlEncoding="NumericString")
} (persisted='true', strato.graphql.typename='XChatMessageDurationRemove')

struct MuteConversation {
    1: optional list<string> muted_conversation_ids
} (persisted='true', strato.graphql.typename='XChatMuteConversation')

struct UnmuteConversation {
    1: optional list<string> unmuted_conversation_ids
} (persisted='true', strato.graphql.typename='XChatUnmuteConversation')

struct ArchiveConversation {
    1: optional list<string> archived_conversation_ids
} (persisted='true', strato.graphql.typename='XChatArchiveConversation')

struct UnarchiveConversation {
    1: optional list<string> unarchived_conversation_ids
} (persisted='true', strato.graphql.typename='XChatUnarchiveConversation')

struct EnableScreenCaptureDetection {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatEnableScreenCaptureDetection')

struct DisableScreenCaptureDetection {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatDisableScreenCaptureDetection')

struct EnableScreenCaptureBlocking {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatEnableScreenCaptureBlocking')

struct DisableScreenCaptureBlocking {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatDisableScreenCaptureBlocking')

struct EnableGrok {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatEnableGrok')

struct DisableGrok {
  1: optional string placeholder
} (persisted='true', strato.graphql.typename='XChatDisableGrok')

union ConversationMetadataChange {
    1: MessageDurationChange message_duration_change
    2: MessageDurationRemove message_duration_remove
    3: MuteConversation mute_conversation
    4: UnmuteConversation unmute_conversation
    5: EnableScreenCaptureDetection enable_screen_capture_detection
    6: DisableScreenCaptureDetection disable_screen_capture_detection
    7: EnableScreenCaptureBlocking enable_screen_capture_blocking
    8: DisableScreenCaptureBlocking disable_screen_capture_blocking
    9: EnableGrok enable_grok
    10: DisableGrok disable_grok
    11: ArchiveConversation archive_conversation
    12: UnarchiveConversation unarchive_conversation
} (persisted='true', strato.graphql.typename='XChatConversationMetadataChange')

struct ConversationMetadataChangeEvent {
    1: optional ConversationMetadataChange conversation_metadata_change
} (persisted='true', strato.graphql.typename='XChatConversationMetadataChangeEvent')

struct GrokSearchResponseEvent {
    1: optional string search_response_id
} (persisted='true', strato.graphql.typename='XChatGrokSearchResponseEvent')

// Server-side event indicating a Grok inference request was received.
// Fields mirror the server's encrypted GME but are not parsed client-side;
// we only need the type for MessageEventDetail union dispatch.
struct GrokMessageEvent {
    1: optional binary encrypted_message
    2: optional binary ephemeral_public_key
    3: optional binary nonce
    4: optional binary iv
    5: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGrokMessageEvent')

struct GrokResponseEvent {
    1: optional binary encrypted_response
    2: optional binary nonce
    3: optional binary signature
    4: optional binary response_iv
    5: optional binary ciphertext_hash
    6: optional string plaintext_response
    // Thrift-serialized product.GrokAttachments (list of MessageAttachment), decoded client-side.
    7: optional binary encoded_attachments
    // Disappearing-message TTL for this Grok reply, stamped by CES from the conversation's TTL.
    // ttl_msec is the lifetime; delivered_at_msec is when the countdown starts (delivery time).
    8: optional i64 ttl_msec (GraphQlEncoding="NumericString")
    9: optional i64 delivered_at_msec (GraphQlEncoding="NumericString")
    // Keys of the @Grok message that triggered this response, echoed back by grokbackend. Only the
    // ids travel; receivers look the parent up locally to build the reply preview.
    10: optional string replying_to_message_sequence_id
    11: optional string replying_to_message_id
    12: optional GrokBotMetadata grok_bot
} (persisted='true', strato.graphql.typename='XChatGrokResponseEvent')

struct MarkConversationReadEvent {
    1: optional string seen_until_sequence_id
    2: optional i64 seen_at_millis (GraphQlEncoding="NumericString")
    // Set when this read marker is emitted on Grok's behalf (Grok isn't a conversation member, so
    // it's sent as the human summoner and the client relabels the sender to Grok).
    3: optional bool is_grok
} (persisted='true', strato.graphql.typename='XChatMarkConversationReadEvent')

struct MarkConversationUnreadEvent {
    1: optional string seen_until_sequence_id
} (persisted='true', strato.graphql.typename='XChatMarkConversationUnreadEvent')

struct MemberAccountDeleteEvent {
    1: optional string member_id
    2: optional string promoted_admin_id
} (persisted='true', strato.graphql.typename='XChatMemberAccountDeleteEvent')

union MessageEventDetail {
    1: MessageCreateEvent messageCreateEvent
    3: ConversationKeyChangeEvent conversationKeyChangeEvent
    4: GroupChangeEvent groupChangeEvent
    5: MessageFailureEvent messageFailureEvent
    6: MessageTypingEvent messageTypingEvent
    7: MessageDeleteEvent messageDeleteEvent
    8: ConversationDeleteEvent conversationDeleteEvent
    9: ConversationMetadataChangeEvent conversationMetadataChangeEvent
    10: GrokSearchResponseEvent grokSearchResponseEvent
    // removed 11: RequestForEncryptedResendEvent
    12: MarkConversationReadEvent markConversationReadEvent
    13: MarkConversationUnreadEvent markConversationUnreadEvent
    14: MemberAccountDeleteEvent memberAccountDeleteEvent
    15: GrokMessageEvent grokMessageEvent
    16: GrokResponseEvent grokResponseEvent
    17: PinMessageEvent pinMessageEvent
    18: UnpinMessageEvent unpinMessageEvent
    19: PmkBundleUpdateEvent pmkBundleUpdateEvent
} (persisted='true', strato.graphql.typename='XChatMessageEventDetail')

enum MessageEventRelaySource {
    LiveFanout
    MessagePull
    LegacyFanout
    ReboundEvent
} (persisted='false', strato.graphql.typename='XChatMessageEventRelaySource')

struct MessageSigningKeyInfo {
    1: optional string member_id // set by the client
    2: optional string public_key_version // set by the client
    3: optional string signing_public_key // signing public key of the signer (could be sender or others)
} (persisted='true', strato.graphql.typename='XChatMessageSigningKeyInfo')

struct MessageEventSignature {
    1: optional string signature // base64 encoded signature
    2: optional string public_key_version
    3: optional string signature_version // signature protocol version
    // Use messageSigningKeyInfoList instead to support multi-user signing key hydration
    4: optional string signing_public_key // signing public key of the signer (sender)
    5: optional list<MessageSigningKeyInfo> message_signing_key_info_list
} (persisted='true', strato.graphql.typename='XChatMessageEventSignature')

struct MessageEvent {
    1: optional string sequence_id
    2: optional string message_id
    3: optional string sender_id
    4: optional string conversation_id
    5: optional string conversation_token
    6: optional string created_at_msec
    7: optional MessageEventDetail detail
    8: optional MessageEventRelaySource relay_source
    9: optional MessageEventSignature message_event_signature
    10: optional string previous_sequence_id
    11: optional bool is_trusted
    // This was never actually implemented, just putting it here so we don't accidentally use field #12
    // 12: optional i64 recipient_scoped_sequence_number
    13: optional string conversation_event_counter
} (persisted='true', strato.graphql.typename='XChatMessageEvent')

struct PullMessagesInstruction {
    1: optional string sequence_start
    2: optional string sender_id
    6: optional bool is_batched_pull
} (persisted='false', strato.graphql.typename='XChatPullMessagesInstruction')

struct KeepAliveInstruction {}

struct PullMessagePageDetails {
    3: optional string min_sequence_id
    4: optional string max_sequence_id
    7: optional bool is_batched_pull
} (persisted='false', strato.graphql.typename='XChatPullMessagePageDetails')

struct PullMessagesFinishedInstruction {
    1: optional bool finished_pull
    2: optional string sequence_continue
    3: optional PullMessagePageDetails pull_message_page_details
} (persisted='false', strato.graphql.typename='XChatPullMessagesFinishedInstruction')

struct PinReminderInstruction {
    1: optional bool should_register
    2: optional bool should_generate
    3: optional bool is_required
}

struct SwitchToHybridPullInstruction {
    1: optional string requesting_user_agent
}

struct DisplayTemporaryPasscodeInstruction {
    1: optional string token
    2: optional string latest_public_key_version
}

enum DeviceEnrollmentStatus {
    PENDING_ACCEPTANCE
    ACCEPTED
    KEY_EXCHANGED
    KEYS_SENT
    COMPLETED
    DENIED
} (persisted='true', strato.graphql.typename='XChatDeviceEnrollmentStatus')

struct DeviceDescriptor {
    1: optional string device_type
    2: optional string device_model
    3: optional string app_version
    4: optional string app_name
} (persisted='true', strato.graphql.typename='XChatDeviceDescriptor')

struct DeviceEnrollmentInstruction {
    1: optional string enrollment_id
    2: optional DeviceEnrollmentStatus status
    /** Enrolled device's ephemeral public key B (set when status = ACCEPTED) */
    3: optional string enrolled_device_public_key
    /** New device's ephemeral public key A (set when status = KEY_EXCHANGED) */
    4: optional string new_device_public_key
    /** AES-GCM ciphertext of serialized private keys (set when status = KEYS_SENT) */
    5: optional string encrypted_key_material
    /** H(A) — new device's public key hash commitment (set when status = PENDING_ACCEPTANCE) */
    6: optional string public_key_hash
    /** Deprecated; prefer device_descriptor. */
    7: optional string user_agent
    8: optional DeviceDescriptor device_descriptor
} (persisted='true', strato.graphql.typename='XChatDeviceEnrollmentInstruction')

// Sent by the server on connect when the user-settings side table is empty (and the FS is on):
// the client should consolidate legacy settings events (pins/nicknames/verified) into the first
// UserMetadata snapshot MCE, then delete the legacy settings events.
struct MigrateUserMetadataInstruction {
    1: optional bool should_migrate
}

struct MessageRequestInfoInstruction {
    1: optional MessageRequestInboxSummary message_request_inbox_summary
} (persisted='true', strato.graphql.typename='XChatMessageRequestInfoInstruction')

// Sent once per user (server-side fatigue) to show the X Number onboarding prompt.
struct XNumberPromptInstruction {} (persisted='true', strato.graphql.typename='XChatXNumberPromptInstruction')

// Sent once per user (server-side fatigue) to prompt a closed-inbox user to open their inbox.
struct OpenInboxInstruction {} (persisted='true', strato.graphql.typename='XChatOpenInboxInstruction')

union MessageInstruction {
    1: PullMessagesInstruction pullMessagesInstruction
    2: KeepAliveInstruction keepAliveInstruction
    3: PullMessagesFinishedInstruction pullMessagesFinishedInstruction
    4: PinReminderInstruction pinReminderInstruction
    5: SwitchToHybridPullInstruction switchToHybridPullInstruction
    6: DisplayTemporaryPasscodeInstruction displayTemporaryPasscodeInstruction
    7: DeviceEnrollmentInstruction deviceEnrollmentInstruction
    8: MigrateUserMetadataInstruction migrateUserMetadataInstruction
    9: MessageRequestInfoInstruction messageRequestInfoInstruction
    10: XNumberPromptInstruction xNumberPromptInstruction
    11: OpenInboxInstruction openInboxInstruction
}

struct BatchedMessageEvents {
    1: optional list<MessageEvent> message_events
} (persisted='false', strato.graphql.typename='XChatBatchedMessageEvents')

union Message {
    1: MessageEvent messageEvent
    2: MessageInstruction messageInstruction
    // Unused, left here so we get a useful nonfatal if we get one of these over the wire
    3: BatchedMessageEvents batchedMessageEvents
}
