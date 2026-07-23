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

struct FrankingData {
    1: optional binary franking_tag
    2: optional binary encrypted_nonce
    // deprecated
    // 3: optional binary encrypted_media_hash
    4: optional list<binary> encrypted_media_hashes   // multiple media, in attachment order
} (persisted='true', strato.graphql.typename='XChatFrankingData')

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
} (persisted='true', strato.graphql.typename='XChatMessageCreateEvent')

struct GroupCreate {
    1: optional list<string> member_ids
    2: optional list<string> admin_ids
    3: optional string title
    4: optional string avatar_url
    5: optional string conversation_key_version
    6: optional bool is_legacy_group_upgrade
    7: optional i64 ttl_msec (GraphQlEncoding="NumericString")
} (persisted='true', strato.graphql.typename='XChatGroupCreate')

struct GroupTitleChange {
    1: optional string custom_title
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupTitleChange')

struct GroupAvatarUrlChange {
    1: optional string custom_avatar_url
    2: optional string conversation_key_version
} (persisted='true', strato.graphql.typename='XChatGroupAvatarUrlChange')

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
   11: optional GroupInviteEnable group_invite_enable
   12: optional GroupAdminSettings admin_settings
} (persisted='true', strato.graphql.typename='XChatGroupMemberAddChange')

struct GroupAdminRemoveChange {
    1: optional list<string> admin_ids
} (persisted='true', strato.graphql.typename='XChatGroupAdminRemoveChange')

struct GroupMemberRemoveChange {
    1: optional list<string> member_ids
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

struct GroupAdminSettings {
    1: optional bool edit_group_info
    2: optional bool edit_message_ttl
    3: optional bool block_screen_capture
    4: optional bool add_member
    5: optional bool send_message
    6: optional bool start_call
} (persisted='true', strato.graphql.typename='XChatGroupAdminSettings')

struct GroupAdminSettingsChange {
    1: optional bool edit_group_info
    2: optional bool edit_message_ttl
    3: optional bool block_screen_capture
    4: optional bool add_member
    5: optional bool send_message
    6: optional bool start_call
} (persisted='true', strato.graphql.typename='XChatGroupAdminSettingsChange')

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

struct MessageTypingEvent {
    1: optional string conversation_id
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
    RATE_LIMIT_UPSELL = 12
    SIGNATURE_FAILED_TO_VERIFY_AGAINST_PUBLIC_KEY = 13
    GENERIC_ERROR = 14
    SENDER_NOT_GROUP_MEMBER = 15
    INVALID_SIGNATURE_VERSION = 16
    INVALID_PIN_REQUEST = 17
    TOO_MANY_PINS = 18
} (persisted='false', strato.graphql.typename='XChatFailureType')

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
} (persisted='true', strato.graphql.typename='XChatMessageDeleteEvent')

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

union ConversationMetadataChange {
    1: MessageDurationChange message_duration_change
    2: MessageDurationRemove message_duration_remove
    3: MuteConversation mute_conversation
    4: UnmuteConversation unmute_conversation
    5: EnableScreenCaptureDetection enable_screen_capture_detection
    6: DisableScreenCaptureDetection disable_screen_capture_detection
    7: EnableScreenCaptureBlocking enable_screen_capture_blocking
    8: DisableScreenCaptureBlocking disable_screen_capture_blocking
} (persisted='true', strato.graphql.typename='XChatConversationMetadataChange')

struct ConversationMetadataChangeEvent {
    1: optional ConversationMetadataChange conversation_metadata_change
} (persisted='true', strato.graphql.typename='XChatConversationMetadataChangeEvent')

struct GrokSearchResponseEvent {
    1: optional string search_response_id
} (persisted='true', strato.graphql.typename='XChatGrokSearchResponseEvent')

struct MarkConversationReadEvent {
    1: optional string seen_until_sequence_id
    2: optional i64 seen_at_millis (GraphQlEncoding="NumericString")
} (persisted='true', strato.graphql.typename='XChatMarkConversationReadEvent')

struct MarkConversationUnreadEvent {
    1: optional string seen_until_sequence_id
} (persisted='true', strato.graphql.typename='XChatMarkConversationUnreadEvent')

struct MemberAccountDeleteEvent {
    1: optional string member_id
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

union MessageInstruction {
    1: PullMessagesInstruction pullMessagesInstruction
    2: KeepAliveInstruction keepAliveInstruction
    3: PullMessagesFinishedInstruction pullMessagesFinishedInstruction
    4: PinReminderInstruction pinReminderInstruction
    5: SwitchToHybridPullInstruction switchToHybridPullInstruction
    6: DisplayTemporaryPasscodeInstruction displayTemporaryPasscodeInstruction
    7: DeviceEnrollmentInstruction deviceEnrollmentInstruction
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
