/**
 * X Chat SDK - TypeScript Definitions
 */

/**
 * Public keys returned from getPublicKeys().
 */
export interface PublicKeys {
  /** Base64-encoded identity public key */
  identity: string;
  /** Base64-encoded signing public key */
  signing: string;
}

/**
 * Public key registration fields for the X API.
 */
export interface PublicKeyRegistration {
  identityPublicKeySignature: string;
  publicKey: string;
  publicKeyFingerprint?: string;
  registrationMethod: string;
  signingPublicKey: string;
  signingPublicKeySignature?: string;
}

/**
 * Public key registration payload for the X API.
 */
export interface PublicKeyRegistrationPayload {
  publicKey: PublicKeyRegistration;
}

/**
 * Result from encryptMessage, encryptReply, encryptAddReaction,
 * encryptRemoveReaction, and encryptEdit.
 */
export interface SendPayload {
  /**
   * Message id (UUID) the SDK generated and embedded in the signed event.
   * Send it as the message's `messageId`, keep it to dedup and to anchor
   * replies, and reuse the same encrypted payload on retries so an id is
   * never minted twice.
   */
  messageId: string;
  /**
   * The outgoing message as a base64 event: what recipients receive, without
   * the fields the server assigns. Pass it to `encryptFile` or
   * `fileEncryptor` to encrypt the message's files, or to `decryptEvent` to
   * read the message back.
   */
  eventB64: string;
  /** Base64-encoded Thrift MessageCreateEvent: the send request's `encoded_message_create_event`. */
  encodedMessageCreateEvent: string;
  /** Base64-encoded ECDSA signature. */
  signature: string;
  /** Base64-encoded Thrift MessageEventSignature: the send request's `encoded_message_event_signature`. */
  encodedMessageEventSignature: string;
  /** Signature metadata (signing key version + signature protocol version). */
  signatureInfo: { publicKeyVersion: string; signatureVersion: string };
  /** Version of the conversation key used to encrypt the content (a snowflake/timestamp string). */
  conversationKeyVersion: string;
  /** Whether the X API should send a push notification for this message. */
  shouldNotify: boolean;
  /** Version of the Chat XDK that built this payload. */
  xdkVersion: string;
}

/**
 * A signed action (conversation-key change, group change, message delete or
 * read receipt), shaped as an entry of a request's `actionSignatures`: the
 * signature is nested under `messageEventSignature`.
 */
export interface ActionSignature {
  messageId: string;
  encodedMessageEventDetail: string;
  /** The signature over the action, with its versions and the signer's signing public key. */
  messageEventSignature: MessageEventSignature;
}

/** The signature of an ActionSignature. */
export interface MessageEventSignature {
  /** Base64 ECDSA signature of the payload. */
  signature: string;
  /** Signature protocol version. */
  signatureVersion: string;
  /** Version of the signing public key. */
  publicKeyVersion: string;
  /** The signer's base64 signing public key, as getPublicKeys returns it. */
  signingPublicKey: string;
}

/**
 * Signed actions for a request that carries no new conversation key and no
 * encrypted group text: the `actionSignatures` it carries. Returned by
 * prepareMessageDelete, prepareMarkConversationRead, prepareGroupLeave (one
 * entry per signed event), prepareGroupAvatarChange, and the admin, invite,
 * join-request, message-TTL and screen-capture prepares.
 */
export interface PreparedAction {
  actionSignatures: ActionSignature[];
}

/**
 * A signed group title or description change: the value encrypted under the
 * conversation key and the `actionSignatures` a request carries.
 */
export interface PreparedGroupMetadataChange {
  /** The value encrypted under the conversation key, base64: what the request sends. */
  encryptedValue: string;
  /** Version of the conversation key the value is encrypted under. */
  conversationKeyVersion: string;
  /** The signed change, one entry. */
  actionSignatures: ActionSignature[];
}

/**
 * A signing key entry for decryptEvent and decryptEvents.
 * Pass all known signing keys for all participants; the SDK matches by userId + version.
 */
export interface SigningKeyEntry {
  /** The participant's user ID (snowflake string). */
  userId: string;
  /** Signing key version from the X API (a snowflake/timestamp string). */
  publicKeyVersion: string;
  /** Base64-encoded signing public key (SEC1 or SPKI). */
  publicKey: string;
  /** Base64-encoded identity public key for this user. */
  identityPublicKey: string;
  /** Base64-encoded raw r||s signature proving the signing key is bound to the identity key. Returned by the X API. */
  identityPublicKeySignature: string;
}

/** Map of key version → raw conversation key bytes. */
export type ConversationKeyMap = { [version: string]: Uint8Array };

/**
 * Result from extractConversationKeys.
 * Contains the key map plus the latest version for convenience.
 */
export interface ConversationKeyResult {
  /** Map of key version → raw conversation key bytes. */
  keys: ConversationKeyMap;
  /**
   * The version to encrypt with: from decryptEvents, the newest version whose
   * key change verified (null until one verifies); from
   * extractConversationKeys, the batch's highest version.
   */
  latestVersion: string | null;
}

/**
 * One event decryptEvents decrypted, of any event type.
 */
export interface DecryptedEvent {
  /** The decrypted event. */
  event: Event;
  /** Original base64 event string (for reference). */
  originalB64?: string;
}

/**
 * Result from decryptEvents batch API.
 */
export interface DecryptEventsResult {
  /** The events that decrypted, in batch order, of every event type. */
  events: DecryptedEvent[];
  /** Extracted conversation keys (for caching). */
  conversationKeys: ConversationKeyResult;
  /**
   * Event index, as a string key → error message, for each event left out of
   * `events`: one that failed, or one decrypt drops, such as a member
   * removal's title or description re-encrypted under the new key.
   */
  errors: { [index: string]: string };
}

/**
 * Image dimensions returned by detectImageDimensions.
 */
export interface ImageDimensions {
  width: number;
  height: number;
}

/**
 * One participant's copy of a conversation key, encrypted to their identity
 * key: an entry of the X API's `conversation_participant_keys`. A prepared
 * change carries these for its request, and a received keyChange event
 * carries them as delivered.
 */
export interface ConversationParticipantKey {
  userId: string;
  encryptedConversationKey: string;
  publicKeyVersion: string;
}

/**
 * A public key input for prepareConversationKeyChange, prepareGroupCreate,
 * prepareGroupMembersChange and prepareGroupMembersRemove.
 *
 * Represents a single public key version for a user, as returned by the
 * X API `GET /2/users/{id}/public_keys` endpoint.
 *
 * Pass the full array — the SDK groups by userId and picks the latest
 * version per user automatically.
 */
export interface PublicKeyInput {
  /** The user's user ID (snowflake string). */
  userId: string;
  /** Base64-encoded identity public key (SEC1 or SPKI): the X API's `public_key`. */
  identityPublicKey: string;
  /** The key's version, as the X API returns it. */
  publicKeyVersion: string;
}

/**
 * Result from prepareConversationKeyChange, prepareGroupCreate,
 * prepareGroupMembersChange and prepareGroupMembersRemove.
 *
 * Contains everything needed to POST the change to the X API: the new key
 * (to keep locally), the per-participant encrypted copies, and the action
 * signature that lets recipients verify the change.
 */
export interface PreparedConversationChange {
  /** Conversation id the change applies to (derived for a one-to-one, or the id you passed). */
  conversationId: string;
  /**
   * Raw conversation key bytes (32 bytes). Store locally for encrypting
   * messages. It is secret, so JSON.stringify leaves it out of this object.
   */
  conversationKey: Uint8Array;
  /** Timestamp-based version string for this conversation key. */
  conversationKeyVersion: string;
  /** Encrypted keys for each participant: the request's `conversation_participant_keys`, ready to POST to the API. */
  conversationParticipantKeys: ConversationParticipantKey[];
  /** Action signatures authenticating the change, ready to POST to the API. */
  actionSignatures: ActionSignature[];
  /**
   * prepareGroupCreate and prepareGroupMembersChange, when the params set a
   * title: the title encrypted under the new conversation key, base64 — the
   * `group_name` a create request sends, and the `encrypted_title` an
   * add-members request sends.
   */
  encryptedTitle?: string;
  /**
   * prepareGroupMembersChange only, when the params set a description: the
   * description encrypted under the new conversation key, base64, as the
   * signed member add carries it.
   */
  encryptedDescription?: string;
}

/**
 * Entity descriptor tuple: [startByteOffset, endByteOffset, entityType].
 * The offsets count bytes of the text's UTF-8 encoding, not string indices
 * (`new TextEncoder().encode(text.slice(0, i)).length` converts index `i`),
 * so `0 <= start <= end <=` the text's UTF-8 length; other offsets fail the
 * call with a `ChatXdkError` of kind `invalidInput` naming them.
 * entityType is one of: "url", "mention", "hashtag", "cashtag", "email",
 * "address", "phoneNumber" (the snake_case spelling "phone_number" is
 * accepted too). Any other entity type, an empty one included, fails the
 * call with a `ChatXdkError` of kind `invalidInput` naming it.
 */
export type EntityTuple = [number, number, string];

/**
 * A quick reply: either a request offering selectable options or a response
 * selecting one. This is the same shape as the quick reply on decrypted text
 * content, so a received value can be passed back to encryptMessage /
 * encryptReply unchanged.
 */
export type QuickReply =
  | { request: QuickReplyRequest }
  | { response: QuickReplyResponse };

/** A quick-reply request offering a set of selectable options. */
export interface QuickReplyRequest {
  options: QuickReplyOptionsRequest;
}

/** A quick-reply response selecting a previously offered option. */
export interface QuickReplyResponse {
  options: QuickReplyOptionsResponse;
}

/** The options offered by a quick-reply request. */
export interface QuickReplyOptionsRequest {
  id?: string | null;
  options?: QuickReplyOption[] | null;
}

/** The option selected in a quick-reply response. */
export interface QuickReplyOptionsResponse {
  requestId?: string | null;
  metadata?: string | null;
  selectedOptionId?: string | null;
}

/** A single selectable quick-reply option. */
export interface QuickReplyOption {
  id?: string | null;
  label?: string | null;
  metadata?: string | null;
  description?: string | null;
}

/** Params for `setIdentity`. */
export interface SetIdentityParams {
  /** Your user ID: the sender of everything this chat signs. */
  userId: string;
  /** The `public_key_version` the X API returned when your keys were registered. */
  signingKeyVersion: string;
}

/** Params for `importKeys`. */
export interface ImportKeysParams {
  /** The private keys, as `exportKeys` returns them. */
  keys: Uint8Array;
  /**
   * The `public_key_version` the X API returned when the keys were
   * registered; key-change entries for other versions of your keys are
   * skipped.
   */
  signingKeyVersion?: string | null;
}

/**
 * What kind of failure a `ChatXdkError` is; every binding names the same
 * failure the same way.
 */
export type ChatXdkErrorKind =
  | 'invalidInput'
  | 'invalidState'
  | 'parse'
  | 'decryption'
  | 'verification'
  | 'invalidPin'
  | 'juicebox'
  | 'internal';

/** The error every SDK call throws. */
export declare class ChatXdkError extends Error {
  constructor(kind: ChatXdkErrorKind, message: string, guessesRemaining?: number | null);
  /** What kind of failure this is. */
  readonly kind: ChatXdkErrorKind;
  /**
   * The PIN attempts left after an `invalidPin` failure, when Juicebox
   * reports them: 0 means the guess budget is exhausted and the stored keys
   * are locked. Null for every other failure.
   */
  readonly guessesRemaining: number | null;
}

/**
 * Parameters for encryptMessage.
 */
export interface EncryptMessageParams {
  /** ID of the conversation the message belongs to. */
  conversationId: string;
  /** The plaintext message text. */
  text: string;
  /** User ID of the sender; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the message; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /**
   * Raw 32-byte conversation key used to encrypt the message content;
   * resolves from the opt-in key cache (setCacheKeys) when omitted. Set
   * together with conversationKeyVersion.
   */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key used for encryption; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
  /** Optional rich-text entities (URLs, mentions, etc.) to embed. */
  entities?: EntityTuple[] | null;
  /**
   * Optional attachments: posts, links, and files (media, and link-card
   * images). Each file names the media hash key its upload started with;
   * encrypt the files afterwards with `encryptFile` or `fileEncryptor`.
   * Upload each file for one message only: reusing another message's
   * uploads can give this message that message's id.
   */
  attachments?: AttachmentDescriptor[] | null;
  /** Optional quick reply: a request offering options, or a response selecting one. */
  quickReply?: QuickReply | null;
  /** Whether to send a push notification. Omitted defaults to true. */
  shouldNotify?: boolean | null;
  /** Optional TTL in milliseconds for disappearing messages. */
  ttlMsec?: number | null;
}

/**
 * Parameters for encryptReply.
 *
 * The preferred form passes `replyToEvent` — the base64 raw signed event
 * being replied to — and lets the SDK derive the reply preview from it. The
 * `replyTo*` field overrides remain for callers that no longer hold the raw
 * event.
 */
export interface EncryptReplyParams {
  /** ID of the conversation the reply belongs to. */
  conversationId: string;
  /** The plaintext reply text. */
  text: string;
  /**
   * Base64 of the raw signed event being replied to. The reply preview
   * (sequence id, message id, sender, text, entities, attachments) is
   * derived from it and the raw event is embedded so recipients can
   * validate the preview.
   */
  replyToEvent?: string | null;
  /** Base64 of the raw signed edit event, when the original was edited. */
  replyToEditEvent?: string | null;
  /**
   * Base64 raw key-change events needed to decrypt the original when it was
   * encrypted under a different key version than this reply.
   */
  replyToCkces?: string[] | null;
  /** User ID of the sender; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the message; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /**
   * Raw 32-byte conversation key used to encrypt the message content;
   * resolves from the opt-in key cache (setCacheKeys) when omitted. Set
   * together with conversationKeyVersion.
   */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key used for encryption; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
  /** The sequenceId of the message being replied to; derived from replyToEvent when omitted. */
  replyToSequenceId?: string | null;
  /**
   * The signed messageId of the message being replied to; derived from
   * replyToEvent when omitted. A reply built without replyToEvent needs it:
   * X clients mark a v1 reply that names no original invalid.
   */
  replyToMessageId?: string | null;
  /**
   * The user ID of the message's sender, as digits (for the preview);
   * derived from replyToEvent when omitted.
   */
  replyToSenderId?: string | null;
  /** The text of the message being replied to (for preview); derived from replyToEvent when omitted. */
  replyToText?: string | null;
  /** Optional rich-text entities (URLs, mentions, etc.) to embed in the outgoing message. */
  entities?: EntityTuple[] | null;
  /** Optional attachments for the reply, as in `EncryptMessageParams.attachments`. */
  attachments?: AttachmentDescriptor[] | null;
  /** Rich-text entities from the original message (for the reply preview); derived from replyToEvent when omitted. */
  replyToEntities?: EntityTuple[] | null;
  /** Attachments from the original message (for the reply preview); derived from replyToEvent when omitted. */
  replyToAttachments?: AttachmentDescriptor[] | null;
  /** Optional quick reply: a request offering options, or a response selecting one. */
  quickReply?: QuickReply | null;
  /** Whether to send a push notification. Omitted defaults to true. */
  shouldNotify?: boolean | null;
  /** Optional TTL in milliseconds for disappearing messages. */
  ttlMsec?: number | null;
}

/**
 * Parameters for encryptAddReaction and encryptRemoveReaction.
 *
 * The preferred form passes `targetEvent` — the base64 raw event being
 * reacted to — and lets the SDK derive the conversation id and target
 * sequence id from it. The same params object can be passed to both methods
 * to add and later remove the same reaction.
 */
export interface EncryptReactionParams {
  /** The reaction emoji. */
  emoji: string;
  /** Base64 of the raw event being reacted to; the conversation id and target sequence id are derived from it. */
  targetEvent?: string | null;
  /** ID of the conversation the reaction belongs to; derived from targetEvent when omitted. */
  conversationId?: string | null;
  /** The sequenceId of the message being reacted to; derived from targetEvent when omitted. */
  targetMessageSequenceId?: string | null;
  /** User ID of the sender; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the message; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /**
   * Raw 32-byte conversation key used to encrypt the reaction content;
   * resolves from the opt-in key cache (setCacheKeys) when omitted. Set
   * together with conversationKeyVersion.
   */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key used for encryption; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
}

/**
 * Parameters for encryptEdit.
 *
 * The preferred form passes `targetEvent` — the base64 raw event of the
 * message being edited — and lets the SDK derive the conversation id, the
 * target sequence id and, for a v1 edit, the target message id from it.
 */
export interface EncryptEditParams {
  /** The replacement message text. */
  updatedText: string;
  /** Rich-text entities for the replacement text; omitting clears any entities the original carried. */
  entities?: EntityTuple[] | null;
  /** Base64 of the raw event being edited; the conversation id and target sequence id are derived from it. */
  targetEvent?: string | null;
  /** ID of the conversation the edit belongs to; derived from targetEvent when omitted. */
  conversationId?: string | null;
  /** The sequenceId of the message being edited; derived from targetEvent when omitted. */
  targetMessageSequenceId?: string | null;
  /**
   * The signed messageId of the message being edited; derived from
   * targetEvent when omitted. A v1 edit names the message it edits, so a v1
   * edit built without targetEvent needs it; a v0 edit names none.
   */
  targetMessageId?: string | null;
  /** User ID of the sender; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the message; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /**
   * Raw 32-byte conversation key used to encrypt the edit content;
   * resolves from the opt-in key cache (setCacheKeys) when omitted. Set
   * together with conversationKeyVersion.
   */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key used for encryption; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
}

/**
 * Parameters for prepareMessageDelete.
 *
 * A delete is a signed plaintext event, not an encrypted message, so no
 * conversation key is involved: the result is an action signature the
 * caller submits alongside the delete request.
 */
export interface MessageDeleteParams {
  /** ID of the conversation the messages belong to. */
  conversationId: string;
  /** The sequenceIds of the messages to delete. */
  sequenceIds: string[];
  /** Delete for every participant (true, own messages only) or only from the caller's view (false). */
  deleteForAll: boolean;
  /** User ID of the sender signing the delete; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the delete; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
}

/**
 * Parameters for prepareMarkConversationRead.
 *
 * A read receipt is a signed plaintext event, not an encrypted message, so
 * no conversation key is involved: the result is an action signature the
 * caller submits alongside the mark-read request.
 */
export interface MarkConversationReadParams {
  /** ID of the conversation being marked read. */
  conversationId: string;
  /** The sequenceId of the newest event read. */
  seenUntilSequenceId: string;
  /** When the conversation was read, in milliseconds since the Unix epoch; the current time when omitted. */
  seenAtMsec?: number | null;
  /** User ID of the sender signing the read receipt; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the read receipt; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
}

/**
 * A screen-capture setting signed by prepareScreenCapture.
 *
 * Blocking names are the events X clients sign. Detection names are the
 * events this SDK's verifier reconstructs.
 */
export type ScreenCaptureChange =
  | "blockingEnabled"
  | "blockingDisabled"
  | "detectionEnabled"
  | "detectionDisabled";

/**
 * Parameters for prepareGroupMembersRemove. The call rotates the
 * conversation key for the members who stay.
 */
export interface GroupMembersRemoveParams {
  /**
   * Identity public keys of the members who stay, yours included; the new key
   * is encrypted for them, and a member left out can't read what the group
   * sends under it.
   */
  publicKeys: PublicKeyInput[];
  /** ID of the group conversation. */
  conversationId: string;
  /** User IDs being removed. */
  userIds: string[];
  /**
   * The group's current title, re-encrypted under the new conversation key and
   * signed with the removal; recipients' decrypt drops it rather than show a
   * change. Pass it when the group has one.
   */
  title?: string | null;
  /** The group's current description, handled as `title` is. Pass it when the group has one. */
  description?: string | null;
  /** User ID of the sender; resolves from the session identity when omitted. */
  senderId?: string | null;
  /** Version of the signing key; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupLeave. Leave does not rotate the conversation key. */
export interface GroupLeaveParams {
  /** ID of the group conversation. */
  conversationId: string;
  /** User ID promoted to admin when the sender is the only admin. */
  promoteAdminId?: string | null;
  /** Conversation-key version the removal names; its signature doesn't cover it. */
  conversationKeyVersion?: string | null;
  /** User ID of the member leaving; resolves from the session identity when omitted. */
  senderId?: string | null;
  /** Version of the signing key; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
}

/**
 * Parameters for prepareGroupTitleChange. `newTitle` is plaintext: the SDK encrypts it under
 * the conversation key — `conversationKey` / `conversationKeyVersion`, or
 * the key cache when both are omitted.
 */
export interface GroupTitleChangeParams {
  /** ID of the group conversation. */
  conversationId: string;
  /** The group's new title, as plaintext. */
  newTitle: string;
  /** User ID of the sender; resolves from the session identity when omitted. */
  senderId?: string | null;
  /** Version of the signing key; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /** Raw 32-byte conversation key; resolves from the key cache when omitted. */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
}

/**
 * Parameters for prepareGroupAvatarChange. A group's avatar URL is not
 * encrypted: `newAvatarUrl` is the media URL of the avatar image, which the
 * app encrypts under the conversation key and uploads first.
 */
export interface GroupAvatarChangeParams {
  /** ID of the group conversation. */
  conversationId: string;
  /** The media URL of the group's new avatar image, signed and sent as is. */
  newAvatarUrl: string;
  /** Version of the conversation key the avatar image is encrypted under. */
  conversationKeyVersion: string;
  /** User ID of the sender; resolves from the session identity when omitted. */
  senderId?: string | null;
  /** Version of the signing key; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
}

/**
 * Parameters for prepareGroupDescriptionChange. `newDescription` is plaintext: the SDK encrypts it under
 * the conversation key — `conversationKey` / `conversationKeyVersion`, or
 * the key cache when both are omitted.
 */
export interface GroupDescriptionChangeParams {
  /** ID of the group conversation. */
  conversationId: string;
  /** The group's new description, as plaintext. */
  newDescription: string;
  /** User ID of the sender; resolves from the session identity when omitted. */
  senderId?: string | null;
  /** Version of the signing key; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /** Raw 32-byte conversation key; resolves from the key cache when omitted. */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
}

/** Parameters for prepareGroupAdminsAdd. */
export interface GroupAdminsAddParams {
  conversationId: string;
  /** User IDs gaining admin. */
  userIds: string[];
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupAdminsRemove. */
export interface GroupAdminsRemoveParams {
  conversationId: string;
  /** User IDs losing admin. */
  userIds: string[];
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupInviteEnable. An omitted expiry or affiliate signs `null`. */
export interface GroupInviteEnableParams {
  conversationId: string;
  inviteUrl: string;
  /** Expiry in milliseconds since the Unix epoch. Omit it to sign `null`. */
  expiresAtMsec?: number | null;
  /** Affiliate id. Omit it to sign `null`. */
  affiliateId?: string | null;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupInviteDisable. `disabledBy` defaults to the sender. */
export interface GroupInviteDisableParams {
  conversationId: string;
  disabledBy?: string | null;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupJoinRequest. `requestingUserId` defaults to the sender. */
export interface GroupJoinRequestParams {
  conversationId: string;
  requestingUserId?: string | null;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareGroupJoinReject. */
export interface GroupJoinRejectParams {
  conversationId: string;
  /** User IDs whose join request is rejected. */
  userIds: string[];
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareMessageTtlChange. The signature covers `ttlMsec` only. */
export interface MessageTtlChangeParams {
  conversationId: string;
  /** New message TTL, in milliseconds. */
  ttlMsec: number;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareMessageTtlRemove. */
export interface MessageTtlRemoveParams {
  conversationId: string;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/** Parameters for prepareScreenCapture. */
export interface ScreenCaptureParams {
  conversationId: string;
  change: ScreenCaptureChange;
  senderId?: string | null;
  signingKeyVersion?: string | null;
}

/**
 * Parameters for prepareConversationKeyChange.
 */
export interface ConversationKeyChangeParams {
  /** Identity public keys for every participant the new key is encrypted for. */
  publicKeys: PublicKeyInput[];
  /** User ID of the sender signing the change; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the change; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /**
   * Conversation the change applies to. Omit for a one-to-one (the canonical
   * id is derived from the two participants); pass the existing id for a
   * group key rotation.
   */
  conversationId?: string | null;
}

/**
 * Parameters for prepareGroupMembersChange.
 *
 * The current* fields snapshot the group state the change is made against.
 * `currentTitle` and `currentDescription` are plaintext: the call encrypts
 * each under the new conversation key it generates and signs the
 * ciphertext. An unset optional signs the null sentinel, so every binding
 * produces identical signed bytes.
 */
export interface GroupMembersChangeParams {
  /** Identity public keys for every participant of the updated roster. */
  publicKeys: PublicKeyInput[];
  /** ID of the group conversation being changed. */
  conversationId: string;
  /** User IDs being added to the group. */
  newMemberIds: string[];
  /** User IDs of the current members. */
  currentMemberIds: string[];
  /** User IDs of the current admins. */
  currentAdminIds: string[];
  /** User IDs of members whose join is still pending. */
  currentPendingMemberIds: string[];
  /** User ID of the sender signing the change; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the change; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /** The group's current title, as plaintext, if set. */
  currentTitle?: string | null;
  /** The group's current avatar media URL, if set; signed as is. */
  currentAvatarUrl?: string | null;
  /** The group's current description, as plaintext, if set. */
  currentDescription?: string | null;
  /** The group's current message TTL in milliseconds, if set. */
  currentTtlMsec?: number | null;
  /** The group's current screen-capture-blocking state; omit when unset. */
  currentScreenCaptureBlockingEnabled?: boolean | null;
}

/**
 * Parameters for prepareGroupCreate.
 *
 * `title` is plaintext: the create encrypts it under the new conversation
 * key and signs the ciphertext. A create sets no avatar; set it afterwards
 * with prepareGroupAvatarChange. An unset optional signs the null sentinel,
 * so every binding produces identical signed bytes.
 */
export interface GroupCreateParams {
  /** Identity public keys for every participant of the new group. */
  publicKeys: PublicKeyInput[];
  /** ID of the new group conversation (the g-prefixed id minted by the initialize endpoint). */
  conversationId: string;
  /** User IDs of the group's members. */
  memberIds: string[];
  /** User IDs of the group's admins. */
  adminIds: string[];
  /** User ID of the sender signing the create; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the create; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /** The group's title, as plaintext, if set. */
  title?: string | null;
  /** The group's message TTL in milliseconds, if set. */
  ttlMsec?: number | null;
}

/**
 * Parameters for decryptEvent.
 */
export interface DecryptEventParams {
  /** The base64 event, as delivered. */
  eventB64: string;
  /**
   * The conversation's key map, from decryptEvents or
   * extractConversationKeys (its `keys`). Omit it, or pass `{}`, for events
   * without message contents, or to take the keys from the opt-in key cache
   * (setCacheKeys).
   */
  conversationKeys?: ConversationKeyMap | null;
  /** Signing keys to verify the event with; the keys stored via setSigningKeys are used when omitted or empty. */
  signingKeys?: SigningKeyEntry[] | null;
}

/**
 * Parameters for decryptEvents.
 */
export interface DecryptEventsParams {
  /**
   * The base64 events, as delivered. Their key changes supply the
   * conversation keys the messages among them are decrypted with.
   */
  events: string[];
  /** Signing keys for all participants; the keys stored via setSigningKeys are used when omitted or empty. */
  signingKeys?: SigningKeyEntry[] | null;
}

/**
 * Parameters for encryptFile.
 */
export interface EncryptFileParams {
  /** The file to encrypt. */
  file: Uint8Array;
  /** The `eventB64` of the payload that encryptMessage or encryptReply returned for the message carrying the file. */
  eventB64: string;
  /** The media hash key the file's upload started with, as listed in the message's attachments. */
  mediaHashKey: string;
  /**
   * The raw 32-byte conversation key the message was encrypted under; with
   * conversationKeyVersion omitted too, it resolves from the opt-in key
   * cache (setCacheKeys), as for encryptMessage.
   */
  conversationKey?: Uint8Array | null;
  /** The version of conversationKey: the message's key version. */
  conversationKeyVersion?: string | null;
}

/**
 * Parameters for fileEncryptor: those of encryptFile apart from the file,
 * which is fed to the encryptor.
 */
export interface FileEncryptorParams {
  /** The `eventB64` of the payload that encryptMessage or encryptReply returned for the message carrying the file. */
  eventB64: string;
  /** The media hash key the file's upload started with, as listed in the message's attachments. */
  mediaHashKey: string;
  /**
   * The raw 32-byte conversation key the message was encrypted under; with
   * conversationKeyVersion omitted too, it resolves from the opt-in key
   * cache (setCacheKeys), as for encryptMessage.
   */
  conversationKey?: Uint8Array | null;
  /** The version of conversationKey: the message's key version. */
  conversationKeyVersion?: string | null;
}

/**
 * Parameters for decryptFile.
 */
export interface DecryptFileParams {
  /** The encrypted file, as downloaded. */
  encrypted: Uint8Array;
  /** The base64 event of the message that carries the file, as passed to decryptEvent. */
  eventB64: string;
  /** The conversation's key map, as passed to decryptEvent; it must hold the key for the message's version. */
  conversationKeys: ConversationKeyMap;
  /**
   * The file's media hash key from the decrypted message: a media
   * attachment, a link card's banner or favicon, or media quoted in its
   * reply preview.
   */
  mediaHashKey: string;
}

/**
 * Parameters for fileDecryptor: those of decryptFile apart from the
 * encrypted file, which is fed to the decryptor.
 */
export interface FileDecryptorParams {
  /** The base64 event of the message that carries the file, as passed to decryptEvent. */
  eventB64: string;
  /** The conversation's key map, as passed to decryptEvent; it must hold the key for the message's version. */
  conversationKeys: ConversationKeyMap;
  /**
   * The file's media hash key from the decrypted message: a media
   * attachment, a link card's banner or favicon, or media quoted in its
   * reply preview.
   */
  mediaHashKey: string;
}

/**
 * Parameters for encryptFileWithKey: a file under a key you already hold
 * rather than a file attached to a message, such as a group's avatar image
 * under the conversation key whose version is signed next to the avatar
 * URL, or an app's own files at rest.
 */
export interface EncryptFileWithKeyParams {
  /** The file to encrypt. */
  file: Uint8Array;
  /** The raw 32-byte key to encrypt the file under, such as a conversation key. */
  key: Uint8Array;
}

/**
 * Parameters for decryptFileWithKey: a file encrypted under a key you
 * already hold, such as a group's avatar image under the conversation key
 * for the version its avatar change names.
 */
export interface DecryptFileWithKeyParams {
  /** The encrypted file, as downloaded. */
  encrypted: Uint8Array;
  /** The raw 32-byte key the file was encrypted under. */
  key: Uint8Array;
}

// NOTE: AttachmentDescriptor uses snake_case as it's part of the Thrift protocol
// and matches the wire format used by the X API
/**
 * Attachment descriptor object. A media attachment's `filesize_bytes` is the
 * encrypted file's size, `encryptedFileSize` of its size; an empty
 * `filename`, a `filesize_bytes` of 0 or less, or a negative `width` or
 * `height` fails the send with a `ChatXdkError` of kind `invalidInput`, as
 * do a `url` attachment with an empty `url` and a `post` attachment with
 * neither `rest_id` nor `post_url`. A media attachment's optional
 * `plaintext_sha256` is the base64 SHA-256 of the file's plaintext bytes,
 * which recipients can check the decrypted file against: the message carries
 * and signs it, and the message is built before its files are encrypted, so
 * hash the file yourself. One that is not the base64 of 32 bytes fails the
 * send the same way.
 */
export type AttachmentDescriptor =
  | { attachment_type: 'media'; media_hash_key: string; width: number; height: number; filesize_bytes: number; filename: string; media_type?: number; duration_millis?: number; plaintext_sha256?: string | null }
  | { attachment_type: 'url'; url: string; display_title?: string; banner_image?: UrlAttachmentImageDescriptor; favicon_image?: UrlAttachmentImageDescriptor }
  | { attachment_type: 'post'; rest_id?: string; post_url?: string };

/**
 * An encrypted preview image referenced by a URL card attachment.
 *
 * Supplying `display_title` plus a `banner_image` on a `url` attachment makes
 * receiving clients render a full clickable preview card. Start the image's
 * upload to the conversation's media store, reference the media hash key it
 * returns here, then encrypt the image with `encryptFile` or `fileEncryptor`
 * and the message's `eventB64` and finish the upload.
 */
export interface UrlAttachmentImageDescriptor {
  media_hash_key: string;
  /**
   * Size of the encrypted image in bytes: `encryptedFileSize` of the image's
   * size. Required: receiving clients silently discard the preview image
   * when this is missing on the wire, so 0 or less fails the send with a
   * `ChatXdkError` of kind `invalidInput`.
   */
  filesize_bytes: number;
  /**
   * Original filename of the image (receivers key their decrypted-file
   * cache on it). Required: receiving clients silently discard the preview
   * image when this is missing on the wire, so an empty one fails the send
   * with a `ChatXdkError` of kind `invalidInput`.
   */
  filename: string;
  /** Width in pixels, when known; a negative one fails the send. */
  width?: number;
  /** Height in pixels, when known; a negative one fails the send. */
  height?: number;
}

/**
 * Why a message failed to deliver.
 */
export type FailureType =
  | 'emptyDetail'
  | 'internalError'
  | 'contentsTooLarge'
  | 'tooManyMessages'
  | 'invalidSenderSignature'
  | 'nonLatestKeyVersion'
  | 'recipientNotTrusted'
  | 'recipientKeyChanged'
  | 'onlyEncryptedMessagesAllowed'
  | 'requesterNotAdmin'
  | 'flaggedAsSpam'
  | 'rateLimitUpsell'
  | 'signatureFailedToVerifyAgainstPublicKey'
  | 'genericError'
  | 'senderNotGroupMember'
  | 'invalidSignatureVersion'
  | 'invalidPinRequest'
  | 'tooManyPins'
  | 'unknown';

export type RateLimitTier =
  | 'free'
  | 'verifiedPhone'
  | 'premium'
  | 'premiumPlus'
  | 'premiumBusiness'
  | 'unknown';

/**
 * Decrypted event from the SDK.
 * Meta fields (sequenceId, id, senderId, etc.) are flattened to top level.
 */
export interface Event {
  /** Discriminates which event variant this is. */
  type: 'message' | 'keyChange' | 'typing' | 'readReceipt' | 'groupChange' | 
        'messageDeleted' | 'memberDeleted' | 'conversationDeleted' | 
        'settingsChange' | 'markedUnread' | 'failure' | 'unknown';
  /** Flattened from meta: unique sequence ID for ordering. */
  sequenceId?: string;
  /** Flattened from meta: unique message/event ID (snowflake string). */
  id?: string;
  /** Flattened from meta: sender's user ID (snowflake string). */
  senderId?: string;
  /** Flattened from meta: conversation ID (snowflake string). */
  conversationId?: string;
  /** Flattened from meta: event creation timestamp in milliseconds. */
  createdAtMsec?: number;
  /** For message events: the decrypted message content. */
  content?: MessageContent;
  /** Whether the event signature was verified. */
  verified?: boolean;
  /** For message events: attachments included with the message (if any). */
  attachments?: AttachmentInfo[];
  /** For message events: media hash keys derived from attachments (if any). */
  mediaHashes?: MediaHashReference[];
  /**
   * For message events carrying a reply preview with an embedded raw
   * original event: the outcome of validating the preview against that
   * signed original. Absent when the message carries no preview or the
   * preview carries no raw event. 'invalid' previews must be treated as
   * untrusted.
   */
  replyPreviewValidation?: 'valid' | 'invalid';
  /**
   * The conversation key version (a snowflake/timestamp string). On message
   * events: the version the message and any attached media were encrypted
   * under — decrypt them with the matching key from the conversationKeys
   * map. On keyChange events: the new key version introduced by the change.
   */
  conversationKeyVersion?: string;
  /** For keyChange events: encrypted conversation keys, one per participant. */
  conversationParticipantKeys?: ConversationParticipantKey[];
  /** For failure events: why the message failed to deliver. */
  failure?: FailureType;
  /** For rate-limit upsell failures: the account tier whose limit was reached. */
  rateLimitTier?: RateLimitTier;
  /** For messageDeleted events: the `sequenceId`s of the deleted messages. */
  sequenceIds?: string[];
  /** For readReceipt and markedUnread events: the `sequenceId` of the newest event read. */
  seenUntilSequenceId?: string;
  /** Index signature for additional event-specific fields. */
  [key: string]: any;
}

/**
 * A group title or description as a received groupChange event carries it:
 * the `title` of a 'created' change, the `newTitle` of a 'titleChanged' one
 * and the `newDescription` of a 'descriptionChanged' one. 'text' carries the
 * value decrypted, or the plaintext an event that names no key version
 * carries. 'unavailable' carries `raw`, a value the SDK could not decrypt, as
 * the event carries it. 0.5.x apps sent titles as plaintext while naming a
 * key version, so show `raw` when a title isn't decryptable. A member removal
 * re-encrypts the title and description under the new key; those
 * re-encryptions aren't changes, and decrypt drops them.
 */
export type GroupText = { kind: 'text'; text: string } | { kind: 'unavailable'; raw: string };

/**
 * Decrypted message content. Permissive convenience shape: `contentType`
 * discriminates which fields are present (e.g. `text` on 'text' content,
 * `emoji`/`targetMessageSequenceId` on reactions, `updatedText` on edits).
 */
export interface MessageContent {
  /**
   * Discriminates the content kind: 'text', 'reaction', 'reactionRemoved',
   * 'edit', 'markRead', 'markUnread', or 'unknown'.
   */
  contentType?: string;
  /** Present on 'text' content. */
  text?: string;
  /** Present on 'edit' content: the replacement text. */
  updatedText?: string;
  /** Present on 'reaction' and 'reactionRemoved' content. */
  emoji?: string;
  /**
   * Present on 'reaction', 'reactionRemoved', and 'edit' content: the
   * `sequenceId` of the target message.
   */
  targetMessageSequenceId?: string;
  /** Present on 'edit' content sent as v1: the target message's signed message id. */
  targetMessageId?: string;
  /** Present on 'text' and 'edit' content: rich-text entities. */
  entities?: unknown[];
  /** Present on 'text' content: message attachments. */
  attachments?: unknown[];
  /** Present on 'text' content: reply-to preview. */
  replyingToPreview?: unknown;
  /** Present on 'text' content: forwarded message metadata. */
  forwardedMessage?: unknown;
  /** Present on 'text' content: the surface the message was sent from. */
  sentFrom?: string | number;
  /** Present on 'text' content: quick-reply payload, accepted unchanged by encryptMessage / encryptReply. */
  quickReply?: QuickReply;
  /** Present on 'text' content: call-to-action buttons. */
  ctas?: unknown[];
  /** Present on 'unknown' content: the unrecognized numeric type id. */
  typeId?: number;
  /** Index signature for additional content-specific fields. */
  [key: string]: any;
}

export interface MediaHashReference {
  source: string;
  mediaHashKey: string;
}

/**
 * An attachment on a decrypted message. Permissive convenience shape: the
 * per-variant fields are flattened and `attachmentType` discriminates which
 * apply ('media', 'url', 'post', 'unifiedCard', or 'money').
 */
export interface AttachmentInfo {
  /** One of: 'media', 'url', 'post', 'unifiedCard', 'money'. */
  attachmentType?: string;
  mediaHashKey?: string;
  dimensions?: { width?: number; height?: number };
  mediaType?: string;
  durationMillis?: number;
  filesizeBytes?: number;
  filename?: string;
  attachmentId?: string;
  legacyMediaUrlHttps?: string;
  legacyMediaPreviewUrl?: string;
  /** Base64 SHA-256 of the file's plaintext bytes, when the sender included it. */
  plaintextSha256?: string;
  url?: string;
  bannerImageMediaHashKey?: string;
  faviconImageMediaHashKey?: string;
  displayTitle?: string;
  restId?: string;
  postUrl?: string;
  fallbackText?: string;
  /** Index signature for additional attachment-specific fields. */
  [key: string]: any;
}

/**
 * Options for creating a Chat instance.
 */
export interface CreateChatOptions {
  /** 
   * Juicebox configuration JSON from the X API.
   * Obtain this from the `juicebox_config` field of
   * GET /2/users/:id/public_keys (your own user, `public_key.fields=juicebox_config`).
   *
   * Optional to support first boot: `juicebox_config` is created by
   * POST /2/users/:id/public_keys, so a brand-new user has none yet. Omit
   * it, call `generateKeypairs()` and POST the payload yourself, then call
   * `updateConfig()` with the config returned by the GET and `setup(pin)`.
   * Until a config is supplied, `setup`/`unlock`/`changePin`/`delete`
   * throw; all crypto methods work.
   *
   * Accepted shapes match the native bindings and are checked in this
   * order: the `sdk_config` wrapper (its embedded SDK config string is
   * unwrapped for the Juicebox client), the X API `juicebox_config` object
   * (its `key_store_token_map_json` string is used verbatim so realm public
   * keys and server thresholds are preserved), a bare `token_map` array
   * (converted to a realms config with majority recover threshold — no
   * realm public keys, so only suitable for realms that don't require
   * them), or a raw realms config. Realm auth tokens always come from
   * `getAuthToken`, not the config. An empty or blank string throws the
   * `ChatXdkError` of kind `invalidState` a chat without a config gives its
   * Juicebox calls; omit the option instead on first boot.
   */
  juiceboxConfig?: string;
  
  /**
   * Async function to get a Juicebox auth token for a realm.
   *
   * Required to use Juicebox (`updateConfig`, `setup`, `unlock`,
   * `changePin`, `delete`), even when `juiceboxConfig` is omitted at first
   * boot. A chat created without it loads no juicebox-sdk and keeps its keys
   * with `importKeys` / `exportKeys`.
   *
   * @param realmId - Hex-encoded realm ID
   * @returns Promise resolving to the auth token string
   * 
   * @example
   * async (realmId) => {
   *   const response = await fetch(`/api/juicebox/token?realm=${realmId}`, {
   *     headers: { Authorization: `Bearer ${userToken}` }
   *   });
   *   return response.text();
   * }
   */
  getAuthToken?: (realmId: string) => Promise<string>;
}

/**
 * Incremental encryptor for one file of an outgoing message.
 *
 * Feed the file with `push`; call `finish` once to emit the final frame.
 * `finish()` consumes and frees the WASM object — do not call `free()` after
 * it (doing so throws). Call `free()` only when abandoning a file without
 * finishing it.
 */
export interface FileEncryptor {
  /** Encrypt a chunk of the file, returning the encrypted bytes available so far. */
  push(plaintext: Uint8Array): Uint8Array;
  /** Emit the final frame; consumes and frees the encryptor. */
  finish(): Uint8Array;
  /** Release the underlying WASM object when abandoning an unfinished file. */
  free(): void;
}

/**
 * Incremental decryptor for one encrypted file.
 *
 * Feed the encrypted bytes with `push`; call `finish` once at end of input.
 * `finish` throws if the file ended before its final frame (truncation), so
 * do not treat bytes from `push` as complete until `finish` succeeds.
 * `finish()` consumes and frees the WASM object — do not call `free()` after
 * it (doing so throws). Call `free()` only when abandoning a file without
 * finishing it.
 */
export interface FileDecryptor {
  /** Decrypt a chunk of the encrypted file, returning the bytes available so far. */
  push(ciphertext: Uint8Array): Uint8Array;
  /** Decrypt the final frame; consumes and frees the decryptor. */
  finish(): Uint8Array;
  /** Release the underlying WASM object when abandoning an unfinished file. */
  free(): void;
}

/**
 * Common interface for all Chat methods (shared by Chat and ChatWithJuicebox).
 *
 * The raw WASM `Chat` class provides only crypto operations.
 * `ChatWithJuicebox` (returned by `createChat()`) adds Juicebox lifecycle methods.
 */
interface ChatCrypto {
  /**
   * When enabled — the default — `decryptEvent` throws for any signed event
   * whose signature cannot be verified (invalid, missing, or no matching
   * signing key) instead of returning it with `verified: false`.
   */
  setRejectUnverified(reject: boolean): void;

  /**
   * Generate new keypairs and return the registration payload. No
   * signing-key version is set: after registering the keys, call
   * `setIdentity` with the `public_key_version` the registration returns.
   */
  generateKeypairs(): PublicKeyRegistrationPayload;

  /**
   * Set the session identity: the owner's user id and signing-key version,
   * used as defaults wherever a params object omits `senderId` /
   * `signingKeyVersion`.
   */
  setIdentity(params: SetIdentityParams): void;

  /**
   * Enable or disable the conversation-key cache (off by default).
   *
   * While enabled, decryptEvents caches, per conversation, the key whose key
   * change carried a valid signature at the highest version seen, and the
   * encrypt methods resolve an omitted `conversationKey` /
   * `conversationKeyVersion` pair from it. Disabling clears the cache.
   */
  setCacheKeys(enabled: boolean): void;

  /**
   * Store signing keys to use when a decrypt call omits its `signingKeys`
   * argument. Only this explicit call populates the store — a key carried
   * inside an event is never trusted for verification. Each call replaces
   * the previous set.
   */
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;

  /**
   * Load private keys, as `exportKeys` returns them. The SDK's copy of the
   * bytes is zeroized after import; zero your own with `fill(0)`.
   */
  importKeys(params: ImportKeysParams): void;

  /**
   * The loaded private keys, unencrypted: store them only where private
   * keys belong, and zero the bytes with `fill(0)` once done. Throws when
   * no identity key is loaded.
   */
  exportKeys(): Uint8Array;

  /** Get current public keys. */
  getPublicKeys(): PublicKeys;

  /** Get the fingerprint of the loaded identity public key for out-of-band verification. */
  getPublicKeyFingerprint(): string;

  /** Returns true when both identity and signing keys are loaded. */
  isUnlocked(): boolean;

  /** Returns true when the identity key is loaded (sufficient for decryption). */
  hasIdentityKey(): boolean;

  /** Clear keys from memory. */
  lock(): void;

  /** Decrypt an encrypted conversation key (ECIES). */
  decryptConversationKey(encryptedKeyB64: string): Uint8Array;

  /** Extract and decrypt conversation keys from raw KeyChange event strings. */
  extractConversationKeys(events: string[]): ConversationKeyResult;

  /**
   * Decrypt multiple events in batch (recommended API).
   *
   * This method:
   * 1. Extracts conversation keys from any KeyChange events
   * 2. For each message, finds the correct signing key by matching userId + version
   * 3. Decrypts the message using the appropriate conversation key
   *
   * Under the default reject-unverified policy, no signing keys (passed or
   * stored via `setSigningKeys`) makes every signed event land in `errors`;
   * only after `setRejectUnverified(false)` are such events returned with
   * `verified: false`. A member removal's title and description,
   * re-encrypted under the new key, aren't changes: they land in `errors`
   * under either policy.
   */
  decryptEvents(params: DecryptEventsParams): DecryptEventsResult;

  /**
   * Decrypt a raw webhook event payload.
   *
   * Under the default reject-unverified policy, no signing keys (passed or
   * stored via `setSigningKeys`) makes every signed event throw; only after
   * `setRejectUnverified(false)` are such events returned with
   * `verified: false`. A member removal's title and description,
   * re-encrypted under the new key, aren't changes: they throw a
   * `ChatXdkError` of kind `'invalidInput'` under either policy.
   */
  decryptEvent(params: DecryptEventParams): Event;

  /**
   * Sign application data. Returns raw signature bytes (64 bytes). Throws for
   * an event signature payload or a public key, which only the SDK signs.
   */
  sign(data: Uint8Array): Uint8Array;

  /** Verify a signature. */
  verify(publicKeyB64: string, signature: Uint8Array, data: Uint8Array): boolean;

  /** Verify that an identity key signed a signing key (key binding). */
  verifyKeyBinding(identityPublicKeyB64: string, signingPublicKeyB64: string, identityPublicKeySignatureB64: string): boolean;

  /**
   * Report whether the loaded identity public key is the key in
   * `publicKeyB64` — accepts the raw SEC1 point (as returned by
   * `getPublicKeys`) or the SPKI/DER encoding (as returned by the X API).
   */
  matchesRegisteredKey(publicKeyB64: string): boolean;

  /** Encrypt a text message. */
  encryptMessage(params: EncryptMessageParams): SendPayload;

  /** Encrypt a reply. */
  encryptReply(params: EncryptReplyParams): SendPayload;

  /** Encrypt a reaction-add. */
  encryptAddReaction(params: EncryptReactionParams): SendPayload;

  /** Encrypt a reaction-remove. */
  encryptRemoveReaction(params: EncryptReactionParams): SendPayload;

  /** Encrypt a message edit. */
  encryptEdit(params: EncryptEditParams): SendPayload;

  /**
   * Build the signed action for deleting messages from a conversation: the
   * request's `actionSignatures`, one entry.
   */
  prepareMessageDelete(params: MessageDeleteParams): PreparedAction;

  /**
   * Build the signed action for marking a conversation read: the
   * `actionSignatures` of the mark-read request
   * (`POST /2/chat/conversations/{id}/read`), one entry.
   */
  prepareMarkConversationRead(params: MarkConversationReadParams): PreparedAction;

  /**
   * Encrypt a file of an outgoing message, after the message is built.
   *
   * The SDK finds the attachment that names `params.mediaHashKey` in the
   * message `params.eventB64` carries, and encrypts the file under that
   * attachment's key. Upload the result under the same media hash key; its
   * size is `encryptedFileSize(file.length)`. Throws, saying what to pass
   * instead, when the event is not a message with this file or the
   * conversation key is not the one the message was encrypted under.
   */
  encryptFile(params: EncryptFileParams): Uint8Array;

  /**
   * Create an incremental encryptor for a file too large to hold in memory.
   * Takes the params of `encryptFile` apart from the file, which is fed to
   * the encryptor.
   */
  fileEncryptor(params: FileEncryptorParams): FileEncryptor;

  /**
   * Decrypt an encrypted file, as downloaded.
   *
   * Throws, saying what to pass instead, when the key version is missing,
   * the event is not an encrypted message with this file, or `encrypted` is
   * not the file's complete encrypted bytes.
   */
  decryptFile(params: DecryptFileParams): Uint8Array;

  /**
   * Create an incremental decryptor for an encrypted file too large to hold
   * in memory. Takes the params of `decryptFile` apart from the encrypted
   * bytes, which are fed to the decryptor.
   */
  fileDecryptor(params: FileDecryptorParams): FileDecryptor;

  /**
   * Encrypt a file under a key you already hold, rather than from a
   * message: a group's avatar image under the conversation key whose
   * version is signed next to the avatar URL, or an app's own files at rest.
   *
   * The file is encrypted under `params.key` itself, in the format
   * `encryptFile` writes; its size is `encryptedFileSize(file.length)`.
   * Throws a `ChatXdkError` of kind `invalidInput` when the key is not 32
   * bytes.
   */
  encryptFileWithKey(params: EncryptFileWithKeyParams): Uint8Array;

  /**
   * Decrypt a file encrypted under a key you already hold, as downloaded,
   * such as a group's avatar image under the conversation key for the
   * version its avatar change names.
   *
   * Throws a `ChatXdkError` of kind `invalidInput` when the key is not 32
   * bytes, and of kind `decryption` when `encrypted` is not the complete
   * file encrypted under the key.
   */
  decryptFileWithKey(params: DecryptFileWithKeyParams): Uint8Array;

  /**
   * Decrypt a group title or description the X API returns for a
   * conversation. Group changes in events need no call of their own:
   * decryptEvent returns them decrypted.
   */
  decrypt(ciphertextB64: string, conversationKey: Uint8Array): string;

  /**
   * Prepare a signed conversation-key change, ready to send to the X API.
   *
   * Use this to start a one-to-one or rotate an existing conversation's key
   * (one-to-one or group). Creating a group or adding members requires a
   * paired group signature as well — use prepareGroupCreate or
   * prepareGroupMembersChange for those.
   *
   * Pass the flat array of public keys (self plus recipients) from the X API
   * in params.publicKeys. Omit params.conversationId for a one-to-one (it is
   * derived from the two participants); pass the existing id for a group key
   * rotation.
   *
   * @returns PreparedConversationChange ready to POST to the API
   */
  prepareConversationKeyChange(params: ConversationKeyChangeParams): PreparedConversationChange;

  /**
   * Prepare a signed group member-add change, ready to send to the X API.
   *
   * Use this when adding members to an existing group. Creating the group is
   * prepareGroupCreate; a key rotation without a roster change is
   * prepareConversationKeyChange.
   *
   * `currentTitle` and `currentDescription` are plaintext: the call encrypts
   * each under the new conversation key and signs the ciphertext.
   *
   * @returns PreparedConversationChange with two action signatures (the
   * conversation-key change and the member add), and `encryptedTitle` and
   * `encryptedDescription` for a title and description the params set
   */
  prepareGroupMembersChange(params: GroupMembersChangeParams): PreparedConversationChange;

  /**
   * Prepare a signed group create, ready to send to the X API.
   *
   * Use this once, when creating a group (conversationId is the g-prefixed id
   * minted by the initialize endpoint). Later key rotations use
   * prepareConversationKeyChange; roster additions use
   * prepareGroupMembersChange.
   *
   * `title` is plaintext: the call encrypts it under the new conversation key
   * and signs the ciphertext. A create sets no avatar; set it afterwards with
   * prepareGroupAvatarChange.
   *
   * @returns PreparedConversationChange with two action signatures (the
   * conversation-key change and the group create), and `encryptedTitle` for a
   * title the params set: the `group_name` the create request sends
   */
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;

  /**
   * Sign a group member removal and rotate the conversation key for the
   * members who stay (`publicKeys`).
   *
   * @returns PreparedConversationChange with the new key and the action
   * signatures: the removal, a title and a description change for each one
   * the params set, re-encrypted under the new key, and the conversation-key
   * change
   */
  prepareGroupMembersRemove(params: GroupMembersRemoveParams): PreparedConversationChange;

  /** Sign leaving a group. Does not rotate the conversation key. */
  prepareGroupLeave(params: GroupLeaveParams): PreparedAction;

  /** Encrypt a new group title under the conversation key and sign the change. */
  prepareGroupTitleChange(params: GroupTitleChangeParams): PreparedGroupMetadataChange;

  /**
   * Sign a group avatar change: the avatar image's media URL, as is, and the
   * version of the key the image is encrypted under.
   */
  prepareGroupAvatarChange(params: GroupAvatarChangeParams): PreparedAction;

  /** Encrypt a new group description under the conversation key and sign the change. */
  prepareGroupDescriptionChange(params: GroupDescriptionChangeParams): PreparedGroupMetadataChange;

  /** Sign adding group admins. */
  prepareGroupAdminsAdd(params: GroupAdminsAddParams): PreparedAction;

  /** Sign removing group admins. */
  prepareGroupAdminsRemove(params: GroupAdminsRemoveParams): PreparedAction;

  /** Sign enabling a group invite. */
  prepareGroupInviteEnable(params: GroupInviteEnableParams): PreparedAction;

  /** Sign disabling a group invite. */
  prepareGroupInviteDisable(params: GroupInviteDisableParams): PreparedAction;

  /** Sign a request to join a group. */
  prepareGroupJoinRequest(params: GroupJoinRequestParams): PreparedAction;

  /** Sign rejecting group join requests. */
  prepareGroupJoinReject(params: GroupJoinRejectParams): PreparedAction;

  /** Sign a message-TTL change. */
  prepareMessageTtlChange(params: MessageTtlChangeParams): PreparedAction;

  /** Sign clearing a conversation's message TTL. */
  prepareMessageTtlRemove(params: MessageTtlRemoveParams): PreparedAction;

  /** Sign one screen-capture setting change. */
  prepareScreenCapture(params: ScreenCaptureParams): PreparedAction;
}

/** Internal crypto engine wrapped by ChatWithJuicebox. Not part of the public API. */
declare class Chat implements ChatCrypto {
  constructor();

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(params: SetIdentityParams): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  /**
   * Import private keys from `keys` (32 or 64 bytes). When
   * `signingKeyVersion` is given it also records the public key version the
   * keys were registered under.
   */
  importKeys(params: ImportKeysParams): void;
  /** Export private keys as raw bytes; throws when no identity key is loaded. */
  exportKeys(): Uint8Array;
  getPublicKeys(): PublicKeys;
  getPublicKeyFingerprint(): string;
  isUnlocked(): boolean;
  hasIdentityKey(): boolean;
  lock(): void;
  decryptConversationKey(encryptedKeyB64: string): Uint8Array;
  extractConversationKeys(events: string[]): ConversationKeyResult;
  decryptEvents(params: DecryptEventsParams): DecryptEventsResult;
  decryptEvent(params: DecryptEventParams): Event;
  sign(data: Uint8Array): Uint8Array;
  verify(publicKeyB64: string, signature: Uint8Array, data: Uint8Array): boolean;
  verifyKeyBinding(identityPublicKeyB64: string, signingPublicKeyB64: string, identityPublicKeySignatureB64: string): boolean;
  matchesRegisteredKey(publicKeyB64: string): boolean;
  encryptMessage(params: EncryptMessageParams): SendPayload;
  encryptReply(params: EncryptReplyParams): SendPayload;
  encryptAddReaction(params: EncryptReactionParams): SendPayload;
  encryptRemoveReaction(params: EncryptReactionParams): SendPayload;
  encryptEdit(params: EncryptEditParams): SendPayload;
  prepareMessageDelete(params: MessageDeleteParams): PreparedAction;
  prepareMarkConversationRead(params: MarkConversationReadParams): PreparedAction;
  encryptFile(params: EncryptFileParams): Uint8Array;
  fileEncryptor(params: FileEncryptorParams): FileEncryptor;
  decryptFile(params: DecryptFileParams): Uint8Array;
  fileDecryptor(params: FileDecryptorParams): FileDecryptor;
  encryptFileWithKey(params: EncryptFileWithKeyParams): Uint8Array;
  decryptFileWithKey(params: DecryptFileWithKeyParams): Uint8Array;
  decrypt(ciphertextB64: string, conversationKey: Uint8Array): string;
  prepareConversationKeyChange(params: ConversationKeyChangeParams): PreparedConversationChange;
  prepareGroupMembersChange(params: GroupMembersChangeParams): PreparedConversationChange;
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;
  prepareGroupMembersRemove(params: GroupMembersRemoveParams): PreparedConversationChange;
  prepareGroupLeave(params: GroupLeaveParams): PreparedAction;
  prepareGroupTitleChange(params: GroupTitleChangeParams): PreparedGroupMetadataChange;
  prepareGroupAvatarChange(params: GroupAvatarChangeParams): PreparedAction;
  prepareGroupDescriptionChange(params: GroupDescriptionChangeParams): PreparedGroupMetadataChange;
  prepareGroupAdminsAdd(params: GroupAdminsAddParams): PreparedAction;
  prepareGroupAdminsRemove(params: GroupAdminsRemoveParams): PreparedAction;
  prepareGroupInviteEnable(params: GroupInviteEnableParams): PreparedAction;
  prepareGroupInviteDisable(params: GroupInviteDisableParams): PreparedAction;
  prepareGroupJoinRequest(params: GroupJoinRequestParams): PreparedAction;
  prepareGroupJoinReject(params: GroupJoinRejectParams): PreparedAction;
  prepareMessageTtlChange(params: MessageTtlChangeParams): PreparedAction;
  prepareMessageTtlRemove(params: MessageTtlRemoveParams): PreparedAction;
  prepareScreenCapture(params: ScreenCaptureParams): PreparedAction;
}

/**
 * Chat with integrated Juicebox key storage (returned by `createChat()`).
 *
 * Key material is managed inside the Juicebox layer.
 */
export declare class ChatWithJuicebox implements ChatCrypto {
  /**
   * Register keys with Juicebox. The PIN must meet strength requirements
   * (4+ characters, not a single repeated character or sequential digit
   * run). Pass a Uint8Array to be able to zero the buffer afterwards.
   *
   * Requires a Juicebox config: throws a `ChatXdkError` of kind
   * `invalidState` if the instance was created without `juiceboxConfig` and
   * `updateConfig()` has not been called yet.
   */
  setup(pin: string | Uint8Array): Promise<PublicKeys>;
  /** Requires a Juicebox config, like setup(). */
  unlock(pin: string | Uint8Array): Promise<void>;
  /** Requires a Juicebox config, like setup(). */
  delete(): Promise<void>;
  /**
   * The new PIN must meet the same strength requirements as setup().
   * Requires a Juicebox config, like setup().
   */
  changePin(oldPin: string | Uint8Array, newPin: string | Uint8Array): Promise<void>;
  /**
   * (Re-)create the Juicebox client from a config (e.g. refreshed auth
   * tokens), with the PIN guess budget the config sets. On an instance
   * created without `juiceboxConfig`, this is the first-boot step that
   * enables `setup`/`unlock`/`changePin`/`delete`.
   */
  updateConfig(juiceboxConfig: string): void;

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(params: SetIdentityParams): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  importKeys(params: ImportKeysParams): void;
  exportKeys(): Uint8Array;
  getPublicKeys(): PublicKeys;
  getPublicKeyFingerprint(): string;
  isUnlocked(): boolean;
  hasIdentityKey(): boolean;
  lock(): void;
  decryptConversationKey(encryptedKeyB64: string): Uint8Array;
  extractConversationKeys(events: string[]): ConversationKeyResult;
  decryptEvents(params: DecryptEventsParams): DecryptEventsResult;
  decryptEvent(params: DecryptEventParams): Event;
  sign(data: Uint8Array): Uint8Array;
  verify(publicKeyB64: string, signature: Uint8Array, data: Uint8Array): boolean;
  verifyKeyBinding(identityPublicKeyB64: string, signingPublicKeyB64: string, identityPublicKeySignatureB64: string): boolean;
  matchesRegisteredKey(publicKeyB64: string): boolean;
  encryptMessage(params: EncryptMessageParams): SendPayload;
  encryptReply(params: EncryptReplyParams): SendPayload;
  encryptAddReaction(params: EncryptReactionParams): SendPayload;
  encryptRemoveReaction(params: EncryptReactionParams): SendPayload;
  encryptEdit(params: EncryptEditParams): SendPayload;
  prepareMessageDelete(params: MessageDeleteParams): PreparedAction;
  prepareMarkConversationRead(params: MarkConversationReadParams): PreparedAction;
  encryptFile(params: EncryptFileParams): Uint8Array;
  fileEncryptor(params: FileEncryptorParams): FileEncryptor;
  decryptFile(params: DecryptFileParams): Uint8Array;
  fileDecryptor(params: FileDecryptorParams): FileDecryptor;
  encryptFileWithKey(params: EncryptFileWithKeyParams): Uint8Array;
  decryptFileWithKey(params: DecryptFileWithKeyParams): Uint8Array;
  decrypt(ciphertextB64: string, conversationKey: Uint8Array): string;
  prepareConversationKeyChange(params: ConversationKeyChangeParams): PreparedConversationChange;
  prepareGroupMembersChange(params: GroupMembersChangeParams): PreparedConversationChange;
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;
  prepareGroupMembersRemove(params: GroupMembersRemoveParams): PreparedConversationChange;
  prepareGroupLeave(params: GroupLeaveParams): PreparedAction;
  prepareGroupTitleChange(params: GroupTitleChangeParams): PreparedGroupMetadataChange;
  prepareGroupAvatarChange(params: GroupAvatarChangeParams): PreparedAction;
  prepareGroupDescriptionChange(params: GroupDescriptionChangeParams): PreparedGroupMetadataChange;
  prepareGroupAdminsAdd(params: GroupAdminsAddParams): PreparedAction;
  prepareGroupAdminsRemove(params: GroupAdminsRemoveParams): PreparedAction;
  prepareGroupInviteEnable(params: GroupInviteEnableParams): PreparedAction;
  prepareGroupInviteDisable(params: GroupInviteDisableParams): PreparedAction;
  prepareGroupJoinRequest(params: GroupJoinRequestParams): PreparedAction;
  prepareGroupJoinReject(params: GroupJoinRejectParams): PreparedAction;
  prepareMessageTtlChange(params: MessageTtlChangeParams): PreparedAction;
  prepareMessageTtlRemove(params: MessageTtlRemoveParams): PreparedAction;
  prepareScreenCapture(params: ScreenCaptureParams): PreparedAction;

  /**
   * Release the WASM-side crypto engine: clears key material (`lock()`) and
   * frees the underlying WASM object. The instance must not be used
   * afterwards. When reusing the instance, `lock()` alone suffices for key
   * hygiene.
   */
  free(): void;
}

/**
 * Create a Chat instance, with Juicebox key storage when `getAuthToken` is
 * given.
 *
 * `juiceboxConfig` is optional: on first boot (no `juicebox_config` on the
 * account yet) create with just `getAuthToken`, `generateKeypairs()`, POST
 * the payload, then `updateConfig()` + `setup(pin)`. Without
 * `getAuthToken`, the chat keeps its keys with `importKeys` / `exportKeys`
 * and needs no juicebox-sdk.
 *
 * Each call creates an independent instance with its own Juicebox client.
 * The Juicebox auth-token callback is a process-wide global that each
 * instance re-arms before its own operations, so sequential use of multiple
 * instances is fine but concurrent Juicebox operations across instances in
 * one process are not supported.
 */
export declare function createChat(options?: CreateChatOptions): Promise<ChatWithJuicebox>;

// Utility Functions

/** Return the exact size of a file once encrypted: the size its upload declares before the file is encrypted. */
export declare function encryptedFileSize(plaintextSize: number): number;

/** Encode bytes to base64 string. */
export declare function bytesToBase64(bytes: Uint8Array): string;

/** Decode base64 string to bytes. Returns undefined if invalid. */
export declare function base64ToBytes(b64: string): Uint8Array | undefined;

/** Encode bytes to lowercase hex string. */
export declare function bytesToHex(bytes: Uint8Array): string;

/** Decode hex string to bytes. Returns undefined if invalid. */
export declare function hexToBytes(hex: string): Uint8Array | undefined;

/** Detect MIME type from file bytes. Returns the MIME type string or undefined. */
export declare function detectMimeType(bytes: Uint8Array): string | undefined;

/** Detect image dimensions from file bytes. Returns { width, height } or null. */
export declare function detectImageDimensions(bytes: Uint8Array): ImageDimensions | null;

// Only the declarations marked `export` above are part of the module.
export {};
