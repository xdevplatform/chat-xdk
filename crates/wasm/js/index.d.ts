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
  /**
   * Always the empty string; reserved. The registered key version is
   * tracked internally and not surfaced here.
   */
  version: string;
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
  version?: string;
  generateVersion: boolean;
}

/**
 * Result from encryptMessage, encryptReply, encryptAddReaction, and
 * encryptRemoveReaction.
 */
export interface SendPayload {
  /**
   * SDK-generated message id (UUID) embedded in the signed event. Send it as
   * the message's `messageId`, keep it to dedup and to anchor replies, and
   * reuse the same encrypted payload on retries so an id is never minted twice.
   */
  messageId: string;
  /** Base64-encoded Thrift MessageCreateEvent. */
  encryptedContent: string;
  /** Base64-encoded ECDSA signature. */
  signature: string;
  /** Base64-encoded Thrift MessageEventSignature. */
  encodedEventSignature: string;
  /** Signature metadata (signing key version + signature protocol version). */
  signatureInfo: { publicKeyVersion: string; signatureVersion: string };
  /** Version of the conversation key used to encrypt the content (a snowflake/timestamp string). */
  conversationKeyVersion: string;
  /** Whether the X API should send a push notification for this message. */
  shouldNotify: boolean;
}

/**
 * An action signature authenticating a conversation key change, member add, or message delete.
 */
export interface ActionSignature {
  messageId: string;
  encodedMessageEventDetail: string;
  signature: string;
  signatureVersion: string;
  publicKeyVersion: string;
  /**
   * The comma-separated payload string that was signed; populated for group
   * changes and message deletes. Omitted for conversation-key changes, whose
   * payload embeds the plaintext conversation key.
   */
  signaturePayload?: string;
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
  /** The latest (highest) key version, for encrypting new messages. */
  latestVersion: string | null;
}

/**
 * A single decrypted message from decryptEvents.
 */
export interface DecryptedMessage {
  /** The decrypted event. */
  event: Event;
  /** Original base64 event string (for reference). */
  originalB64?: string;
}

/**
 * Result from decryptEvents batch API.
 */
export interface DecryptEventsResult {
  /** Successfully decrypted messages. */
  messages: DecryptedMessage[];
  /** Extracted conversation keys (for caching). */
  conversationKeys: ConversationKeyResult;
  /** Errors encountered during decryption (event index, as a string key → error message). */
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
 * Encrypted conversation key for a single participant.
 */
export interface EncryptedKeyForRecipient {
  userId: string;
  encryptedKey: string;
  publicKeyVersion: string;
}

/**
 * A public key input for prepareConversationKeyChange / prepareGroupMembersChange.
 *
 * Represents a single public key version for a user, as returned by the
 * X API `GET /2/dm/encryption/public_keys` endpoint.
 *
 * Pass the full array — the SDK groups by userId and picks the latest
 * version per user automatically.
 */
export interface PublicKeyInput {
  /** The user's user ID (snowflake string). */
  userId: string;
  /** Base64-encoded identity public key (SEC1 or SPKI). */
  publicKey: string;
  /** Key version string from the X API. */
  keyVersion: string;
}

/**
 * Result from prepareConversationKeyChange / prepareGroupMembersChange.
 *
 * Contains everything needed to POST the change to the X API: the new key
 * (to keep locally), the per-participant encrypted copies, and the action
 * signature that lets recipients verify the change.
 */
export interface PreparedConversationChange {
  /** Conversation id the change applies to (derived for a one-to-one, or the id you passed). */
  conversationId: string;
  /** Raw conversation key bytes (32 bytes). Store locally for encrypting messages. */
  conversationKey: Uint8Array;
  /** Timestamp-based version string for this conversation key. */
  conversationKeyVersion: string;
  /** Encrypted keys for each participant, ready to POST to the API. */
  participantKeys: EncryptedKeyForRecipient[];
  /** Action signatures authenticating the change, ready to POST to the API. */
  actionSignatures: ActionSignature[];
}

/**
 * Entity descriptor tuple: [startByteOffset, endByteOffset, entityType].
 * entityType is one of: "url", "mention", "hashtag", "cashtag", "email",
 * "address", "phoneNumber" (the snake_case spelling "phone_number" is
 * accepted too). Unrecognized entity types are silently dropped — the
 * message encrypts without that entity and no error is raised.
 */
export type EntityTuple = [number, number, string];

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
  /** Optional attachments (posts, URLs, media, etc.) to include in the message. */
  attachments?: AttachmentDescriptor[] | null;
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
   * (sequence id, sender, text, entities, attachments) is derived from it
   * and the raw event is embedded so recipients can validate the preview.
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
   * The sender ID of the message being replied to (for preview); derived
   * from replyToEvent when omitted.
   * Prefer a string: snowflake user ids exceed the range where JavaScript
   * numbers stay exact. Numbers are accepted only while integral and within
   * `Number.MAX_SAFE_INTEGER`.
   */
  replyToSenderId?: string | number | null;
  /** The text of the message being replied to (for preview); derived from replyToEvent when omitted. */
  replyToText?: string | null;
  /** Optional rich-text entities (URLs, mentions, etc.) to embed in the outgoing message. */
  entities?: EntityTuple[] | null;
  /** Optional attachments (posts, URLs, media, etc.) to include in the outgoing message. */
  attachments?: AttachmentDescriptor[] | null;
  /** Rich-text entities from the original message (for the reply preview); derived from replyToEvent when omitted. */
  replyToEntities?: EntityTuple[] | null;
  /** Attachments from the original message (for the reply preview); derived from replyToEvent when omitted. */
  replyToAttachments?: AttachmentDescriptor[] | null;
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
 * message being edited — and lets the SDK derive the conversation id and
 * target sequence id from it.
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
 * An unset optional signs the null sentinel, so every binding produces
 * identical signed bytes.
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
  /** The group's current title, if set. */
  currentTitle?: string | null;
  /** The group's current avatar URL, if set. */
  currentAvatarUrl?: string | null;
  /** The group's current message TTL in milliseconds, if set. */
  currentTtlMsec?: number | null;
  /** The group's current screen-capture-blocking state; omit when unset. */
  currentScreenCaptureBlockingEnabled?: boolean | null;
}

/**
 * Parameters for prepareGroupCreate.
 *
 * An unset optional signs the null sentinel, so every binding produces
 * identical signed bytes.
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
  /** The group's title, if set. */
  title?: string | null;
  /** The group's avatar URL, if set. */
  avatarUrl?: string | null;
  /** The group's message TTL in milliseconds, if set. */
  ttlMsec?: number | null;
}

// NOTE: AttachmentDescriptor uses snake_case as it's part of the Thrift protocol
// and matches the wire format used by the X API
/**
 * Attachment descriptor object.
 */
export type AttachmentDescriptor =
  | { attachment_type: 'media'; media_hash_key: string; width: number; height: number; filesize_bytes: number; filename: string; media_type?: number; duration_millis?: number }
  | { attachment_type: 'url'; url: string; display_title?: string; banner_image?: UrlAttachmentImageDescriptor; favicon_image?: UrlAttachmentImageDescriptor }
  | { attachment_type: 'post'; rest_id?: string; post_url?: string };

/**
 * An encrypted preview image referenced by a URL card attachment.
 *
 * Supplying `display_title` plus a `banner_image` on a `url` attachment makes
 * receiving clients render a full clickable preview card. Encrypt the image
 * with `encryptStream`/`streamEncryptor`, upload it to the conversation's
 * media store, and reference the returned media hash key here.
 */
export interface UrlAttachmentImageDescriptor {
  media_hash_key: string;
  /**
   * Size of the encrypted image in bytes. Required: receiving clients
   * silently discard the preview image when this is missing on the wire.
   */
  filesize_bytes: number;
  /**
   * Original filename of the image (receivers key their decrypted-file
   * cache on it). Required: receiving clients silently discard the preview
   * image when this is missing on the wire.
   */
  filename: string;
  width?: number;
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
  keyVersion?: string;
  /** For keyChange events: encrypted conversation keys, one per participant. */
  participantKeys?: ParticipantKey[];
  /** For failure events: why the message failed to deliver. */
  failure?: FailureType;
  /** For rate-limit upsell failures: the account tier whose limit was reached. */
  rateLimitTier?: RateLimitTier;
  /** Index signature for additional event-specific fields. */
  [key: string]: any;
}

/**
 * Decrypted message content. Permissive convenience shape: `contentType`
 * discriminates which fields are present (e.g. `text` on 'text' content,
 * `emoji`/`targetMessageId` on reactions, `newText` on edits).
 */
export interface MessageContent {
  /**
   * Discriminates the content kind: 'text', 'reaction', 'reactionRemoved',
   * 'edit', 'markRead', 'markUnread', or 'unknown'.
   */
  contentType?: string;
  /** Present on 'text' content. */
  text?: string;
  /** Present on 'edit' content. */
  newText?: string;
  /** Present on 'reaction' and 'reactionRemoved' content. */
  emoji?: string;
  /** Present on 'reaction', 'reactionRemoved', and 'edit' content. */
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
  /** Present on 'text' content: quick-reply payload. */
  quickReply?: unknown;
  /** Present on 'text' content: call-to-action buttons. */
  ctas?: unknown[];
  /** Present on 'unknown' content: the unrecognized numeric type id. */
  typeId?: number;
  /** Index signature for additional content-specific fields. */
  [key: string]: any;
}

export interface ParticipantKey {
  userId: string;
  encryptedKey: string;
  publicKeyVersion: string;
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
 * Options for creating a Chat instance with Juicebox integration.
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
   * `getAuthToken`, not the config.
   */
  juiceboxConfig?: string;
  
  /**
   * Async function to get a Juicebox auth token for a realm.
   *
   * Required even when `juiceboxConfig` is omitted: the first Juicebox
   * operation after `updateConfig()` (typically first-boot `setup`) needs it.
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
  getAuthToken: (realmId: string) => Promise<string>;

  /**
   * Optional override for the number of PIN guesses allowed before lockout.
   * A non-negative integer wins over the config, including across later
   * `updateConfig()` calls. When omitted, the config's `max_guess_count`
   * applies when it is a non-negative integer (0 included), defaulting to
   * 20 for the `sdk_config` and `key_store_token_map_json` shapes and 5
   * otherwise.
   */
  maxGuessCount?: number;
}

/**
 * Incremental stream encryptor for large payloads.
 *
 * Feed plaintext with `push`; call `finish` once to emit the final frame.
 * `finish()` consumes and frees the WASM object — do not call `free()` after
 * it (doing so throws). Call `free()` only when abandoning a stream without
 * finishing it.
 */
export declare class StreamEncryptor {
  /** Encrypt a plaintext chunk, returning ciphertext available so far. */
  push(plaintext: Uint8Array): Uint8Array;
  /** Emit the final frame; consumes and frees the encryptor. */
  finish(): Uint8Array;
  /** Release the underlying WASM object when abandoning an unfinished stream. */
  free(): void;
}

/**
 * Incremental stream decryptor for large payloads.
 *
 * Feed ciphertext with `push`; call `finish` once at end of input. `finish`
 * throws if the stream ended before its final frame (truncation), so do not
 * treat plaintext from `push` as complete until `finish` succeeds.
 * `finish()` consumes and frees the WASM object — do not call `free()` after
 * it (doing so throws). Call `free()` only when abandoning a stream without
 * finishing it.
 */
export declare class StreamDecryptor {
  /** Decrypt a ciphertext chunk, returning plaintext available so far. */
  push(ciphertext: Uint8Array): Uint8Array;
  /** Decrypt the final frame; consumes and frees the decryptor. */
  finish(): Uint8Array;
  /** Release the underlying WASM object when abandoning an unfinished stream. */
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

  /** Generate new keypairs and return the registration payload. */
  generateKeypairs(): PublicKeyRegistrationPayload;

  /**
   * Set the session identity: the owner's user id and signing-key version,
   * used as defaults wherever a params object omits `senderId` /
   * `signingKeyVersion`.
   */
  setIdentity(userId: string, signingKeyVersion: string): void;

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
   * @param events - Raw base64-encoded event strings from the webhook
   * @param signingKeys - All known signing keys for all participants (with
   * userId). Omitting this falls back to the keys stored via
   * `setSigningKeys`. Under the default reject-unverified policy, no signing
   * keys from either source makes every signed event land in `errors`; only
   * after `setRejectUnverified(false)` are such events returned with
   * `verified: false`.
   */
  decryptEvents(events: string[], signingKeys?: SigningKeyEntry[]): DecryptEventsResult;

  /**
   * Decrypt a raw webhook event payload.
   *
   * Omitting `conversationKeys` falls back to the opt-in key cache
   * (`setCacheKeys(true)`); omitting `signingKeys` falls back to the keys
   * stored via `setSigningKeys`. Under the default reject-unverified policy,
   * no signing keys from either source makes every signed event throw; only
   * after `setRejectUnverified(false)` are such events returned with
   * `verified: false`.
   */
  decryptEvent(eventB64: string, conversationKeys?: ConversationKeyMap | null, signingKeys?: SigningKeyEntry[]): Event;

  /** Sign data. Returns raw signature bytes (64 bytes). */
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

  /** Build the signed action for deleting messages from a conversation. */
  prepareMessageDelete(params: MessageDeleteParams): ActionSignature;

  /** Encrypt a stream (e.g. media). */
  encryptStream(plaintext: Uint8Array, conversationKey: Uint8Array): Uint8Array;

  /** Decrypt a streaming-encrypted payload (e.g. media). */
  decryptStream(encrypted: Uint8Array, conversationKey: Uint8Array): Uint8Array;

  /** Create an incremental stream encryptor for large payloads. */
  streamEncryptor(conversationKey: Uint8Array): StreamEncryptor;

  /** Create an incremental stream decryptor for large payloads. */
  streamDecryptor(conversationKey: Uint8Array): StreamDecryptor;

  /** Encrypt a UTF-8 string and return base64 ciphertext. Use for metadata fields like group names. */
  encrypt(plaintext: string, conversationKey: Uint8Array): string;

  /** Decrypt a base64-encoded ciphertext and return the UTF-8 plaintext. Use for metadata fields like group names. */
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
   * @returns PreparedConversationChange with two action signatures: the
   * conversation-key change and the member add
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
   * @returns PreparedConversationChange with two action signatures: the
   * conversation-key change and the group create
   */
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;
}

/** Internal crypto engine wrapped by ChatWithJuicebox. Not part of the public API. */
declare class Chat implements ChatCrypto {
  constructor();

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(userId: string, signingKeyVersion: string): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  /**
   * Import private keys from raw bytes. When `version` is given it also
   * records the public key version the keys were registered under. The
   * input bytes are zeroized after import.
   */
  importKeys(keys: Uint8Array, version?: string): void;
  /** Export private keys as raw bytes. */
  exportKeys(): Uint8Array;
  getPublicKeys(): PublicKeys;
  getPublicKeyFingerprint(): string;
  isUnlocked(): boolean;
  hasIdentityKey(): boolean;
  lock(): void;
  decryptConversationKey(encryptedKeyB64: string): Uint8Array;
  extractConversationKeys(events: string[]): ConversationKeyResult;
  decryptEvents(events: string[], signingKeys?: SigningKeyEntry[]): DecryptEventsResult;
  decryptEvent(eventB64: string, conversationKeys?: ConversationKeyMap | null, signingKeys?: SigningKeyEntry[]): Event;
  sign(data: Uint8Array): Uint8Array;
  verify(publicKeyB64: string, signature: Uint8Array, data: Uint8Array): boolean;
  verifyKeyBinding(identityPublicKeyB64: string, signingPublicKeyB64: string, identityPublicKeySignatureB64: string): boolean;
  matchesRegisteredKey(publicKeyB64: string): boolean;
  encryptMessage(params: EncryptMessageParams): SendPayload;
  encryptReply(params: EncryptReplyParams): SendPayload;
  encryptAddReaction(params: EncryptReactionParams): SendPayload;
  encryptRemoveReaction(params: EncryptReactionParams): SendPayload;
  encryptEdit(params: EncryptEditParams): SendPayload;
  prepareMessageDelete(params: MessageDeleteParams): ActionSignature;
  encryptStream(plaintext: Uint8Array, conversationKey: Uint8Array): Uint8Array;
  decryptStream(encrypted: Uint8Array, conversationKey: Uint8Array): Uint8Array;
  streamEncryptor(conversationKey: Uint8Array): StreamEncryptor;
  streamDecryptor(conversationKey: Uint8Array): StreamDecryptor;
  encrypt(plaintext: string, conversationKey: Uint8Array): string;
  decrypt(ciphertextB64: string, conversationKey: Uint8Array): string;
  prepareConversationKeyChange(params: ConversationKeyChangeParams): PreparedConversationChange;
  prepareGroupMembersChange(params: GroupMembersChangeParams): PreparedConversationChange;
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;
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
   * Requires a Juicebox config: throws if the instance was created without
   * `juiceboxConfig` and `updateConfig()` has not been called yet.
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
   * tokens) and re-resolve the PIN guess budget from it; an explicit
   * createChat `maxGuessCount` override keeps winning. On an instance
   * created without `juiceboxConfig`, this is the first-boot step that
   * enables `setup`/`unlock`/`changePin`/`delete`.
   */
  updateConfig(juiceboxConfig: string): void;

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(userId: string, signingKeyVersion: string): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  getPublicKeys(): PublicKeys;
  getPublicKeyFingerprint(): string;
  isUnlocked(): boolean;
  hasIdentityKey(): boolean;
  lock(): void;
  decryptConversationKey(encryptedKeyB64: string): Uint8Array;
  extractConversationKeys(events: string[]): ConversationKeyResult;
  decryptEvents(events: string[], signingKeys?: SigningKeyEntry[]): DecryptEventsResult;
  decryptEvent(eventB64: string, conversationKeys?: ConversationKeyMap | null, signingKeys?: SigningKeyEntry[]): Event;
  sign(data: Uint8Array): Uint8Array;
  verify(publicKeyB64: string, signature: Uint8Array, data: Uint8Array): boolean;
  verifyKeyBinding(identityPublicKeyB64: string, signingPublicKeyB64: string, identityPublicKeySignatureB64: string): boolean;
  matchesRegisteredKey(publicKeyB64: string): boolean;
  encryptMessage(params: EncryptMessageParams): SendPayload;
  encryptReply(params: EncryptReplyParams): SendPayload;
  encryptAddReaction(params: EncryptReactionParams): SendPayload;
  encryptRemoveReaction(params: EncryptReactionParams): SendPayload;
  encryptEdit(params: EncryptEditParams): SendPayload;
  prepareMessageDelete(params: MessageDeleteParams): ActionSignature;
  encryptStream(plaintext: Uint8Array, conversationKey: Uint8Array): Uint8Array;
  decryptStream(encrypted: Uint8Array, conversationKey: Uint8Array): Uint8Array;
  streamEncryptor(conversationKey: Uint8Array): StreamEncryptor;
  streamDecryptor(conversationKey: Uint8Array): StreamDecryptor;
  encrypt(plaintext: string, conversationKey: Uint8Array): string;
  decrypt(ciphertextB64: string, conversationKey: Uint8Array): string;
  prepareConversationKeyChange(params: ConversationKeyChangeParams): PreparedConversationChange;
  prepareGroupMembersChange(params: GroupMembersChangeParams): PreparedConversationChange;
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;

  /**
   * Release the WASM-side crypto engine: clears key material (`lock()`) and
   * frees the underlying WASM object. The instance must not be used
   * afterwards. When reusing the instance, `lock()` alone suffices for key
   * hygiene.
   */
  free(): void;
}

/**
 * Create a Chat instance with integrated Juicebox key storage.
 *
 * `juiceboxConfig` is optional: on first boot (no `juicebox_config` on the
 * account yet) create with just `getAuthToken`, `generateKeypairs()`, POST
 * the payload, then `updateConfig()` + `setup(pin)`.
 *
 * Each call creates an independent instance with its own Juicebox client.
 * The Juicebox auth-token callback is a process-wide global that each
 * instance re-arms before its own operations, so sequential use of multiple
 * instances is fine but concurrent Juicebox operations across instances in
 * one process are not supported.
 */
export declare function createChat(options: CreateChatOptions): Promise<ChatWithJuicebox>;

// Utility Functions

/**
 * Remaining PIN attempts from an invalid-PIN unlock()/changePin() failure,
 * or null when the error carries no count. 0 means the guess budget is
 * exhausted and the stored keys are locked.
 */
export declare function guessesRemaining(err: unknown): number | null;

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
