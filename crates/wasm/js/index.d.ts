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
 * Result from extractConversationKeys, and `conversationKeys` of the result
 * from decryptEvents: the conversation keys a batch's key changes carry, and
 * the key version to encrypt with.
 *
 * `keysByConversation` and `latestVersions` are keyed by conversation id, in
 * the form events carry (`event.conversationId`): a group's `g…` id, and a
 * one-to-one's two user ids ordered numerically and colon-separated. `keys`
 * and `latestVersion` hold the same without the conversation id, for a batch
 * whose events all belong to one conversation.
 */
export interface ConversationKeyResult {
  /**
   * Map of key version → raw conversation key bytes, over every conversation
   * of the batch. For a batch of one conversation it holds that
   * conversation's keys. A version that key changes of more than one
   * conversation carry is left out, because a lookup by version alone cannot
   * say which conversation's key it wants: read `keysByConversation`.
   */
  keys: ConversationKeyMap;
  /**
   * Map of conversation id → key version → raw conversation key bytes: each
   * key under the conversation of the key change that carries it, so two
   * conversations' keys at one version stay apart.
   */
  keysByConversation: { [conversationId: string]: ConversationKeyMap };
  /**
   * The version to encrypt with, when every event of the batch belongs to
   * one conversation: that conversation's entry in `latestVersions`, null
   * when it has none. Null for a batch whose events belong to more than one
   * conversation, where one version cannot name each conversation's key:
   * read `latestVersions`.
   */
  latestVersion: string | null;
  /**
   * Map of conversation id → the version to encrypt with there. From
   * decryptEvents, the newest version whose key change verified; a
   * conversation without one has no entry. From extractConversationKeys,
   * which checks no signature, each conversation's highest version in the
   * batch.
   */
  latestVersions: { [conversationId: string]: string };
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
 * Why a key change's signature did not verify.
 *
 * - `'missingSigningKey'`: none of the signing keys the call verified with is
 *   the sender's at the key version the signature names. Pass that user's
 *   public keys as signing keys and decrypt again.
 * - `'rejectedSigningKey'`: the sender's signing key at that key version was
 *   among the signing keys, but its identity binding does not verify, so the
 *   call left it out: it is listed in `rejectedSigningKeys`. Fetching the
 *   same entry again changes nothing.
 * - `'invalidSignature'`: the signature does not verify against the sender's
 *   signing key.
 * - `'unverifiable'`: the key change carries no signature, or one this SDK
 *   cannot check: an unsupported signature version, or one below the first
 *   whose payload a recipient can rebuild.
 */
export type UnverifiedKeyChangeReason =
  | 'missingSigningKey'
  | 'rejectedSigningKey'
  | 'invalidSignature'
  | 'unverifiable';

/**
 * A key change in a decryptEvents batch whose key this identity decrypted
 * but whose signature did not verify.
 */
export interface UnverifiedKeyChange {
  /** Why its signature did not verify. */
  reason: UnverifiedKeyChangeReason;
  /**
   * Whether its key was left out of `conversationKeys`, so the messages of
   * its conversation under that key version did not decrypt. A key that was
   * kept decrypts messages but never becomes the version to encrypt with.
   */
  keyDropped: boolean;
  /** The conversation the key change belongs to. */
  conversationId: string | null;
  /** The conversation key version the key change carries. */
  conversationKeyVersion: string;
  /** The user who signed the key change: the member who made it. */
  senderId: string | null;
  /** The version of that user's signing key the signature names. */
  publicKeyVersion: string | null;
}

/**
 * Why this identity could not decrypt the conversation key a key change
 * carries.
 *
 * - `'locked'`: no identity key is loaded. Load or unlock the keys, then
 *   decrypt again.
 * - `'notARecipient'`: the key change holds no key for this chat's user, the
 *   user `setIdentity` names; without a session identity, it holds no key at
 *   all. The user was not a member when the key change was made.
 * - `'otherKeyVersion'`: the key change holds keys for this chat's user, or
 *   for some user when no session identity names one, but none at this
 *   chat's key version: it was made for another registration of the user's
 *   keys. Check the key version given to `setIdentity` or `importKeys`.
 * - `'decryptionFailed'`: a key the key change holds for this chat's key
 *   version does not decrypt under the loaded identity key: the loaded
 *   private key is not the one registered at that version.
 */
export type UndecryptableKeyChangeReason =
  | 'locked'
  | 'notARecipient'
  | 'otherKeyVersion'
  | 'decryptionFailed';

/**
 * A key change in a decryptEvents batch whose conversation key this identity
 * could not decrypt.
 */
export interface UndecryptableKeyChange {
  /** Why its key could not be decrypted. */
  reason: UndecryptableKeyChangeReason;
  /** The conversation the key change belongs to. */
  conversationId: string | null;
  /** The conversation key version the key change carries. */
  conversationKeyVersion: string;
  /** The user who made the key change. */
  senderId: string | null;
}

/**
 * A signing key a decryptEvents call left out of verification because its
 * identity binding does not verify: `identityPublicKeySignature` is not the
 * signing key's signature over `identityPublicKey`.
 */
export interface RejectedSigningKey {
  /** The entry's `userId`. */
  userId: string;
  /** The entry's `publicKeyVersion`. */
  publicKeyVersion: string;
}

/**
 * A signing key a decryptEvents call did not have: an event's signature
 * names it, and it was not among the signing keys the call verified with.
 * Fetch the user's public keys (`GET /2/users/{id}/public_keys`) and add
 * them with addPublicKeys.
 */
export interface MissingSigningKey {
  /** The user who sent the event, whose signing key it is. */
  userId: string;
  /** The version of that user's key the signature names. */
  publicKeyVersion: string;
}

/**
 * Result from decryptEvents batch API.
 *
 * `errors`, `unverifiedKeyChanges`, `undecryptableKeyChanges` and
 * `missingSigningKeys` are keyed by an event's index in the batch, as a
 * string, and `rejectedSigningKeys` by a signing key's index, as a string.
 * Each is empty when it has nothing to report.
 */
export interface DecryptEventsResult {
  /** The events that decrypted, in batch order, of every event type. */
  events: DecryptedEvent[];
  /** Extracted conversation keys (for caching). */
  conversationKeys: ConversationKeyResult;
  /**
   * Event index → error message, for each event left out of `events`: one
   * that failed, or one decrypt drops, such as a member removal's title or
   * description re-encrypted under the new key.
   */
  errors: { [index: string]: string };
  /**
   * Event index → key change, for each key change whose signature did not
   * verify: why, and whether its key was dropped.
   */
  unverifiedKeyChanges: { [index: string]: UnverifiedKeyChange };
  /**
   * Event index → key change, for each key change whose conversation key
   * this identity could not decrypt: why. Such a key change gives the batch
   * no key, so the messages of its conversation under its key version did
   * not decrypt.
   */
  undecryptableKeyChanges: { [index: string]: UndecryptableKeyChange };
  /**
   * Signing key index → signing key, for each of the signing keys the call
   * verified with (`signingKeys`, or the stored ones when it was given none)
   * that it left out because its identity binding does not verify. An event
   * signed with such a key does not verify.
   */
  rejectedSigningKeys: { [index: string]: RejectedSigningKey };
  /**
   * Event index → signing key, for each signed event, of any type, whose
   * sender's signing key at the version it names was not among the signing
   * keys the call verified with. Under the default reject-unverified policy
   * such an event is in `errors`; otherwise it is in `events`, unverified. A
   * key change listed here is also in `unverifiedKeyChanges` when this
   * identity decrypted its key. missingPublicKeys reads the users to fetch
   * keys for from this map.
   */
  missingSigningKeys: { [index: string]: MissingSigningKey };
}

/**
 * One of a user's public keys, as the X API returns it in the `data` of
 * `GET /2/users/{id}/public_keys`: pass the API's records as they are.
 *
 * Each of the four values is read under its snake_case name or the
 * camelCase name the X API client libraries give it, the key version as a
 * string or a number, and any other field, such as `juicebox_config`, is
 * ignored. addPublicKeys leaves out a record without a key version, an
 * identity key or a signing key.
 */
export interface PublicKeyRecord {
  /** The version of this key. */
  public_key_version?: string | number | null;
  /** The user's identity public key, base64. */
  public_key?: string | null;
  /** The user's signing public key, base64. */
  signing_public_key?: string | null;
  /** The signing key's signature over the identity key, base64: what binds the two. */
  identity_public_key_signature?: string | null;
  /** `public_key_version` under its camelCase name. */
  publicKeyVersion?: string | number | null;
  /** `public_key` under its camelCase name. */
  publicKey?: string | null;
  /** `signing_public_key` under its camelCase name. */
  signingPublicKey?: string | null;
  /** `identity_public_key_signature` under its camelCase name. */
  identityPublicKeySignature?: string | null;
  /** Any other field of the API's record; ignored. */
  [field: string]: any;
}

/** Users' public keys: each user's records, by user id. */
export type PublicKeyRecords = { [userId: string]: PublicKeyRecord[] };

/**
 * A hook that fetches users' public keys: given user ids, it returns, or
 * resolves to, each user's records from `GET /2/users/{id}/public_keys`, by
 * user id. A user it has nothing for is left out. What it throws reaches the
 * caller of the method that called it.
 */
export type ResolvePublicKeys = (userIds: string[]) => PublicKeyRecords | Promise<PublicKeyRecords>;

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
 * Parameters for encryptForward.
 *
 * A forward is a new message carrying another message: its full text and
 * entities as `forwardedText` and `forwardedEntities`, and its attachments,
 * each file uploaded again to this conversation, as `attachments`. `text`
 * is an optional comment. A forward with no `forwardedText` needs
 * `attachments`.
 */
export interface EncryptForwardParams {
  /** ID of the conversation the message is forwarded to. */
  conversationId: string;
  /** The full text of the message being forwarded; `""` when it has none. */
  forwardedText: string;
  /** Optional rich-text entities of the forwarded message, as offsets into forwardedText. */
  forwardedEntities?: EntityTuple[] | null;
  /** Optional comment sent with the forward. */
  text?: string | null;
  /** Optional rich-text entities of the comment, as offsets into text. */
  entities?: EntityTuple[] | null;
  /**
   * Optional attachments of the forwarded message, each file uploaded again
   * to this conversation and named by the media hash key that upload
   * started with.
   */
  attachments?: AttachmentDescriptor[] | null;
  /** User ID of the sender; resolves from the session identity (setIdentity) when omitted. */
  senderId?: string | null;
  /** Version of the signing key used to sign the message; resolves from the session identity when omitted. */
  signingKeyVersion?: string | null;
  /** Raw 32-byte conversation key; resolves from the key cache when omitted. Set together with conversationKeyVersion. */
  conversationKey?: Uint8Array | null;
  /** Version of the conversation key used for encryption; resolves from the key cache when omitted. */
  conversationKeyVersion?: string | null;
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
   * recipients treat a v1 reply that names no original as invalid. With
   * replyToEvent, one other than the id the event carries fails with a
   * `ChatXdkError` of kind `invalidInput`.
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
  /**
   * Base64 of the raw event being edited; the conversation id, the target
   * sequence id and, for a v1 edit, the target message id are derived from it.
   */
  targetEvent?: string | null;
  /** ID of the conversation the edit belongs to; derived from targetEvent when omitted. */
  conversationId?: string | null;
  /** The sequenceId of the message being edited; derived from targetEvent when omitted. */
  targetMessageSequenceId?: string | null;
  /**
   * The signed messageId of the message being edited; derived from
   * targetEvent when omitted. A v1 edit names the message it edits, so a v1
   * edit built without targetEvent needs it; a v0 edit names none. With
   * targetEvent, one other than the id the event carries fails with a
   * `ChatXdkError` of kind `invalidInput`.
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
   * sends under it. Omit it, or pass none, to take them from the stored
   * public keys (addPublicKeys) of `remainingMemberIds`.
   */
  publicKeys?: PublicKeyInput[] | null;
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
  /**
   * User IDs of the members who stay, yours included: read only when
   * `publicKeys` passes none, to take each one's key from the stored public
   * keys.
   */
  remainingMemberIds?: string[] | null;
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
  /**
   * Version of the conversation key the avatar image is encrypted under.
   * Omitted, null or empty, it is the version of the conversation's newest
   * key in the opt-in key cache (setCacheKeys).
   */
  conversationKeyVersion?: string | null;
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
  /**
   * Identity public keys for every participant the new key is encrypted for.
   * Omit it, or pass none, to take them from the stored public keys
   * (addPublicKeys) of `memberIds`, or, for a one-to-one `conversationId`,
   * of its two users.
   */
  publicKeys?: PublicKeyInput[] | null;
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
  /**
   * User IDs of every participant the new key is encrypted for, yours
   * included: read only when `publicKeys` passes none, to take each one's
   * key from the stored public keys.
   */
  memberIds?: string[] | null;
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
  /**
   * Identity public keys for every participant of the updated roster. Omit
   * it, or pass none, to take them from the stored public keys
   * (addPublicKeys) of `currentMemberIds` and `newMemberIds`.
   */
  publicKeys?: PublicKeyInput[] | null;
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
  /**
   * Identity public keys for every participant of the new group. Omit it,
   * or pass none, to take them from the stored public keys (addPublicKeys)
   * of `memberIds` and `adminIds`.
   */
  publicKeys?: PublicKeyInput[] | null;
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
   * extractConversationKeys: the event's conversation's entry in
   * `keysByConversation`, or `keys` when the batch was one conversation's.
   * Omit it, or pass `{}`, for events without message contents, or to take
   * the keys from the opt-in key cache (setCacheKeys).
   */
  conversationKeys?: ConversationKeyMap | null;
  /**
   * Signing keys to verify the event with; the keys stored via
   * setSigningKeys, addSigningKeys and addPublicKeys are used when omitted
   * or empty.
   */
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
  /**
   * Signing keys for all participants, the members who signed the batch's key
   * changes included; the keys stored via setSigningKeys, addSigningKeys and
   * addPublicKeys are used when omitted or empty. A key change whose
   * signature does not verify is in the result's `unverifiedKeyChanges`, a
   * signing key whose identity binding does not verify in its
   * `rejectedSigningKeys`, and an event whose sender's signing key was not
   * among them in its `missingSigningKeys`.
   */
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
  /**
   * The conversation's key map, as passed to decryptEvent; a map that is
   * passed must hold the key for the message's version. Omit it, or pass
   * null or `{}`, to take the conversation's keys from the opt-in key cache
   * (setCacheKeys).
   */
  conversationKeys?: ConversationKeyMap | null;
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
  /**
   * The conversation's key map, as passed to decryptEvent; a map that is
   * passed must hold the key for the message's version. Omit it, or pass
   * null or `{}`, to take the conversation's keys from the opt-in key cache
   * (setCacheKeys).
   */
  conversationKeys?: ConversationKeyMap | null;
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
   * boot. A chat created without it has no Juicebox and loads no
   * juicebox-sdk; on a server, the chat `@xdevplatform/chat-xdk-server`
   * creates loads saved keys with `importKeys`.
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

  /**
   * Hook that fetches users' public keys, as passed to
   * `setResolvePublicKeys`: `decryptEventsAsync` and the prepare methods
   * ending in `Async` call it for the keys they are missing. Setting it
   * turns the key cache on (`setCacheKeys`).
   *
   * @example
   * async (userIds) => {
   *   const records = {};
   *   for (const userId of userIds) {
   *     const response = await fetch(`https://api.x.com/2/users/${userId}/public_keys`, {
   *       headers: { Authorization: `Bearer ${userToken}` }
   *     });
   *     if (response.ok) records[userId] = (await response.json()).data;
   *   }
   *   return records;
   * }
   */
  resolvePublicKeys?: ResolvePublicKeys | null;
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
   * `signingKeyVersion`. The chat then reads its feature switches for this
   * sender's bucket, the last four digits of the user id.
   */
  setIdentity(params: SetIdentityParams): void;

  /**
   * Enable or disable the conversation-key cache (off by default).
   *
   * While enabled, the cache keeps, per conversation, the key of every key
   * change whose signature verified in decryptEvents or decryptEvent, and
   * the key of every key change this chat prepared
   * (prepareConversationKeyChange, prepareGroupCreate,
   * prepareGroupMembersChange or prepareGroupMembersRemove). A call that
   * omits its conversation key reads it from there: the encrypt methods and
   * the title, description and avatar changes use the conversation's newest
   * key, and decryptEvent, decryptFile and fileDecryptor the key at the
   * version the event names. Disabling clears the cache.
   *
   * A prepared key is cached when the prepare call returns, before its
   * request is sent. If the X API rejects the request, no one else holds
   * that key: prepare the change again, or pass the key to encrypt with
   * explicitly, until a newer key change verifies.
   */
  setCacheKeys(enabled: boolean): void;

  /**
   * Store signing keys to use when a decrypt call omits its `signingKeys`
   * argument. Only this call, addSigningKeys and addPublicKeys populate the
   * store — a key carried inside an event is never trusted for
   * verification. Each call replaces the previous set; addSigningKeys and
   * addPublicKeys keep it.
   */
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;

  /**
   * Add signing keys to the store setSigningKeys sets, keeping the keys it
   * holds: an entry replaces the stored entry of the same `userId` and
   * `publicKeyVersion`, and any other is added.
   */
  addSigningKeys(signingKeys: SigningKeyEntry[]): void;

  /**
   * Add users' public keys to the store setSigningKeys sets, as
   * addSigningKeys adds entries: `records` holds, by user id, the records
   * `GET /2/users/{id}/public_keys` returns for that user, as the X API
   * sends them. `undefined` or `null` adds nothing.
   *
   * The decrypt calls verify with the stored keys when they are passed no
   * signing keys, and prepareConversationKeyChange, prepareGroupCreate,
   * prepareGroupMembersChange and prepareGroupMembersRemove read their
   * members' identity keys from them when they are passed no `publicKeys`.
   */
  addPublicKeys(records: PublicKeyRecords | null | undefined): void;

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

  /**
   * Extract and decrypt conversation keys from raw KeyChange event strings.
   * Signatures are not checked. `latestVersion` is the batch's highest key
   * version when every event belongs to one conversation, and null when they
   * belong to more than one: read `latestVersions` by conversation id.
   */
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
   * stored via `setSigningKeys`, `addSigningKeys` or `addPublicKeys`) makes
   * every signed event land in `errors`; only after
   * `setRejectUnverified(false)` are such events returned with
   * `verified: false`. A member removal's title and description,
   * re-encrypted under the new key, aren't changes: they land in `errors`
   * under either policy.
   *
   * The signing keys must include those of every member who signed a key
   * change in the batch, whether or not that member sent a message in it.
   * Under either policy, a recent key change whose signature does not verify
   * has its key dropped, and every message under that key then lands in
   * `errors`. `unverifiedKeyChanges` holds each such key change with why it
   * did not verify and, when its signer's key was missing, the `senderId`
   * and `publicKeyVersion` to fetch: add that user's public keys and decrypt
   * again. `undecryptableKeyChanges` holds each key change whose key this
   * chat could not decrypt, and `rejectedSigningKeys` each signing key left
   * out because its identity binding does not verify.
   *
   * `missingSigningKeys` holds each signed event whose sender's signing key
   * the call did not have. missingPublicKeys lists those senders: fetch
   * their public keys, add them with addPublicKeys, and decrypt the batch
   * again. decryptEventsAsync does all of that through the public-key hook
   * (setResolvePublicKeys); this method never calls the hook.
   *
   * For a batch whose events belong to more than one conversation, read
   * `conversationKeys.keysByConversation` and
   * `conversationKeys.latestVersions` by conversation id:
   * `conversationKeys.latestVersion` is null for such a batch.
   */
  decryptEvents(params: DecryptEventsParams): DecryptEventsResult;

  /**
   * Decrypt a raw webhook event payload.
   *
   * Under the default reject-unverified policy, no signing keys (passed or
   * stored via `setSigningKeys`, `addSigningKeys` or `addPublicKeys`) makes
   * every signed event throw; only after `setRejectUnverified(false)` are
   * such events returned with `verified: false`. A member removal's title
   * and description, re-encrypted under the new key, aren't changes: they
   * throw a `ChatXdkError` of kind `'invalidInput'` under either policy.
   *
   * A key change that verifies is recorded as decryptEvents records it: its
   * version is the conversation's newest verified one unless a newer is
   * known, and while the key cache is on (setCacheKeys) its key is cached.
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

  /** Encrypt a forward of an existing message. */
  encryptForward(params: EncryptForwardParams): SendPayload;

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
   * With `params.conversationKeys` omitted, null or `{}`, the conversation's
   * keys come from the opt-in key cache (setCacheKeys); a key map that is
   * passed is the only source.
   *
   * Throws, saying what to pass instead, when the key version is missing,
   * the event is not an encrypted message with this file, or `encrypted` is
   * not the file's complete encrypted bytes.
   */
  decryptFile(params: DecryptFileParams): Uint8Array;

  /**
   * Create an incremental decryptor for an encrypted file too large to hold
   * in memory. Takes the params of `decryptFile` apart from the encrypted
   * bytes, which are fed to the decryptor, and reads the key cache as
   * `decryptFile` does when `params.conversationKeys` is omitted.
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
   * With params.publicKeys omitted, null or empty, the participants' identity
   * keys come from the stored public keys (addPublicKeys): of
   * params.memberIds, the user ids of every participant, yours included, or
   * of the two users of a one-to-one params.conversationId. Only a stored
   * key whose identity binding verifies is used, and the call throws a
   * `ChatXdkError` of kind `invalidInput` naming each participant who has
   * none. prepareGroupCreate, prepareGroupMembersChange and
   * prepareGroupMembersRemove read the store the same way for the members
   * their params name. None of the four calls the public-key hook
   * (setResolvePublicKeys): the methods ending in `Async` do.
   *
   * While the key cache is on (setCacheKeys), the call caches the new key as
   * the conversation's newest key, as every prepare call that makes a
   * conversation key does.
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
   * each under the new conversation key and signs the ciphertext. While the
   * key cache is on (setCacheKeys), the call caches the new key as the
   * conversation's newest key.
   *
   * With params.publicKeys omitted, null or empty, the identity keys are the
   * stored public keys (addPublicKeys) of params.currentMemberIds and
   * params.newMemberIds.
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
   * prepareGroupAvatarChange. While the key cache is on (setCacheKeys), the
   * call caches the new key as the conversation's newest key.
   *
   * With params.publicKeys omitted, null or empty, the identity keys are the
   * stored public keys (addPublicKeys) of params.memberIds and
   * params.adminIds.
   *
   * @returns PreparedConversationChange with two action signatures (the
   * conversation-key change and the group create), and `encryptedTitle` for a
   * title the params set: the `group_name` the create request sends
   */
  prepareGroupCreate(params: GroupCreateParams): PreparedConversationChange;

  /**
   * Sign a group member removal and rotate the conversation key for the
   * members who stay (`publicKeys`). While the key cache is on
   * (setCacheKeys), the call caches the new key as the conversation's newest
   * key.
   *
   * With params.publicKeys omitted, null or empty, the identity keys are the
   * stored public keys (addPublicKeys) of params.remainingMemberIds, the
   * user ids of the members who stay.
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
   * version of the key the image is encrypted under. With
   * `params.conversationKeyVersion` omitted, null or empty, the change signs
   * the version of the conversation's newest key in the opt-in key cache
   * (setCacheKeys), and throws a `ChatXdkError` of kind `invalidState` when
   * no key is cached.
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

  missingPublicKeys(result: DecryptEventsResult): string[];

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(params: SetIdentityParams): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  addSigningKeys(signingKeys: SigningKeyEntry[]): void;
  addPublicKeys(records: PublicKeyRecords | null | undefined): void;
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
  encryptForward(params: EncryptForwardParams): SendPayload;
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
 * Key material is managed inside the Juicebox layer: `setup` stores the
 * private keys and `unlock` loads them, and no method returns them.
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

  /**
   * Set the hook that fetches users' public keys, or remove it with `null`.
   * With a hook set:
   *
   * - decryptEventsAsync, when it is passed no signing keys, calls the hook
   *   for missingPublicKeys of its result, adds what it returns, and
   *   decrypts the batch once more.
   * - prepareConversationKeyChangeAsync, prepareGroupCreateAsync,
   *   prepareGroupMembersChangeAsync and prepareGroupMembersRemoveAsync,
   *   when they are passed no `publicKeys`, call it for the members they
   *   encrypt to who have no stored key, and add what it returns.
   *
   * Only those five methods call the hook: every other method, the ones
   * they are named after included, never does. The hook is not called again
   * within a minute for a key it did not bring.
   *
   * Setting a hook turns the key cache on (setCacheKeys); turn it off again
   * afterwards to keep it off. Removing the hook leaves the cache as it is.
   * Throws a `ChatXdkError` of kind `invalidInput` for anything but a
   * function or `null`.
   */
  setResolvePublicKeys(resolvePublicKeys: ResolvePublicKeys | null): void;

  /**
   * The users whose public keys a decryptEvents result was missing: the
   * sender of each event in its `missingSigningKeys`, once each, in batch
   * order. Fetch their keys (`GET /2/users/{id}/public_keys`), add them with
   * addPublicKeys, and decrypt the batch again.
   *
   * A key this call returned a user for is not asked for again for a minute:
   * a lookup that did not bring the key is not repeated with every batch. A
   * key that arrives is no longer missing, and a key version not asked for
   * before is asked for at once.
   */
  missingPublicKeys(result: DecryptEventsResult): string[];

  /**
   * decryptEvents, fetching the public keys the batch is missing through the
   * hook (setResolvePublicKeys): when a hook is set and `params` passes no
   * signing keys, the hook is called once for missingPublicKeys of the
   * result, what it returns is added with addPublicKeys, and the batch is
   * decrypted once more. A user the hook has no keys for stays in the
   * result's `missingSigningKeys`.
   *
   * Without a hook, or when `params` passes signing keys, resolves to what
   * decryptEvents returns. Rejects with what the hook throws.
   */
  decryptEventsAsync(params: DecryptEventsParams): Promise<DecryptEventsResult>;

  /**
   * prepareConversationKeyChange, fetching the public keys it is missing
   * through the hook (setResolvePublicKeys): when a hook is set and `params`
   * passes no `publicKeys`, the hook is called once for the participants who
   * have no stored key, and what it returns is added with addPublicKeys
   * before the change is prepared.
   *
   * Without a hook, or when `params` passes `publicKeys`, resolves to what
   * prepareConversationKeyChange returns. Rejects with what the hook throws.
   */
  prepareConversationKeyChangeAsync(params: ConversationKeyChangeParams): Promise<PreparedConversationChange>;

  /** prepareGroupCreate, fetching the public keys it is missing through the hook, as prepareConversationKeyChangeAsync does. */
  prepareGroupCreateAsync(params: GroupCreateParams): Promise<PreparedConversationChange>;

  /** prepareGroupMembersChange, fetching the public keys it is missing through the hook, as prepareConversationKeyChangeAsync does. */
  prepareGroupMembersChangeAsync(params: GroupMembersChangeParams): Promise<PreparedConversationChange>;

  /** prepareGroupMembersRemove, fetching the public keys it is missing through the hook, as prepareConversationKeyChangeAsync does. */
  prepareGroupMembersRemoveAsync(params: GroupMembersRemoveParams): Promise<PreparedConversationChange>;

  setRejectUnverified(reject: boolean): void;
  generateKeypairs(): PublicKeyRegistrationPayload;
  setIdentity(params: SetIdentityParams): void;
  setCacheKeys(enabled: boolean): void;
  setSigningKeys(signingKeys: SigningKeyEntry[]): void;
  addSigningKeys(signingKeys: SigningKeyEntry[]): void;
  addPublicKeys(records: PublicKeyRecords | null | undefined): void;
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
  encryptForward(params: EncryptForwardParams): SendPayload;
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
 * `getAuthToken`, the chat has no Juicebox and needs no juicebox-sdk: it
 * runs the calls that need no private key, and keeps the keys
 * `generateKeypairs()` makes for as long as it lives.
 *
 * `resolvePublicKeys` sets the hook that fetches users' public keys, as
 * `setResolvePublicKeys` does.
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
