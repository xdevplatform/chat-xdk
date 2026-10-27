/**
 * Crypto core for the JavaScript/WASM chat-xdk example.
 *
 * A thin wrapper around the chat-xdk WASM binding. Everything that touches the
 * SDK lives here so it can be unit-tested directly (see
 * test/chat-core.test.mjs). The four core feature touchpoints are all here:
 *
 *   - key management     -> loadKeys / generateAndRegister / setIdentity
 *   - conversation keys  -> prepareConversationKeyChange / setCacheKeys
 *   - message encryption -> encryptReply / encryptReaction, then encryptMedia for files
 *   - event decryption   -> decryptBatch (decryptEvents) and decryptOne (decryptEvent)
 *
 * The session model: identity (setIdentity), signing keys (setSigningKeys),
 * and the conversation-key cache (setCacheKeys) are set once, so the
 * per-message calls need only the conversation id and text.
 */
import {
  base64ToBytes,
  bytesToBase64,
  createChat,
  encryptedFileSize,
} from "../../../crates/wasm/js/index.js";

/** Concatenate Uint8Array chunks into one buffer. */
function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export class ChatCore {
  #chat;
  signingKeyVersion = null;

  constructor(chat) {
    this.#chat = chat;
  }

  /**
   * Async factory. The keys live in a local blob rather than Juicebox, so the
   * chat is created without getAuthToken.
   */
  static async create() {
    return new ChatCore(await createChat());
  }

  /** The size of a file once encrypted: the size its upload declares. */
  static encryptedFileSize(plaintextSize) {
    return encryptedFileSize(plaintextSize);
  }

  // -- Key management -------------------------------------------------------

  /**
   * Import an existing base64 private-key blob (identity[+signing]) registered
   * under signingKeyVersion, the public_key_version the X API returned.
   */
  loadKeys(privateKeysB64, signingKeyVersion) {
    const bytes = base64ToBytes(privateKeysB64);
    if (!bytes) throw new Error("invalid base64 private keys");
    this.#chat.importKeys({ keys: bytes, signingKeyVersion: signingKeyVersion });
    this.signingKeyVersion = signingKeyVersion;
  }

  /** Generate a fresh identity; returns the registration payload + private blob. */
  generateAndRegister() {
    const payload = this.#chat.generateKeypairs();
    const exported = this.#chat.exportKeys();
    return { registration: payload, privateKeysB64: bytesToBase64(exported) };
  }

  publicKeys() {
    return this.#chat.getPublicKeys();
  }

  // -- Session --------------------------------------------------------------

  /**
   * Set the session identity once; every encrypt/prepare call afterwards
   * resolves its sender id and signing-key version from it.
   */
  setIdentity(userId) {
    if (!this.signingKeyVersion) {
      throw new Error(
        "signing key version unknown: pass loadKeys the public_key_version " +
          "the X API returned when the keys were registered",
      );
    }
    this.#chat.setIdentity({ userId: userId, signingKeyVersion: this.signingKeyVersion });
  }

  /**
   * Store the participants' signing keys; decrypt calls that omit their
   * signingKeys argument verify against this store.
   */
  setSigningKeys(signingKeys) {
    this.#chat.setSigningKeys(signingKeys);
  }

  /**
   * Opt in to the conversation-key cache: decryptBatch caches each
   * conversation's verified key, and encrypt calls that omit the key pair
   * resolve it from the cache.
   */
  setCacheKeys(enabled) {
    this.#chat.setCacheKeys(enabled);
  }

  // -- Conversation keys ----------------------------------------------------

  /**
   * Generate, encrypt, and sign a conversation-key change.
   *
   * `publicKeys` is `[{ userId, identityPublicKey, publicKeyVersion }, ...]`. Omit
   * `conversationId` for a one-to-one to derive it; pass it for a group.
   */
  prepareConversationKeyChange({ publicKeys, conversationId }) {
    return this.#chat.prepareConversationKeyChange({ publicKeys, conversationId });
  }

  /** ECIES-decrypt one conversation key -> raw 32-byte Uint8Array. */
  decryptConversationKey(encryptedKeyB64) {
    return this.#chat.decryptConversationKey(encryptedKeyB64);
  }

  // -- Decryption: the two paths -------------------------------------------

  /** Batch path — used on initial conversation load (also feeds the key cache). */
  decryptBatch(eventsB64, signingKeys) {
    return this.#chat.decryptEvents({ events: eventsB64, signingKeys });
  }

  /**
   * Single-event path — used for each new event after the initial load.
   * With the session set up, both key arguments can be omitted: an empty
   * key map resolves from the cache and signing keys from the store.
   */
  decryptOne(eventB64, conversationKeys = {}, signingKeys) {
    return this.#chat.decryptEvent({ eventB64, conversationKeys, signingKeys });
  }

  // -- Message encryption ---------------------------------------------------

  /**
   * Encrypt + sign a message; returns fields ready for the X API send.
   * With `replyToEvent` (the base64 raw event being answered) the SDK builds
   * a *threaded* reply and derives the preview from the signed original;
   * without it this sends a fresh message. The conversation key pair is
   * optional once the cache is enabled. `entities` are `[start, end, type]`
   * byte ranges; `attachments` are attachment descriptors, each file naming
   * the media hash key its upload started with; `quickReply` offers
   * selectable options or answers them; `ttlMsec` makes the message
   * disappear after the given lifetime.
   *
   * The result also carries `event_b64`, the outgoing message as an event:
   * it is not sent, but `encryptMedia` takes it to encrypt the message's
   * files.
   */
  encryptReply({
    conversationId,
    text,
    conversationKey,
    conversationKeyVersion,
    replyToEvent,
    entities,
    attachments,
    quickReply,
    ttlMsec,
  }) {
    const params = {
      conversationId,
      text,
      conversationKey,
      conversationKeyVersion,
      entities,
      attachments,
      quickReply,
      ttlMsec,
    };
    const payload = replyToEvent
      ? this.#chat.encryptReply({ ...params, replyToEvent })
      : this.#chat.encryptMessage(params);
    return {
      // The SDK generates the message id and returns it in the payload.
      message_id: payload.messageId,
      encoded_message_create_event: payload.encodedMessageCreateEvent,
      encoded_message_event_signature: payload.encodedMessageEventSignature,
      xdk_version: payload.xdkVersion,
      event_b64: payload.eventB64,
    };
  }

  /**
   * Encrypt + sign a reaction add/remove. `targetEvent` is the base64 raw
   * event being reacted to; the conversation id and target sequence id are
   * derived from it.
   */
  encryptReaction({ add, targetEvent, emoji, conversationKey, conversationKeyVersion }) {
    const params = { emoji, targetEvent, conversationKey, conversationKeyVersion };
    const payload = add
      ? this.#chat.encryptAddReaction(params)
      : this.#chat.encryptRemoveReaction(params);
    return {
      // The SDK generates the message id and returns it in the payload.
      message_id: payload.messageId,
      encoded_message_create_event: payload.encodedMessageCreateEvent,
      encoded_message_event_signature: payload.encodedMessageEventSignature,
      xdk_version: payload.xdkVersion,
    };
  }

  /**
   * Encrypt + sign a message edit. `targetEvent` is the base64 raw event of
   * the message being edited; the conversation id and target sequence id are
   * derived from it.
   */
  encryptEdit({ targetEvent, updatedText, entities, conversationKey, conversationKeyVersion }) {
    const payload = this.#chat.encryptEdit({
      targetEvent,
      updatedText,
      entities,
      conversationKey,
      conversationKeyVersion,
    });
    return {
      // The SDK generates the message id and returns it in the payload.
      message_id: payload.messageId,
      encoded_message_create_event: payload.encodedMessageCreateEvent,
      encoded_message_event_signature: payload.encodedMessageEventSignature,
      xdk_version: payload.xdkVersion,
    };
  }

  /**
   * Sign a message delete. Returns a `PreparedAction` whose `actionSignatures`
   * (one entry) the delete request takes as they are.
   */
  prepareMessageDelete({ conversationId, sequenceIds, deleteForAll }) {
    return this.#chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll });
  }

  // -- Group management ------------------------------------------------------

  /**
   * Prepare a group creation: fresh key + the two required signatures. A
   * plaintext `title` is encrypted under the new key; send the result's
   * `encryptedTitle` as the request's group_name.
   */
  prepareGroupCreate({ publicKeys, conversationId, memberIds, adminIds, title }) {
    return this.#chat.prepareGroupCreate({
      publicKeys,
      conversationId,
      memberIds,
      adminIds,
      title,
    });
  }

  /** Prepare a member add: rotated key + the two required signatures. */
  prepareGroupMembersChange({
    publicKeys,
    conversationId,
    newMemberIds,
    currentMemberIds,
    currentAdminIds,
  }) {
    return this.#chat.prepareGroupMembersChange({
      publicKeys,
      conversationId,
      newMemberIds,
      currentMemberIds,
      currentAdminIds,
      currentPendingMemberIds: [],
    });
  }

  /**
   * Prepare a member removal that rotates the key for who stays.
   * `publicKeys` are the identity keys of the members who remain.
   */
  prepareGroupMembersRemove({ publicKeys, conversationId, userIds }) {
    return this.#chat.prepareGroupMembersRemove({
      publicKeys,
      conversationId,
      userIds,
    });
  }

  // -- Media files ------------------------------------------------------------

  static MEDIA_CHUNK = 1024 * 1024;

  /**
   * Encrypt a media file of an outgoing message with the incremental API.
   *
   * `eventB64` is the `event_b64` that `encryptReply` returned for the
   * message, `conversationKey` and `conversationKeyVersion` the key the
   * message was encrypted under, and `mediaHashKey` the hash key the file's
   * upload started with, as listed in the message's attachments; the SDK
   * encrypts the file under that attachment's key. Feeding fixed-size chunks
   * through `push` keeps memory bounded no matter how large the file is (the
   * WASM heap cannot hold large files whole); `finish` emits the final frame
   * that seals the file — decryption fails without it.
   */
  encryptMedia(plaintext, eventB64, conversationKey, conversationKeyVersion, mediaHashKey) {
    const enc = this.#chat.fileEncryptor({ eventB64, conversationKey, conversationKeyVersion, mediaHashKey });
    const parts = [];
    // A throw from push would otherwise leak the encryptor's live key state
    // in WASM memory; free() reclaims it. finish() consumes the
    // encryptor even when it fails, so it needs no explicit cleanup (and
    // free() after it would hit an already-null pointer).
    try {
      for (let offset = 0; offset < plaintext.length; offset += ChatCore.MEDIA_CHUNK) {
        parts.push(enc.push(plaintext.subarray(offset, offset + ChatCore.MEDIA_CHUNK)));
      }
    } catch (e) {
      enc.free();
      throw e;
    }
    parts.push(enc.finish());
    return concatBytes(parts);
  }

  /**
   * Decrypt a downloaded media file with the incremental API.
   *
   * `eventB64` is the raw event of the message that carries the media and
   * `conversationKeys` its conversation's key map, as passed to `decryptOne`;
   * the SDK finds `mediaHashKey` in the event and derives that file's key.
   * `finish` throws if the file was truncated, so bytes from `push` must not
   * be treated as complete until it succeeds.
   */
  decryptMedia(ciphertext, eventB64, conversationKeys, mediaHashKey) {
    const dec = this.#chat.fileDecryptor({ eventB64, conversationKeys, mediaHashKey });
    const parts = [];
    // As in encryptMedia: free() the decryptor if push throws mid-file;
    // finish() consumes it even when it fails.
    try {
      for (let offset = 0; offset < ciphertext.length; offset += ChatCore.MEDIA_CHUNK) {
        parts.push(dec.push(ciphertext.subarray(offset, offset + ChatCore.MEDIA_CHUNK)));
      }
    } catch (e) {
      dec.free();
      throw e;
    }
    parts.push(dec.finish());
    return concatBytes(parts);
  }

  // -- Group metadata ---------------------------------------------------------

  /**
   * Prepare a group title change: the SDK encrypts the plaintext title under
   * the conversation key and signs it. Send `encryptedValue` as the group's
   * name and `actionSignatures` on the request.
   */
  prepareGroupTitleChange({ conversationId, title, conversationKey, conversationKeyVersion }) {
    return this.#chat.prepareGroupTitleChange({
      conversationId,
      newTitle: title,
      conversationKey,
      conversationKeyVersion,
    });
  }

  /** Decrypt a group title or description the X API returns. */
  decrypt(ciphertextB64, conversationKey) {
    return this.#chat.decrypt(ciphertextB64, conversationKey);
  }
}

/** Pull the plain text out of a decrypted Message event, or null. */
export function messageText(event) {
  if (!event || event.type !== "message") return null;
  return event.content?.text ?? null;
}

/**
 * Map a prepared conversation change into the X API request shape.
 *
 * Works for 1:1 key changes (one signature) and group create / member add
 * (two signatures). The participant keys and action signatures already have
 * the request's shape.
 */
export function prepToRequest(prep) {
  return {
    conversationKeyVersion: prep.conversationKeyVersion,
    conversationParticipantKeys: prep.conversationParticipantKeys,
    actionSignatures: prep.actionSignatures,
  };
}

/**
 * Map a rotating member removal into the members/remove request.
 *
 * Both signatures go in `actionSignatures`. The new key version and the
 * participant keys for the members who stay go in `groupKeyRotationData`
 * (`group_key_rotation_data` on the wire).
 */
export function removalToRequest(userIds, prep) {
  return {
    userIds,
    actionSignatures: prep.actionSignatures,
    groupKeyRotationData: {
      conversationKeyVersion: prep.conversationKeyVersion,
      conversationParticipantKeys: prep.conversationParticipantKeys,
    },
  };
}
