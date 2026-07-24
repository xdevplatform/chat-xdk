/**
 * Crypto core for the JavaScript/WASM chat-xdk example.
 *
 * A thin wrapper around the chat-xdk WASM binding. Everything that touches the
 * SDK lives here so it can be unit-tested directly (see
 * test/chat-core.test.mjs). The four core feature touchpoints are all here:
 *
 *   - key management     -> loadKeys / generateAndRegister / setIdentity
 *   - conversation keys  -> prepareConversationKeyChange / setCacheKeys
 *   - message encryption -> encryptMessage / encryptReply / encryptReaction
 *   - event decryption   -> decryptBatch (decryptEvents) and decryptOne (decryptEvent)
 *
 * The session model: identity (setIdentity), signing keys (setSigningKeys),
 * and the conversation-key cache (setCacheKeys) are set once, so the
 * per-message calls need only the conversation id and text.
 */
import { readFile } from "node:fs/promises";

import init, {
  Chat,
  base64ToBytes,
  bytesToBase64,
} from "../../../crates/wasm/pkg/chat_xdk_wasm.js";

// The WASM public API does not expose raw key import/export, so the local-blob
// example drives the lower-level WASM Chat directly.
let wasmReady;
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

function ensureWasm() {
  if (!wasmReady) {
    const wasmUrl = new URL(
      "../../../crates/wasm/pkg/chat_xdk_wasm_bg.wasm",
      import.meta.url,
    );
    wasmReady = readFile(wasmUrl).then((bytes) => init({ module_or_path: bytes }));
  }
  return wasmReady;
}

export class ChatCore {
  #chat;
  signingKeyVersion = "1";

  constructor(chat) {
    this.#chat = chat;
  }

  /** Async factory — the WASM module must be initialized before use. */
  static async create() {
    await ensureWasm();
    return new ChatCore(new Chat());
  }

  // -- Key management -------------------------------------------------------

  /** Import an existing base64 private-key blob (identity[+signing]). */
  loadKeys(privateKeysB64, signingKeyVersion = "1") {
    const bytes = base64ToBytes(privateKeysB64);
    if (!bytes) throw new Error("invalid base64 private keys");
    this.#chat.importKeys(bytes, signingKeyVersion);
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
    this.#chat.setIdentity(userId, this.signingKeyVersion);
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
   * `publicKeys` is `[{ userId, publicKey, keyVersion }, ...]`. Omit
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
    return this.#chat.decryptEvents(eventsB64, signingKeys);
  }

  /**
   * Single-event path — used for each new event after the initial load.
   * With the session set up, both key arguments can be omitted:
   * conversation keys resolve from the cache and signing keys from the store.
   */
  decryptOne(eventB64, conversationKeys, signingKeys) {
    return this.#chat.decryptEvent(eventB64, conversationKeys, signingKeys);
  }

  // -- Message encryption ---------------------------------------------------

  /**
   * Encrypt + sign a message; returns fields ready for the X API send.
   * With `replyToEvent` (the base64 raw event being answered) the SDK builds
   * a *threaded* reply and derives the preview from the signed original;
   * without it this sends a fresh message. The conversation key pair is
   * optional once the cache is enabled. `entities` are `[start, end, type]`
   * byte ranges; `ttlMsec` makes the message disappear after the given
   * lifetime.
   */
  encryptReply({
    conversationId,
    text,
    conversationKey,
    conversationKeyVersion,
    replyToEvent,
    entities,
    attachments,
    ttlMsec,
  }) {
    const params = {
      conversationId,
      text,
      conversationKey,
      conversationKeyVersion,
      entities,
      attachments,
      ttlMsec,
    };
    const payload = replyToEvent
      ? this.#chat.encryptReply({ ...params, replyToEvent })
      : this.#chat.encryptMessage(params);
    return {
      // The SDK generates the message id and returns it in the payload.
      message_id: payload.messageId,
      encoded_message_create_event: payload.encryptedContent,
      encoded_message_event_signature: payload.encodedEventSignature,
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
      encoded_message_create_event: payload.encryptedContent,
      encoded_message_event_signature: payload.encodedEventSignature,
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
      encoded_message_create_event: payload.encryptedContent,
      encoded_message_event_signature: payload.encodedEventSignature,
    };
  }

  /**
   * Sign a message delete. Returns the action signature to submit alongside
   * the delete request.
   */
  prepareMessageDelete({ conversationId, sequenceIds, deleteForAll }) {
    return this.#chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll });
  }

  // -- Group management ------------------------------------------------------

  /** Prepare a group creation: fresh key + the two required signatures. */
  prepareGroupCreate({ publicKeys, conversationId, memberIds, adminIds }) {
    return this.#chat.prepareGroupCreate({
      publicKeys,
      conversationId,
      memberIds,
      adminIds,
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

  // -- Media streaming --------------------------------------------------------

  static MEDIA_CHUNK = 1024 * 1024;

  /**
   * Encrypt a media blob with the incremental stream API.
   *
   * Feeding fixed-size chunks through `push` keeps memory bounded no matter
   * how large the file is (the WASM heap cannot hold large files whole);
   * `finish` emits the final frame that seals the stream — decryption fails
   * without it.
   */
  encryptMedia(plaintext, conversationKey) {
    const enc = this.#chat.streamEncryptor(conversationKey);
    const parts = [];
    // A throw from push would otherwise leak the encryptor's live secretstream
    // key state in WASM memory; free() reclaims it. finish() consumes the
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
   * Decrypt a media blob with the incremental stream API.
   *
   * `finish` throws if the stream was truncated, so plaintext from `push`
   * must not be treated as complete until it succeeds.
   */
  decryptMedia(ciphertext, conversationKey) {
    const dec = this.#chat.streamDecryptor(conversationKey);
    const parts = [];
    // As in encryptMedia: free() the decryptor if push throws mid-stream;
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

  // -- Generic helpers (handy for metadata + tests) -------------------------

  encrypt(plaintext, conversationKey) {
    return this.#chat.encrypt(plaintext, conversationKey);
  }

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
 * (two signatures). `signingPublicKey` is the sender's own signing key,
 * which the API expects alongside each signature.
 */
export function prepToRequest(prep, signingPublicKey) {
  return {
    conversationKeyVersion: prep.conversationKeyVersion,
    conversationParticipantKeys: prep.participantKeys.map((pk) => ({
      userId: String(pk.userId),
      encryptedConversationKey: pk.encryptedKey,
      publicKeyVersion: String(pk.publicKeyVersion),
    })),
    actionSignatures: prep.actionSignatures.map((sig) => ({
      messageId: sig.messageId,
      encodedMessageEventDetail: sig.encodedMessageEventDetail,
      ...(sig.signaturePayload ? { signaturePayload: sig.signaturePayload } : {}),
      messageEventSignature: {
        signature: sig.signature,
        signatureVersion: sig.signatureVersion,
        publicKeyVersion: sig.publicKeyVersion,
        signingPublicKey,
      },
    })),
  };
}
