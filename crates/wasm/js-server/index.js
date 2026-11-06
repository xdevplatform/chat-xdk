/**
 * X Chat SDK - JavaScript entry point for servers (@xdevplatform/chat-xdk-server)
 *
 * The API of @xdevplatform/chat-xdk, with a chat that also moves its raw
 * private keys in and out, so a server can keep them in its own secret
 * store. Server code only: whatever can reach a ServerChat can take its keys.
 */
import { ChatWithJuicebox, newChat } from "./chat.js";

export {
  ChatXdkError,
  ChatWithJuicebox,
  encryptedFileSize,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  detectMimeType,
  detectImageDimensions,
} from "./chat.js";

/**
 * A `ChatWithJuicebox` that also moves its raw private keys in and out
 * (returned by `createChat()`).
 */
export class ServerChat extends ChatWithJuicebox {
  #engine;

  constructor(wasmChat, ...juicebox) {
    super(wasmChat, ...juicebox);
    this.#engine = wasmChat;
  }

  /**
   * Load private keys, as `exportKeys` returns them, with the
   * `signingKeyVersion` they were registered under. The SDK's copy of the
   * bytes is zeroized after import; zero your own with `fill(0)`.
   */
  importKeys(params) {
    return this.#engine.importKeys(params);
  }

  /**
   * The loaded private keys, unencrypted: store them only where private keys
   * belong, and zero the bytes with `fill(0)` once stored. Throws when no
   * identity key is loaded.
   */
  exportKeys() {
    return this.#engine.exportKeys();
  }
}

/**
 * Create a ServerChat, with Juicebox key storage when `getAuthToken` is
 * given. Takes the options of @xdevplatform/chat-xdk's `createChat`.
 *
 * @param {Object} [options] - `{ juiceboxConfig?, getAuthToken? }`
 * @returns {Promise<ServerChat>} Initialized chat instance
 *
 * @example
 * // Once: unlock the keys (or generate and register them), and keep them
 * // in your secret store
 * const chat = await createChat({ juiceboxConfig, getAuthToken });
 * await chat.unlock(pin);
 * const keys = chat.exportKeys();
 * await secretStore.put("chat-keys", keys);
 * keys.fill(0);
 *
 * // Each process: load them, with no Juicebox call
 * const chat = await createChat();
 * chat.importKeys({ keys: await secretStore.get("chat-keys"), signingKeyVersion });
 */
export async function createChat(options = {}) {
  return newChat(ServerChat, options);
}
