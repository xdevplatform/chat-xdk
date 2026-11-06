/**
 * X Chat SDK for servers - TypeScript Definitions
 *
 * Everything @xdevplatform/chat-xdk declares, and `createChat` returns a
 * `ServerChat`, which also moves its raw private keys in and out.
 */
import { ChatWithJuicebox, CreateChatOptions } from "./chat.js";

export * from "./chat.js";

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
 * A `ChatWithJuicebox` that also moves its raw private keys in and out
 * (returned by `createChat()`). Server code only: whatever can reach the
 * chat can take its keys with `exportKeys`.
 */
export declare class ServerChat extends ChatWithJuicebox {
  /**
   * Load private keys, as `exportKeys` returns them. The SDK's copy of the
   * bytes is zeroized after import; zero your own with `fill(0)`.
   */
  importKeys(params: ImportKeysParams): void;

  /**
   * The loaded private keys, unencrypted: store them only where private
   * keys belong, and zero the bytes with `fill(0)` once stored. Throws when
   * no identity key is loaded.
   */
  exportKeys(): Uint8Array;
}

/**
 * Create a `ServerChat`, with Juicebox key storage when `getAuthToken` is
 * given; the options are those of @xdevplatform/chat-xdk's `createChat`.
 * Without `getAuthToken`, the chat has no Juicebox and needs no
 * juicebox-sdk: load saved keys with `importKeys`.
 */
export declare function createChat(options?: CreateChatOptions): Promise<ServerChat>;
