/**
 * Many signed-in users in one process.
 *
 * A chat holds one user's private keys and signs as that user. A process
 * that serves several signed-in users keeps one chat per user, for all of
 * that user's conversations, and never one per conversation: the chat keeps
 * its conversation keys by conversation and the public keys it has met by
 * user id.
 *
 * Other users' public keys are the same whichever chat asks, so the chats
 * share one function that fetches them:
 *
 *   - sharedPublicKeys -> a `resolvePublicKeys` function over one cache of
 *                         GET /2/users/{id}/public_keys answers
 *   - UserChats        -> one ChatCore per signed-in user, each with that
 *                         function as its public-keys hook
 *
 * multi-bot.mjs runs one bot per signed-in user this way.
 */
import { ChatCore } from "./chat-core.mjs";

/** How long a fetched answer is served before it is fetched again. */
export const PUBLIC_KEYS_TTL_MS = 5 * 60 * 1000;

/**
 * A `resolvePublicKeys` function for every chat in the process: it takes
 * user ids and resolves to each user's records, by user id.
 *
 * `getPublicKeys(userId)` resolves to one user's records, as
 * GET /2/users/{id}/public_keys returns them. Its answers are kept by user
 * id, so the chats of two signed-in users who meet the same user cost one
 * request:
 *
 *   - Calls that ask for a user whose lookup is under way wait for that
 *     lookup.
 *   - A lookup that fails is logged and dropped, and the user is left out of
 *     the answer: the next call fetches again.
 *   - An answer is served for `ttlMs`, then fetched again, so a key a user
 *     registers later is picked up.
 *
 * `now` is the clock, in milliseconds.
 */
export function sharedPublicKeys(
  getPublicKeys,
  { ttlMs = PUBLIC_KEYS_TTL_MS, now = Date.now } = {},
) {
  // userId -> { records: Promise<records | null>, expires }
  const lookups = new Map();

  const lookUp = (userId) => {
    const at = now();
    const cached = lookups.get(userId);
    if (cached && cached.expires > at) return cached.records;
    // Answers past their time go here, so the cache holds no more than the
    // users looked up within one `ttlMs`.
    for (const [id, lookup] of lookups) {
      if (lookup.expires <= at) lookups.delete(id);
    }
    const lookup = { expires: at + ttlMs, records: null };
    lookup.records = Promise.resolve()
      .then(() => getPublicKeys(userId))
      .catch((err) => {
        if (lookups.get(userId) === lookup) lookups.delete(userId);
        console.warn(`public_keys_fetch_failed user=${userId} err=${err?.message ?? err}`);
        return null;
      });
    lookups.set(userId, lookup);
    return lookup.records;
  };

  return async (userIds) => {
    const found = await Promise.all(userIds.map(lookUp));
    const records = {};
    userIds.forEach((userId, index) => {
      if (found[index]) records[userId] = found[index];
    });
    return records;
  };
}

/** One chat per signed-in user, all fetching public keys with one function. */
export class UserChats {
  #resolvePublicKeys;
  // userId -> Promise<ChatCore>
  #chats = new Map();

  /** `resolvePublicKeys` is the function every chat shares, from `sharedPublicKeys`. */
  constructor(resolvePublicKeys) {
    this.#resolvePublicKeys = resolvePublicKeys;
  }

  /**
   * Resolves to the chat of the signed-in user `userId`, created on first use
   * from the user's private-key blob and the `public_key_version` it was
   * registered under. Calls for one user share one chat, also while it is
   * being created, and that chat serves every conversation of the user.
   */
  chatFor({ userId, privateKeysB64, signingKeyVersion }) {
    let chat = this.#chats.get(userId);
    if (!chat) {
      chat = this.#open({ userId, privateKeysB64, signingKeyVersion });
      this.#chats.set(userId, chat);
      // A chat that could not be created is not kept: the next call tries
      // again.
      chat.catch(() => {
        if (this.#chats.get(userId) === chat) this.#chats.delete(userId);
      });
    }
    return chat;
  }

  async #open({ userId, privateKeysB64, signingKeyVersion }) {
    // Setting the hook also turns the conversation-key cache on.
    const core = await ChatCore.create({ resolvePublicKeys: this.#resolvePublicKeys });
    try {
      core.loadKeys(privateKeysB64, signingKeyVersion);
      core.setIdentity(userId);
    } catch (err) {
      core.close();
      throw err;
    }
    return core;
  }

  /** Sign `userId` out: forget the user's chat and clear its keys from memory. */
  async close(userId) {
    const chat = this.#chats.get(userId);
    if (!chat) return;
    this.#chats.delete(userId);
    (await chat).close();
  }
}
