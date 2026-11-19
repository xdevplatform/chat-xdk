/**
 * Several bots in one process, one per signed-in user (Node).
 *
 *   CHAT_USERS_FILE=users.json node src/multi-bot.mjs
 *
 * The file lists the signed-in users:
 *
 *   [
 *     {
 *       "accessToken": "...",        the user's OAuth2 token (dm.read + dm.write)
 *       "privateKeysB64": "...",     the user's private-key blob
 *       "signingKeyVersion": "...",  the public_key_version it was registered under
 *       "conversationIds": ["..."],  the conversations the user's bot watches
 *       "userId": "..."              optional: fetched via /2/users/me when absent
 *     }
 *   ]
 *
 * Each user gets one chat, which serves every conversation listed for that
 * user. The chats fetch other users' public keys with one function over one
 * cache (see multi-user.mjs), so a user two of them meet is fetched once.
 */
import { readFile } from "node:fs/promises";

import { ChatBot } from "./bot.mjs";
import { sharedPublicKeys, UserChats } from "./multi-user.mjs";
import { XChatClient } from "./x-api.mjs";

/** Run one bot per entry of `users`, in each of the entry's conversations. */
export async function runBots(users, pollIntervalMs = 3000) {
  if (users.length === 0) throw new Error("no signed-in users");
  const clients = users.map((user) => new XChatClient(user.accessToken));
  // One lookup function for every chat. The first user's client makes the
  // requests, so that user's token must be able to read the public keys of
  // every user the others talk to.
  const resolvePublicKeys = sharedPublicKeys((userId) => clients[0].getPublicKeys(userId));
  const chats = new UserChats(resolvePublicKeys);

  const runs = [];
  for (const [index, user] of users.entries()) {
    const api = clients[index];
    const userId = user.userId || (await api.getMyUserId());
    const core = await chats.chatFor({
      userId,
      privateKeysB64: user.privateKeysB64,
      signingKeyVersion: user.signingKeyVersion,
    });
    const bot = new ChatBot(core, api, userId, { resolvePublicKeys });
    for (const conversationId of user.conversationIds) {
      runs.push(bot.run(conversationId, pollIntervalMs));
    }
  }
  await Promise.all(runs);
}

// Entrypoint when run directly: `node src/multi-bot.mjs`
if (import.meta.url === `file://${process.argv[1]}`) {
  const usersFile = process.env.CHAT_USERS_FILE;
  if (!usersFile) {
    console.log("Set CHAT_USERS_FILE to a JSON file that lists the signed-in users.");
    process.exit(1);
  }
  await runBots(JSON.parse(await readFile(usersFile, "utf8")));
}
