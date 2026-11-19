/**
 * Headless auto-responder (Node).
 *
 * Flow: load keys -> batch-decrypt the backlog -> poll for new events ->
 * batch-decrypt each page (decryptEventsAsync) -> reply -> encrypt + sign ->
 * send. Conversation state is in memory. The browser app (public/) is the
 * interactive counterpart; both share the same crypto core.
 *
 * One bot serves one signed-in user, in any number of conversations. A
 * process with several signed-in users runs one bot per user and hands each
 * the same `resolvePublicKeys` (see multi-user.mjs and multi-bot.mjs).
 */
import { ChatCore, messageText } from "./chat-core.mjs";
import { XChatClient } from "./x-api.mjs";

/** Turn an incoming message into a reply (simple echo by default). */
export function generateReply(text) {
  const t = text.trim();
  if (t === "ping" || t === "!ping") return "pong";
  return `You said: ${t}`;
}

export class ChatBot {
  /**
   * `resolvePublicKeys` is the function the process's chats share to fetch
   * public keys (`sharedPublicKeys` in multi-user.mjs). Without it the bot
   * fetches them for its own chat, with `api`.
   */
  constructor(core, api, botUserId, { resolvePublicKeys } = {}) {
    this.core = core;
    this.api = api;
    this.botUserId = botUserId;
    this.state = new Map();
    // One-time session setup: the identity signs every outgoing message, the
    // key cache resolves conversation keys for encryption, and the SDK
    // fetches the public keys a page of events lacks from the X API.
    this.core.setIdentity(botUserId);
    this.core.setCacheKeys(true);
    if (resolvePublicKeys) {
      this.core.resolvePublicKeysWith(resolvePublicKeys);
    } else {
      this.core.fetchPublicKeysWith((userId) => this.api.getPublicKeys(userId));
    }
  }

  #state(conversationId) {
    if (!this.state.has(conversationId)) {
      this.state.set(conversationId, {
        seenEventIds: new Set(),
        paginationToken: undefined,
      });
    }
    return this.state.get(conversationId);
  }

  /**
   * Batch-decrypt a page of events from the X API, and log what the batch
   * could not use.
   *
   * Key changes arrive in meta.conversation_key_events, separate from data.
   * They go into the same batch as the data events: they carry the
   * conversation keys the messages decrypt under. The verified keys land in
   * the SDK's key cache, so the bot keeps no key state.
   */
  async #decryptPage(conversationId, page) {
    const keyEventsB64 =
      page.meta?.conversationKeyEvents ?? page.meta?.conversation_key_events ?? [];
    const eventsB64 = [
      ...keyEventsB64,
      ...(page.data ?? []).map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean),
    ];
    const batch = await this.core.decryptBatchAsync(eventsB64);
    for (const [index, error] of Object.entries(batch.errors)) {
      console.warn(`decrypt_failed conv=${conversationId} event=${index} err=${error}`);
    }
    for (const [index, key] of Object.entries(batch.missingSigningKeys)) {
      console.warn(
        `signing_key_missing conv=${conversationId} event=${index} user=${key.userId} ` +
          `version=${key.publicKeyVersion}`,
      );
    }
    for (const [index, change] of Object.entries(batch.unverifiedKeyChanges)) {
      console.warn(
        `key_change_unverified conv=${conversationId} event=${index} reason=${change.reason} ` +
          `signer=${change.senderId} key_dropped=${change.keyDropped}`,
      );
    }
    for (const [index, change] of Object.entries(batch.undecryptableKeyChanges)) {
      console.warn(`key_change_undecryptable conv=${conversationId} event=${index} reason=${change.reason}`);
    }
    for (const [index, key] of Object.entries(batch.rejectedSigningKeys)) {
      console.warn(`signing_key_rejected index=${index} user=${key.userId} version=${key.publicKeyVersion}`);
    }
    return batch;
  }

  /** Initial load: batch-decrypt the backlog, which fills the key cache. */
  async loadBacklog(conversationId) {
    const st = this.#state(conversationId);
    const page = await this.api.getEvents(conversationId, { maxResults: 100 });
    const batch = await this.#decryptPage(conversationId, page);
    // The XDK response model may expose either casing for the token.
    st.paginationToken = page.meta?.nextToken ?? page.meta?.next_token;
    console.log(
      `backlog_loaded conv=${conversationId} messages=${batch.events.length} keys=${
        Object.keys(batch.conversationKeys.keys ?? {}).length
      }`,
    );
  }

  /** Poll for new events; batch-decrypt the page and reply to each new message. */
  async pollOnce(conversationId) {
    const st = this.#state(conversationId);
    const page = await this.api.getEvents(conversationId, {
      maxResults: 50,
      paginationToken: st.paginationToken,
    });
    const batch = await this.#decryptPage(conversationId, page);
    // Each decrypted event comes with the raw event it was decrypted from,
    // which a threaded reply needs.
    for (const { event, originalB64 } of batch.events) {
      await this.#maybeReply(conversationId, event, originalB64);
    }
    st.paginationToken = page.meta?.nextToken ?? page.meta?.next_token ?? st.paginationToken;
  }

  async #maybeReply(conversationId, event, eventB64) {
    const st = this.#state(conversationId);
    const eventId = String(event.id ?? "");
    const senderId = String(event.senderId ?? "");
    if (!eventId || st.seenEventIds.has(eventId)) return;
    st.seenEventIds.add(eventId);
    if (senderId === this.botUserId) return;

    const text = messageText(event);
    if (!text) return;

    // The message signature covers the conversation_id, so sign with the
    // canonical id carried inside the event (the X API uses a different
    // separator in its URL paths than the form embedded in events).
    const replyConvId = event.conversationId ?? conversationId;
    const reply = generateReply(text);
    // Threaded reply: the raw event being answered supplies the preview, and
    // the sender identity + conversation key resolve from the session.
    const body = this.core.encryptReply({
      conversationId: replyConvId,
      text: reply,
      replyToEvent: eventB64,
    });
    await this.api.sendMessage(replyConvId, body);
    console.log(`reply_sent conv=${replyConvId} len=${reply.length}`);
  }

  async run(conversationId, pollIntervalMs = 3000) {
    await this.loadBacklog(conversationId);
    console.log(`bot_running conv=${conversationId} polling every ${pollIntervalMs}ms`);
    for (;;) {
      try {
        await this.pollOnce(conversationId);
      } catch (e) {
        console.error(`poll_error conv=${conversationId}`, e);
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }
}

/** Tiny .env loader so the example has no extra dependencies. */
async function loadDotenv() {
  const { readFile } = await import("node:fs/promises");
  try {
    const text = await readFile(new URL("../.env", import.meta.url), "utf8");
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#") || !t.includes("=")) continue;
      const [k, ...rest] = t.split("=");
      if (process.env[k.trim()] === undefined) process.env[k.trim()] = rest.join("=").trim();
    }
  } catch {
    /* no .env */
  }
}

// Entrypoint when run directly: `node src/bot.mjs`
if (import.meta.url === `file://${process.argv[1]}`) {
  await loadDotenv();
  const core = await ChatCore.create();
  const privateKeys = process.env.CHAT_PRIVATE_KEYS_B64;
  if (!privateKeys) {
    const info = core.generateAndRegister();
    console.log("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.\n");
    console.log("1) Register this public key with the X API (one-time provisioning):");
    console.log(JSON.stringify(info.registration, null, 2));
    console.log("\n2) Save the private key in your .env so the bot reuses the identity:");
    console.log(`CHAT_PRIVATE_KEYS_B64=${info.privateKeysB64}`);
    console.log(
      "\n3) Set CHAT_SIGNING_KEY_VERSION in .env to the public_key_version the X API returns.",
    );
    process.exit(0);
  }
  const signingKeyVersion = process.env.CHAT_SIGNING_KEY_VERSION;
  if (!signingKeyVersion) {
    console.log(
      "Set CHAT_SIGNING_KEY_VERSION in .env to the public_key_version the X API " +
        "returned when the bot's public key was registered.",
    );
    process.exit(1);
  }
  core.loadKeys(privateKeys, signingKeyVersion);

  const accessToken = process.env.X_ACCESS_TOKEN;
  const conversationId = process.env.CHAT_CONVERSATION_ID;
  if (!accessToken || !conversationId) {
    console.log("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.");
    process.exit(1);
  }
  const api = new XChatClient(accessToken);
  const botUserId = process.env.CHAT_BOT_USER_ID || (await api.getMyUserId());
  await new ChatBot(core, api, botUserId).run(conversationId);
}
