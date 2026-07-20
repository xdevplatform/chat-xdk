/**
 * Headless auto-responder (Node).
 *
 * Flow: load keys -> batch-decrypt the backlog (decryptEvents) -> poll for new
 * events -> decrypt each (decryptEvent) -> reply -> encrypt + sign -> send.
 * Conversation state is in memory. The browser app (public/) is the
 * interactive counterpart; both share the same crypto core.
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
  constructor(core, api, botUserId) {
    this.core = core;
    this.api = api;
    this.botUserId = botUserId;
    this.state = new Map();
    // One-time session setup: the identity signs every outgoing message, the
    // key cache resolves conversation keys for encryption, and the signing
    // key store backs decrypt calls that omit their signingKeys argument.
    this.core.setIdentity(botUserId);
    this.core.setCacheKeys(true);
    this.signingKeys = new Map(); // userId -> entries from the X API
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

  /** Fetch signing keys for unseen senders and refresh the SDK's store. */
  async #storeSigningKeysFor(events) {
    const senders = new Set(
      events
        .map((e) => String(e.senderId ?? e.sender_id ?? ""))
        .filter((id) => id && id !== this.botUserId),
    );
    let changed = false;
    for (const senderId of senders) {
      if (this.signingKeys.has(senderId)) continue;
      try {
        const entries = (await this.api.getPublicKeys(senderId)).map((pk) => ({
          userId: senderId,
          publicKeyVersion: String(pk.publicKeyVersion ?? pk.public_key_version ?? ""),
          publicKey: pk.signingPublicKey ?? pk.signing_public_key ?? "",
          identityPublicKey: pk.publicKey ?? pk.public_key ?? "",
          identityPublicKeySignature:
            pk.identityPublicKeySignature ?? pk.identity_public_key_signature ?? "",
        }));
        this.signingKeys.set(senderId, entries);
        changed = true;
      } catch {
        console.warn(`public_keys_fetch_failed sender=${senderId}`);
      }
    }
    // setSigningKeys replaces the previous set, so pass every known entry.
    if (changed) this.core.setSigningKeys([...this.signingKeys.values()].flat());
  }

  /** Initial load: batch-decrypt the backlog (decryptEvents path). */
  async loadBacklog(conversationId) {
    const st = this.#state(conversationId);
    const page = await this.api.getEvents(conversationId, { maxResults: 100 });
    const raw = page.data ?? [];
    const eventsB64 = raw.map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean);
    await this.#storeSigningKeysFor(raw);

    // Signing keys come from the store; the verified conversation keys land
    // in the SDK's key cache, so no key state is kept in the bot.
    const batch = this.core.decryptBatch(eventsB64);
    // The XDK response model may expose either casing for the token.
    st.paginationToken = page.meta?.nextToken ?? page.meta?.next_token;
    console.log(
      `backlog_loaded conv=${conversationId} messages=${batch.messages.length} keys=${
        Object.keys(batch.conversationKeys.keys ?? {}).length
      }`,
    );
  }

  /** Poll for new events; reply to each new message (decryptEvent path). */
  async pollOnce(conversationId) {
    const st = this.#state(conversationId);
    const page = await this.api.getEvents(conversationId, {
      maxResults: 50,
      paginationToken: st.paginationToken,
    });
    const raw = page.data ?? [];
    await this.#storeSigningKeysFor(raw);

    for (const item of raw) {
      const eventB64 = item.encodedEvent ?? item.encoded_event;
      if (!eventB64) continue;
      // Both key arguments omitted: conversation keys resolve from the cache
      // and signing keys from the store.
      const event = this.core.decryptOne(eventB64);

      if (event.type === "keyChange") {
        // Only the batch path feeds the key cache, so route key changes back
        // through it to adopt the rotated key.
        this.core.decryptBatch([eventB64]);
        continue;
      }
      await this.#maybeReply(conversationId, event, eventB64);
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
    process.exit(0);
  }
  core.loadKeys(privateKeys, process.env.CHAT_SIGNING_KEY_VERSION ?? "1");

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
