/**
 * Browser chat client for the chat-xdk example.
 *
 * All crypto runs here in the browser with the chat-xdk WASM binding. REST
 * calls go to this app's own dev server (/api/*), which relays them to the X
 * Chat API via the XDK using a server-held token. The token never reaches the
 * browser.
 *
 * Everything is imported from the one wasm module that `init()` initializes;
 * importing from a second module URL would yield a separate, uninitialized
 * wasm instance whose exports throw.
 */
import init, { Chat, base64ToBytes, bytesToBase64 } from "/chat-xdk/pkg/chat_xdk_wasm.js";

const $ = (id) => document.getElementById(id);
const log = (msg) => {
  $("log").textContent += `${msg}\n`;
};

let chat;
let botUserId = "";
const state = {
  conversationId: "",
  // The canonical conversation_id carried inside events — used for signing,
  // which differs from the form used in API URL paths.
  canonicalConversationId: "",
  seen: new Set(),
  paginationToken: undefined,
  signingKeyVersion: "",
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

(async () => {
  try {
    await init();
    // The lower-level WASM Chat takes a raw key blob but doesn't read the X
    // API's feature switches, so this app sends v0 messages.
    chat = new Chat();
    log("WASM binding loaded.");
  } catch (e) {
    log(`Failed to load WASM binding: ${e}\nRun \`npm run build:wasm\` for a web build.`);
  }
})();

$("btn-generate").addEventListener("click", () => {
  const payload = chat.generateKeypairs();
  const priv = bytesToBase64(chat.exportKeys());
  $("privkeys").value = priv;
  $("key-status").textContent =
    "Generated. Register the public key with the X API, then save the blob and the " +
    "public_key_version it returns.";
  log("Registration payload:\n" + JSON.stringify(payload, null, 2));
});

$("btn-load").addEventListener("click", () => {
  const bytes = base64ToBytes($("privkeys").value.trim());
  if (!bytes) return ($("key-status").textContent = "Invalid base64.");
  const version = $("keyversion").value.trim();
  if (!version) return ($("key-status").textContent = "Enter the key's public_key_version.");
  state.signingKeyVersion = version;
  chat.importKeys({ keys: bytes, signingKeyVersion: state.signingKeyVersion });
  // Opt in to the SDK's conversation-key cache: decryptEvents feeds it and
  // encryptMessage resolves the key from it, so the app keeps no key state.
  chat.setCacheKeys(true);
  $("key-status").textContent = "Keys loaded.";
  $("chat").hidden = false;
});

$("btn-connect").addEventListener("click", async () => {
  state.conversationId = $("convid").value.trim();
  if (!state.conversationId) return;
  try {
    const me = await api("/api/me");
    botUserId = String(me.id);
    // The session identity signs every outgoing message from here on.
    chat.setIdentity({ userId: botUserId, signingKeyVersion: state.signingKeyVersion });
    await loadBacklog();
    poll();
  } catch (e) {
    log(`connect failed: ${e}`);
  }
});

$("compose").addEventListener("keydown", async (ev) => {
  if (ev.key !== "Enter") return;
  const text = ev.target.value.trim();
  if (!text) return;
  ev.target.value = "";
  await sendMessage(text);
});

/**
 * Fetch the public keys of `userIds` through the dev server: each user's
 * records as the X API returns them, by user id. A user whose fetch fails is
 * logged and left out, so one user's failure does not fail the page.
 */
async function fetchPublicKeys(userIds) {
  const records = {};
  for (const userId of userIds) {
    try {
      const resp = await api(`/api/public-keys?user_id=${encodeURIComponent(userId)}`);
      records[userId] = resp.data ?? [];
    } catch (e) {
      log(`public keys of user ${userId} not fetched: ${e.message}`);
    }
  }
  return records;
}

/**
 * Batch-decrypt a page of events, and log what the batch could not use.
 *
 * Key changes arrive in meta, separate from data. They go into the same
 * batch as the data events: they carry the conversation keys the messages
 * decrypt under, and the verified keys land in the SDK's key cache.
 *
 * The SDK verifies with the public keys it has stored. A chat from the
 * packages' `createChat` fetches the keys a page lacks through its
 * `resolvePublicKeys` hook (`decryptEventsAsync`). The lower-level `Chat`
 * has no hook, so this does the same by hand: it asks which users' keys the
 * page lacked, fetches and stores them, and decrypts the page once more.
 */
async function decryptPage(page) {
  const events = [
    ...(page.meta?.conversationKeyEvents ?? page.meta?.conversation_key_events ?? []),
    ...(page.data ?? []).map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean),
  ];
  let batch = chat.decryptEvents({ events });
  const missing = chat.missingPublicKeys(batch);
  if (missing.length) {
    chat.addPublicKeys(await fetchPublicKeys(missing));
    batch = chat.decryptEvents({ events });
  }
  for (const [index, error] of Object.entries(batch.errors)) {
    log(`event ${index} did not decrypt: ${error}`);
  }
  for (const [index, key] of Object.entries(batch.missingSigningKeys)) {
    log(`event ${index}: no signing key of user ${key.userId} at version ${key.publicKeyVersion}`);
  }
  for (const [index, change] of Object.entries(batch.unverifiedKeyChanges)) {
    log(`key change ${index} did not verify: ${change.reason}`);
  }
  for (const [index, change] of Object.entries(batch.undecryptableKeyChanges)) {
    log(`key change ${index} could not be decrypted: ${change.reason}`);
  }
  for (const key of Object.values(batch.rejectedSigningKeys)) {
    log(`signing key of user ${key.userId} at version ${key.publicKeyVersion} was rejected`);
  }
  return batch;
}

async function loadBacklog() {
  const page = await api(`/api/events?conversation_id=${encodeURIComponent(state.conversationId)}`);
  const batch = await decryptPage(page);
  state.paginationToken = page.meta?.next_token;
  for (const m of batch.events) renderMessage(m.event);
  log(`backlog: ${batch.events.length} messages, ${Object.keys(batch.conversationKeys.keys ?? {}).length} keys`);
}

async function poll() {
  try {
    const page = await api(
      `/api/events?conversation_id=${encodeURIComponent(state.conversationId)}` +
        (state.paginationToken ? `&pagination_token=${state.paginationToken}` : ""),
    );
    const batch = await decryptPage(page);
    for (const m of batch.events) renderMessage(m.event);
    state.paginationToken = page.meta?.next_token ?? state.paginationToken;
  } catch (e) {
    log(`poll error: ${e}`);
  }
  setTimeout(poll, 3000);
}

function renderMessage(event) {
  if (event.conversationId) state.canonicalConversationId = event.conversationId;
  const id = String(event.id ?? "");
  if (!id || state.seen.has(id)) return;
  state.seen.add(id);
  if (event.type !== "message") return;
  const text = event.content?.text;
  if (!text) return;
  const who = String(event.senderId ?? "") === botUserId ? "me" : event.senderId;
  const div = document.createElement("div");
  div.className = "msg";
  div.innerHTML = `<div class="who"></div><div class="text"></div>`;
  div.querySelector(".who").textContent = who;
  div.querySelector(".text").textContent = text;
  $("messages").appendChild(div);
}

async function sendMessage(text) {
  // Sign with the canonical conversation_id from events (falls back to the
  // typed id for a brand-new conversation).
  const signConvId = state.canonicalConversationId || state.conversationId;
  // The sender identity and the conversation key both resolve from the
  // session (setIdentity + the key cache fed by decryptEvents).
  let payload;
  try {
    payload = chat.encryptMessage({ conversationId: signConvId, text });
  } catch (e) {
    return log(`send failed (no cached conversation key yet?): ${e}`);
  }
  // The SDK generates the message id and returns it in the payload.
  const messageId = payload.messageId;
  await api("/api/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      conversation_id: signConvId,
      message_id: messageId,
      encoded_message_create_event: payload.encodedMessageCreateEvent,
      encoded_message_event_signature: payload.encodedMessageEventSignature,
      xdk_version: payload.xdkVersion,
    }),
  });
  renderMessage({ id: messageId, type: "message", senderId: botUserId, content: { text } });
}
