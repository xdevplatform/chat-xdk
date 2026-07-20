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
  signingKeyVersion: "1",
  // Signing keys fetched per sender; setSigningKeys replaces the SDK's
  // store, so every known entry is passed on each refresh.
  signingKeys: new Map(), // userId -> entries
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

(async () => {
  try {
    await init();
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
    "Generated. Register the public key with the X API, then save the blob.";
  log("Registration payload:\n" + JSON.stringify(payload, null, 2));
});

$("btn-load").addEventListener("click", () => {
  const bytes = base64ToBytes($("privkeys").value.trim());
  if (!bytes) return ($("key-status").textContent = "Invalid base64.");
  chat.importKeys(bytes, state.signingKeyVersion);
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
    chat.setIdentity(botUserId, state.signingKeyVersion);
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

/** Fetch signing keys for unseen senders and refresh the SDK's store. */
async function storeSigningKeysFor(events) {
  const senders = new Set(
    events.map((e) => String(e.senderId ?? e.sender_id ?? "")).filter((id) => id && id !== botUserId),
  );
  let changed = false;
  for (const senderId of senders) {
    if (state.signingKeys.has(senderId)) continue;
    try {
      const resp = await api(`/api/public-keys?user_id=${encodeURIComponent(senderId)}`);
      state.signingKeys.set(
        senderId,
        (resp.data ?? []).map((pk) => ({
          userId: senderId,
          publicKeyVersion: String(pk.publicKeyVersion ?? pk.public_key_version ?? ""),
          publicKey: pk.signingPublicKey ?? pk.signing_public_key ?? "",
          identityPublicKey: pk.publicKey ?? pk.public_key ?? "",
          identityPublicKeySignature:
            pk.identityPublicKeySignature ?? pk.identity_public_key_signature ?? "",
        })),
      );
      changed = true;
    } catch {
      /* ignore */
    }
  }
  if (changed) chat.setSigningKeys([...state.signingKeys.values()].flat());
}

async function loadBacklog() {
  const page = await api(`/api/events?conversation_id=${encodeURIComponent(state.conversationId)}`);
  const raw = page.data ?? [];
  const eventsB64 = raw.map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean);
  await storeSigningKeysFor(raw);
  // Signing keys come from the store; the verified conversation keys land in
  // the SDK's key cache for encryptMessage to resolve later.
  const batch = chat.decryptEvents(eventsB64);
  state.paginationToken = page.meta?.next_token;
  for (const m of batch.messages) renderMessage(m.event);
  log(`backlog: ${batch.messages.length} messages, ${Object.keys(batch.conversationKeys.keys ?? {}).length} keys`);
}

async function poll() {
  try {
    const page = await api(
      `/api/events?conversation_id=${encodeURIComponent(state.conversationId)}` +
        (state.paginationToken ? `&pagination_token=${state.paginationToken}` : ""),
    );
    const raw = page.data ?? [];
    await storeSigningKeysFor(raw);
    for (const item of raw) {
      const eventB64 = item.encodedEvent ?? item.encoded_event;
      if (!eventB64) continue;
      // Both key arguments omitted: conversation keys resolve from the cache
      // and signing keys from the store.
      const event = chat.decryptEvent(eventB64);
      if (event.type === "keyChange") {
        // Only the batch path feeds the key cache, so route key changes back
        // through it to adopt the rotated key.
        chat.decryptEvents([eventB64]);
        continue;
      }
      renderMessage(event);
    }
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
      encoded_message_create_event: payload.encryptedContent,
      encoded_message_event_signature: payload.encodedEventSignature,
    }),
  });
  renderMessage({ id: messageId, type: "message", senderId: botUserId, content: { text } });
}
