/**
 * Live end-to-end check against the X Chat API, using the example's real
 * ChatCore (WASM binding) and XChatClient (XDK). Run manually:
 *
 *   CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... CHAT_SIGNING_KEY_VERSION=... \
 *   CHAT_CONVERSATION_ID=... node e2e-live.mjs
 *
 * Flow (each numbered step asserts against the live API):
 *   1. batch-decrypt inbound history (pagination when a second page exists)
 *   2. rotate the conversation key (prepare -> POST /keys -> decrypt own CKCE)
 *   3. send a threaded reply with an entity + TTL under the rotated key,
 *      fetch it back, decrypt it via the single-event path, and verify it
 *   4. react to the sent message (add + remove), decrypting the add back
 *
 * Optional extras: CHATXDK_E2E_MEDIA=1 also stream-encrypts a media blob,
 * uploads it, sends a message referencing it, then downloads and
 * stream-decrypts it back to the original bytes; CHATXDK_E2E_GROUPS=1 also
 * creates a group (two-signature create), sends a group message, and adds
 * the 1:1 partner as a member.
 *
 * Not part of `node --test` (kept outside test/ and without a .test suffix).
 */
import { ChatCore, messageText, prepToRequest } from "./src/chat-core.mjs";
import { XChatClient } from "./src/x-api.mjs";

const need = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing ${k}`);
  return v;
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const token = need("X_ACCESS_TOKEN");
const blob = need("CHAT_PRIVATE_KEYS_B64");
const ver = need("CHAT_SIGNING_KEY_VERSION");
const conv = need("CHAT_CONVERSATION_ID");

function signingFrom(pk, userId) {
  return {
    userId,
    publicKeyVersion: String(pk.publicKeyVersion ?? pk.public_key_version ?? ""),
    publicKey: pk.signingPublicKey ?? pk.signing_public_key ?? "",
    identityPublicKey: pk.publicKey ?? pk.public_key ?? "",
    identityPublicKeySignature:
      pk.identityPublicKeySignature ?? pk.identity_public_key_signature ?? "",
  };
}

/** Public-keys response -> the flat entries the prepare methods take. */
function keyEntries(pks, userId) {
  return pks.map((pk) => ({
    userId,
    publicKey: pk.publicKey ?? pk.public_key ?? "",
    keyVersion: String(pk.publicKeyVersion ?? pk.public_key_version ?? ""),
  }));
}

/**
 * Poll the conversation until the event for `messageId` lands, and return it
 * decrypted via the single-event path (`decryptOne`) as
 * `{ event, b64 }` — the raw base64 alongside, for reply/reaction-by-event.
 *
 * The target envelope is matched by its raw event id before decrypting, so a
 * decrypt failure on our own event (e.g. a broken sign->verify loop) surfaces
 * in the timeout message instead of being silently swallowed.
 */
async function awaitDecrypted(api, core, conversationId, convKeys, signing, messageId, tries = 10) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    const page = await api.getEvents(conversationId, { maxResults: 25 });
    for (const e of page.data ?? []) {
      const b64 = e.encodedEvent ?? e.encoded_event;
      if (!b64) continue;
      const isTarget = String(e.id ?? "") === messageId;
      let one;
      try {
        one = core.decryptOne(b64, convKeys, signing);
      } catch (err) {
        if (isTarget) lastErr = err;
        continue;
      }
      if (isTarget || String(one.id ?? "") === messageId) {
        // The REST item's id IS the event's sequence id.
        if (!one.sequenceId) one.sequenceId = e.id;
        return { event: one, b64 };
      }
    }
    await sleep(1000);
  }
  throw new Error(
    `event for sent message ${messageId} never appeared` +
      (lastErr ? ` (last decrypt error: ${lastErr})` : ""),
  );
}

const core = await ChatCore.create();
core.loadKeys(blob, ver);
const api = new XChatClient(token);
const myId = await api.getMyUserId();
// The session identity signs everything sent below; per-call senderId /
// signingKeyVersion arguments are gone.
core.setIdentity(myId);

// KeyChange events arrive in meta.conversation_key_events, separate from
// data; they carry the conversation keys and must go into the same
// decryptEvents batch as the data events.
const keyEventsOf = (p) =>
  p.meta?.conversationKeyEvents ?? p.meta?.conversation_key_events ?? [];

// -- 1. Inbound history: batch decrypt (+ pagination when available) --------
const page = await api.getEvents(conv, { maxResults: 10 });
let raw = page.data ?? [];
const keyEventsB64 = [...keyEventsOf(page)];
const nextToken = page.meta?.nextToken ?? page.meta?.next_token;
if (nextToken) {
  const page2 = await api.getEvents(conv, { maxResults: 10, paginationToken: nextToken });
  const raw2 = page2.data ?? [];
  const ids1 = new Set(raw.map((e) => String(e.id)));
  assert(
    raw2.length > 0 && !raw2.some((e) => ids1.has(String(e.id))),
    "pagination made no progress",
  );
  raw = raw.concat(raw2);
  keyEventsB64.push(...keyEventsOf(page2));
  console.log(`pagination: fetched second page with ${raw2.length} events`);
}

const ids = new Set([myId]);
for (const e of raw) {
  const s = String(e.senderId ?? e.sender_id ?? "");
  if (s) ids.add(s);
}
const signing = [];
const pksByUser = new Map();
for (const id of ids) {
  try {
    const pks = await api.getPublicKeys(id);
    pksByUser.set(id, pks);
    for (const pk of pks) signing.push(signingFrom(pk, id));
  } catch {
    /* ignore */
  }
}

const eventsB64 = [
  ...keyEventsB64,
  ...raw.map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean),
];
let batch = core.decryptBatch(eventsB64, signing);
const decrypted = batch.messages.filter((m) => messageText(m.event)).length;
let convKeys = { ...batch.conversationKeys.keys };
console.log(
  `live inbound messages decrypted: ${decrypted}; conversation keys: ${Object.keys(convKeys).length}`,
);
assert(decrypted > 0, "expected to decrypt at least one live message");

// Canonical conversation_id + partner id + the last inbound message (raw
// b64, for the reply-by-event form below).
let canonicalConv = conv;
let lastInboundB64;
for (const m of batch.messages) {
  const ev = m.event ?? {};
  if (ev.conversationId) canonicalConv = ev.conversationId;
  if (ev.type === "message" && String(ev.senderId) !== myId && ev.sequenceId && m.originalB64) {
    lastInboundB64 = m.originalB64;
  }
}
const partnerId = [...ids].find((id) => id !== myId);
assert(partnerId, "expected a conversation partner among the senders");

// -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE -------------
const bothKeys = [
  ...keyEntries(pksByUser.get(myId) ?? [], myId),
  ...keyEntries(pksByUser.get(partnerId) ?? [], partnerId),
];
const prep = core.prepareConversationKeyChange({
  publicKeys: bothKeys,
});
const signingPub = core.publicKeys().signing;
const resp = await api.addConversationKeys(conv, prepToRequest(prep, signingPub));
const data = resp.data ?? {};
assert(
  data.sequenceId ||
    data.sequence_id ||
    data.conversationKeyChangeSequenceId ||
    data.conversation_key_change_sequence_id,
  `key rotation not acknowledged: ${JSON.stringify(resp)}`,
);
const serverConv = data.conversationId ?? data.conversation_id;
console.log(
  `rotated conversation key to version ${prep.conversationKeyVersion}` +
    (serverConv ? `; server conversation_id: ${serverConv}` : ""),
);

// Re-fetch (polling briefly, in case the CKCE has not propagated yet) so our
// own CKCE decrypts and the cache includes the new version.
const kv = prep.conversationKeyVersion;
for (let i = 0; i < 5; i++) {
  const page3 = await api.getEvents(conv, { maxResults: 10 });
  batch = core.decryptBatch(
    [
      ...keyEventsOf(page3),
      ...(page3.data ?? []).map((e) => e.encodedEvent ?? e.encoded_event).filter(Boolean),
    ],
    signing,
  );
  convKeys = { ...batch.conversationKeys.keys };
  if (convKeys[kv]) break;
  await sleep(1500);
}
assert(convKeys[kv], `own rotated CKCE (version ${kv}) did not decrypt+verify`);
const key = convKeys[kv];

// -- 3. Send under the rotated key; fetch back; single-event decrypt --------
const marker = `chat-xdk e2e [js] ${Date.now()}`;
assert(lastInboundB64, "expected a raw inbound event to reply to");
const body = core.encryptReply({
  conversationId: canonicalConv,
  text: `@user ${marker}`,
  conversationKey: key,
  conversationKeyVersion: kv,
  replyToEvent: lastInboundB64,
  entities: [[0, 5, "mention"]],
  ttlMsec: 24 * 60 * 60 * 1000,
});
await api.sendMessage(canonicalConv, body);
console.log(`sent live encrypted message: ${JSON.stringify(marker)}`);

const { event: one, b64: oneB64 } = await awaitDecrypted(
  api,
  core,
  conv,
  convKeys,
  signing,
  body.message_id,
);
assert(messageText(one) === `@user ${marker}`, `round-trip text mismatch: ${JSON.stringify(one)}`);
assert(one.verified === true, "own sent message failed signature verification");
console.log("sent message decrypted + verified via the single-event path");

// -- 4. Reactions: add (round-trip) then remove — both target the raw event --
const add = core.encryptReaction({
  add: true,
  targetEvent: oneB64,
  emoji: "\u{1f44d}",
  conversationKey: key,
  conversationKeyVersion: kv,
});
await api.sendMessage(canonicalConv, add);
const { event: reaction } = await awaitDecrypted(api, core, conv, convKeys, signing, add.message_id);
assert(
  reaction.content?.contentType === "reaction" && reaction.content?.emoji === "\u{1f44d}",
  `expected a reaction event, got ${JSON.stringify(reaction.content)}`,
);
assert(reaction.verified === true, "reaction failed signature verification");
console.log("reaction add decrypted + verified");

const remove = core.encryptReaction({
  add: false,
  targetEvent: oneB64,
  emoji: "\u{1f44d}",
  conversationKey: key,
  conversationKeyVersion: kv,
});
await api.sendMessage(canonicalConv, remove);
console.log("reaction remove sent");

// -- 5. Optional: media — stream-encrypt, upload, send, download, decrypt ----
if (process.env.CHATXDK_E2E_MEDIA === "1") {
  // A deterministic multi-chunk payload, so the incremental encryptor emits
  // several frames and any corruption is byte-attributable.
  const plaintext = Uint8Array.from({ length: 300_000 }, (_, i) => (i * 31 + 7) % 256);
  const ciphertext = core.encryptMedia(plaintext, key);
  const mediaHashKey = await api.uploadMedia(canonicalConv, ciphertext);
  console.log(`encrypted media uploaded: ${mediaHashKey} (${ciphertext.length} bytes)`);

  const mediaMsg = core.encryptReply({
    conversationId: canonicalConv,
    text: `chat-xdk e2e media [js] ${Date.now()}`,
    conversationKey: key,
    conversationKeyVersion: kv,
    attachments: [
      {
        attachment_type: "media",
        media_hash_key: mediaHashKey,
        width: 0,
        height: 0,
        filesize_bytes: plaintext.length,
        filename: "e2e.bin",
        media_type: 5,
      },
    ],
    ttlMsec: 24 * 60 * 60 * 1000,
  });
  await api.sendMessage(canonicalConv, mediaMsg);
  const { event: mediaOne } = await awaitDecrypted(
    api,
    core,
    conv,
    convKeys,
    signing,
    mediaMsg.message_id,
  );
  assert(mediaOne.verified === true, "media message failed signature verification");
  const atts = mediaOne.content?.attachments ?? [];
  const gotKey = atts.find((a) => a.media)?.media?.mediaHashKey;
  assert(gotKey === mediaHashKey, `attachment did not round-trip: ${JSON.stringify(atts)}`);

  const downloaded = await api.downloadMedia(canonicalConv, mediaHashKey);
  const decrypted = core.decryptMedia(downloaded, key);
  assert(
    decrypted.length === plaintext.length && decrypted.every((b, i) => b === plaintext[i]),
    "downloaded media did not decrypt to the original bytes",
  );
  console.log("media downloaded + stream-decrypted to the original bytes");
}

// -- 6. Optional: group create + message + member add ------------------------
if (process.env.CHATXDK_E2E_GROUPS === "1") {
  const myKeys = keyEntries(pksByUser.get(myId) ?? [], myId);
  const groupId = await api.initializeGroup();
  assert(groupId.startsWith("g"), `unexpected group id: ${groupId}`);

  // Create with the caller as sole member/admin so the member add below
  // exercises prepareGroupMembersChange with the partner.
  let gPrep = core.prepareGroupCreate({
    publicKeys: myKeys,
    conversationId: groupId,
    memberIds: [myId],
    adminIds: [myId],
  });
  let members = [myId];
  try {
    await api.createConversation({
      conversationId: groupId,
      groupMembers: members,
      groupAdmins: [myId],
      groupName: "chat-xdk e2e",
      ...prepToRequest(gPrep, signingPub),
    });
  } catch {
    // Some deployments reject single-member groups; fall back to creating
    // with both participants (skipping the member-add below).
    gPrep = core.prepareGroupCreate({
      publicKeys: bothKeys,
      conversationId: groupId,
      memberIds: [myId, partnerId],
      adminIds: [myId],
    });
    members = [myId, partnerId];
    await api.createConversation({
      conversationId: groupId,
      groupMembers: members,
      groupAdmins: [myId],
      groupName: "chat-xdk e2e",
      ...prepToRequest(gPrep, signingPub),
    });
  }
  const gkv = gPrep.conversationKeyVersion;
  const gkey = gPrep.conversationKey;
  console.log(`group created: ${groupId} with ${members.length} member(s)`);

  const gMarker = `chat-xdk e2e group [js] ${Date.now()}`;
  const gBody = core.encryptReply({
    conversationId: groupId,
    text: gMarker,
    conversationKey: gkey,
    conversationKeyVersion: gkv,
  });
  await api.sendMessage(groupId, gBody);
  const { event: gOne } = await awaitDecrypted(
    api,
    core,
    groupId,
    { [gkv]: gkey },
    signing,
    gBody.message_id,
  );
  assert(
    messageText(gOne) === gMarker && gOne.verified === true,
    `group message round-trip failed: ${JSON.stringify(gOne)}`,
  );
  console.log("group message decrypted + verified");

  if (!members.includes(partnerId)) {
    const mPrep = core.prepareGroupMembersChange({
      publicKeys: bothKeys,
      conversationId: groupId,
      newMemberIds: [partnerId],
      currentMemberIds: members,
      currentAdminIds: [myId],
    });
    await api.addGroupMembers(groupId, {
      userIds: [partnerId],
      ...prepToRequest(mPrep, signingPub),
    });
    console.log(
      `group member add: ${partnerId} added (key rotated to ${mPrep.conversationKeyVersion})`,
    );
  }
}

console.log("E2E JS: PASS");
