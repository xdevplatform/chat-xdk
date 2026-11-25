/**
 * Offline tests for the JS example's crypto core.
 *
 * These drive the REAL chat-xdk WASM binding through the same ChatCore the bot
 * and browser app use — no mocking. They prove an actual encrypt -> decrypt
 * round-trip and that the binding reproduces the committed key vectors.
 *
 *   node --test
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { delivered, deliveredAction } from "../../../crates/wasm/js/tests/frame.mjs";
import { ChatCore, messageText } from "../src/chat-core.mjs";

const vectors = JSON.parse(
  await readFile(new URL("../../../tests/fixtures/sdk_vectors.json", import.meta.url), "utf8"),
);

const convKey = () => new Uint8Array(Buffer.from(vectors.conversation_key_b64, "base64"));

const fixtureSigningKeys = () => [
  {
    userId: vectors.event_sender_id,
    publicKeyVersion: vectors.event_signing_key_version,
    publicKey: vectors.signing_public_b64,
    identityPublicKey: vectors.identity_public_b64,
    identityPublicKeySignature: vectors.identity_public_key_signature_b64,
  },
];

async function loadedCore() {
  const core = await ChatCore.create();
  core.loadKeys(vectors.private_keys_concat_b64, "1");
  // The session identity signs everything; no per-call senderId.
  core.setIdentity(vectors.event_sender_id);
  return core;
}

test("loadKeys reproduces the fixture public keys", async () => {
  const core = await loadedCore();
  const keys = core.publicKeys();
  assert.equal(keys.identity, vectors.identity_public_b64);
  assert.equal(keys.signing, vectors.signing_public_b64);
});

test("setIdentity needs the registered version", async () => {
  // Freshly generated keys have no registered version yet, so the bot cannot
  // sign as itself until loadKeys provides one.
  const core = await ChatCore.create();
  core.generateAndRegister();
  assert.throws(() => core.setIdentity("12345"), /signing key version unknown/);
});

test("group title change signs the encrypted title, which decrypts back", async () => {
  const core = await loadedCore();
  const key = convKey();
  const title = "hello from the js example";
  const prepared = core.prepareGroupTitleChange({
    conversationId: "g123",
    title,
    conversationKey: key,
    conversationKeyVersion: "1",
  });
  assert.notEqual(prepared.encryptedValue, title);
  assert.equal(prepared.conversationKeyVersion, "1");
  assert.equal(core.decrypt(prepared.encryptedValue, key), title);
});

test("conversation key prepare -> decrypt round-trip", async () => {
  const core = await loadedCore();
  const prepared = await core.prepareConversationKeyChangeAsync({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        identityPublicKey: vectors.identity_public_b64,
        publicKeyVersion: "1",
      },
    ],
    conversationId: "conv-1",
  });
  assert.equal(prepared.conversationParticipantKeys.length, 1);
  assert.equal(prepared.actionSignatures.length, 1);
  const decrypted = core.decryptConversationKey(prepared.conversationParticipantKeys[0].encryptedConversationKey);
  assert.deepEqual(Array.from(decrypted), Array.from(prepared.conversationKey));
});

test("encryptReply produces a sendable payload", async () => {
  const core = await loadedCore();
  const body = core.encryptReply({
    conversationId: "6789:12345",
    text: "pong",
    conversationKey: convKey(),
    conversationKeyVersion: "1710000000000",
  });
  assert.ok(body.encoded_message_create_event);
  assert.ok(body.encoded_message_event_signature);
  assert.ok(body.message_id);
  assert.ok(body.xdk_version);
});

test("session cache: decryptBatch feeds the key cache, encryptReply omits the key", async () => {
  const core = await loadedCore();
  core.setCacheKeys(true);
  core.setSigningKeys(fixtureSigningKeys());
  // Signing keys resolve from the store; the verified key change lands in
  // the cache.
  const batch = core.decryptBatch([vectors.event_key_change_b64]);
  assert.deepEqual(batch.errors, {});
  const body = core.encryptReply({
    conversationId: vectors.event_conversation_id,
    text: "pong from the cache",
  });
  assert.ok(body.encoded_message_create_event);
  assert.ok(body.message_id);
  assert.ok(body.xdk_version);
});

/**
 * A core with fresh keys as user `userId`, the entry a prepare call takes for
 * it, and its record as GET /2/users/{id}/public_keys returns it.
 */
async function party(userId) {
  const core = await ChatCore.create();
  const { registration, privateKeysB64 } = core.generateAndRegister();
  core.loadKeys(privateKeysB64, "1");
  core.setIdentity(userId);
  const key = registration.publicKey;
  return {
    core,
    userId,
    publicKey: { userId, identityPublicKey: key.publicKey, publicKeyVersion: "1" },
    record: {
      public_key_version: "1",
      public_key: key.publicKey,
      signing_public_key: key.signingPublicKey,
      identity_public_key_signature: key.identityPublicKeySignature,
    },
  };
}

/**
 * Resolves to the page a bot receives after `admin` rotates the key of the
 * group of the three and `member` sends a message under it: the key change,
 * then the message. The admin sent none of the page's messages.
 */
async function groupPage(admin, member, bot) {
  const prepared = await admin.core.prepareConversationKeyChangeAsync({
    publicKeys: [admin, member, bot].map((each) => each.publicKey),
    conversationId: "g900",
  });
  const keyChange = deliveredAction(prepared.actionSignatures[0], admin.userId, "g900", "2100000000000000000");
  const body = member.core.encryptReply({
    conversationId: "g900",
    text: "hello group",
    conversationKey: prepared.conversationKey,
    conversationKeyVersion: prepared.conversationKeyVersion,
  });
  return [keyChange, delivered(body.event_b64, "2100000000000000001")];
}

test("decryptBatchAsync fetches the keys of the member who made a key change", async () => {
  const [admin, member, bot] = await Promise.all(["5001", "5002", "5003"].map(party));
  const events = await groupPage(admin, member, bot);

  // Without the admin's keys the key change does not verify: its key is
  // dropped and the message does not decrypt.
  assert.deepEqual(bot.core.decryptBatch(events).events, []);

  const directory = { [admin.userId]: [admin.record], [member.userId]: [member.record] };
  const asked = [];
  bot.core.fetchPublicKeysWith(async (userId) => {
    asked.push(userId);
    return directory[userId];
  });
  const page = await bot.core.decryptBatchAsync(events);
  assert.deepEqual(asked, ["5001", "5002"]);
  assert.deepEqual(page.errors, {});
  assert.deepEqual(page.missingSigningKeys, {});
  assert.deepEqual(page.unverifiedKeyChanges, {});
  assert.deepEqual(
    page.events.map(({ event }) => messageText(event)),
    [null, "hello group"],
  );
  // The raw event a reply to the message quotes.
  assert.equal(page.events[1].originalB64, events[1]);

  // The fetched keys are stored: the same page fetches nothing more.
  asked.length = 0;
  const again = await bot.core.decryptBatchAsync(events);
  assert.deepEqual(asked, []);
  assert.deepEqual(again.errors, {});
});

test("decryptBatchAsync keeps going when one user's keys cannot be fetched", async () => {
  const [admin, member, bot] = await Promise.all(["5001", "5002", "5003"].map(party));
  const events = await groupPage(admin, member, bot);

  bot.core.fetchPublicKeysWith(async (userId) => {
    if (userId === member.userId) throw new Error("HTTP 503");
    return [admin.record];
  });
  const page = await bot.core.decryptBatchAsync(events);
  // The admin's key change verified. Only the member's message, whose
  // signing key is still missing, is left out.
  assert.deepEqual(
    page.events.map(({ event }) => event.type),
    ["keyChange"],
  );
  assert.deepEqual(page.unverifiedKeyChanges, {});
  assert.deepEqual(page.missingSigningKeys, { 1: { userId: "5002", publicKeyVersion: "1" } });
  assert.deepEqual(Object.keys(page.errors), ["1"]);
});

test("prepareConversationKeyChangeAsync fetches the keys of both users of a one-to-one", async () => {
  const [sender, partner] = await Promise.all(["5001", "5002"].map(party));
  const directory = { [sender.userId]: [sender.record], [partner.userId]: [partner.record] };
  const asked = [];
  sender.core.fetchPublicKeysWith(async (userId) => {
    asked.push(userId);
    return directory[userId];
  });

  // The one-to-one is named by the partner's id, and no public keys are
  // passed.
  const prepared = await sender.core.prepareConversationKeyChangeAsync({ conversationId: partner.userId });
  assert.deepEqual(asked.sort(), ["5001", "5002"]);
  assert.deepEqual(prepared.conversationParticipantKeys.map((key) => key.userId).sort(), ["5001", "5002"]);
  // Each user decrypts the key the change holds for that user.
  for (const user of [sender, partner]) {
    const own = prepared.conversationParticipantKeys.find((key) => key.userId === user.userId);
    assert.deepEqual(
      Array.from(user.core.decryptConversationKey(own.encryptedConversationKey)),
      Array.from(prepared.conversationKey),
    );
  }
});

test("decryptBatch on an empty list is safe", async () => {
  const core = await loadedCore();
  const result = core.decryptBatch([], []);
  assert.equal(result.events.length, 0);
});

test("decryptOne rejects garbage input", async () => {
  const core = await loadedCore();
  assert.throws(() => core.decryptOne("not-valid-base64!!!", {}, []));
});

test("decryptOne falls back to the session stores", async () => {
  const core = await loadedCore();
  core.setCacheKeys(true);
  core.setSigningKeys(fixtureSigningKeys());
  core.decryptBatch([vectors.event_key_change_b64]);
  // Both key arguments omitted: the cached conversation key and the stored
  // signing keys decrypt + verify the fixture message.
  const event = core.decryptOne(vectors.event_message_b64);
  assert.equal(event.type, "message");
  assert.equal(event.content?.text, vectors.event_message_text);
  assert.equal(event.verified, true);
});

test("prepToRequest maps the X API request shape", async () => {
  const { prepToRequest } = await import("../src/chat-core.mjs");
  const core = await loadedCore();
  const prep = await core.prepareConversationKeyChangeAsync({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        identityPublicKey: vectors.identity_public_b64,
        publicKeyVersion: "1",
      },
    ],
    conversationId: "1000:2000",
  });
  const body = prepToRequest(prep);

  assert.equal(body.conversationKeyVersion, prep.conversationKeyVersion);
  assert.equal(body.conversationParticipantKeys.length, 1);
  assert.deepEqual(Object.keys(body.conversationParticipantKeys[0]).sort(), [
    "encryptedConversationKey",
    "publicKeyVersion",
    "userId",
  ]);
  assert.equal(body.actionSignatures.length, 1);
  const sig = body.actionSignatures[0];
  assert.equal(sig.messageId, prep.actionSignatures[0].messageId);
  assert.ok(sig.encodedMessageEventDetail);
  assert.equal(sig.messageEventSignature.signingPublicKey, core.publicKeys().signing);
  assert.ok(sig.messageEventSignature.signature);
});

test("removalToRequest rotates the key for the members who stay", async () => {
  const { removalToRequest } = await import("../src/chat-core.mjs");
  const core = await loadedCore();
  const prep = await core.prepareGroupMembersRemoveAsync({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        identityPublicKey: vectors.identity_public_b64,
        publicKeyVersion: "1",
      },
    ],
    conversationId: "g123",
    userIds: ["2000"],
  });
  const body = removalToRequest(["2000"], prep);

  assert.deepEqual(body.userIds, ["2000"]);
  assert.equal(body.actionSignatures.length, 2);
  assert.equal(body.actionSignatures, prep.actionSignatures);
  assert.equal(
    body.groupKeyRotationData.conversationKeyVersion,
    prep.conversationKeyVersion,
  );
  assert.equal(body.groupKeyRotationData.conversationParticipantKeys.length, 1);
  assert.equal(
    body.groupKeyRotationData.conversationParticipantKeys[0].userId,
    vectors.event_sender_id,
  );
  assert.deepEqual(
    Object.keys(body.groupKeyRotationData.conversationParticipantKeys[0]).sort(),
    ["encryptedConversationKey", "publicKeyVersion", "userId"],
  );
  assert.equal(body.conversationKeyVersion, undefined);
  assert.equal(body.conversationParticipantKeys, undefined);
});

test("prepareGroupCreateAsync yields the two required signatures", async () => {
  const core = await loadedCore();
  const prep = await core.prepareGroupCreateAsync({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        identityPublicKey: vectors.identity_public_b64,
        publicKeyVersion: "1",
      },
    ],
    conversationId: "g123",
    memberIds: [vectors.event_sender_id],
    adminIds: [vectors.event_sender_id],
    title: "hello from the js example",
  });
  assert.equal(prep.actionSignatures.length, 2);
  assert.ok(prep.conversationKey?.length === 32);
  // The title goes out encrypted under the new key: the group_name the
  // create request sends.
  assert.equal(core.decrypt(prep.encryptedTitle, prep.conversationKey), "hello from the js example");
});

test("prepareConversationMute signs a mute and an unmute", async () => {
  const core = await loadedCore();
  for (const muted of [true, false]) {
    const prepared = core.prepareConversationMute({ conversationId: "g123", muted });
    assert.equal(prepared.actionSignatures.length, 1, `muted=${muted}`);
    const [sig] = prepared.actionSignatures;
    assert.ok(sig.messageId, `muted=${muted}`);
    assert.ok(sig.encodedMessageEventDetail, `muted=${muted}`);
    assert.ok(sig.messageEventSignature.signature, `muted=${muted}`);
    assert.equal(sig.messageEventSignature.signingPublicKey, core.publicKeys().signing);
  }
});

test("encryptReaction targeting a raw event produces a sendable payload", async () => {
  const core = await loadedCore();
  const body = core.encryptReaction({
    add: true,
    targetEvent: vectors.event_message_b64,
    emoji: "\u{1f44d}",
    conversationKey: convKey(),
    conversationKeyVersion: "1",
  });
  assert.deepEqual(Object.keys(body).sort(), [
    "encoded_message_create_event",
    "encoded_message_event_signature",
    "message_id",
    "xdk_version",
  ]);
});

test("threaded reply by raw event with entities and TTL encrypts", async () => {
  const core = await loadedCore();
  const body = core.encryptReply({
    conversationId: vectors.event_conversation_id,
    text: "@user hello",
    conversationKey: convKey(),
    conversationKeyVersion: vectors.event_conversation_key_version,
    replyToEvent: vectors.event_message_b64,
    entities: [[0, 5, "mention"]],
    ttlMsec: 60_000,
  });
  assert.ok(body.encoded_message_create_event);
});

test("media encrypt -> decrypt round-trip and truncation", async () => {
  // The message-first media flow: the message names the file by the media
  // hash key its upload started with, the file is encrypted from the
  // message's event_b64 in chunks, and it decrypts through that event. A
  // truncated file is detected.
  const core = await loadedCore();
  core.setIdentity("1000");
  const key = new Uint8Array(Buffer.from(vectors.conversation_key_b64, "base64"));
  const keys = { 1: key };
  const plaintext = Uint8Array.from({ length: 300_000 }, (_, i) => (i * 31 + 7) % 256);
  const body = core.encryptReply({
    conversationId: "1000:2000",
    text: "a photo",
    conversationKey: key,
    conversationKeyVersion: "1",
    attachments: [
      {
        attachment_type: "media",
        media_hash_key: "photo",
        width: 4,
        height: 3,
        filesize_bytes: ChatCore.encryptedFileSize(plaintext.length),
        filename: "photo.bin",
        media_type: 5,
      },
    ],
  });
  assert.ok(body.event_b64);

  const ciphertext = core.encryptMedia(plaintext, body.event_b64, key, "1", "photo");
  assert.equal(ciphertext.length, ChatCore.encryptedFileSize(plaintext.length));
  const decrypted = core.decryptMedia(ciphertext, body.event_b64, keys, "photo");
  assert.equal(decrypted.length, plaintext.length);
  assert.ok(decrypted.every((b, i) => b === plaintext[i]));

  assert.throws(
    () => core.decryptMedia(ciphertext.subarray(0, ciphertext.length - 4), body.event_b64, keys, "photo"),
    /truncated/,
  );
});

test("media from the fixture message opens", async () => {
  // Media encrypted by another client opens through its message's event.
  const core = await loadedCore();
  const keys = {
    [vectors.message_key_conversation_key_version]: new Uint8Array(
      Buffer.from(vectors.message_key_conversation_key_hex, "hex"),
    ),
  };
  for (const name of ["first", "second"]) {
    const decrypted = core.decryptMedia(
      new Uint8Array(Buffer.from(vectors[`media_${name}_encrypted_b64`], "base64")),
      vectors.event_message_key_b64,
      keys,
      vectors[`media_${name}_hash_key`],
    );
    assert.deepEqual(
      Buffer.from(decrypted),
      Buffer.from(vectors[`media_${name}_plaintext_b64`], "base64"),
    );
  }
});
