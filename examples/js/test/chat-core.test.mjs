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

import { ChatCore } from "../src/chat-core.mjs";

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

test("generic encrypt -> decrypt round-trip returns the plaintext", async () => {
  const core = await loadedCore();
  const key = convKey();
  const plaintext = "hello from the js example";
  const ciphertext = core.encrypt(plaintext, key);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(core.decrypt(ciphertext, key), plaintext);
});

test("conversation key prepare -> decrypt round-trip", async () => {
  const core = await loadedCore();
  const prepared = core.prepareConversationKeyChange({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        publicKey: vectors.identity_public_b64,
        keyVersion: "1",
      },
    ],
    conversationId: "conv-1",
  });
  assert.equal(prepared.participantKeys.length, 1);
  assert.equal(prepared.actionSignatures.length, 1);
  const decrypted = core.decryptConversationKey(prepared.participantKeys[0].encryptedKey);
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
});

test("decryptBatch on an empty list is safe", async () => {
  const core = await loadedCore();
  const result = core.decryptBatch([], []);
  assert.equal(result.messages.length, 0);
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
  const prep = core.prepareConversationKeyChange({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        publicKey: vectors.identity_public_b64,
        keyVersion: "1",
      },
    ],
    conversationId: "1000:2000",
  });
  const body = prepToRequest(prep, core.publicKeys().signing);

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
  // CKCE signature payloads are withheld (they embed the plaintext key).
  assert.ok(!("signaturePayload" in sig));
});

test("prepareGroupCreate yields the two required signatures", async () => {
  const core = await loadedCore();
  const prep = core.prepareGroupCreate({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        publicKey: vectors.identity_public_b64,
        keyVersion: "1",
      },
    ],
    conversationId: "g123",
    memberIds: [vectors.event_sender_id],
    adminIds: [vectors.event_sender_id],
  });
  assert.equal(prep.actionSignatures.length, 2);
  assert.ok(prep.conversationKey?.length === 32);
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

test("media stream encrypt -> decrypt round-trip and truncation", async () => {
  // The chunked stream path the media flow uses: multi-chunk payload in,
  // identical bytes out, and truncation is detected.
  const core = await loadedCore();
  const key = convKey();
  const plaintext = Uint8Array.from({ length: 300_000 }, (_, i) => (i * 31 + 7) % 256);

  const ciphertext = core.encryptMedia(plaintext, key);
  const decrypted = core.decryptMedia(ciphertext, key);
  assert.equal(decrypted.length, plaintext.length);
  assert.ok(decrypted.every((b, i) => b === plaintext[i]));

  assert.throws(() => core.decryptMedia(ciphertext.subarray(0, ciphertext.length - 4), key));
});
