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

test("setIdentity needs the registered version", async () => {
  // Freshly generated keys have no registered version yet, so the bot cannot
  // sign as itself until loadKeys provides one.
  const core = await ChatCore.create();
  core.generateAndRegister();
  assert.throws(() => core.setIdentity("12345"), /signing key version unknown/);
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
  // CKCE signature payloads are withheld (they embed the plaintext key).
  assert.ok(!("signaturePayload" in sig));
});

test("removalToRequest rotates the key for the members who stay", async () => {
  const { removalToRequest } = await import("../src/chat-core.mjs");
  const core = await loadedCore();
  const prep = core.prepareGroupMembersRemove({
    publicKeys: [
      {
        userId: vectors.event_sender_id,
        publicKey: vectors.identity_public_b64,
        keyVersion: "1",
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
        filesize_bytes: plaintext.length,
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
