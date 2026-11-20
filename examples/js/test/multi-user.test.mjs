/**
 * Offline tests for the JS example's multi-user helpers: one chat per
 * signed-in user, all fetching public keys with one function over one cache.
 *
 * Like chat-core.test.mjs, these drive the real chat-xdk WASM binding.
 *
 *   node --test
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { delivered, deliveredAction } from "../../../crates/wasm/js/tests/frame.mjs";
import { ChatCore, messageText } from "../src/chat-core.mjs";
import { sharedPublicKeys, UserChats } from "../src/multi-user.mjs";

/**
 * A user with fresh keys: a core that signs as the user, what signs the user
 * in to `UserChats`, the entry a prepare call takes for the user, and the
 * user's record as GET /2/users/{id}/public_keys returns it.
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
    signIn: { userId, privateKeysB64, signingKeyVersion: "1" },
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
 * Resolves to the page each of `readers` receives after `admin` rotates the
 * key of the group `conversationId`, which they and `member` are in, and
 * `member` sends `text` under it: the key change, then the message.
 */
async function groupPage(admin, member, readers, conversationId, text) {
  const prepared = await admin.core.prepareConversationKeyChangeAsync({
    publicKeys: [admin, member, ...readers].map((each) => each.publicKey),
    conversationId,
  });
  const keyChange = deliveredAction(
    prepared.actionSignatures[0],
    admin.userId,
    conversationId,
    "2100000000000000000",
  );
  const body = member.core.encryptReply({
    conversationId,
    text,
    conversationKey: prepared.conversationKey,
    conversationKeyVersion: prepared.conversationKeyVersion,
  });
  return [keyChange, delivered(body.event_b64, "2100000000000000001")];
}

test("the chats of two signed-in users fetch the keys of a user they both meet once", async () => {
  const [admin, member, alice, bob] = await Promise.all(["5001", "5002", "5003", "5004"].map(party));
  const directory = { [admin.userId]: [admin.record], [member.userId]: [member.record] };
  const asked = [];
  const chats = new UserChats(
    sharedPublicKeys(async (userId) => {
      asked.push(userId);
      return directory[userId];
    }),
  );
  const events = await groupPage(admin, member, [alice, bob], "g900", "hello group");

  for (const signedIn of [alice, bob]) {
    const chat = await chats.chatFor(signedIn.signIn);
    const page = await chat.decryptBatchAsync(events);
    assert.deepEqual(page.errors, {});
    assert.deepEqual(page.missingSigningKeys, {});
    assert.deepEqual(
      page.events.map(({ event }) => messageText(event)),
      [null, "hello group"],
    );
  }
  // Each chat needed the keys of the admin and the member: the second chat
  // took them from the cache the first one filled.
  assert.deepEqual(asked.sort(), ["5001", "5002"]);
});

test("a signed-in user has one chat, which serves every conversation of the user", async () => {
  const [admin, member, alice, bob] = await Promise.all(["5001", "5002", "5003", "5004"].map(party));
  const directory = { [admin.userId]: [admin.record], [member.userId]: [member.record] };
  const chats = new UserChats(sharedPublicKeys(async (userId) => directory[userId]));

  const [chat, again, other] = await Promise.all([
    chats.chatFor(alice.signIn),
    chats.chatFor(alice.signIn),
    chats.chatFor(bob.signIn),
  ]);
  assert.equal(again, chat);
  assert.notEqual(other, chat);

  for (const conversationId of ["g900", "g901"]) {
    const events = await groupPage(admin, member, [alice], conversationId, `hello ${conversationId}`);
    const page = await chat.decryptBatchAsync(events);
    assert.deepEqual(page.errors, {});
    // The reply takes the conversation's key from the chat's key cache.
    const body = chat.encryptReply({ conversationId, text: "hi" });
    assert.ok(body.encoded_message_create_event);
  }
  // The chat holds no key for a conversation it has not read.
  assert.throws(() => chat.encryptReply({ conversationId: "g902", text: "hi" }));

  // After a sign-out, the next sign-in makes a new chat.
  await chats.close(alice.userId);
  assert.notEqual(await chats.chatFor(alice.signIn), chat);
});

test("sharedPublicKeys shares a lookup under way, retries a failed one and fetches again after the TTL", async () => {
  let time = 1_000;
  let failing = true;
  const asked = [];
  const resolvePublicKeys = sharedPublicKeys(
    async (userId) => {
      asked.push(userId);
      if (userId === "7" && failing) throw new Error("HTTP 503");
      return [{ public_key_version: String(asked.length) }];
    },
    { ttlMs: 100, now: () => time },
  );

  // Two calls at once: user 5 is fetched once, and both calls get the answer.
  const [first, second] = await Promise.all([resolvePublicKeys(["5"]), resolvePublicKeys(["5", "6"])]);
  assert.deepEqual(asked, ["5", "6"]);
  assert.deepEqual(first, { 5: [{ public_key_version: "1" }] });
  assert.deepEqual(second, { 5: [{ public_key_version: "1" }], 6: [{ public_key_version: "2" }] });

  // A lookup that fails leaves the user out and is not kept: the next call
  // fetches again.
  assert.deepEqual(await resolvePublicKeys(["7"]), {});
  failing = false;
  assert.deepEqual(await resolvePublicKeys(["7"]), { 7: [{ public_key_version: "4" }] });
  assert.deepEqual(asked, ["5", "6", "7", "7"]);

  // An answer is served until its time is up, then fetched again.
  time += 99;
  assert.deepEqual(await resolvePublicKeys(["5"]), first);
  assert.equal(asked.length, 4);
  time += 1;
  assert.deepEqual(await resolvePublicKeys(["5"]), { 5: [{ public_key_version: "5" }] });
});
