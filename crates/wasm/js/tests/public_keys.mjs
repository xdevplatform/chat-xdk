// Other users' public keys: the signing keys a batch reports missing, the
// records addPublicKeys stores, the keys the prepare calls read from the
// store, and the hook that fetches what is missing. Each package's suite
// runs this against the chats its createChat makes.
import assert from "node:assert/strict";

import { free, sendVersion } from "./key_cache.mjs";
import { GROUP, KEY_VERSION, keyChange, message, party, texts } from "./key_change_signers.mjs";

/** The record `GET /2/users/{id}/public_keys` returns for the keys of `user`, a party. */
function record(user) {
  return {
    public_key_version: KEY_VERSION,
    public_key: user.signingKey.identityPublicKey,
    signing_public_key: user.signingKey.publicKey,
    identity_public_key_signature: user.signingKey.identityPublicKeySignature,
  };
}

/** The records of `users`, by user id: what a public-key hook returns. */
function records(...users) {
  return Object.fromEntries(users.map((user) => [user.userId, [record(user)]]));
}

/** What a result's `missingSigningKeys` holds for an event `user` signed. */
function signingKeyOf(user) {
  return { userId: user.userId, publicKeyVersion: KEY_VERSION };
}

/**
 * A hook that answers from `directory`, records by user id, and the user ids
 * of each call it gets. It returns the records themselves when `sync` is
 * set, and a promise of them otherwise.
 */
function hookOver(directory, { sync = false } = {}) {
  const calls = [];
  const answer = (userIds) => {
    calls.push([...userIds]);
    return Object.fromEntries(userIds.filter((id) => id in directory).map((id) => [id, directory[id]]));
  };
  return { calls, resolvePublicKeys: sync ? answer : async (userIds) => answer(userIds) };
}

/** A party whose chat, created with `options`, has the party as its session identity. */
async function withIdentity(newChat, userId, options) {
  const identified = await party(() => newChat(options), userId);
  identified.chat.setIdentity({ userId, signingKeyVersion: KEY_VERSION });
  return identified;
}

/** The users a prepared change encrypted its key to, sorted. */
function recipients(prepared) {
  return prepared.conversationParticipantKeys.map((key) => key.userId).sort();
}

/**
 * The page a bot receives: the key change `admin` makes for the group of the
 * three, and the message `member` sends under it.
 */
function pageFor(admin, member, bot) {
  const change = keyChange(admin, [admin, member, bot], GROUP);
  return { change, events: [change.eventB64, message(member, GROUP, change, "hello group")] };
}

/** What a call throws for a hook that is neither a function nor null. */
const NOT_A_HOOK = {
  name: "ChatXdkError",
  kind: "invalidInput",
  message: /resolvePublicKeys must be a function, or null to remove it/,
};

/** What a prepare call that passes no public keys throws when the store has none for `userIds`. */
function noStoredKeysFor(...userIds) {
  return {
    kind: "invalidInput",
    message: new RegExp(`no public keys are stored for user\\(s\\) ${userIds.join(", ")}:`),
  };
}

/** A batch names each signing key it was not given, and missingPublicKeys the users to fetch. */
async function missingSigningKeysNameTheSenders(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await party(newChat, "5003");
  const { events } = pageFor(admin, member, bot);

  const result = bot.chat.decryptEvents({ events });
  assert.deepEqual(result.events, []);
  assert.deepEqual(result.missingSigningKeys, { 0: signingKeyOf(admin), 1: signingKeyOf(member) });
  assert.deepEqual(bot.chat.missingPublicKeys(result), [admin.userId, member.userId]);
  // Neither lookup brought a key: neither is asked for again at once.
  assert.deepEqual(bot.chat.missingPublicKeys(result), []);

  // With the member's keys given, only the admin's is missing.
  const withMember = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey] });
  assert.deepEqual(withMember.missingSigningKeys, { 0: signingKeyOf(admin) });

  // A batch that was given every key names no one.
  const complete = bot.chat.decryptEvents({ events, signingKeys: [admin.signingKey, member.signingKey] });
  assert.deepEqual(complete.missingSigningKeys, {});
  assert.deepEqual(bot.chat.missingPublicKeys(complete), []);

  free(admin, member, bot);
}

/** addPublicKeys stores the records the X API returns, under either naming of their fields. */
async function addPublicKeysStoresApiRecords(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await party(newChat, "5003");
  const { events } = pageFor(admin, member, bot);

  // No records, and a record without its signing key, store nothing.
  for (const none of [undefined, null, {}]) bot.chat.addPublicKeys(none);
  const { signing_public_key: _signingKey, ...partial } = record(admin);
  bot.chat.addPublicKeys({ [admin.userId]: [partial] });
  assert.deepEqual(bot.chat.decryptEvents({ events }).events, []);
  assert.throws(() => bot.chat.addPublicKeys("records"), {
    kind: "invalidInput",
    message: /Invalid public key records/,
  });

  bot.chat.addPublicKeys({
    // The X API's field names, with a field the SDK does not read.
    [admin.userId]: [{ ...record(admin), juicebox_config: { key_store_token_map_json: "{}", max_guess_count: 20 } }],
    // The names the X API client libraries give the fields, with the key
    // version as a number.
    [member.userId]: [
      {
        publicKeyVersion: Number(KEY_VERSION),
        publicKey: member.signingKey.identityPublicKey,
        signingPublicKey: member.signingKey.publicKey,
        identityPublicKeySignature: member.signingKey.identityPublicKeySignature,
        juiceboxConfig: { maxGuessCount: 20 },
      },
    ],
  });
  const result = bot.chat.decryptEvents({ events });
  assert.deepEqual(result.errors, {});
  assert.deepEqual(result.missingSigningKeys, {});
  assert.deepEqual(texts(result), ["hello group"]);

  free(admin, member, bot);
}

/** decryptEventsAsync fetches the keys a batch is missing through the hook and decrypts once more. */
async function decryptEventsAsyncFetchesThroughTheHook(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const hook = hookOver(records(admin, member));
  // The create option sets the hook.
  const bot = await withIdentity(newChat, "5003", { resolvePublicKeys: hook.resolvePublicKeys });
  const { change, events } = pageFor(admin, member, bot);

  // decryptEvents never calls the hook.
  assert.deepEqual(bot.chat.decryptEvents({ events }).events, []);
  assert.deepEqual(hook.calls, []);

  const result = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(result.errors, {});
  assert.deepEqual(result.missingSigningKeys, {});
  assert.deepEqual(texts(result), ["hello group"]);
  assert.deepEqual(hook.calls, [[admin.userId, member.userId]]);

  // Setting the hook turned the key cache on: a send finds the verified key.
  assert.equal(sendVersion(bot, GROUP), change.version);

  // The keys are stored: the next batch needs no lookup.
  const again = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(texts(again), ["hello group"]);
  assert.equal(hook.calls.length, 1);

  free(admin, member, bot);
}

/** The hook is not called for keys that were passed, or again for keys it could not find. */
async function hookIsNotCalledForKeysPassedOrNotFound(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await withIdentity(newChat, "5003");
  const { events } = pageFor(admin, member, bot);
  // The hook knows the admin alone, and answers without a promise.
  const hook = hookOver(records(admin), { sync: true });
  bot.chat.setResolvePublicKeys(hook.resolvePublicKeys);

  // Signing keys that are passed are what the call verifies with.
  const passed = await bot.chat.decryptEventsAsync({ events, signingKeys: [member.signingKey] });
  assert.deepEqual(passed.missingSigningKeys, { 0: signingKeyOf(admin) });
  assert.deepEqual(hook.calls, []);

  // The member's keys are not found: the result says so, and the next call
  // does not ask again.
  const result = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(result.missingSigningKeys, { 1: signingKeyOf(member) });
  assert.deepEqual(hook.calls, [[admin.userId, member.userId]]);
  const again = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(again.missingSigningKeys, { 1: signingKeyOf(member) });
  assert.equal(hook.calls.length, 1);

  free(admin, member, bot);
}

/** What the hook throws reaches the caller of the Async method. */
async function hookFailuresReachTheCaller(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await withIdentity(newChat, "5003");
  const { events } = pageFor(admin, member, bot);
  const failure = new Error("public keys lookup failed");
  let lookups = 0;
  bot.chat.setResolvePublicKeys(() => {
    lookups += 1;
    throw failure;
  });

  await assert.rejects(bot.chat.decryptEventsAsync({ events }), (err) => err === failure);
  // The lookup is remembered: the next call does not repeat it.
  const after = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(after.missingSigningKeys, { 0: signingKeyOf(admin), 1: signingKeyOf(member) });
  assert.equal(lookups, 1);

  // A hook that returns nothing adds nothing.
  const reader = await withIdentity(newChat, "5006");
  let unanswered = 0;
  reader.chat.setResolvePublicKeys(() => {
    unanswered += 1;
  });
  const still = await reader.chat.decryptEventsAsync({ events });
  assert.deepEqual(still.missingSigningKeys, { 0: signingKeyOf(admin), 1: signingKeyOf(member) });
  assert.equal(unanswered, 1);

  free(admin, member, bot, reader);
}

/** The hook is a function or null; removing it leaves the key cache on. */
async function hookIsSetAndRemoved(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await withIdentity(newChat, "5003");
  const { events } = pageFor(admin, member, bot);

  for (const notAHook of ["hook", 7, {}]) {
    assert.throws(() => bot.chat.setResolvePublicKeys(notAHook), NOT_A_HOOK);
    await assert.rejects(async () => newChat({ resolvePublicKeys: notAHook }), NOT_A_HOOK);
  }
  // A null option sets no hook, and leaves the key cache off.
  const plain = await withIdentity(newChat, "5005", { resolvePublicKeys: null });
  plain.chat.prepareConversationKeyChange({ publicKeys: [plain.publicKey], conversationId: GROUP });
  assert.throws(() => sendVersion(plain, GROUP), { kind: "invalidState" });

  // Without a hook the Async methods do what the methods they are named
  // after do.
  const unresolved = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(unresolved.missingSigningKeys, { 0: signingKeyOf(admin), 1: signingKeyOf(member) });
  const own = await bot.chat.prepareConversationKeyChangeAsync({ publicKeys: [bot.publicKey], conversationId: GROUP });
  assert.deepEqual(recipients(own), [bot.userId]);
  assert.throws(() => sendVersion(bot, GROUP), { kind: "invalidState" });

  // A hook that is removed is not called, and the key cache it turned on
  // stays on.
  const hook = hookOver(records(admin, member));
  bot.chat.setResolvePublicKeys(hook.resolvePublicKeys);
  bot.chat.setResolvePublicKeys(null);
  const removed = await bot.chat.decryptEventsAsync({ events });
  assert.deepEqual(removed.events, []);
  assert.deepEqual(hook.calls, []);
  const cached = bot.chat.prepareConversationKeyChange({ publicKeys: [bot.publicKey], conversationId: GROUP });
  assert.equal(sendVersion(bot, GROUP), cached.conversationKeyVersion);

  free(admin, member, bot, plain);
}

/**
 * The prepare calls that make a conversation key, each with params that
 * pass no public keys and the users it encrypts the key to, in the order
 * the params name them. The sender is user 5001.
 */
const PREPARE_CALLS = [
  {
    method: "prepareGroupCreate",
    params: { conversationId: GROUP, memberIds: ["5001", "5002"], adminIds: ["5001"] },
    users: ["5001", "5002"],
  },
  {
    method: "prepareGroupMembersChange",
    params: {
      conversationId: GROUP,
      newMemberIds: ["5004"],
      currentMemberIds: ["5001", "5002"],
      currentAdminIds: ["5001"],
      currentPendingMemberIds: [],
    },
    users: ["5001", "5002", "5004"],
  },
  {
    method: "prepareGroupMembersRemove",
    params: { conversationId: GROUP, userIds: ["5004"], remainingMemberIds: ["5001", "5002"] },
    users: ["5001", "5002"],
  },
  {
    method: "prepareConversationKeyChange",
    params: { conversationId: GROUP, memberIds: ["5001", "5002"] },
    users: ["5001", "5002"],
  },
  {
    // A one-to-one names its two users by its id: here the other user's id.
    method: "prepareConversationKeyChange",
    params: { conversationId: "5002" },
    users: ["5001", "5002"],
    conversationId: "5001:5002",
  },
];

/** Each prepare call that is passed no public keys encrypts to the stored keys of its members. */
async function prepareCallsReadStoredPublicKeys(newChat) {
  const admin = await withIdentity(newChat, "5001");
  const member = await party(newChat, "5002");
  const joiner = await party(newChat, "5004");
  const everyone = { 5001: admin, 5002: member, 5004: joiner };

  // With nothing stored, each call says whose keys it lacks.
  for (const { method, params, users } of PREPARE_CALLS) {
    assert.throws(() => admin.chat[method](params), noStoredKeysFor(...users));
  }

  admin.chat.addPublicKeys(records(admin, joiner));
  assert.throws(
    () => admin.chat.prepareGroupCreate(PREPARE_CALLS[0].params),
    noStoredKeysFor(member.userId),
  );
  admin.chat.addPublicKeys(records(member));

  for (const { method, params, users, conversationId = GROUP } of PREPARE_CALLS) {
    // Public keys that are absent, null or empty all read the store.
    for (const publicKeys of [undefined, null, []]) {
      const prepared = admin.chat[method](publicKeys === undefined ? params : { ...params, publicKeys });
      assert.equal(prepared.conversationId, conversationId);
      assert.deepEqual(recipients(prepared), users);
      // Each user decrypts the key the change holds for that user.
      for (const { userId, encryptedConversationKey } of prepared.conversationParticipantKeys) {
        assert.deepEqual(
          everyone[userId].chat.decryptConversationKey(encryptedConversationKey),
          prepared.conversationKey,
        );
      }
    }
  }

  // Public keys that are passed are used as they are: the store has none
  // for this user.
  const stranger = await party(newChat, "5006");
  const passed = admin.chat.prepareGroupCreate({
    publicKeys: [admin.publicKey, stranger.publicKey],
    conversationId: GROUP,
    memberIds: [admin.userId, stranger.userId],
    adminIds: [admin.userId],
  });
  assert.deepEqual(recipients(passed), [admin.userId, stranger.userId]);

  // Without members to read keys for, a call reports its empty public keys.
  assert.throws(() => admin.chat.prepareConversationKeyChange({ conversationId: GROUP }), {
    kind: "invalidInput",
    message: /public_keys must not be empty/,
  });
  assert.throws(() => admin.chat.prepareGroupMembersRemove({ conversationId: GROUP, userIds: ["5004"] }), {
    kind: "invalidInput",
    message: /public_keys is empty: pass the public keys of the remaining members/,
  });

  free(admin, member, joiner, stranger);
}

/** The Async prepare calls fetch the keys they are missing through the hook; the others never do. */
async function asyncPrepareCallsFetchThroughTheHook(newChat) {
  const member = await party(newChat, "5002");
  const joiner = await party(newChat, "5004");

  for (const { method, params, users, conversationId = GROUP } of PREPARE_CALLS) {
    const admin = await withIdentity(newChat, "5001");
    const everyone = { 5001: admin, 5002: member, 5004: joiner };
    const hook = hookOver(records(admin, member, joiner), { sync: true });
    admin.chat.setResolvePublicKeys(hook.resolvePublicKeys);
    const prepareAsync = (callParams) => admin.chat[`${method}Async`](callParams);

    // Public keys that are passed are used as they are.
    const publicKeys = users.map((userId) => everyone[userId].publicKey);
    assert.deepEqual(recipients(await prepareAsync({ ...params, publicKeys })), users);
    assert.deepEqual(hook.calls, []);

    // The call the Async one is named after never calls the hook.
    assert.throws(() => admin.chat[method](params), noStoredKeysFor(...users));
    assert.deepEqual(hook.calls, []);

    const prepared = await prepareAsync(params);
    assert.equal(prepared.conversationId, conversationId);
    assert.deepEqual(recipients(prepared), users);
    assert.deepEqual(hook.calls, [users]);

    // The keys are stored: neither call needs a lookup.
    assert.deepEqual(recipients(await prepareAsync(params)), users);
    assert.deepEqual(recipients(admin.chat[method](params)), users);
    assert.equal(hook.calls.length, 1);

    free(admin);
  }

  // A member the hook has no keys for: the call says so, and the next call
  // does not ask again.
  const create = PREPARE_CALLS[0].params;
  const creator = await withIdentity(newChat, "5001");
  const ownKeysOnly = hookOver(records(creator));
  creator.chat.setResolvePublicKeys(ownKeysOnly.resolvePublicKeys);
  await assert.rejects(creator.chat.prepareGroupCreateAsync(create), noStoredKeysFor(member.userId));
  assert.deepEqual(ownKeysOnly.calls, [[creator.userId, member.userId]]);
  await assert.rejects(creator.chat.prepareGroupCreateAsync(create), noStoredKeysFor(member.userId));
  assert.equal(ownKeysOnly.calls.length, 1);

  // What the hook throws reaches the caller.
  const failing = await withIdentity(newChat, "5001");
  const failure = new Error("public keys lookup failed");
  failing.chat.setResolvePublicKeys(async () => {
    throw failure;
  });
  await assert.rejects(failing.chat.prepareGroupCreateAsync(create), (err) => err === failure);

  free(member, joiner, creator, failing);
}

/**
 * Run the checks with chats from `newChat`, which takes the options of the
 * package's createChat and returns a chat without keys (or a promise of
 * one).
 */
export async function publicKeyTests(newChat) {
  await missingSigningKeysNameTheSenders(newChat);
  await addPublicKeysStoresApiRecords(newChat);
  await decryptEventsAsyncFetchesThroughTheHook(newChat);
  await hookIsNotCalledForKeysPassedOrNotFound(newChat);
  await hookFailuresReachTheCaller(newChat);
  await hookIsSetAndRemoved(newChat);
  await prepareCallsReadStoredPublicKeys(newChat);
  await asyncPrepareCallsFetchThroughTheHook(newChat);
}
