// The conversation-key cache and the signing-key store: what fills them and
// which calls read them. Each package's suite runs this against its own
// chat.
import assert from "node:assert/strict";

import { GROUP, KEY_VERSION, keyChange, message, party } from "./key_change_signers.mjs";

const AVATAR_URL = "https://ton.x.com/xchat_media/g900/avatar";

// What a call that needs a conversation key throws when it is passed none
// and the cache holds none for the group.
const NO_CACHED_KEY = { kind: "invalidState", message: /no cached conversation key for 'g900'/ };

/** A party with a session identity whose key cache is on. */
async function caching(newChat, userId) {
  const cached = await party(newChat, userId);
  cached.chat.setIdentity({ userId, signingKeyVersion: KEY_VERSION });
  cached.chat.setCacheKeys(true);
  return cached;
}

/** The key version `sender` encrypts under in `conversationId` when the call passes no key. */
function sendVersion(sender, conversationId) {
  return sender.chat.encryptMessage({ conversationId, text: "hello" }).conversationKeyVersion;
}

/**
 * The text of `eventB64`, a message from `author`, as `receiver` decrypts it
 * on its own with no key map.
 */
function read(receiver, eventB64, author) {
  const event = receiver.chat.decryptEvent({ eventB64, signingKeys: [author.signingKey] });
  assert.equal(event.type, "message");
  assert.equal(event.verified, true);
  return event.content.text;
}

/**
 * Resolves once the clock is past `version`. A prepared key's version is the
 * clock's millisecond, so a key prepared after this has a newer version.
 */
async function clockPast(version) {
  while (Date.now() <= Number(version)) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

/**
 * Whether `prepared`, an avatar change `signer` made for AVATAR_URL, signs
 * key version `version`. The signature covers the event name, the action's
 * message id, the sender, the conversation, the key version and the URL.
 */
function avatarSigns(signer, prepared, version) {
  assert.equal(prepared.actionSignatures.length, 1);
  const [action] = prepared.actionSignatures;
  const signed = action.messageEventSignature;
  return signer.chat.verify(
    signed.signingPublicKey,
    Uint8Array.from(Buffer.from(signed.signature, "base64")),
    new TextEncoder().encode(
      `GroupChangeEvent.GroupAvatarUrlChange,${action.messageId},${signer.userId},${GROUP},${version},${AVATAR_URL}`,
    ),
  );
}

function free(...parties) {
  for (const { chat } of parties) chat.free();
}

/** decryptEvent caches the key of a key change that verifies. */
async function singleDecryptFillsTheCache(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await caching(newChat, "5003");
  const change = keyChange(admin, [admin, member, bot], GROUP);
  const hello = message(member, GROUP, change, "hello group");

  // Nothing is cached yet: neither a send nor the message finds a key.
  assert.throws(() => sendVersion(bot, GROUP), NO_CACHED_KEY);
  assert.throws(() => bot.chat.decryptEvent({ eventB64: hello, signingKeys: [member.signingKey] }));

  const event = bot.chat.decryptEvent({ eventB64: change.eventB64, signingKeys: [admin.signingKey] });
  assert.equal(event.type, "keyChange");
  assert.equal(event.verified, true);
  assert.equal(event.conversationKeyVersion, change.version);

  assert.equal(sendVersion(bot, GROUP), change.version);
  assert.equal(read(bot, hello, member), "hello group");
  // A later batch reports the version the single call recorded.
  const batch = bot.chat.decryptEvents({ events: [hello], signingKeys: [member.signingKey] });
  assert.deepEqual(batch.errors, {});
  assert.equal(batch.conversationKeys.latestVersion, change.version);

  free(admin, member, bot);
}

/** decryptEvent does not cache the key of a key change that does not verify. */
async function unverifiedKeyChangeIsNotCached(newChat) {
  const admin = await party(newChat, "5001");
  const bot = await caching(newChat, "5003");
  bot.chat.setRejectUnverified(false);
  const change = keyChange(admin, [admin, bot], GROUP);

  // Without the admin's signing keys the key change is returned unverified.
  const event = bot.chat.decryptEvent({ eventB64: change.eventB64 });
  assert.equal(event.type, "keyChange");
  assert.equal(event.verified, false);
  assert.throws(() => sendVersion(bot, GROUP), NO_CACHED_KEY);

  free(admin, bot);
}

/** Each prepare call that makes a conversation key caches it while the cache is on. */
async function prepareCallsCacheTheirKey(newChat) {
  const admin = await caching(newChat, "5001");
  const member = await party(newChat, "5002");
  const joiner = await party(newChat, "5004");
  const both = [admin.publicKey, member.publicKey];
  const prepares = [
    () =>
      admin.chat.prepareGroupCreate({
        publicKeys: both,
        conversationId: GROUP,
        memberIds: [admin.userId, member.userId],
        adminIds: [admin.userId],
      }),
    () =>
      admin.chat.prepareGroupMembersChange({
        publicKeys: [...both, joiner.publicKey],
        conversationId: GROUP,
        newMemberIds: [joiner.userId],
        currentMemberIds: [admin.userId, member.userId],
        currentAdminIds: [admin.userId],
        currentPendingMemberIds: [],
      }),
    () => admin.chat.prepareGroupMembersRemove({ publicKeys: both, conversationId: GROUP, userIds: [joiner.userId] }),
    () => admin.chat.prepareConversationKeyChange({ publicKeys: both, conversationId: GROUP }),
  ];

  // Sends use the key the latest prepare call made.
  const prepared = [];
  for (const prepare of prepares) {
    if (prepared.length > 0) await clockPast(prepared.at(-1).conversationKeyVersion);
    const change = prepare();
    assert.equal(sendVersion(admin, GROUP), change.conversationKeyVersion);
    prepared.push(change);
  }

  // Every prepared key stays cached: a message under it decrypts with no
  // key map.
  for (const { conversationKey, conversationKeyVersion } of prepared) {
    const under = { key: conversationKey, version: conversationKeyVersion };
    const sent = message(member, GROUP, under, conversationKeyVersion);
    assert.equal(read(admin, sent, member), conversationKeyVersion);
  }

  // A one-to-one is cached under the id the call derives.
  const direct = admin.chat.prepareConversationKeyChange({ publicKeys: both });
  assert.equal(direct.conversationId, "5001:5002");
  assert.equal(sendVersion(admin, direct.conversationId), direct.conversationKeyVersion);

  // With the cache off a prepared key is not kept, and turning the cache on
  // later does not bring it back.
  const uncached = await party(newChat, "5005");
  uncached.chat.setIdentity({ userId: uncached.userId, signingKeyVersion: KEY_VERSION });
  uncached.chat.prepareConversationKeyChange({ publicKeys: [uncached.publicKey], conversationId: GROUP });
  assert.throws(() => sendVersion(uncached, GROUP), NO_CACHED_KEY);
  uncached.chat.setCacheKeys(true);
  assert.throws(() => sendVersion(uncached, GROUP), NO_CACHED_KEY);

  free(admin, member, joiner, uncached);
}

/** The cache keeps the key of every verified version, and sends use the newest. */
async function everyVersionIsKept(newChat) {
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await caching(newChat, "5003");
  const members = [admin, member, bot];
  const first = keyChange(admin, members, GROUP);
  await clockPast(first.version);
  const second = keyChange(admin, members, GROUP);
  assert.ok(BigInt(first.version) < BigInt(second.version));

  // The older key change arrives after the newer one: its key is kept for
  // decryption and does not become the key sends use.
  for (const change of [second, first]) {
    const event = bot.chat.decryptEvent({ eventB64: change.eventB64, signingKeys: [admin.signingKey] });
    assert.equal(event.verified, true);
    assert.equal(sendVersion(bot, GROUP), second.version);
  }
  for (const change of [first, second]) {
    const sent = message(member, GROUP, change, change.version);
    assert.equal(read(bot, sent, member), change.version);
  }

  free(admin, member, bot);
}

/** decryptFile and fileDecryptor read the cache when no key map is passed. */
async function filesReadTheCache(newChat) {
  const sender = await caching(newChat, "5001");
  const { conversationKeyVersion: version } = sender.chat.prepareConversationKeyChange({
    publicKeys: [sender.publicKey],
    conversationId: GROUP,
  });
  const payload = sender.chat.encryptMessage({
    conversationId: GROUP,
    text: "a photo",
    attachments: [
      {
        attachment_type: "media",
        media_hash_key: "photo",
        width: 4,
        height: 3,
        filesize_bytes: 64,
        filename: "photo.jpg",
        media_type: 1,
      },
    ],
  });
  assert.equal(payload.conversationKeyVersion, version);
  const photo = { eventB64: payload.eventB64, mediaHashKey: "photo" };
  const file = new TextEncoder().encode("photo bytes");
  const encrypted = sender.chat.encryptFile({ ...photo, file });
  /** The file as a decryptor made with `params` decrypts it. */
  const streamed = (params) => {
    const decryptor = sender.chat.fileDecryptor(params);
    return Buffer.concat([decryptor.push(encrypted), decryptor.finish()]);
  };

  // No key map, or an empty one: the keys come from the cache.
  assert.deepEqual(sender.chat.decryptFile({ ...photo, encrypted }), file);
  assert.deepEqual(streamed(photo), Buffer.from(file));
  for (const conversationKeys of [undefined, null, {}]) {
    assert.deepEqual(sender.chat.decryptFile({ ...photo, encrypted, conversationKeys }), file);
    assert.deepEqual(streamed({ ...photo, conversationKeys }), Buffer.from(file));
  }

  // A key map that is passed is the only source: one without the message's
  // version fails though the cache holds that version.
  const otherVersion = { 9: new Uint8Array(32).fill(7) };
  const noKey = new RegExp(`conversation_keys has no key for version '${version}'`);
  assert.throws(() => sender.chat.decryptFile({ ...photo, encrypted, conversationKeys: otherVersion }), noKey);
  assert.throws(() => sender.chat.fileDecryptor({ ...photo, conversationKeys: otherVersion }), noKey);

  // With the cache off there are no keys to read.
  sender.chat.setCacheKeys(false);
  assert.throws(() => sender.chat.decryptFile({ ...photo, encrypted }), noKey);
  assert.throws(() => sender.chat.fileDecryptor(photo), noKey);

  free(sender);
}

/** An avatar change that passes no key version signs the newest cached one. */
async function avatarChangeSignsTheNewestCachedVersion(newChat) {
  const admin = await caching(newChat, "5001");
  const avatar = { conversationId: GROUP, newAvatarUrl: AVATAR_URL };

  assert.throws(() => admin.chat.prepareGroupAvatarChange(avatar), {
    kind: "invalidState",
    message: /conversation_key_version is not set and no conversation key is cached for 'g900'/,
  });

  const rotation = { publicKeys: [admin.publicKey], conversationId: GROUP };
  const older = admin.chat.prepareConversationKeyChange(rotation).conversationKeyVersion;
  await clockPast(older);
  const newest = admin.chat.prepareConversationKeyChange(rotation).conversationKeyVersion;

  assert.ok(avatarSigns(admin, admin.chat.prepareGroupAvatarChange(avatar), newest));
  for (const conversationKeyVersion of [undefined, null, ""]) {
    const prepared = admin.chat.prepareGroupAvatarChange({ ...avatar, conversationKeyVersion });
    assert.ok(avatarSigns(admin, prepared, newest));
  }
  // A version that is passed is signed as is.
  const explicit = admin.chat.prepareGroupAvatarChange({ ...avatar, conversationKeyVersion: older });
  assert.ok(avatarSigns(admin, explicit, older));

  free(admin);
}

/** addSigningKeys merges into the stored signing keys; setSigningKeys replaces them. */
async function addSigningKeysMerges(newChat) {
  const alice = await party(newChat, "5001");
  const bob = await party(newChat, "5002");
  const reader = await party(newChat, "5003");
  const under = { key: new Uint8Array(32).fill(7), version: "7" };
  const conversationKeys = { [under.version]: under.key };
  // Whether `reader` verifies a message from `author` with its stored
  // signing keys; the conversation key is passed.
  const verifies = (author) =>
    reader.chat.decryptEvent({ eventB64: message(author, GROUP, under, "hi"), conversationKeys }).verified;
  const noSigningKeyFor = (author) => ({
    kind: "verification",
    message: new RegExp(`no signing key for sender ${author.userId} at public_key_version ${KEY_VERSION}`),
  });

  reader.chat.setSigningKeys([alice.signingKey]);
  assert.equal(verifies(alice), true);
  assert.throws(() => verifies(bob), noSigningKeyFor(bob));

  // Adding keeps what is stored.
  reader.chat.addSigningKeys([bob.signingKey]);
  assert.equal(verifies(alice), true);
  assert.equal(verifies(bob), true);

  // An entry for a stored user and version replaces that entry alone.
  reader.chat.addSigningKeys([{ ...bob.signingKey, userId: alice.userId }]);
  assert.throws(() => verifies(alice), { kind: "verification" });
  assert.equal(verifies(bob), true);

  // setSigningKeys replaces the whole set.
  reader.chat.setSigningKeys([bob.signingKey]);
  assert.throws(() => verifies(alice), noSigningKeyFor(alice));
  assert.equal(verifies(bob), true);

  free(alice, bob, reader);
}

/**
 * Run the checks with chats from `newChat`, which returns a chat without
 * keys (or a promise of one).
 */
export async function keyCacheTests(newChat) {
  await singleDecryptFillsTheCache(newChat);
  await unverifiedKeyChangeIsNotCached(newChat);
  await prepareCallsCacheTheirKey(newChat);
  await everyVersionIsKept(newChat);
  await filesReadTheCache(newChat);
  await avatarChangeSignsTheNewestCachedVersion(newChat);
  await addSigningKeysMerges(newChat);
}
