// decryptEvents and the key changes of a batch: a key change needs its
// signer's keys to verify, the result says which key changes did not verify
// or could not be decrypted and why, and keys and the version to encrypt with
// are reported per conversation. Each package's suite runs this against its
// own chat.
import assert from "node:assert/strict";

import { delivered, deliveredAction } from "./frame.mjs";

// A sequence id past the cut-over, where a key change that does not verify
// has its key dropped, and one before it, where the key is kept.
const ENFORCED_SEQUENCE = "2100000000000000000";
const UNENFORCED_SEQUENCE = "100";
export const GROUP = "g900";
const OTHER_GROUP = "g901";
const THIRD_GROUP = "g902";
export const KEY_VERSION = "1";

/** A chat with fresh keys as user `userId`, and the keys others hold for it. */
export async function party(newChat, userId) {
  const chat = await newChat();
  const { publicKey } = chat.generateKeypairs();
  return {
    chat,
    userId,
    signingKey: {
      userId,
      publicKeyVersion: KEY_VERSION,
      publicKey: publicKey.signingPublicKey,
      identityPublicKey: publicKey.publicKey,
      identityPublicKeySignature: publicKey.identityPublicKeySignature,
    },
    publicKey: { userId, identityPublicKey: publicKey.publicKey, publicKeyVersion: KEY_VERSION },
  };
}

/** The key change `signer` makes in `conversationId` for `members`, with its key. */
export function keyChange(signer, members, conversationId) {
  const prepared = signer.chat.prepareConversationKeyChange({
    senderId: signer.userId,
    signingKeyVersion: KEY_VERSION,
    publicKeys: members.map((member) => member.publicKey),
    conversationId,
  });
  const action = prepared.actionSignatures[0];
  return {
    action,
    eventB64: deliveredAction(action, signer.userId, conversationId, ENFORCED_SEQUENCE),
    key: prepared.conversationKey,
    version: prepared.conversationKeyVersion,
  };
}

/**
 * `change`, a key change from `signer` in `conversationId`, as delivered
 * before the cut-over with its key version rewritten to `version`. The
 * signature no longer verifies, and the key is kept.
 */
function atVersion(change, signer, conversationId, version) {
  assert.equal(change.version.length, version.length);
  const detail = Buffer.from(change.action.encodedMessageEventDetail, "base64").toString("latin1");
  assert.ok(detail.includes(change.version));
  const action = {
    ...change.action,
    encodedMessageEventDetail: Buffer.from(detail.replace(change.version, version), "latin1").toString("base64"),
  };
  return {
    eventB64: deliveredAction(action, signer.userId, conversationId, UNENFORCED_SEQUENCE),
    key: change.key,
    version,
  };
}

/** The message `author` sends in `conversationId` under the key of `change`, as delivered. */
export function message(author, conversationId, change, text) {
  const payload = author.chat.encryptMessage({
    conversationId,
    text,
    senderId: author.userId,
    signingKeyVersion: KEY_VERSION,
    conversationKey: change.key,
    conversationKeyVersion: change.version,
  });
  return delivered(payload.eventB64, "2100000000000000001");
}

/** The text of each message among a result's events. */
export function texts(result) {
  return result.events.filter(({ event }) => event.type === "message").map(({ event }) => event.content.text);
}

/**
 * Run the checks with chats from `newChat`, which returns a chat without
 * keys (or a promise of one).
 */
export async function keyChangeSignerTests(newChat) {
  // An admin rotates a group's key, a member sends a message under it, and
  // the bot receives both.
  const admin = await party(newChat, "5001");
  const member = await party(newChat, "5002");
  const bot = await party(newChat, "5003");
  const change = keyChange(admin, [admin, member, bot], GROUP);
  const events = [change.eventB64, message(member, GROUP, change, "hello group")];
  const unverified = (reason) => ({
    0: {
      reason,
      keyDropped: true,
      conversationId: GROUP,
      conversationKeyVersion: change.version,
      senderId: admin.userId,
      publicKeyVersion: KEY_VERSION,
    },
  });

  // With the keys of the member who wrote the message but not of the admin
  // who made the key change, the key is dropped and the result says why.
  const missing = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey] });
  assert.deepEqual(missing.events, []);
  assert.deepEqual(missing.conversationKeys.keys, {});
  assert.deepEqual(missing.conversationKeys.keysByConversation, {});
  assert.equal(missing.conversationKeys.latestVersion, null);
  assert.deepEqual(missing.conversationKeys.latestVersions, {});
  assert.deepEqual(missing.unverifiedKeyChanges, unverified("missingSigningKey"));
  assert.deepEqual(missing.undecryptableKeyChanges, {});
  assert.deepEqual(missing.rejectedSigningKeys, {});
  assert.match(missing.errors["0"], /no signing key for sender 5001 at public_key_version 1/);
  assert.match(
    missing.errors["1"],
    /no matching key found: the key change for that version, event 0 of the batch, did not verify/,
  );

  // A signing key under the admin's user id and key version that is not the
  // key the admin signed with: the signature is invalid.
  const otherKey = await party(newChat, admin.userId);
  const invalid = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey, otherKey.signingKey] });
  assert.deepEqual(invalid.events, []);
  assert.deepEqual(invalid.unverifiedKeyChanges, unverified("invalidSignature"));
  assert.match(invalid.errors["0"], /ECDSA mismatch/);

  // The admin's signing key with a binding signature that is not its
  // signature over the identity key: the key is left out, and the result
  // says so rather than asking for a key it was given.
  const unbound = { ...admin.signingKey, identityPublicKeySignature: member.signingKey.identityPublicKeySignature };
  const rejected = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey, unbound] });
  assert.deepEqual(rejected.events, []);
  assert.deepEqual(rejected.rejectedSigningKeys, { 1: { userId: admin.userId, publicKeyVersion: KEY_VERSION } });
  assert.deepEqual(rejected.unverifiedKeyChanges, unverified("rejectedSigningKey"));
  assert.match(
    rejected.errors["0"],
    /the signing key given for sender 5001 at public_key_version 1 was rejected: its identity binding does not verify/,
  );

  // With the admin's keys the key change verifies and the message decrypts.
  const verified = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey, admin.signingKey] });
  assert.deepEqual(verified.errors, {});
  assert.deepEqual(verified.unverifiedKeyChanges, {});
  assert.deepEqual(verified.undecryptableKeyChanges, {});
  assert.deepEqual(verified.rejectedSigningKeys, {});
  assert.deepEqual(
    verified.events.map(({ event }) => event.type),
    ["keyChange", "message"],
  );
  assert.deepEqual(texts(verified), ["hello group"]);
  assert.equal(verified.conversationKeys.latestVersion, change.version);
  assert.deepEqual(verified.conversationKeys.latestVersions, { [GROUP]: change.version });
  assert.deepEqual(verified.conversationKeys.keys, { [change.version]: change.key });
  assert.deepEqual(verified.conversationKeys.keysByConversation, { [GROUP]: { [change.version]: change.key } });

  // A key change made for the admin and the member only: a chat whose
  // identity is the bot's finds no key for its user in it.
  const outsider = await party(newChat, bot.userId);
  outsider.chat.setIdentity({ userId: bot.userId, signingKeyVersion: KEY_VERSION });
  const notForBot = keyChange(admin, [admin, member], GROUP);
  const undecryptable = outsider.chat.decryptEvents({
    events: [notForBot.eventB64, message(member, GROUP, notForBot, "not for the bot")],
    signingKeys: [member.signingKey, admin.signingKey],
  });
  assert.deepEqual(undecryptable.events, []);
  assert.deepEqual(undecryptable.unverifiedKeyChanges, {});
  assert.deepEqual(undecryptable.undecryptableKeyChanges, {
    0: {
      reason: "notARecipient",
      conversationId: GROUP,
      conversationKeyVersion: notForBot.version,
      senderId: admin.userId,
    },
  });
  assert.match(
    undecryptable.errors["1"],
    /event 0 of the batch, holds no key this chat can decrypt: it holds no key for this chat's user/,
  );

  // Key changes of two conversations in one batch: each conversation has its
  // own keys and its own version to encrypt with, and no single version
  // stands for both.
  let other = keyChange(admin, [admin, bot], OTHER_GROUP);
  while (other.version === change.version) {
    other = keyChange(admin, [admin, bot], OTHER_GROUP);
  }
  const versions = { [GROUP]: change.version, [OTHER_GROUP]: other.version };
  const both = bot.chat.decryptEvents({
    events: [change.eventB64, other.eventB64],
    signingKeys: [admin.signingKey],
  });
  assert.deepEqual(both.errors, {});
  assert.deepEqual(both.conversationKeys.latestVersions, versions);
  assert.equal(both.conversationKeys.latestVersion, null);
  assert.deepEqual(both.conversationKeys.keysByConversation, {
    [GROUP]: { [change.version]: change.key },
    [OTHER_GROUP]: { [other.version]: other.key },
  });
  assert.deepEqual(both.conversationKeys.keys, { [change.version]: change.key, [other.version]: other.key });
  const one = bot.chat.decryptEvents({ events: [other.eventB64], signingKeys: [admin.signingKey] });
  assert.equal(one.conversationKeys.latestVersion, other.version);
  assert.deepEqual(one.conversationKeys.latestVersions, { [OTHER_GROUP]: other.version });

  // A batch of two conversations has no single version even when only one
  // of them has a verified key change.
  const strayMessage = message(admin, THIRD_GROUP, other, "hello third group");
  const mixed = bot.chat.decryptEvents({ events: [change.eventB64, strayMessage], signingKeys: [admin.signingKey] });
  assert.equal(mixed.conversationKeys.latestVersion, null);
  assert.deepEqual(mixed.conversationKeys.latestVersions, { [GROUP]: change.version });

  // extractConversationKeys checks no signature, and reports the same way.
  const extracted = bot.chat.extractConversationKeys([change.eventB64, other.eventB64]);
  assert.deepEqual(extracted.latestVersions, versions);
  assert.equal(extracted.latestVersion, null);
  assert.deepEqual(extracted.keysByConversation, both.conversationKeys.keysByConversation);
  assert.equal(bot.chat.extractConversationKeys([other.eventB64]).latestVersion, other.version);

  // Two conversations whose keys have the same version: each message
  // decrypts under its own conversation's key, and a lookup by version alone
  // finds neither.
  const sameVersion = atVersion(other, admin, OTHER_GROUP, change.version);
  const collided = bot.chat.decryptEvents({
    events: [
      change.eventB64,
      sameVersion.eventB64,
      message(admin, GROUP, change, "hello group"),
      message(admin, OTHER_GROUP, sameVersion, "hello other group"),
    ],
    signingKeys: [admin.signingKey],
  });
  assert.deepEqual(texts(collided), ["hello group", "hello other group"]);
  assert.deepEqual(Object.keys(collided.errors), ["1"]);
  assert.deepEqual(collided.conversationKeys.keysByConversation, {
    [GROUP]: { [change.version]: change.key },
    [OTHER_GROUP]: { [change.version]: other.key },
  });
  assert.deepEqual(collided.conversationKeys.keys, {});
  assert.equal(collided.unverifiedKeyChanges["1"].reason, "invalidSignature");
  assert.equal(collided.unverifiedKeyChanges["1"].keyDropped, false);

  for (const { chat } of [admin, member, bot, otherKey, outsider]) chat.free();
}
