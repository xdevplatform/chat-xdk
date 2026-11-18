// decryptEvents and the members who sign a batch's key changes: a key change
// needs its signer's keys to verify, the result says which key changes did
// not verify and why, and the version to encrypt with is reported per
// conversation. Each package's suite runs this against its own chat.
import assert from "node:assert/strict";

import { delivered, deliveredAction } from "./frame.mjs";

// A sequence id past the cut-over, where a key change that does not verify
// has its key dropped.
const ENFORCED_SEQUENCE = "2100000000000000000";
const GROUP = "g900";
const OTHER_GROUP = "g901";
const KEY_VERSION = "1";

/** A chat with fresh keys as user `userId`, and the keys others hold for it. */
async function party(newChat, userId) {
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

/** The key change `signer` makes in `conversationId` for `members`, as delivered, with its key. */
function keyChange(signer, members, conversationId) {
  const prepared = signer.chat.prepareConversationKeyChange({
    senderId: signer.userId,
    signingKeyVersion: KEY_VERSION,
    publicKeys: members.map((member) => member.publicKey),
    conversationId,
  });
  return {
    eventB64: deliveredAction(prepared.actionSignatures[0], signer.userId, conversationId, ENFORCED_SEQUENCE),
    key: prepared.conversationKey,
    version: prepared.conversationKeyVersion,
  };
}

/** The message `author` sends in `conversationId` under the key of `change`, as delivered. */
function message(author, conversationId, change, text) {
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

  // With the keys of the member who wrote the message but not of the admin
  // who made the key change, the key is dropped and the result says why.
  const missing = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey] });
  assert.deepEqual(missing.events, []);
  assert.deepEqual(missing.conversationKeys.keys, {});
  assert.equal(missing.conversationKeys.latestVersion, null);
  assert.deepEqual(missing.conversationKeys.latestVersions, {});
  assert.deepEqual(missing.unverifiedKeyChanges, [
    {
      index: 0,
      reason: "missingSigningKey",
      keyDropped: true,
      conversationId: GROUP,
      conversationKeyVersion: change.version,
      senderId: admin.userId,
      publicKeyVersion: KEY_VERSION,
    },
  ]);
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
  assert.equal(invalid.unverifiedKeyChanges.length, 1);
  assert.equal(invalid.unverifiedKeyChanges[0].reason, "invalidSignature");
  assert.equal(invalid.unverifiedKeyChanges[0].keyDropped, true);
  assert.match(invalid.errors["0"], /ECDSA mismatch/);

  // With the admin's keys the key change verifies and the message decrypts.
  const verified = bot.chat.decryptEvents({ events, signingKeys: [member.signingKey, admin.signingKey] });
  assert.deepEqual(verified.errors, {});
  assert.deepEqual(verified.unverifiedKeyChanges, []);
  assert.deepEqual(
    verified.events.map(({ event }) => event.type),
    ["keyChange", "message"],
  );
  assert.equal(verified.events[1].event.content.text, "hello group");
  assert.equal(verified.conversationKeys.latestVersion, change.version);
  assert.deepEqual(verified.conversationKeys.latestVersions, { [GROUP]: change.version });

  // Key changes of two conversations in one batch: each conversation has its
  // own version to encrypt with, and no single one stands for both.
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
  const one = bot.chat.decryptEvents({ events: [other.eventB64], signingKeys: [admin.signingKey] });
  assert.equal(one.conversationKeys.latestVersion, other.version);
  assert.deepEqual(one.conversationKeys.latestVersions, { [OTHER_GROUP]: other.version });

  // extractConversationKeys checks no signature: its latestVersion is the
  // batch's highest, and latestVersions each conversation's.
  const extracted = bot.chat.extractConversationKeys([change.eventB64, other.eventB64]);
  assert.deepEqual(extracted.latestVersions, versions);
  assert.equal(
    extracted.latestVersion,
    String(Math.max(Number(change.version), Number(other.version))),
  );

  for (const { chat } of [admin, member, bot, otherKey]) chat.free();
}
