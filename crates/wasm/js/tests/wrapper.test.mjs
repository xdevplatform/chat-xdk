// Tests for the shipped JS wrapper (index.js): ChatWithJuicebox's Juicebox
// lifecycle plumbing, every crypto delegation, the guess-budget/config
// resolution through createChat and updateConfig, and the errors it throws. The wasm Chat underneath is
// the real SDK; only the Juicebox *network client* is a stub (the SDK is
// never mocked). Each delegated method is exercised with assertions that fail
// if a delegation drops or reorders an argument.
import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, { Chat, bytesToBase64 } from "../pkg/chat_xdk_wasm.js";
import { keepOffline } from "./feature_server.mjs";
import {
  ChatWithJuicebox,
  ChatXdkError,
  createChat,
  encryptedFileSize,
} from "../index.js";

/** File encrypt params from params that carry a one-key `conversationKeys` map. */
const withKey = ({ conversationKeys, ...rest }) => {
  const [[conversationKeyVersion, conversationKey]] = Object.entries(conversationKeys);
  return { ...rest, conversationKey, conversationKeyVersion };
};

// Node 18 exposes WebCrypto only via node:crypto; the wasm module's
// random-byte source needs it on the global scope.
if (typeof globalThis.crypto === "undefined") {
  const { webcrypto } = await import("node:crypto");
  globalThis.crypto = webcrypto;
}

async function loadVectors() {
  const path = new URL("../../../../tests/fixtures/sdk_vectors.json", import.meta.url);
  const raw = await fs.readFile(path, "utf-8");
  return JSON.parse(raw);
}

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

/** The error every binding reports for a Juicebox call on a chat without a config. */
const NO_JUICEBOX_CONFIG =
  "Invalid state: no Juicebox config: pass the juicebox_config the X API returns when " +
  "you create the chat, or call update_config() first";

/** The config a stub client's Juicebox Configuration was built from. */
function configOf(client) {
  return JSON.parse(client.configuration.value);
}

/** A check for `assert.throws`/`rejects`: a ChatXdkError of `kind` matching `message`. */
function chatXdkError(kind, message) {
  return (err) => {
    assert.ok(err instanceof ChatXdkError, String(err));
    assert.equal(err.kind, kind, err.message);
    assert.match(err.message, message);
    return true;
  };
}

// Network-backend stubs (Juicebox realm I/O lives outside the SDK).
class StubJuiceboxConfiguration {
  static instances = [];

  constructor(value) {
    this.value = value;
    StubJuiceboxConfiguration.instances.push(this);
  }
}

class StubJuiceboxClient {
  static instances = [];

  constructor(configuration, previousConfigurations) {
    this.configuration = configuration;
    this.previousConfigurations = previousConfigurations;
    this.stored = null;
    this.registerCalls = 0;
    this.deleted = false;
    StubJuiceboxClient.instances.push(this);
  }

  async register(pinBytes, secretBytes, info, numGuesses) {
    this.registerCalls += 1;
    this.lastPin = new Uint8Array(pinBytes); // copies: the wrapper zeroizes its buffers
    this.stored = new Uint8Array(secretBytes);
    this.lastNumGuesses = numGuesses;
  }

  async recover(pinBytes) {
    this.lastRecoverPin = new Uint8Array(pinBytes);
    if (!this.stored) throw new Error("nothing registered");
    return new Uint8Array(this.stored);
  }

  async delete() {
    this.deleted = true;
    this.stored = null;
  }
}

async function delegationTests() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  keepOffline();
  const v = await loadVectors();

  const stubClient = new StubJuiceboxClient(new StubJuiceboxConfiguration({ realms: [] }), []);
  let armCount = 0;
  const chat = new ChatWithJuicebox(
    new Chat(),
    stubClient,
    7,
    StubJuiceboxConfiguration,
    StubJuiceboxClient,
    () => {
      armCount += 1;
    },
  );

  // Juicebox lifecycle: generate → setup registers the exported secret.
  const payload = chat.generateKeypairs();
  assert.equal(payload.publicKey.publicKeyFingerprint.length, 43);
  const setupKeys = await chat.setup("2580");
  assert.equal(stubClient.registerCalls, 1);
  assert.equal(stubClient.lastNumGuesses, 7);
  assert.equal(stubClient.stored.length, 64);
  assert.equal(new TextDecoder().decode(stubClient.lastPin), "2580");
  assert.equal(setupKeys.identity, chat.getPublicKeys().identity);
  assert.ok(armCount >= 1);

  // Weak PINs are rejected before any Juicebox call.
  await assert.rejects(() => chat.setup("111"), chatXdkError("invalidInput", /at least 4 characters/));
  await assert.rejects(() => chat.setup("1111"), /repeated character/);
  await assert.rejects(() => chat.setup("1234"), /sequential run/);
  await assert.rejects(() => chat.changePin("2580", "0000"), /repeated character/);
  assert.equal(stubClient.registerCalls, 1);

  // importKeys/exportKeys round-trip the loaded keys.
  const exported = chat.exportKeys();
  assert.equal(exported.length, 64);
  chat.lock();
  assert.throws(() => chat.exportKeys(), chatXdkError("invalidState", /not unlocked/));
  chat.importKeys({ keys: exported });
  assert.equal(chat.getPublicKeys().identity, setupKeys.identity);
  exported.fill(0);

  // unlock imports exactly the bytes recover() returns: swap in the fixture
  // secret and check the fixture public keys and signature come out.
  chat.lock();
  assert.equal(chat.isUnlocked(), false);
  stubClient.stored = b64ToBytes(v.private_keys_concat_b64);
  await chat.unlock("2580");
  assert.equal(chat.isUnlocked(), true);
  assert.equal(chat.hasIdentityKey(), true);
  const keys = chat.getPublicKeys();
  assert.equal(keys.identity, v.identity_public_b64);
  assert.equal(keys.signing, v.signing_public_b64);
  assert.equal(chat.getPublicKeyFingerprint().length, 43);

  // sign / verify (fixture-deterministic, tamper rejected)
  const msgBytes = new TextEncoder().encode(v.message_utf8);
  const sig = chat.sign(msgBytes);
  assert.equal(bytesToBase64(sig), v.signature_b64);
  assert.equal(chat.verify(v.signing_public_b64, sig, msgBytes), true);
  assert.equal(
    chat.verify(v.signing_public_b64, sig, new TextEncoder().encode(v.message_utf8 + "!")),
    false,
  );

  // verifyKeyBinding (all three arguments flow through)
  assert.equal(
    chat.verifyKeyBinding(
      v.identity_public_b64,
      v.signing_public_b64,
      v.identity_public_key_signature_b64,
    ),
    true,
  );
  assert.equal(
    chat.verifyKeyBinding(
      v.signing_public_b64,
      v.signing_public_b64,
      v.identity_public_key_signature_b64,
    ),
    false,
  );

  // matchesRegisteredKey flows through the wrapper: the raw SEC1 fixture key
  // matches, another key does not. (The SPKI form and the error paths are
  // covered in api.test.mjs.)
  assert.equal(chat.matchesRegisteredKey(v.identity_public_b64), true);
  assert.equal(chat.matchesRegisteredKey(v.signing_public_b64), false);

  // Event decryption over the fixture vectors.
  chat.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_recipient_key_version });
  assert.throws(
    () => chat.setIdentity({ userId: "user-1", signingKeyVersion: "1" }),
    chatXdkError("invalidInput", /Invalid user_id 'user-1'/),
  );
  assert.throws(
    () => chat.setIdentity({ userId: "1001", signingKeyVersion: "v1" }),
    /Invalid signing_key_version 'v1'/,
  );
  const signingKeys = [
    {
      userId: v.event_sender_id,
      publicKeyVersion: v.event_signing_key_version,
      publicKey: v.signing_public_b64,
      identityPublicKey: v.identity_public_b64,
      identityPublicKeySignature: v.identity_public_key_signature_b64,
    },
  ];
  const batch = chat.decryptEvents({
    events: [v.event_key_change_b64, v.event_message_b64, v.event_garbage_b64],
    signingKeys,
  });
  assert.deepEqual(Object.keys(batch.errors), ["2"]);
  assert.equal(batch.conversationKeys.latestVersion, v.event_conversation_key_version);
  const verifiedMessages = batch.events.filter((m) => m.event.type === "message");
  assert.equal(verifiedMessages.length, 1);
  assert.equal(verifiedMessages[0].event.content.text, v.event_message_text);
  assert.equal(verifiedMessages[0].event.verified, true);

  const conversationKeys = batch.conversationKeys.keys;
  const single = chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys, signingKeys });
  assert.equal(single.content.text, v.event_message_text);
  assert.equal(single.verified, true);
  assert.throws(
    () => chat.decryptEvent({ eventB64: v.event_garbage_b64, conversationKeys: {}, signingKeys }),
    chatXdkError("parse", /./),
  );

  const bundle = chat.extractConversationKeys([v.event_key_change_b64]);
  assert.deepEqual(
    bundle.keys[v.event_conversation_key_version],
    b64ToBytes(v.conversation_key_b64),
  );

  // setRejectUnverified is behavioral: with no signing keys the signed
  // message throws under the default policy and passes unverified once
  // disabled.
  assert.throws(
    () => chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys }),
    chatXdkError("verification", /./),
  );
  chat.setRejectUnverified(false);
  const unverified = chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys });
  assert.equal(unverified.verified, false);
  assert.equal(unverified.content.text, v.event_message_text);
  chat.setRejectUnverified(true);

  // setSigningKeys delegation is behavioral too: with the store armed, the
  // same omitted-signingKeys decrypt now verifies.
  chat.setSigningKeys(signingKeys);
  const viaStore = chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys });
  assert.equal(viaStore.verified, true);
  chat.setSigningKeys([]);

  // setIdentity + setCacheKeys delegations: the session identity and the
  // cached key (populated by the decryptEvents call above re-run with the
  // cache enabled) back an encryptMessage with no explicit identity or key.
  chat.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_signing_key_version });
  chat.setCacheKeys(true);
  chat.decryptEvents({ events: [v.event_key_change_b64], signingKeys });
  // With no conversationKeys, decryptEvent takes the key from the cache.
  const fromCache = chat.decryptEvent({ eventB64: v.event_message_b64, signingKeys });
  assert.equal(fromCache.content.text, v.event_message_text);
  const sessionPayload = chat.encryptMessage({
    conversationId: v.event_conversation_id,
    text: "hello from the session",
  });
  assert.equal(sessionPayload.conversationKeyVersion, v.event_conversation_key_version);
  assert.equal(sessionPayload.signatureInfo.publicKeyVersion, v.event_signing_key_version);
  chat.setCacheKeys(false);

  // Conversation-key change + ECIES decrypt through the wrapper.
  const prep = chat.prepareConversationKeyChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.equal(prep.conversationKey.length, 32);
  assert.deepEqual(
    chat.decryptConversationKey(prep.conversationParticipantKeys[0].encryptedConversationKey),
    prep.conversationKey,
  );

  const groupPrep = chat.prepareGroupCreate({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["910002", "910005"],
    adminIds: ["910002"],
    title: "Wrapper Group",
  });
  assert.equal(groupPrep.actionSignatures.length, 2);
  const create = groupPrep.actionSignatures[1];
  assert.ok(chat.verify(
    create.messageEventSignature.signingPublicKey,
    b64ToBytes(create.messageEventSignature.signature),
    new TextEncoder().encode(
      `GroupChangeEvent.GroupCreate,${create.messageId},910002,${groupPrep.conversationKeyVersion},` +
      `910002,910005,null,${groupPrep.encryptedTitle},null`,
    ),
  ));

  const membersPrep = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["910005"],
    currentMemberIds: ["910002"],
    currentAdminIds: ["910002"],
    currentPendingMemberIds: [],
  });
  assert.equal(membersPrep.actionSignatures.length, 2);
  const add = membersPrep.actionSignatures[1];
  assert.ok(chat.verify(
    add.messageEventSignature.signingPublicKey,
    b64ToBytes(add.messageEventSignature.signature),
    new TextEncoder().encode(
      `GroupChangeEvent.GroupMemberAddChange,${add.messageId},910002,g-1,910005,910002,910002,` +
      `null,null,null,${membersPrep.conversationKeyVersion},null`,
    ),
  ));

  // The conversation key is secret: JSON.stringify leaves it out of every
  // prepared change, while the object, its keys and its copies still carry it.
  const removalPrep = chat.prepareGroupMembersRemove({
    senderId: "910002",
    signingKeyVersion: "1",
    conversationId: "g-1",
    userIds: ["910005"],
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
  });
  for (const prepared of [prep, groupPrep, membersPrep, removalPrep]) {
    assert.equal(prepared.conversationKey.length, 32);
    assert.ok(Object.keys(prepared).includes("conversationKey"));
    assert.equal({ ...prepared }.conversationKey, prepared.conversationKey);
    const json = JSON.parse(JSON.stringify(prepared));
    assert.equal("conversationKey" in json, false);
    assert.deepEqual(
      Object.keys(json),
      Object.keys(prepared).filter((key) => key !== "conversationKey"),
    );
    assert.equal("conversationKey" in JSON.parse(JSON.stringify({ body: prepared })).body, false);
  }

  // Message-encryption delegations (params objects flow through intact).
  const convKey = b64ToBytes(v.conversation_key_b64);
  const sendPayload = chat.encryptMessage({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "hello from the wrapper",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.equal(sendPayload.signatureInfo.signatureVersion, "7");
  assert.ok(sendPayload.messageId.length > 0);
  const replyPayload = chat.encryptReply({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "wrapper reply",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
    replyToSequenceId: "seq-1",
  });
  assert.ok(replyPayload.encodedMessageCreateEvent.length > 0);
  const addReaction = chat.encryptAddReaction({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-1",
    emoji: "\u{1F44D}",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.ok(addReaction.encodedMessageCreateEvent.length > 0);
  const removeReaction = chat.encryptRemoveReaction({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-1",
    emoji: "\u{1F44D}",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.ok(removeReaction.encodedMessageCreateEvent.length > 0);

  // Metadata + file crypto delegations (roundtrips prove every field): the
  // title a title change encrypts decrypts with the same key, and two files
  // encrypted from the message's eventB64 open from the same event.
  const title = chat.prepareGroupTitleChange({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    newTitle: "wrapper text",
    conversationKey: convKey,
    conversationKeyVersion: "1",
  });
  assert.equal(chat.decrypt(title.encryptedValue, convKey), "wrapper text");
  const mediaKeys = { [v.event_conversation_key_version]: convKey };
  const photo = (mediaHashKey) => ({
    attachment_type: "media",
    media_hash_key: mediaHashKey,
    width: 4,
    height: 3,
    filesize_bytes: 64,
    filename: `${mediaHashKey}.jpg`,
    media_type: 1,
  });
  const mediaPayload = chat.encryptMessage({
    conversationId: v.event_conversation_id,
    text: "wrapper photos",
    conversationKey: convKey,
    conversationKeyVersion: v.event_conversation_key_version,
    attachments: [photo("first"), photo("second")],
  });
  const fileCt = chat.encryptFile(withKey({
    file: b64ToBytes(v.plaintext_b64),
    eventB64: mediaPayload.eventB64,
    conversationKeys: mediaKeys,
    mediaHashKey: "first",
  }));
  const enc = chat.fileEncryptor(withKey({
    eventB64: mediaPayload.eventB64,
    conversationKeys: mediaKeys,
    mediaHashKey: "second",
  }));
  const piece = enc.push(b64ToBytes(v.plaintext_b64));
  const finalPiece = enc.finish();
  const streamed = new Uint8Array([...piece, ...finalPiece]);
  assert.deepEqual(
    chat.decryptFile({
      encrypted: fileCt,
      eventB64: mediaPayload.eventB64,
      conversationKeys: mediaKeys,
      mediaHashKey: "first",
    }),
    b64ToBytes(v.plaintext_b64),
  );
  const dec = chat.fileDecryptor({
    eventB64: mediaPayload.eventB64,
    conversationKeys: mediaKeys,
    mediaHashKey: "second",
  });
  const out = new Uint8Array([...dec.push(streamed), ...dec.finish()]);
  assert.deepEqual(out, b64ToBytes(v.plaintext_b64));
  const keyedCt = chat.encryptFileWithKey({ file: b64ToBytes(v.plaintext_b64), key: convKey });
  assert.deepEqual(chat.decryptFileWithKey({ encrypted: keyedCt, key: convKey }), b64ToBytes(v.plaintext_b64));
  assert.throws(() => chat.decryptFileWithKey({ encrypted: keyedCt, key: new Uint8Array(32) }), {
    name: "ChatXdkError",
    kind: "decryption",
  });

  // The edit, delete, read-receipt and group-action delegations: each signed
  // payload carries the values its params named.
  const ident = { senderId: "111", signingKeyVersion: "1" };
  const edit = chat.encryptEdit({
    ...ident,
    conversationId: "conv-1",
    targetMessageSequenceId: "seq-7",
    updatedText: "edited through the wrapper",
    conversationKey: convKey,
    conversationKeyVersion: "1",
  });
  const editSigningKeys = [{ ...signingKeys[0], userId: "111", publicKeyVersion: "1" }];
  const editEvent = chat.decryptEvent({
    eventB64: edit.eventB64,
    conversationKeys: { 1: convKey },
    signingKeys: editSigningKeys,
  });
  assert.equal(editEvent.content.contentType, "edit");
  assert.equal(editEvent.content.updatedText, "edited through the wrapper");
  assert.equal(editEvent.content.targetMessageSequenceId, "seq-7");
  const signs = (action, payload) => chat.verify(
    action.messageEventSignature.signingPublicKey,
    b64ToBytes(action.messageEventSignature.signature),
    new TextEncoder().encode(payload),
  );
  const group = { ...ident, conversationId: "g100" };
  const metadataKey = { conversationKey: convKey, conversationKeyVersion: "4" };
  const actions = [
    ["MessageDeleteEvent", ",111,g100,2,seq-5",
      () => chat.prepareMessageDelete({ ...group, sequenceIds: ["seq-5"], deleteForAll: true })],
    ["MarkConversationReadEvent", ",111,g100,seq-9,1700000000123",
      () => chat.prepareMarkConversationRead({ ...group, seenUntilSequenceId: "seq-9", seenAtMsec: 1700000000123 })],
    ["GroupChangeEvent.GroupTitleChange", (result) => `,111,g100,4,${result.encryptedValue}`,
      () => chat.prepareGroupTitleChange({ ...group, ...metadataKey, newTitle: "Team" })],
    ["GroupChangeEvent.GroupAvatarUrlChange", ",111,g100,4,https://img/a.png",
      () => chat.prepareGroupAvatarChange({ ...group, conversationKeyVersion: "4", newAvatarUrl: "https://img/a.png" })],
    ["GroupChangeEvent.GroupDescriptionChange", (result) => `,111,g100,4,${result.encryptedValue}`,
      () => chat.prepareGroupDescriptionChange({ ...group, ...metadataKey, newDescription: "Ships the app" })],
    ["GroupChangeEvent.GroupAdminAddChange", ",111,g100,910008,910009",
      () => chat.prepareGroupAdminsAdd({ ...group, userIds: ["910008", "910009"] })],
    ["GroupChangeEvent.GroupAdminRemoveChange", ",111,g100,910008",
      () => chat.prepareGroupAdminsRemove({ ...group, userIds: ["910008"] })],
    ["GroupChangeEvent.GroupInviteEnable", ",111,g100,https://x.com/i/invite/abc,null,null",
      () => chat.prepareGroupInviteEnable({ ...group, inviteUrl: "https://x.com/i/invite/abc" })],
    ["GroupChangeEvent.GroupInviteDisable", ",111,g100,910011",
      () => chat.prepareGroupInviteDisable({ ...group, disabledBy: "910011" })],
    ["GroupChangeEvent.GroupJoinRequest", ",111,g100,910012",
      () => chat.prepareGroupJoinRequest({ ...group, requestingUserId: "910012" })],
    ["GroupChangeEvent.GroupJoinReject", ",111,g100,910010",
      () => chat.prepareGroupJoinReject({ ...group, userIds: ["910010"] })],
    ["ConversationMetadataChangeEvent.MessageDurationChange", ",111,g100,86400000",
      () => chat.prepareMessageTtlChange({ ...group, ttlMsec: 86400000 })],
    ["ConversationMetadataChangeEvent.MessageDurationRemove", ",111,g100",
      () => chat.prepareMessageTtlRemove({ ...group })],
    ["ConversationMetadataChangeEvent.EnableScreenCaptureBlocking", ",111,g100",
      () => chat.prepareScreenCapture({ ...group, change: "blockingEnabled" })],
  ];
  for (const [event, fields, prepare] of actions) {
    const result = prepare();
    assert.equal(result.actionSignatures.length, 1, event);
    const [action] = result.actionSignatures;
    const signedFields = typeof fields === "function" ? fields(result) : fields;
    assert.ok(signs(action, `${event},${action.messageId}${signedFields}`), event);
  }
  const removal = chat.prepareGroupMembersRemove({
    ...group,
    userIds: ["910007"],
    publicKeys: [{ userId: "111", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
  });
  assert.equal(removal.actionSignatures.length, 2);
  const [removed] = removal.actionSignatures;
  assert.ok(signs(removed,
    `GroupChangeEvent.GroupMemberRemoveChange,${removed.messageId},111,g100,910007`));
  const left = chat.prepareGroupLeave({ ...group, promoteAdminId: "910008", conversationKeyVersion: "7" });
  assert.equal(left.actionSignatures.length, 3);
  const [, promoted, deleted] = left.actionSignatures;
  assert.ok(signs(promoted, `GroupChangeEvent.GroupAdminAddChange,${promoted.messageId},111,g100,910008`));
  assert.ok(signs(deleted, `ConversationDeleteEvent,${deleted.messageId},111,g100`));

  // changePin re-registers through the stub with the new PIN.
  await chat.changePin("2580", "1359");
  assert.equal(stubClient.registerCalls, 2);
  assert.equal(new TextDecoder().decode(stubClient.lastPin), "1359");

  // updateConfig builds a new client from the injected constructors …
  chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: 3 }));
  const newClient = StubJuiceboxClient.instances.at(-1);
  assert.notEqual(newClient, stubClient);
  assert.deepEqual(configOf(newClient), { realms: [], max_guess_count: 3 });

  // … and delete() drives that new client, then locks the engine.
  await chat.delete();
  assert.equal(newClient.deleted, true);
  assert.equal(chat.isUnlocked(), false);

  // free() clears keys and releases the wasm object.
  chat.free();

  
}

const juiceboxModule = {
  Client: StubJuiceboxClient,
  Configuration: StubJuiceboxConfiguration,
};

function makeChat(juiceboxConfig) {
  return createChat({
    juiceboxConfig: JSON.stringify(juiceboxConfig),
    getAuthToken: async () => "stub-token",
    juiceboxModule,
  });
}

function lastClient() {
  return StubJuiceboxClient.instances.at(-1);
}

async function guessBudgetTests() {
  // Baseline lifecycle: the config's max_guess_count drives registration,
  // and unlock() restores exactly the registered keys.
  const chat = await makeChat({ realms: [], max_guess_count: 6 });
  const client = lastClient();
  assert.deepEqual(configOf(client), { realms: [], max_guess_count: 6 });
  chat.generateKeypairs();
  const keys = chat.getPublicKeys();
  await chat.setup("2580");
  assert.equal(client.registerCalls, 1);
  assert.equal(client.lastNumGuesses, 6);
  chat.lock();
  assert.equal(chat.isUnlocked(), false);
  await chat.unlock("2580");
  assert.equal(chat.isUnlocked(), true);
  assert.deepEqual(chat.getPublicKeys(), keys);

  // Weak PINs are rejected before any Juicebox call.
  await assert.rejects(() => chat.setup("111"), /at least 4 characters/);

  // updateConfig re-creates the client AND re-resolves the guess budget:
  // a setup() after updateConfig registers with the NEW budget.
  chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: 3 }));
  const refreshedClient = lastClient();
  assert.notEqual(refreshedClient, client);
  assert.deepEqual(configOf(refreshedClient), { realms: [], max_guess_count: 3 });
  await chat.setup("2580");
  assert.equal(refreshedClient.lastNumGuesses, 3);

  // An updateConfig without max_guess_count falls back to the shape default.
  chat.updateConfig(JSON.stringify({ realms: [] }));
  await chat.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 5);

  // A max_guess_count that is not a count falls back to the shape default.
  for (const notACount of [7.5, -3, "9", 70000]) {
    chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: notACount }));
    await chat.setup("2580");
    assert.equal(lastClient().lastNumGuesses, 5, String(notACount));
  }
  chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: 0 }));
  await chat.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 0);

  // The sdk_config wrapper shape is unwrapped for the Juicebox client (the
  // embedded SDK config string is what the constructor receives) and
  // defaults the guess budget to 20, like the native parser.
  const sdkConfigStr = '{"realms":[]}';
  const wrapped = await makeChat({ sdk_config: sdkConfigStr, tokens: {} });
  assert.equal(lastClient().configuration.value, sdkConfigStr);
  wrapped.generateKeypairs();
  await wrapped.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 20);

  // updateConfig unwraps the sdk_config shape the same way.
  wrapped.updateConfig(JSON.stringify({ sdk_config: sdkConfigStr, tokens: {}, max_guess_count: 4 }));
  assert.equal(lastClient().configuration.value, sdkConfigStr);
  await wrapped.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 4);

  // The token_map shape is converted to a realms config (register = all,
  // recover = majority), in createChat and updateConfig alike; a malformed
  // entry is rejected with a clear error.
  const tokenMap = {
    token_map: [
      { key: "r1", value: { address: "https://r1.example", token: "t1" } },
      { key: "r2", value: { address: "https://r2.example", token: "t2" } },
    ],
  };
  const tmWrapped = await makeChat(tokenMap);
  tmWrapped.generateKeypairs();
  await tmWrapped.setup("2580");
  assert.deepEqual(configOf(lastClient()), {
    realms: [
      { id: "r1", address: "https://r1.example" },
      { id: "r2", address: "https://r2.example" },
    ],
    register_threshold: 2,
    recover_threshold: 2,
    pin_hashing_mode: "Standard2019",
  });
  assert.equal(lastClient().lastNumGuesses, 5);
  wrapped.updateConfig(JSON.stringify(tokenMap));
  await wrapped.setup("2580");
  assert.equal(configOf(lastClient()).register_threshold, 2);
  assert.throws(
    () => wrapped.updateConfig(JSON.stringify({ token_map: [{ key: "r1" }] })),
    chatXdkError("invalidInput", /^Invalid Juicebox config: Missing value$/),
  );

  // A defined but non-array token_map is rejected at config resolution with
  // the core parser's wording, not handed raw to the Juicebox constructor.
  assert.throws(
    () => wrapped.updateConfig(JSON.stringify({ token_map: { r1: "t1" } })),
    /Missing token_map or sdk_config/,
  );

  // The X API juicebox_config shape is unwrapped to its embedded
  // key_store_token_map_json string verbatim — realm public keys and the
  // server's thresholds must reach the Juicebox client untouched — and
  // defaults the guess budget to 20 like the native parser. The token_map
  // alongside it feeds auth tokens in the native bindings and must NOT
  // trigger the lossy realms derivation here.
  const keyStoreStr =
    '{"realms":[{"id":"r1","address":"https://r1.example/"},' +
    '{"id":"r2","address":"https://r2.example/","public_key":"e8b2"}],' +
    '"register_threshold":2,"recover_threshold":2,"pin_hashing_mode":"Standard2019"}';
  const xApiShape = {
    key_store_token_map_json: keyStoreStr,
    token_map: [
      { key: "r1", value: { address: "https://r1.example/", token: "t1" } },
      { key: "r2", value: { address: "https://r2.example/", token: "t2" } },
    ],
  };
  const xApiWrapped = await makeChat(xApiShape);
  assert.equal(lastClient().configuration.value, keyStoreStr);
  xApiWrapped.generateKeypairs();
  await xApiWrapped.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 20);

  // updateConfig unwraps the X API shape the same way, and an explicit
  // max_guess_count still wins over the shape default.
  xApiWrapped.updateConfig(JSON.stringify({ ...xApiShape, max_guess_count: 4 }));
  assert.equal(lastClient().configuration.value, keyStoreStr);
  await xApiWrapped.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 4);

  // A malformed embedded config is an error, never a silent fall-through to
  // the lossy token_map derivation.
  assert.throws(
    () =>
      xApiWrapped.updateConfig(
        JSON.stringify({ ...xApiShape, key_store_token_map_json: "not json" }),
      ),
    /Invalid key_store_token_map_json/,
  );
  assert.throws(
    () =>
      xApiWrapped.updateConfig(
        JSON.stringify({ ...xApiShape, key_store_token_map_json: 42 }),
      ),
    /key_store_token_map_json must be a string/,
  );

  // Syntactically valid JSON that is not an object ("42", "[]", "null") is
  // rejected too, rather than handed to the Juicebox constructor to fail
  // obscurely at setup/unlock time. Matches the core parser.
  for (const notAnObject of ["42", "[]", "null"]) {
    assert.throws(
      () =>
        xApiWrapped.updateConfig(
          JSON.stringify({ ...xApiShape, key_store_token_map_json: notAnObject }),
        ),
      /Invalid key_store_token_map_json: not a JSON object/,
    );
  }

  // An empty token_map array derives an empty realms config, matching the
  // core parser (which accepts it and derives the same thresholds).
  wrapped.updateConfig(JSON.stringify({ token_map: [] }));
  assert.deepEqual(configOf(lastClient()), {
    realms: [],
    register_threshold: 0,
    recover_threshold: 1,
    pin_hashing_mode: "Standard2019",
  });
}

// First boot: the account's juicebox_config is created by the public-key
// POST, so createChat must work without one — crypto (including
// generateKeypairs) available immediately, Juicebox lifecycle gated until
// updateConfig supplies the real config.
async function firstBootTests() {
  const clientsBefore = StubJuiceboxClient.instances.length;
  const configsBefore = StubJuiceboxConfiguration.instances.length;
  const chat = await createChat({
    getAuthToken: async () => "stub-token",
    juiceboxModule,
  });
  // No config ⇒ no Juicebox Configuration/Client is constructed.
  assert.equal(StubJuiceboxClient.instances.length, clientsBefore);
  assert.equal(StubJuiceboxConfiguration.instances.length, configsBefore);

  // Crypto works before any config: generateKeypairs yields a full
  // registration payload the caller can POST.
  const payload = chat.generateKeypairs();
  assert.ok(payload.publicKey.publicKey.length > 0);
  assert.ok(payload.publicKey.signingPublicKey.length > 0);
  assert.equal(chat.isUnlocked(), true);

  // Juicebox lifecycle before any config fails with the deliberate error —
  // not a constructor crash — and never reaches a client.
  for (const op of [
    () => chat.setup("2580"),
    () => chat.unlock("2580"),
    () => chat.changePin("2580", "1359"),
    () => chat.delete(),
  ]) {
    await assert.rejects(op, (err) => {
      chatXdkError("invalidState", /./)(err);
      assert.equal(err.message, NO_JUICEBOX_CONFIG);
      return true;
    });
  }
  assert.equal(StubJuiceboxClient.instances.length, clientsBefore);

  // An empty or blank config is no config: createChat and updateConfig fail
  // with the same error and build no client.
  const noConfig = (err) => {
    chatXdkError("invalidState", /./)(err);
    assert.equal(err.message, NO_JUICEBOX_CONFIG);
    return true;
  };
  for (const empty of ["", "  "]) {
    await assert.rejects(
      createChat({ juiceboxConfig: empty, getAuthToken: async () => "stub-token", juiceboxModule }),
      noConfig,
    );
    assert.throws(() => chat.updateConfig(empty), noConfig);
  }
  assert.equal(StubJuiceboxClient.instances.length, clientsBefore);

  // updateConfig with the real (post-POST) config enables setup: exactly one
  // register call, on the client built from that config.
  chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: 6 }));
  assert.equal(StubJuiceboxClient.instances.length, clientsBefore + 1);
  const client = lastClient();
  assert.equal(client.registerCalls, 0);
  const keys = await chat.setup("2580");
  assert.equal(client.registerCalls, 1);
  assert.equal(client.lastNumGuesses, 6);
  assert.equal(keys.identity, chat.getPublicKeys().identity);

  // The stored identity round-trips through unlock on the same instance.
  chat.lock();
  await chat.unlock("2580");
  assert.equal(chat.isUnlocked(), true);
  assert.equal(chat.getPublicKeys().identity, keys.identity);

  assert.throws(
    () => chat.updateConfig({ realms: [] }),
    chatXdkError("invalidInput", /juiceboxConfig must be the Juicebox config JSON string/),
  );

  // A config needs getAuthToken; without either, the chat keeps its keys
  // with importKeys/exportKeys and loads no juicebox-sdk.
  await assert.rejects(
    () => createChat({ juiceboxConfig: JSON.stringify({ realms: [] }), juiceboxModule }),
    chatXdkError("invalidInput", /getAuthToken must be an async function/),
  );
  await assert.rejects(
    () => createChat({ getAuthToken: "token" }),
    chatXdkError("invalidInput", /getAuthToken must be an async function/),
  );
  const keyless = await createChat();
  keyless.importKeys({ keys: chat.exportKeys() });
  assert.equal(keyless.getPublicKeys().identity, keys.identity);
  for (const op of [
    () => keyless.updateConfig(JSON.stringify({ realms: [] })),
    () => keyless.setup("2580"),
    () => keyless.unlock("2580"),
  ]) {
    await assert.rejects(async () => op(), chatXdkError("invalidState", /No Juicebox for this chat/));
  }
  keyless.free();
}

// A Juicebox failure throws the ChatXdkError the native bindings report for
// it: juicebox-sdk rejects register and delete with a reason value, and
// recover with an object carrying one and, for a wrong PIN, the attempts left.
async function juiceboxErrorTests() {
  const failures = {};
  class FailingClient extends StubJuiceboxClient {
    async register() {
      throw failures.register;
    }
    async recover() {
      throw failures.recover;
    }
    async delete() {
      throw failures.delete;
    }
  }
  const chat = await createChat({
    juiceboxConfig: JSON.stringify({ realms: [] }),
    getAuthToken: async () => "stub-token",
    juiceboxModule: { Client: FailingClient, Configuration: StubJuiceboxConfiguration },
  });
  chat.generateKeypairs();

  failures.recover = { reason: 0, guesses_remaining: 3 };
  await assert.rejects(
    () => chat.unlock("2580"),
    (err) => {
      chatXdkError("invalidPin", /^Juicebox error: Invalid PIN: guesses_remaining=3$/)(err);
      assert.equal(err.guessesRemaining, 3);
      return true;
    },
  );
  failures.recover = { reason: 0, guesses_remaining: 0 };
  await assert.rejects(() => chat.changePin("2580", "1359"), (err) => err.guessesRemaining === 0);
  failures.recover = { reason: 1 };
  await assert.rejects(
    () => chat.unlock("2580"),
    (err) => {
      chatXdkError("juicebox", /^Juicebox error: Keys not registered$/)(err);
      assert.equal(err.guessesRemaining, null);
      return true;
    },
  );

  failures.register = 0;
  await assert.rejects(() => chat.setup("2580"), chatXdkError("juicebox", /^Juicebox error: Invalid auth token$/));
  failures.register = new Error("socket hang up");
  await assert.rejects(() => chat.setup("2580"), chatXdkError("juicebox", /^Juicebox error: socket hang up$/));

  failures.delete = 4;
  await assert.rejects(() => chat.delete(), chatXdkError("juicebox", /^Juicebox error: Delete failed: Transient$/));
  assert.equal(chat.isUnlocked(), true, "a failed delete keeps the keys loaded");
}

// The juicebox-sdk WASM must be loaded once per process: its glue keeps
// typed-array views of a single instance's memory, and a second instantiation
// leaves those views stale, crashing the next `new Configuration`. This suite
// needs the real juicebox-sdk package (the stubs bypass the loader), so it
// runs only when the optional peer dependency is installed.
async function realJuiceboxSingletonTests() {
  try {
    await import("juicebox-sdk/juicebox-sdk_bg.js");
  } catch {
    console.log("wrapper.test.mjs: juicebox-sdk not installed; skipping singleton tests");
    return;
  }

  const juiceboxConfig = JSON.stringify({
    realms: [{ id: "0f".repeat(16), address: "https://realm.invalid/" }],
    register_threshold: 1,
    recover_threshold: 1,
    pin_hashing_mode: "Standard2019",
  });
  const opts = { juiceboxConfig, getAuthToken: async () => "stub-token" };

  // First use of the loader: concurrent createChat calls must share the same
  // in-flight load rather than instantiate the WASM twice.
  const [a, b] = await Promise.all([createChat(opts), createChat(opts)]);
  a.free();
  b.free();

  // Later calls reuse the settled module; a fresh instantiation here would
  // leave the glue's memory views stale and crash the Configuration
  // constructor.
  const later = await createChat(opts);
  later.free();
}

async function main() {
  await delegationTests();
  assert.equal(encryptedFileSize(5000), 5109);
  await guessBudgetTests();
  await firstBootTests();
  await juiceboxErrorTests();
  await realJuiceboxSingletonTests();
  console.log("wrapper.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
