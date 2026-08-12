// Tests for the shipped JS wrapper (index.js): ChatWithJuicebox's Juicebox
// lifecycle plumbing, every crypto delegation, and the guess-budget/config
// resolution through createChat and updateConfig. The wasm Chat underneath is
// the real SDK; only the Juicebox *network client* is a stub (the SDK is
// never mocked). Each delegated method is exercised with assertions that fail
// if a delegation drops or reorders an argument.
import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, { Chat, bytesToBase64 } from "../pkg/chat_xdk_wasm.js";
import { ChatWithJuicebox, createChat, guessesRemaining } from "../index.js";

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
  await assert.rejects(() => chat.setup("111"), /at least 4 characters/);
  await assert.rejects(() => chat.setup("1111"), /repeated character/);
  await assert.rejects(() => chat.setup("1234"), /sequential run/);

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
  chat.setIdentity(v.event_sender_id, v.event_recipient_key_version);
  const signingKeys = [
    {
      userId: v.event_sender_id,
      publicKeyVersion: v.event_signing_key_version,
      publicKey: v.signing_public_b64,
      identityPublicKey: v.identity_public_b64,
      identityPublicKeySignature: v.identity_public_key_signature_b64,
    },
  ];
  const batch = chat.decryptEvents(
    [v.event_key_change_b64, v.event_message_b64, v.event_garbage_b64],
    signingKeys,
  );
  assert.deepEqual(Object.keys(batch.errors), ["2"]);
  assert.equal(batch.conversationKeys.latestVersion, v.event_conversation_key_version);
  const verifiedMessages = batch.messages.filter((m) => m.event.type === "message");
  assert.equal(verifiedMessages.length, 1);
  assert.equal(verifiedMessages[0].event.content.text, v.event_message_text);
  assert.equal(verifiedMessages[0].event.verified, true);

  const single = chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys, signingKeys);
  assert.equal(single.content.text, v.event_message_text);
  assert.equal(single.verified, true);
  assert.throws(() => chat.decryptEvent(v.event_garbage_b64, {}, signingKeys));

  const bundle = chat.extractConversationKeys([v.event_key_change_b64]);
  assert.deepEqual(
    bundle.keys[v.event_conversation_key_version],
    b64ToBytes(v.conversation_key_b64),
  );

  // setRejectUnverified is behavioral: with no signing keys the signed
  // message throws under the default policy and passes unverified once
  // disabled (also covers the wrapper's `signingKeys ?? []` defaults).
  assert.throws(() => chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys));
  chat.setRejectUnverified(false);
  const unverified = chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys);
  assert.equal(unverified.verified, false);
  assert.equal(unverified.content.text, v.event_message_text);
  chat.setRejectUnverified(true);

  // setSigningKeys delegation is behavioral too: with the store armed, the
  // same omitted-signingKeys decrypt now verifies.
  chat.setSigningKeys(signingKeys);
  const viaStore = chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys);
  assert.equal(viaStore.verified, true);
  chat.setSigningKeys([]);

  // setIdentity + setCacheKeys delegations: the session identity and the
  // cached key (populated by the decryptEvents call above re-run with the
  // cache enabled) back an encryptMessage with no explicit identity or key.
  chat.setIdentity(v.event_sender_id, v.event_signing_key_version);
  chat.setCacheKeys(true);
  chat.decryptEvents([v.event_key_change_b64], signingKeys);
  const sessionPayload = chat.encryptMessage({
    conversationId: v.event_conversation_id,
    text: "hello from the session",
  });
  assert.equal(sessionPayload.conversationKeyVersion, v.event_conversation_key_version);
  assert.equal(sessionPayload.signatureInfo.publicKeyVersion, v.event_signing_key_version);
  chat.setCacheKeys(false);

  // Conversation-key change + ECIES decrypt through the wrapper.
  const prep = chat.prepareConversationKeyChange({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.equal(prep.conversationKey.length, 32);
  assert.deepEqual(
    chat.decryptConversationKey(prep.participantKeys[0].encryptedKey),
    prep.conversationKey,
  );

  const groupPrep = chat.prepareGroupCreate({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["me", "friend"],
    adminIds: ["me"],
    title: "Wrapper Group",
  });
  assert.equal(groupPrep.actionSignatures.length, 2);
  assert.ok(groupPrep.actionSignatures[1].signaturePayload.startsWith("GroupChangeEvent.GroupCreate,"));

  const membersPrep = chat.prepareGroupMembersChange({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["friend"],
    currentMemberIds: ["me"],
    currentAdminIds: ["me"],
    currentPendingMemberIds: [],
  });
  assert.equal(membersPrep.actionSignatures.length, 2);
  assert.ok(
    membersPrep.actionSignatures[1].signaturePayload.startsWith(
      "GroupChangeEvent.GroupMemberAddChange,",
    ),
  );

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
  assert.ok(replyPayload.encryptedContent.length > 0);
  const addReaction = chat.encryptAddReaction({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-1",
    emoji: "\u{1F44D}",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.ok(addReaction.encryptedContent.length > 0);
  const removeReaction = chat.encryptRemoveReaction({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-1",
    emoji: "\u{1F44D}",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.ok(removeReaction.encryptedContent.length > 0);

  // Generic + stream crypto delegations (roundtrips prove both arguments).
  const ct = chat.encrypt("wrapper text", convKey);
  assert.equal(chat.decrypt(ct, convKey), "wrapper text");
  const streamCt = chat.encryptStream(b64ToBytes(v.plaintext_b64), convKey);
  assert.deepEqual(chat.decryptStream(streamCt, convKey), b64ToBytes(v.plaintext_b64));
  const enc = chat.streamEncryptor(convKey);
  const piece = enc.push(b64ToBytes(v.plaintext_b64));
  const finalPiece = enc.finish();
  const streamed = new Uint8Array([...piece, ...finalPiece]);
  const dec = chat.streamDecryptor(convKey);
  const out = new Uint8Array([...dec.push(streamed), ...dec.finish()]);
  assert.deepEqual(out, b64ToBytes(v.plaintext_b64));

  // changePin re-registers through the stub with the new PIN.
  await chat.changePin("2580", "1359");
  assert.equal(stubClient.registerCalls, 2);
  assert.equal(new TextDecoder().decode(stubClient.lastPin), "1359");

  // updateConfig builds a new client from the injected constructors …
  chat.updateConfig(JSON.stringify({ realms: [], max_guess_count: 3 }));
  const newClient = StubJuiceboxClient.instances.at(-1);
  assert.notEqual(newClient, stubClient);
  assert.deepEqual(newClient.configuration.value, { realms: [], max_guess_count: 3 });

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

function makeChat(juiceboxConfig, extraOptions = {}) {
  return createChat({
    juiceboxConfig: JSON.stringify(juiceboxConfig),
    getAuthToken: async () => "stub-token",
    juiceboxModule,
    ...extraOptions,
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
  assert.deepEqual(client.configuration.value, { realms: [], max_guess_count: 6 });
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
  assert.deepEqual(refreshedClient.configuration.value, { realms: [], max_guess_count: 3 });
  await chat.setup("2580");
  assert.equal(refreshedClient.lastNumGuesses, 3);

  // An updateConfig without max_guess_count falls back to the shape default.
  chat.updateConfig(JSON.stringify({ realms: [] }));
  await chat.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 5);

  // An explicit createChat maxGuessCount overrides the config and is NOT
  // displaced by updateConfig.
  const pinned = await makeChat({ realms: [], max_guess_count: 6 }, { maxGuessCount: 9 });
  pinned.generateKeypairs();
  await pinned.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 9);
  pinned.updateConfig(JSON.stringify({ realms: [], max_guess_count: 3 }));
  await pinned.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 9);

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
  assert.deepEqual(lastClient().configuration.value, {
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
  assert.equal(lastClient().configuration.value.register_threshold, 2);
  assert.throws(
    () => wrapped.updateConfig(JSON.stringify({ token_map: [{ key: "r1" }] })),
    /Invalid token_map entry/,
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
  assert.deepEqual(lastClient().configuration.value, {
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
    await assert.rejects(op, /No Juicebox config/);
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

  // An explicit createChat maxGuessCount override survives a config-less
  // construction and still beats the config supplied later by updateConfig.
  const pinned = await createChat({
    getAuthToken: async () => "stub-token",
    juiceboxModule,
    maxGuessCount: 9,
  });
  pinned.updateConfig(JSON.stringify({ realms: [], max_guess_count: 3 }));
  pinned.generateKeypairs();
  await pinned.setup("2580");
  assert.equal(lastClient().lastNumGuesses, 9);

  // A present-but-empty config is a caller bug, not first boot: it fails at
  // createChat rather than deferring to a missing-config error at setup.
  await assert.rejects(
    () =>
      createChat({
        juiceboxConfig: "",
        getAuthToken: async () => "stub-token",
        juiceboxModule,
      }),
    SyntaxError,
  );

  // getAuthToken stays mandatory even when the config is omitted.
  await assert.rejects(
    () => createChat({ juiceboxModule }),
    /getAuthToken must be an async function/,
  );
}

// guessesRemaining reads the attempt count out of the wrapper's own
// invalid-PIN unlock error; 0 means the guess budget is exhausted.
async function guessesRemainingTests() {
  class InvalidPinClient extends StubJuiceboxClient {
    async recover() {
      // The wire shape juicebox-sdk rejects a wrong PIN with:
      // reason 0 = InvalidPin, plus the remaining attempt budget.
      throw { reason: 0, guesses_remaining: 3 };
    }
  }
  const chat = await createChat({
    juiceboxConfig: JSON.stringify({ realms: [] }),
    getAuthToken: async () => "stub-token",
    juiceboxModule: { Client: InvalidPinClient, Configuration: StubJuiceboxConfiguration },
  });
  let unlockErr;
  try {
    await chat.unlock("2580");
  } catch (err) {
    unlockErr = err;
  }
  assert.equal(guessesRemaining(unlockErr), 3);

  // No count on non-PIN failures, unrelated messages that happen to carry
  // the token, or non-errors.
  assert.equal(guessesRemaining(new Error("Juicebox recovery failed: reason=Transient")), null);
  assert.equal(guessesRemaining(new Error("delete failed: guesses_remaining=7")), null);
  assert.equal(guessesRemaining(undefined), null);
}

async function main() {
  await delegationTests();
  await guessBudgetTests();
  await firstBootTests();
  await guessesRemainingTests();
  console.log("wrapper.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
