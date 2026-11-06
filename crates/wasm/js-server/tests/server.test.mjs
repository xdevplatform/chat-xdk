// Tests for the server package (index.js over the chat.js `make wasm`
// stages): ServerChat's importKeys/exportKeys on the real wasm Chat, the API
// it shares with @xdevplatform/chat-xdk, and the staged copies it ships. The
// SDK is never mocked; only the Juicebox network client is a stub.
import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, { __featureSetDefaultEndpoint } from "../pkg/chat_xdk_wasm.js";
import * as browser from "../../js/index.js";
import * as server from "../index.js";

const { ChatWithJuicebox, ChatXdkError, ServerChat, bytesToBase64, createChat } = server;

// Node 18 exposes WebCrypto only via node:crypto; the wasm module's
// random-byte source needs it on the global scope.
if (typeof globalThis.crypto === "undefined") {
  const { webcrypto } = await import("node:crypto");
  globalThis.crypto = webcrypto;
}

// Nothing listens here: every chat's feature-switch read fails and it stays
// on v0, with no request leaving the machine.
const OFFLINE = "http://127.0.0.1:9/2/chat/features";

async function loadVectors() {
  const path = new URL("../../../../tests/fixtures/sdk_vectors.json", import.meta.url);
  return JSON.parse(await fs.readFile(path, "utf-8"));
}

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, "base64"));
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

/** The signing-key version a message delete from `chat` is signed under. */
function deleteSignedUnder(chat) {
  const prepared = chat.prepareMessageDelete({
    senderId: "1234",
    conversationId: "1234-5678",
    sequenceIds: ["seq-1"],
    deleteForAll: false,
  });
  return prepared.actionSignatures[0].messageEventSignature.publicKeyVersion;
}

// The package ships copies of crates/wasm/js files; a stale copy would test,
// and publish, code other than the source.
async function stagedCopiesTests() {
  const read = (path) => fs.readFile(new URL(path, import.meta.url));
  for (const [copy, source] of [
    ["../chat.js", "../../js/chat.js"],
    ["../chat.d.ts", "../../js/index.d.ts"],
    ["../pkg/chat_xdk_wasm.js", "../../js/pkg/chat_xdk_wasm.js"],
    ["../pkg/chat_xdk_wasm_bg.wasm", "../../js/pkg/chat_xdk_wasm_bg.wasm"],
  ]) {
    assert.ok((await read(copy)).equals(await read(source)), `${copy} is stale: run \`make js-server\``);
  }
}

// Everything @xdevplatform/chat-xdk exports, and ServerChat; only the server
// package's chat moves its keys in and out.
async function exportsTests() {
  assert.deepEqual(Object.keys(server).sort(), [...Object.keys(browser), "ServerChat"].sort());
  assert.notEqual(server.createChat, browser.createChat);
  assert.equal(Object.getPrototypeOf(ServerChat), ChatWithJuicebox);
  for (const name of ["importKeys", "exportKeys"]) {
    assert.equal(typeof ServerChat.prototype[name], "function", name);
    assert.equal(name in browser.ChatWithJuicebox.prototype, false, name);
  }
}

// Keys exported from one chat import into another: the same identity, which
// signs, verifies, and opens what is encrypted to it.
async function exportImportRoundTripTests() {
  const source = await createChat();
  assert.ok(source instanceof ServerChat);
  assert.ok(source instanceof ChatWithJuicebox);
  source.generateKeypairs();
  const publicKeys = source.getPublicKeys();
  const exported = source.exportKeys();
  assert.ok(exported instanceof Uint8Array);
  assert.equal(exported.length, 64);

  const restored = await createChat();
  assert.equal(restored.hasIdentityKey(), false);
  restored.importKeys({ keys: new Uint8Array(exported), signingKeyVersion: "1700000000456" });
  assert.equal(restored.isUnlocked(), true);
  assert.deepEqual(restored.getPublicKeys(), publicKeys);
  assert.equal(restored.getPublicKeyFingerprint(), source.getPublicKeyFingerprint());
  assert.deepEqual(restored.exportKeys(), exported);

  const data = new TextEncoder().encode("signed by the restored chat");
  assert.equal(source.verify(publicKeys.signing, restored.sign(data), data), true);
  const keyChange = source.prepareConversationKeyChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: publicKeys.identity, publicKeyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.deepEqual(
    restored.decryptConversationKey(keyChange.conversationParticipantKeys[0].encryptedConversationKey),
    keyChange.conversationKey,
  );

  // The signing-key version passed with the keys signs the chat's actions,
  // and keys imported without one leave it unset.
  assert.equal(deleteSignedUnder(restored), "1700000000456");
  restored.importKeys({ keys: new Uint8Array(exported) });
  assert.throws(() => deleteSignedUnder(restored), /signing_key_version is not set/);

  exported.fill(0);
  source.free();
  restored.free();
}

// The fixture keys import byte for byte and sign the fixture signature; the
// errors are those of every binding.
async function fixtureKeysTests(v) {
  const chat = await createChat();
  assert.throws(() => chat.exportKeys(), chatXdkError("invalidState", /not unlocked/));
  assert.throws(() => chat.importKeys({ keys: new Uint8Array(5) }), chatXdkError("invalidInput", /./));
  chat.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
  assert.equal(chat.getPublicKeys().identity, v.identity_public_b64);
  assert.equal(chat.getPublicKeys().signing, v.signing_public_b64);
  assert.deepEqual(chat.exportKeys(), b64ToBytes(v.private_keys_concat_b64));
  assert.equal(bytesToBase64(chat.sign(new TextEncoder().encode(v.message_utf8))), v.signature_b64);
  chat.lock();
  assert.throws(() => chat.exportKeys(), chatXdkError("invalidState", /not unlocked/));
  chat.free();
  assert.throws(() => chat.exportKeys());
}

// A server unlocks the keys a device stored in Juicebox once, exports them
// for its secret store, and loads them into each later chat with no
// Juicebox call.
async function juiceboxThenImportTests() {
  class StubConfiguration {
    constructor(value) {
      this.value = value;
    }
  }
  class StubClient {
    stored = null;
    async register(pinBytes, secretBytes) {
      this.stored = new Uint8Array(secretBytes);
    }
    async recover() {
      return new Uint8Array(this.stored);
    }
    async delete() {
      this.stored = null;
    }
  }
  const chat = await createChat({
    juiceboxConfig: JSON.stringify({ realms: [] }),
    getAuthToken: async () => "stub-token",
    juiceboxModule: { Client: StubClient, Configuration: StubConfiguration },
  });
  chat.generateKeypairs();
  const publicKeys = await chat.setup("2580");
  chat.lock();
  await chat.unlock("2580");
  const keys = chat.exportKeys();
  chat.free();

  const worker = await createChat();
  worker.importKeys({ keys, signingKeyVersion: "1" });
  assert.deepEqual(worker.getPublicKeys(), publicKeys);
  await assert.rejects(async () => worker.unlock("2580"), chatXdkError("invalidState", /No Juicebox for this chat/));
  await assert.rejects(
    () => createChat({ getAuthToken: "token" }),
    chatXdkError("invalidInput", /getAuthToken must be an async function/),
  );
  keys.fill(0);
  worker.free();
}

async function main() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  __featureSetDefaultEndpoint(OFFLINE);
  const v = await loadVectors();

  await stagedCopiesTests();
  await exportsTests();
  await exportImportRoundTripTests();
  await fixtureKeysTests(v);
  await juiceboxThenImportTests();
  console.log("server.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
