// Tests for the feature switches (GET /2/chat/features) through the shipped
// JS wrapper: loadFeatureConfig against a local server, the key-bucket
// refetch, the downgrade-only re-check, and the v0/v1 send switch. The wasm
// Chat underneath is the real SDK.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";

import init, { Chat } from "../pkg/chat_xdk_wasm.js";
import { ChatWithJuicebox, FEATURES_ENDPOINT } from "../index.js";

if (typeof globalThis.crypto === "undefined") {
  const { webcrypto } = await import("node:crypto");
  globalThis.crypto = webcrypto;
}

async function loadVectors() {
  const path = new URL("../../../../tests/fixtures/sdk_vectors.json", import.meta.url);
  return JSON.parse(await fs.readFile(path, "utf-8"));
}

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

/** A local GET /2/chat/features that records each request's bucket. */
async function featureServer() {
  const state = { status: 200, body: '{"features":{"v1_send":true}}', delayMs: 0, buckets: [] };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    state.buckets.push(url.searchParams.get("bucket"));
    const reply = () => {
      res.writeHead(state.status, { "Content-Type": "application/json" });
      res.end(state.body);
    };
    if (state.delayMs > 0) {
      const timer = setTimeout(reply, state.delayMs);
      req.on("close", () => clearTimeout(timer));
    } else {
      reply();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  state.endpoint = `http://127.0.0.1:${server.address().port}/2/chat/features`;
  state.close = () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(resolve);
    });
  return state;
}

function newChat() {
  return new ChatWithJuicebox(new Chat(), null, undefined, null, null, null);
}

function loadKeys(chat) {
  chat.generateKeypairs();
  chat.setIdentity("111", "1");
}

function send(chat, v) {
  return chat.encryptMessage({
    conversationId: "conv-1",
    conversationKey: b64ToBytes(v.conversation_key_b64),
    conversationKeyVersion: "1",
    text: "hello",
  });
}

async function waitFor(what, predicate) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.ok(predicate(), `timed out waiting for ${what}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function everyFlagIsOffBeforeAnyLoad(v) {
  const chat = newChat();
  loadKeys(chat);
  assert.equal(chat.isEnabled("v1_send"), false);
  const payload = send(chat, v);
  assert.equal(payload.signatureInfo.signatureVersion, "7");
  assert.equal(typeof payload.xdkVersion, "string");
  assert.ok(payload.xdkVersion.length > 0);
  chat.free();
}

async function loadAfterKeysSendsTheKeyBucket(v) {
  const server = await featureServer();
  const chat = newChat();
  loadKeys(chat);
  const bucket = chat.featureBucket();
  assert.ok(Number.isInteger(bucket) && bucket >= 0 && bucket < 10000);
  assert.equal(
    await chat.loadFeatureConfig({ endpoint: server.endpoint, timeoutMs: 1000, refreshSeconds: 0 }),
    true,
  );
  assert.deepEqual(server.buckets, [String(bucket)]);
  assert.equal(chat.isEnabled("v1_send"), true);
  assert.equal(send(chat, v).signatureInfo.signatureVersion, "10");
  chat.free();
  await server.close();
}

async function unknownKeysAreReadableAndMissingKeysAreOff() {
  const server = await featureServer();
  server.body = '{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}';
  const chat = newChat();
  loadKeys(chat);
  assert.equal(await chat.loadFeatureConfig({ endpoint: server.endpoint, refreshSeconds: 0 }), true);
  assert.equal(chat.isEnabled("later_flag"), true);
  assert.equal(chat.isEnabled("v1_send"), false);
  assert.equal(chat.isEnabled("missing"), false);
  chat.free();
  await server.close();
}

async function anyFailureLeavesEveryFlagOff(v) {
  const cases = [
    [404, '{"features":{"v1_send":true}}', 0],
    [500, '{"features":{"v1_send":true}}', 0],
    [200, "not json", 0],
    [200, '{"v1_send":true}', 0],
    [200, '{"features":{"v1_send":true}}', 1500],
  ];
  for (const [status, body, delayMs] of cases) {
    const server = await featureServer();
    Object.assign(server, { status, body, delayMs });
    const chat = newChat();
    loadKeys(chat);
    const applied = await chat.loadFeatureConfig({
      endpoint: server.endpoint,
      timeoutMs: 300,
      refreshSeconds: 0,
    });
    assert.equal(applied, false, `${status} ${body}`);
    assert.equal(chat.isEnabled("v1_send"), false, `${status} ${body}`);
    assert.equal(send(chat, v).signatureInfo.signatureVersion, "7", `${status} ${body}`);
    chat.free();
    await server.close();
  }
}

async function loadBeforeKeysRefetchesWithTheKeyBucket() {
  const server = await featureServer();
  const params = { endpoint: server.endpoint, timeoutMs: 1000, refreshSeconds: 0 };
  const chat = newChat();
  assert.equal(chat.featureBucket(), null);
  assert.equal(await chat.loadFeatureConfig(params), true);
  assert.deepEqual(server.buckets, [null]);
  assert.equal(chat.isEnabled("v1_send"), true);

  server.body = '{"features":{"v1_send":false}}';
  loadKeys(chat);
  assert.equal(chat.isEnabled("v1_send"), false, "off until the key-bucketed refetch");
  const bucket = String(chat.featureBucket());
  await waitFor("the key-bucketed refetch", () =>
    server.buckets.includes(bucket) && !chat.featureRefetchDue(),
  );
  assert.equal(chat.isEnabled("v1_send"), false);
  chat.free();

  const other = newChat();
  server.body = '{"features":{"v1_send":false}}';
  assert.equal(await other.loadFeatureConfig(params), true);
  server.body = '{"features":{"v1_send":true}}';
  loadKeys(other);
  await waitFor("the refetch to turn v1_send on", () => other.isEnabled("v1_send"));
  other.free();
  await server.close();
}

async function theRecheckTurnsFlagsOffButNeverOn() {
  const server = await featureServer();
  const chat = newChat();
  loadKeys(chat);
  assert.equal(await chat.loadFeatureConfig({ endpoint: server.endpoint, refreshSeconds: 1 }), true);
  server.body = '{"features":{}}';
  await waitFor("the re-check to turn v1_send off", () => !chat.isEnabled("v1_send"));
  server.body = '{"features":{"v1_send":true}}';
  const seen = server.buckets.length;
  await waitFor("two more re-checks", () => server.buckets.length >= seen + 2);
  assert.equal(chat.isEnabled("v1_send"), false);

  server.status = 503;
  chat.applyFeatureConfig('{"features":{"v1_send":true}}', chat.featureBucket());
  const before = server.buckets.length;
  await waitFor("two failed re-checks", () => server.buckets.length >= before + 2);
  assert.equal(chat.isEnabled("v1_send"), true, "a failed re-check changes nothing");
  chat.free();
  await server.close();
}

async function freeStopsTheRefresher() {
  const server = await featureServer();
  const chat = newChat();
  loadKeys(chat);
  assert.equal(await chat.loadFeatureConfig({ endpoint: server.endpoint, refreshSeconds: 1 }), true);
  server.delayMs = 5000;
  await sleep(1200);
  chat.free();
  const seen = server.buckets.length;
  await sleep(2500);
  assert.equal(server.buckets.length, seen, "no request after free()");
  await server.close();
}

async function applyFeatureConfigRejectsAMalformedBody() {
  const chat = newChat();
  loadKeys(chat);
  chat.applyFeatureConfig('{"features":{"v1_send":true}}', chat.featureBucket());
  assert.throws(() => chat.applyFeatureConfig("[]", chat.featureBucket(), true));
  assert.equal(chat.isEnabled("v1_send"), true);
  chat.applyFeatureConfig('{"features":{}}', chat.featureBucket(), true);
  assert.equal(chat.isEnabled("v1_send"), false);
  chat.free();
}

async function main() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  const v = await loadVectors();
  assert.equal(FEATURES_ENDPOINT, "https://api.x.com/2/chat/features");

  await everyFlagIsOffBeforeAnyLoad(v);
  await loadAfterKeysSendsTheKeyBucket(v);
  await unknownKeysAreReadableAndMissingKeysAreOff();
  await anyFailureLeavesEveryFlagOff(v);
  await loadBeforeKeysRefetchesWithTheKeyBucket();
  await theRecheckTurnsFlagsOffButNeverOn();
  await freeStopsTheRefresher();
  await applyFeatureConfigRejectsAMalformedBody();
  console.log("features.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
