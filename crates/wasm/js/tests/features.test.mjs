// Tests for the feature switches (GET /2/chat/features) through the shipped
// JS wrapper. Nothing is called: every ChatWithJuicebox fetches by itself,
// pointed at a local server through the internal environment hooks, and the
// flags are read through the internal methods of the wasm Chat underneath,
// which is the real SDK.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

import init, { Chat } from "../pkg/chat_xdk_wasm.js";
import * as pkg from "../index.js";

const { ChatWithJuicebox, createChat } = pkg;

if (typeof globalThis.crypto === "undefined") {
  const { webcrypto } = await import("node:crypto");
  globalThis.crypto = webcrypto;
}

// The internal hooks, read when a chat is created: shorter timings than the
// defaults (2000 ms, 300 s, 1000 ms).
const HOOKS = {
  CHAT_XDK_FEATURES_TIMEOUT_MS: "500",
  CHAT_XDK_FEATURES_REFRESH_SECONDS: "3600",
  CHAT_XDK_FEATURES_KEY_POLL_MS: "20",
};

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
    // The answer is fixed before the request is recorded, so a test that
    // sees the request can change the next answer.
    const { status, body, delayMs } = state;
    state.buckets.push(new URL(req.url, "http://localhost").searchParams.get("bucket"));
    const reply = () => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(body);
    };
    if (delayMs > 0) {
      const timer = setTimeout(reply, delayMs);
      res.on("close", () => clearTimeout(timer));
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

/** Run `create` with the hooks (and `endpoint`) set, restoring the environment. */
async function withHooks(endpoint, hooks, create) {
  const vars = { ...HOOKS, CHAT_XDK_FEATURES_ENDPOINT: endpoint, ...hooks };
  const saved = Object.fromEntries(Object.keys(vars).map((name) => [name, process.env[name]]));
  Object.assign(process.env, vars);
  try {
    return await create();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

/**
 * A ChatWithJuicebox whose feature fetch goes to `endpoint`; `inner` is the
 * wasm Chat underneath, which exposes the internal flag methods.
 */
async function newChat(endpoint, hooks = {}) {
  return withHooks(endpoint, hooks, () => {
    const inner = new Chat();
    return { chat: new ChatWithJuicebox(inner, null, undefined, null, null, null), inner };
  });
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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(what, predicate) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await sleep(20);
  }
  assert.ok(predicate(), `timed out waiting for ${what}`);
}

/** Wait for a request carrying the chat's key bucket. */
async function keyedRequest(server, inner) {
  const bucket = String(inner.__featureBucket());
  await waitFor(`a request with bucket ${bucket}`, () => server.buckets.includes(bucket));
}

function exposeGc() {
  if (typeof globalThis.gc === "function") return globalThis.gc;
  setFlagsFromString("--expose-gc");
  return runInNewContext("gc");
}

async function featureSwitchesAreNotPublicApi() {
  for (const name of ["FEATURES_ENDPOINT", "LoadFeatureConfigParams", "loadFeatureConfig"]) {
    assert.equal(name in pkg, false, name);
  }
  const methods = ["loadFeatureConfig", "isEnabled", "featureBucket", "applyFeatureConfig", "featureRefetchDue"];
  for (const name of methods) {
    assert.equal(name in ChatWithJuicebox.prototype, false, name);
  }
  const declared = /FEATURES_ENDPOINT|LoadFeatureConfig|loadFeatureConfig|isEnabled|featureBucket|applyFeatureConfig|featureRefetchDue/;
  assert.doesNotMatch(await fs.readFile(new URL("../index.d.ts", import.meta.url), "utf-8"), declared);
  // The wasm Chat's own declarations leave its internal methods out too.
  const generated = await fs.readFile(new URL("../pkg/chat_xdk_wasm.d.ts", import.meta.url), "utf-8");
  const wasmChat = /export class Chat \{[\s\S]*?\n\}/.exec(generated);
  assert.ok(wasmChat, "the generated declarations have a Chat class");
  assert.doesNotMatch(wasmChat[0], declared);
}

async function creatingAChatNeverWaitsForTheFetch(v, server) {
  server.delayMs = 2000;
  const hooks = { CHAT_XDK_FEATURES_TIMEOUT_MS: "5000" };
  let started = Date.now();
  const { chat } = await newChat(server.endpoint, hooks);
  assert.ok(Date.now() - started < 1000);
  loadKeys(chat);
  assert.equal(send(chat, v).signatureInfo.signatureVersion, "7");
  chat.free();

  const juiceboxModule = { Client: class {}, Configuration: class {} };
  started = Date.now();
  const created = await withHooks(server.endpoint, hooks, () =>
    createChat({ getAuthToken: async () => "", juiceboxModule }),
  );
  assert.ok(Date.now() - started < 1000);
  created.free();
}

async function everyFlagIsOffAndSendsAreV0UntilAResponseApplies(v, server) {
  server.status = 503;
  const { chat, inner } = await newChat(server.endpoint);
  loadKeys(chat);
  await keyedRequest(server, inner);
  assert.equal(inner.__isEnabled("v1_send"), false);
  const payload = send(chat, v);
  assert.equal(payload.signatureInfo.signatureVersion, "7");
  assert.equal(typeof payload.xdkVersion, "string");
  assert.ok(payload.xdkVersion.length > 0);
  chat.free();
}

async function aChatFetchesOnCreationAndAgainWithTheKeyBucket(v, server) {
  const { chat, inner } = await newChat(server.endpoint);
  assert.equal(inner.__featureBucket(), undefined);
  await waitFor("the request on creation", () => server.buckets.length === 1);
  assert.deepEqual(server.buckets, [null]);

  loadKeys(chat);
  const bucket = inner.__featureBucket();
  assert.ok(Number.isInteger(bucket) && bucket >= 0 && bucket < 10000);
  await keyedRequest(server, inner);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));
  assert.equal(inner.__featureRefetchDue(), false);
  assert.deepEqual(server.buckets, [null, String(bucket)]);
  assert.equal(send(chat, v).signatureInfo.signatureVersion, "10");
  chat.free();
}

async function keysLoadedBeforeTheFirstAnswerStillGetTheKeyBucket(server) {
  server.delayMs = 200;
  const { chat, inner } = await newChat(server.endpoint);
  loadKeys(chat);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));
  assert.deepEqual(server.buckets, [null, String(inner.__featureBucket())]);
  chat.free();
}

async function theKeyBucketAnswerReplacesTheIpAnswer(server) {
  // An IP-bucketed "on" reads off once keys load, and the key's own answer
  // decides.
  const first = await newChat(server.endpoint);
  await waitFor("the IP answer", () => first.inner.__isEnabled("v1_send"));
  server.body = '{"features":{"v1_send":false}}';
  loadKeys(first.chat);
  assert.equal(first.inner.__isEnabled("v1_send"), false, "off until the key-bucketed refetch");
  await keyedRequest(server, first.inner);
  await waitFor("the key answer", () => !first.inner.__featureRefetchDue());
  assert.equal(first.inner.__isEnabled("v1_send"), false);
  first.chat.free();

  // ...and the key's answer can turn a flag on that the IP answer left off.
  server.body = '{"features":{"v1_send":false,"ip_answer":true}}';
  const second = await newChat(server.endpoint);
  await waitFor("the IP answer", () => second.inner.__isEnabled("ip_answer"));
  server.body = '{"features":{"v1_send":true}}';
  loadKeys(second.chat);
  await waitFor("the key answer", () => second.inner.__isEnabled("v1_send"));
  assert.equal(second.inner.__isEnabled("ip_answer"), false);
  second.chat.free();
}

async function unknownKeysAreReadableAndMissingKeysAreOff(server) {
  server.body = '{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}';
  const { chat, inner } = await newChat(server.endpoint);
  loadKeys(chat);
  await waitFor("later_flag on", () => inner.__isEnabled("later_flag"));
  assert.equal(inner.__isEnabled("v1_send"), false);
  assert.equal(inner.__isEnabled("missing"), false);
  chat.free();
}

async function anyFailureLeavesEveryFlagOff(v, server) {
  const cases = [
    [404, '{"features":{"v1_send":true}}', 0],
    [500, '{"features":{"v1_send":true}}', 0],
    [200, "not json", 0],
    [200, '{"v1_send":true}', 0],
    [200, '{"features":{"v1_send":true}}', 1500],
    [200, '{"features":{"v1_send":true}}' + " ".repeat(64 * 1024), 0],
  ];
  for (const [status, body, delayMs] of cases) {
    const label = `${status} ${body.slice(0, 40)} (${body.length} bytes) ${delayMs}`;
    Object.assign(server, { status, body, delayMs });
    server.buckets.length = 0;
    const { chat, inner } = await newChat(server.endpoint);
    loadKeys(chat);
    await keyedRequest(server, inner);
    await sleep(delayMs ? 600 : 100);
    assert.equal(inner.__isEnabled("v1_send"), false, label);
    assert.equal(send(chat, v).signatureInfo.signatureVersion, "7", label);
    chat.free();
  }
}

async function anUnreachableEndpointLeavesEveryFlagOff(v, server) {
  const endpoint = server.endpoint;
  await server.close();
  const { chat, inner } = await newChat(endpoint);
  loadKeys(chat);
  await sleep(300);
  assert.equal(inner.__isEnabled("v1_send"), false);
  assert.equal(inner.__featureRefetchDue(), true);
  assert.equal(send(chat, v).signatureInfo.signatureVersion, "7");
  chat.free();
}

async function theRecheckTurnsFlagsOffButNeverOn(v, server) {
  const { chat, inner } = await newChat(server.endpoint, { CHAT_XDK_FEATURES_REFRESH_SECONDS: "0.3" });
  loadKeys(chat);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));

  server.body = '{"features":{}}';
  await waitFor("the re-check to turn v1_send off", () => !inner.__isEnabled("v1_send"));
  assert.equal(send(chat, v).signatureInfo.signatureVersion, "7");

  server.body = '{"features":{"v1_send":true}}';
  const seen = server.buckets.length;
  await waitFor("two more re-checks", () => server.buckets.length >= seen + 2);
  assert.equal(inner.__isEnabled("v1_send"), false);
  chat.free();
}

async function aFailedRecheckChangesNothing(server) {
  const { chat, inner } = await newChat(server.endpoint, { CHAT_XDK_FEATURES_REFRESH_SECONDS: "0.3" });
  loadKeys(chat);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));
  server.status = 503;
  const seen = server.buckets.length;
  await waitFor("two failed re-checks", () => server.buckets.length >= seen + 2);
  assert.equal(inner.__isEnabled("v1_send"), true);
  chat.free();
}

async function freeStopsTheFetches(server) {
  const { chat, inner } = await newChat(server.endpoint, { CHAT_XDK_FEATURES_REFRESH_SECONDS: "0.3" });
  loadKeys(chat);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));
  server.delayMs = 5000;
  await sleep(400);
  chat.free();
  const seen = server.buckets.length;
  await sleep(1000);
  assert.equal(server.buckets.length, seen, "no request after free()");
}

/** A keyed, re-checking chat that nothing references once this returns. */
async function startUnreferencedChat(endpoint) {
  const { chat, inner } = await newChat(endpoint, { CHAT_XDK_FEATURES_REFRESH_SECONDS: "0.3" });
  loadKeys(chat);
  await waitFor("v1_send on", () => inner.__isEnabled("v1_send"));
}

async function theFetchesEndWithACollectedChat(server) {
  const gc = exposeGc();
  await startUnreferencedChat(server.endpoint);
  const running = server.buckets.length;
  await waitFor("a re-check", () => server.buckets.length > running);
  for (let i = 0; i < 5; i++) {
    await sleep(50);
    gc();
  }
  await sleep(800);
  const seen = server.buckets.length;
  await sleep(1200);
  assert.equal(server.buckets.length, seen, "no request once the chat is collected");
}

async function chatsAskingAtOnceShareARequest(v, server) {
  server.delayMs = 300;
  const chats = [];
  for (let i = 0; i < 4; i++) chats.push(await newChat(server.endpoint));
  await waitFor("the IP answer", () => chats.every(({ inner }) => inner.__isEnabled("v1_send")));
  assert.deepEqual(server.buckets, [null]);

  const keys = b64ToBytes(v.private_keys_concat_b64);
  for (const { inner } of chats) inner.importKeys(keys);
  await waitFor("the key answer", () => chats.every(({ inner }) => !inner.__featureRefetchDue()));
  assert.deepEqual(server.buckets, [null, String(chats[0].inner.__featureBucket())]);
  for (const { chat } of chats) chat.free();
}

/**
 * A Node process with a feature request still in flight exits once its own
 * work is done, rather than when the request ends. Runtimes without
 * `process.getBuiltinModule` fall back to fetch(), which holds the process.
 */
async function aFetchInFlightNeverKeepsNodeRunning(server) {
  if (typeof process.getBuiltinModule !== "function") return;
  server.delayMs = 60_000;
  const url = (path) => JSON.stringify(new URL(path, import.meta.url).href);
  const script = `
    const fs = await import("node:fs/promises");
    const { default: init, Chat } = await import(${url("../pkg/chat_xdk_wasm.js")});
    const { ChatWithJuicebox } = await import(${url("../index.js")});
    await init({ module_or_path: await fs.readFile(new URL(${url("../pkg/chat_xdk_wasm_bg.wasm")})) });
    const chat = new ChatWithJuicebox(new Chat(), null, undefined, null, null, null);
    chat.generateKeypairs();
    await new Promise((resolve) => setTimeout(resolve, 300));
  `;
  const started = Date.now();
  const code = await new Promise((resolve) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: {
        ...process.env,
        ...HOOKS,
        CHAT_XDK_FEATURES_ENDPOINT: server.endpoint,
        CHAT_XDK_FEATURES_TIMEOUT_MS: "10000",
      },
      stdio: "inherit",
    });
    child.on("exit", resolve);
  });
  const elapsed = Date.now() - started;
  assert.equal(code, 0);
  assert.ok(server.buckets.length >= 1, "a feature request was in flight");
  assert.ok(elapsed < 5000, `the process exited after ${elapsed} ms`);
}

async function aMalformedBodyIsRejectedAndChangesNothing(server) {
  server.status = 503;
  const { chat, inner } = await newChat(server.endpoint);
  loadKeys(chat);
  await keyedRequest(server, inner);
  const bucket = inner.__featureBucket();
  inner.__applyFeatureConfig('{"features":{"v1_send":true}}', bucket, false);
  assert.throws(() => inner.__applyFeatureConfig("[]", bucket, true));
  assert.equal(inner.__isEnabled("v1_send"), true);
  inner.__applyFeatureConfig('{"features":{}}', bucket, true);
  assert.equal(inner.__isEnabled("v1_send"), false);
  chat.free();
}

async function main() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  const v = await loadVectors();

  const tests = [
    () => featureSwitchesAreNotPublicApi(),
    (server) => creatingAChatNeverWaitsForTheFetch(v, server),
    (server) => everyFlagIsOffAndSendsAreV0UntilAResponseApplies(v, server),
    (server) => aChatFetchesOnCreationAndAgainWithTheKeyBucket(v, server),
    (server) => keysLoadedBeforeTheFirstAnswerStillGetTheKeyBucket(server),
    (server) => theKeyBucketAnswerReplacesTheIpAnswer(server),
    (server) => unknownKeysAreReadableAndMissingKeysAreOff(server),
    (server) => anyFailureLeavesEveryFlagOff(v, server),
    (server) => anUnreachableEndpointLeavesEveryFlagOff(v, server),
    (server) => theRecheckTurnsFlagsOffButNeverOn(v, server),
    (server) => aFailedRecheckChangesNothing(server),
    (server) => freeStopsTheFetches(server),
    (server) => theFetchesEndWithACollectedChat(server),
    (server) => aMalformedBodyIsRejectedAndChangesNothing(server),
    (server) => aFetchInFlightNeverKeepsNodeRunning(server),
    (server) => chatsAskingAtOnceShareARequest(v, server),
  ];
  for (const test of tests) {
    const server = await featureServer();
    try {
      await test(server);
    } finally {
      await server.close();
    }
  }
  console.log("features.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
