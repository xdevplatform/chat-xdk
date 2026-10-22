// Tests for the feature switches (GET /2/chat/features) through the shipped
// JS wrapper. Nothing is called: each ChatWithJuicebox is pointed at a local
// server through the internal hook on the wasm Chat underneath, and sends
// show the format: signature version "7" is v0, "10" is v1.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

import init, { Chat, __featureSetDefaultEndpoint } from "../pkg/chat_xdk_wasm.js";
import * as pkg from "../index.js";
import { featureServer, keepOffline, sleep, waitFor } from "./feature_server.mjs";

const { ChatWithJuicebox, createChat } = pkg;

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

/**
 * A keyed ChatWithJuicebox whose feature fetch goes to `endpoint`; `inner` is
 * the wasm Chat underneath.
 */
function newChat(v, endpoint, { timeoutMs = 2000, recheckMs = 3_600_000, firstRetryMs = 50, keys } = {}) {
  const inner = new Chat();
  inner.__configureFeatures(endpoint, timeoutMs, recheckMs, firstRetryMs);
  inner.importKeys({ keys: keys ?? b64ToBytes(v.private_keys_concat_b64) });
  const chat = new ChatWithJuicebox(inner, null, undefined, null, null, null);
  chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
  return chat;
}

/** The signature version of a send: "7" for v0, "10" for v1. */
function send(chat, v) {
  return chat.encryptMessage({
    conversationId: "conv-1",
    conversationKey: b64ToBytes(v.conversation_key_b64),
    conversationKeyVersion: "1",
    text: "hello",
  }).signatureInfo.signatureVersion;
}

function exposeGc() {
  if (typeof globalThis.gc === "function") return globalThis.gc;
  setFlagsFromString("--expose-gc");
  return runInNewContext("gc");
}

/** Run `body` in a child Node process; resolves with its exit code and run time. */
function runNode(body) {
  const url = (path) => JSON.stringify(new URL(path, import.meta.url).href);
  const script = `
    const fs = await import("node:fs/promises");
    const { default: init, Chat, __featureSetDefaultEndpoint } = await import(${url("../pkg/chat_xdk_wasm.js")});
    const { ChatWithJuicebox } = await import(${url("../index.js")});
    if (typeof globalThis.crypto === "undefined") {
      globalThis.crypto = (await import("node:crypto")).webcrypto;
    }
    await init({ module_or_path: await fs.readFile(new URL(${url("../pkg/chat_xdk_wasm_bg.wasm")})) });
    ${body}
  `;
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: "inherit" });
    child.on("exit", (code) => resolve({ code, elapsed: Date.now() - started }));
  });
}

async function featureSwitchesAreNotPublicApi() {
  const featureNames = (names) => names.filter((name) => /feature/i.test(name));
  assert.deepEqual(featureNames(Object.keys(pkg)), []);
  assert.deepEqual(featureNames(Object.getOwnPropertyNames(ChatWithJuicebox.prototype)), []);
  // No declaration names a feature switch: neither the wrapper's nor the
  // generated ones for the wasm Chat and the module's functions.
  const declaresFeature =
    /^\s*(?:export\s+)?(?:declare\s+)?(?:function\s+|class\s+|interface\s+|type\s+|const\s+)?[\w$]*[Ff]eature[\w$]*\s*[(<:]/m;
  assert.doesNotMatch(await fs.readFile(new URL("../index.d.ts", import.meta.url), "utf-8"), declaresFeature);
  const generated = await fs.readFile(new URL("../pkg/chat_xdk_wasm.d.ts", import.meta.url), "utf-8");
  const wasmChat = /export class Chat \{[\s\S]*?\n\}/.exec(generated);
  assert.ok(wasmChat, "the generated declarations have a Chat class");
  assert.doesNotMatch(wasmChat[0], declaresFeature);
  for (const line of generated.split("\n").filter((l) => l.startsWith("export function"))) {
    assert.doesNotMatch(line, declaresFeature);
  }
}

async function noRequestIsMadeUntilTheFirstSend(v, server) {
  const chat = newChat(v, server.endpoint);
  await sleep(300);
  assert.deepEqual(server.buckets, []);

  assert.equal(send(chat, v), "7", "the first send does not wait for the answer");
  await waitFor("the request", () => server.buckets.length === 1);
  const bucket = Number(server.buckets[0]);
  assert.ok(Number.isInteger(bucket) && bucket >= 0 && bucket < 10000, String(server.buckets[0]));
  chat.free();
}

async function creatingAChatMakesNoRequest(server) {
  __featureSetDefaultEndpoint(server.endpoint);
  try {
    const juiceboxModule = { Client: class {}, Configuration: class {} };
    const created = await createChat({ getAuthToken: async () => "", juiceboxModule });
    created.generateKeypairs();
    created.setIdentity({ userId: "111", signingKeyVersion: "1" });
    await sleep(200);
    assert.deepEqual(server.buckets, []);
    created.free();
  } finally {
    keepOffline();
  }
}

async function v1StartsOnceTheAnswerTurnsItOn(v, server) {
  const chat = newChat(v, server.endpoint);
  assert.equal(send(chat, v), "7");
  await waitFor("v1", () => send(chat, v) === "10");
  assert.equal(server.buckets.length, 1);
  chat.free();
}

async function aSendNeverWaitsForTheRequest(v, server) {
  server.delayMs = 2000;
  const chat = newChat(v, server.endpoint);
  const started = Date.now();
  assert.equal(send(chat, v), "7");
  assert.ok(Date.now() - started < 1000);
  chat.free();
}

async function chatsWithOneKeyShareOneRequest(v, server) {
  server.delayMs = 300;
  const chats = [0, 1, 2, 3].map(() => newChat(v, server.endpoint));
  for (const chat of chats) assert.equal(send(chat, v), "7");
  await waitFor("v1 everywhere", () => chats.every((chat) => send(chat, v) === "10"));
  assert.equal(server.buckets.length, 1, server.buckets.join());

  const later = newChat(v, server.endpoint);
  assert.equal(send(later, v), "10", "a later chat takes the answer at hand");
  assert.equal(server.buckets.length, 1);
  for (const chat of [...chats, later]) chat.free();
}

async function chatsWithDifferentKeysAskSeparately(v, server) {
  const generated = new Chat();
  generated.generateKeypairs();
  const first = newChat(v, server.endpoint);
  const second = newChat(v, server.endpoint, { keys: generated.exportKeys() });
  generated.free();
  send(first, v);
  send(second, v);
  await waitFor("two requests", () => server.buckets.length === 2);
  assert.notEqual(server.buckets[0], server.buckets[1]);
  first.free();
  second.free();
}

async function anyFailureLeavesSendsOnV0(v) {
  const cases = [
    [404, '{"features":{"v1_send":true}}', 0],
    [500, '{"features":{"v1_send":true}}', 0],
    [200, "not json", 0],
    [200, '{"v1_send":true}', 0],
    [200, '{"features":{"v1_send":"true"}}', 0],
    [200, '{"features":{"v1_send":true}}' + " ".repeat(64 * 1024), 0],
    [200, '{"features":{"v1_send":true}}', 1000],
  ];
  for (const [status, body, delayMs] of cases) {
    const label = `${status} ${body.slice(0, 40)} (${body.length} bytes) ${delayMs}`;
    // A server of its own: chats share an answer per endpoint and bucket,
    // and the case before may have left one.
    const server = await featureServer(body);
    Object.assign(server, { status, delayMs });
    try {
      const chat = newChat(v, server.endpoint, { timeoutMs: 500, firstRetryMs: 60_000 });
      assert.equal(send(chat, v), "7", label);
      await waitFor(`the request (${label})`, () => server.buckets.length === 1);
      await sleep(delayMs ? 1200 : 200);
      assert.equal(send(chat, v), "7", label);
      chat.free();
    } finally {
      await server.close();
    }
  }
}

async function anUnreachableEndpointLeavesSendsOnV0(v, server) {
  const endpoint = server.endpoint;
  await server.close();
  const chat = newChat(v, endpoint, { timeoutMs: 500 });
  assert.equal(send(chat, v), "7");
  await sleep(500);
  assert.equal(send(chat, v), "7");
  chat.free();
}

async function aRequestStillOpenAtItsTimeoutFailsAndIsRetried(v, server) {
  server.delayMs = 3000;
  const chat = newChat(v, server.endpoint, { timeoutMs: 300, firstRetryMs: 200 });
  assert.equal(send(chat, v), "7");
  await waitFor("a retry", () => server.buckets.length >= 2, 2500);
  assert.equal(send(chat, v), "7");
  chat.free();
}

async function theRecheckTurnsV1OffAndNeverBackOn(v, server) {
  const chat = newChat(v, server.endpoint, { recheckMs: 300 });
  send(chat, v);
  await waitFor("v1", () => send(chat, v) === "10");

  server.body = '{"features":{}}';
  await waitFor("the re-check to turn v1 off", () => send(chat, v) === "7");

  server.body = '{"features":{"v1_send":true}}';
  const seen = server.buckets.length;
  await waitFor("two more re-checks", () => server.buckets.length >= seen + 2);
  assert.equal(send(chat, v), "7", "a running chat never sees it turn on");
  const later = newChat(v, server.endpoint, { recheckMs: 300 });
  assert.equal(send(later, v), "10", "a new chat takes the latest answer");
  chat.free();
  later.free();
}

async function aFailedRecheckChangesNothing(v, server) {
  const chat = newChat(v, server.endpoint, { recheckMs: 300 });
  send(chat, v);
  await waitFor("v1", () => send(chat, v) === "10");
  server.status = 503;
  const seen = server.buckets.length;
  await waitFor("two failed re-checks", () => server.buckets.length >= seen + 2);
  assert.equal(send(chat, v), "10");
  chat.free();
}

async function freeStopsTheRequests(v, server) {
  const chat = newChat(v, server.endpoint, { recheckMs: 300 });
  send(chat, v);
  await waitFor("v1", () => send(chat, v) === "10");
  chat.free();
  const seen = server.buckets.length;
  await sleep(1000);
  assert.equal(server.buckets.length, seen, "no request after free()");
}

/** A re-checking chat that nothing references once this returns. */
async function startUnreferencedChat(v, endpoint) {
  const chat = newChat(v, endpoint, { recheckMs: 300 });
  send(chat, v);
  await waitFor("v1", () => send(chat, v) === "10");
}

async function theRequestsEndWithACollectedChat(v, server) {
  const gc = exposeGc();
  await startUnreferencedChat(v, server.endpoint);
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

/** A Node process whose chats never send exits at once, on any Node version. */
async function aProcessThatNeverSendsExitsAtOnce(server) {
  const { code, elapsed } = await runNode(`
    __featureSetDefaultEndpoint(${JSON.stringify(server.endpoint)});
    const chat = new ChatWithJuicebox(new Chat(), null, undefined, null, null, null);
    chat.generateKeypairs();
    chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
  `);
  assert.equal(code, 0);
  assert.deepEqual(server.buckets, [], "no request without a send");
  assert.ok(elapsed < 5000, `the process exited after ${elapsed} ms`);
}

/**
 * A Node process whose request is still in flight exits once its own work is
 * done. Runtimes without `process.getBuiltinModule` use fetch(), which holds
 * the process until the request ends or times out.
 */
async function aPendingRequestNeverKeepsNodeRunning(v, server) {
  if (typeof process.getBuiltinModule !== "function") return;
  server.delayMs = 60_000;
  const { code, elapsed } = await runNode(`
    const chat = new ChatWithJuicebox(new Chat(), null, undefined, null, null, null);
    chat.generateKeypairs();
    chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
    __featureSetDefaultEndpoint(${JSON.stringify(server.endpoint)});
    chat.encryptMessage({
      conversationId: "conv-1",
      conversationKey: Uint8Array.from(Buffer.from(${JSON.stringify(v.conversation_key_b64)}, "base64")),
      conversationKeyVersion: "1",
      text: "hello",
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
  `);
  assert.equal(code, 0);
  assert.ok(server.buckets.length >= 1, "a feature request was in flight");
  assert.ok(elapsed < 5000, `the process exited after ${elapsed} ms`);
}

async function main() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  keepOffline();
  const v = await loadVectors();

  const tests = [
    () => featureSwitchesAreNotPublicApi(),
    (server) => noRequestIsMadeUntilTheFirstSend(v, server),
    (server) => creatingAChatMakesNoRequest(server),
    (server) => v1StartsOnceTheAnswerTurnsItOn(v, server),
    (server) => aSendNeverWaitsForTheRequest(v, server),
    (server) => chatsWithOneKeyShareOneRequest(v, server),
    (server) => chatsWithDifferentKeysAskSeparately(v, server),
    () => anyFailureLeavesSendsOnV0(v),
    (server) => anUnreachableEndpointLeavesSendsOnV0(v, server),
    (server) => aRequestStillOpenAtItsTimeoutFailsAndIsRetried(v, server),
    (server) => theRecheckTurnsV1OffAndNeverBackOn(v, server),
    (server) => aFailedRecheckChangesNothing(v, server),
    (server) => freeStopsTheRequests(v, server),
    (server) => theRequestsEndWithACollectedChat(v, server),
    (server) => aProcessThatNeverSendsExitsAtOnce(server),
    (server) => aPendingRequestNeverKeepsNodeRunning(v, server),
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
