// Tests for the feature switches (GET /2/chat/features) through the shipped
// JS wrapper. Nothing is called: each ChatWithJuicebox is pointed at a local
// server through the internal hook on the wasm Chat underneath, and sends
// show the format: signature version "7" is v0, "10" is v1.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";

import init, { Chat, __featureSetDefaultEndpoint } from "../pkg/chat_xdk_wasm.js";
import * as pkg from "../index.js";
import { REDIRECT_TARGET, featureServer, keepOffline, sleep, waitFor } from "./feature_server.mjs";

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

/** A keyed ChatWithJuicebox that reads its feature switches from `endpoint`. */
function newChat(v, endpoint, { timeoutMs = 2000 } = {}) {
  const inner = new Chat();
  inner.__configureFeatures(endpoint, timeoutMs);
  inner.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
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

async function aNewChatReadsTheSwitchesOnce(v, server) {
  const chat = newChat(v, server.endpoint);
  await waitFor("the request", () => server.queries.length === 1);
  assert.equal(server.queries[0], "", "the request carries no query");
  await waitFor("v1", () => send(chat, v) === "10");
  chat.generateKeypairs();
  chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
  for (let i = 0; i < 5; i++) send(chat, v);
  await sleep(300);
  assert.equal(server.queries.length, 1, server.queries.join());
  chat.free();
}

async function createChatReadsTheSwitches(v, server) {
  __featureSetDefaultEndpoint(server.endpoint);
  try {
    const juiceboxModule = { Client: class {}, Configuration: class {} };
    const created = await createChat({ getAuthToken: async () => "", juiceboxModule });
    await waitFor("the request", () => server.queries.length === 1);
    created.generateKeypairs();
    created.setIdentity({ userId: "111", signingKeyVersion: "1" });
    await waitFor("v1", () => send(created, v) === "10");
    created.free();
  } finally {
    keepOffline();
  }
}

async function aSendNeverWaitsForTheRequest(v, server) {
  server.delayMs = 2000;
  const chat = newChat(v, server.endpoint, { timeoutMs: 3000 });
  const started = Date.now();
  assert.equal(send(chat, v), "7");
  assert.ok(Date.now() - started < 1000);
  chat.free();
}

async function chatsCreatedWhileARequestIsInFlightShareIt(v, server) {
  server.delayMs = 800;
  const chats = [0, 1, 2, 3].map(() => newChat(v, server.endpoint));
  await waitFor("v1 everywhere", () => chats.every((chat) => send(chat, v) === "10"));
  assert.equal(server.queries.length, 1, server.queries.join());

  const later = newChat(v, server.endpoint);
  await waitFor("the later chat to ask for itself", () => server.queries.length === 2);
  await waitFor("v1 for the later chat", () => send(later, v) === "10");
  for (const chat of [...chats, later]) chat.free();
}

async function theAnswerHoldsForTheChatsLifetime(v, server) {
  const chat = newChat(v, server.endpoint);
  await waitFor("v1", () => send(chat, v) === "10");
  server.body = '{"features":{}}';
  const other = newChat(v, server.endpoint);
  await waitFor("the second request", () => server.queries.length === 2);
  await sleep(200);
  assert.equal(send(other, v), "7", "the second chat reads its own answer");
  assert.equal(send(chat, v), "10", "the first chat's answer holds");
  chat.free();
  other.free();
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
    const server = await featureServer(body);
    Object.assign(server, { status, delayMs });
    try {
      const chat = newChat(v, server.endpoint, { timeoutMs: 500 });
      await waitFor(`the request (${label})`, () => server.queries.length === 1);
      await sleep(delayMs + 200);
      assert.equal(send(chat, v), "7", label);
      chat.free();
    } finally {
      await server.close();
    }
  }
}

async function aFailedReadIsRetriedAndTheRetrysAnswerTurnsV1On(v, server) {
  server.status = 503;
  const chat = newChat(v, server.endpoint);
  await waitFor("the first request", () => server.queries.length === 1);
  server.status = 200;
  assert.equal(send(chat, v), "7", "the failed read leaves sends on v0");
  await waitFor("v1 from the retry", () => send(chat, v) === "10");
  assert.equal(server.queries.length, 2, server.queries.join());
  chat.free();
}

async function anUnreachableEndpointLeavesSendsOnV0(v, server) {
  const endpoint = server.endpoint;
  await server.close();
  const chat = newChat(v, endpoint, { timeoutMs: 500 });
  await sleep(700);
  assert.equal(send(chat, v), "7");
  chat.free();
}

async function aRequestStillOpenAtItsTimeoutFails(v, server) {
  server.delayMs = 3000;
  const chat = newChat(v, server.endpoint, { timeoutMs: 300 });
  await sleep(1000);
  assert.equal(send(chat, v), "7");
  assert.equal(server.queries.length, 1);
  chat.free();
}

async function aRequestEndsSafelyForAFreedChat(v, server) {
  server.delayMs = 800;
  newChat(v, server.endpoint).free();
  const kept = newChat(v, server.endpoint);
  await waitFor("v1", () => send(kept, v) === "10");
  assert.equal(server.queries.length, 1);
  kept.free();
}

/**
 * A Node process whose read is still in flight exits once its own work is
 * done: at once where Node's http module is at hand, and within the read's
 * timeout where fetch() performs it.
 */
async function aReadInFlightNeverKeepsNodeRunning(server) {
  server.delayMs = 60_000;
  const { code, elapsed } = await runNode(`
    __featureSetDefaultEndpoint(${JSON.stringify(server.endpoint)});
    const chat = new ChatWithJuicebox(new Chat(), null, undefined, null, null, null);
    chat.generateKeypairs();
    chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
    await new Promise((resolve) => setTimeout(resolve, 300));
  `);
  assert.equal(code, 0);
  assert.equal(server.queries.length, 1, "the chat's read was in flight");
  const limitMs = typeof process.getBuiltinModule === "function" ? 5000 : 7000;
  assert.ok(elapsed < limitMs, `the process exited after ${elapsed} ms`);
}

/**
 * Where fetch() performs the read, the body is capped while it streams, and
 * a body the runtime cannot stream is never read whole: either way the read
 * fails and sends stay v0.
 */
async function theFetchReadCapsTheBodyWhileItStreams(v) {
  const getBuiltinModule = process.getBuiltinModule;
  const realFetch = globalThis.fetch;
  process.getBuiltinModule = undefined;
  const enabled = '{"features":{"v1_send":true}}';
  let pulled = 0;
  let readWhole = 0;
  const streamed = (chunks) => ({
    status: 200,
    body: new ReadableStream({
      pull(controller) {
        pulled += 1;
        const chunk = chunks.shift();
        if (chunk === undefined) controller.close();
        else controller.enqueue(new TextEncoder().encode(chunk));
      },
    }),
    arrayBuffer: async () => {
      readWhole += 1;
      return new ArrayBuffer(0);
    },
  });
  const unstreamable = {
    status: 200,
    body: undefined,
    arrayBuffer: async () => {
      readWhole += 1;
      return new TextEncoder().encode(enabled).buffer;
    },
  };
  try {
    const cases = [
      ["a body that fits", () => streamed([enabled]), "10"],
      ["an oversized body", () => streamed([enabled, ...Array(200).fill(" ".repeat(1024))]), "7"],
      ["a body that cannot stream", () => unstreamable, "7"],
    ];
    for (const [index, [label, response, expected]] of cases.entries()) {
      globalThis.fetch = async () => response();
      // An endpoint per case, so no case shares another's retry.
      const chat = newChat(v, `http://127.0.0.1:9/${index}/features`, { timeoutMs: 1000 });
      await sleep(300);
      assert.equal(send(chat, v), expected, label);
      chat.free();
    }
    assert.ok(pulled < 100, `the oversized body was read to its end (${pulled} reads)`);
    assert.equal(readWhole, 0, "a body was read whole");
  } finally {
    process.getBuiltinModule = getBuiltinModule;
    globalThis.fetch = realFetch;
  }
}

/**
 * Run `body` with each way the wrapper performs the GET in Node: its http
 * module, and fetch() as where that module is out of reach.
 */
async function withEachGetPath(body) {
  await body("node:http");
  const getBuiltinModule = process.getBuiltinModule;
  process.getBuiltinModule = undefined;
  try {
    assert.equal(process.getBuiltinModule, undefined, "the read goes through fetch()");
    await body("fetch");
  } finally {
    process.getBuiltinModule = getBuiltinModule;
  }
}

async function theReadSendsNoCookiesOrCredentials(v) {
  await withEachGetPath(async (path) => {
    const server = await featureServer();
    server.setCookie = "session=from-the-first-answer; Path=/";
    try {
      const first = newChat(v, server.endpoint);
      await waitFor(`the first answer (${path})`, () => send(first, v) === "10");
      first.free();
      const second = newChat(v, server.endpoint);
      await waitFor(`the second request (${path})`, () => server.queries.length === 2);
      await waitFor(`the second answer (${path})`, () => send(second, v) === "10");
      second.free();
      for (const headers of server.headers) {
        assert.equal(headers.cookie, undefined, `the read sends no cookie (${path})`);
        assert.equal(headers.authorization, undefined, `the read sends no credentials (${path})`);
      }
    } finally {
      await server.close();
    }
  });
}

async function aRedirectIsNotFollowed(v) {
  await withEachGetPath(async (path) => {
    const server = await featureServer();
    Object.assign(server, { status: 302, location: server.origin + REDIRECT_TARGET });
    try {
      const chat = newChat(v, server.endpoint, { timeoutMs: 500 });
      await waitFor(`the request (${path})`, () => server.queries.length === 1);
      await sleep(700);
      assert.equal(send(chat, v), "7", `a redirect is a failed read (${path})`);
      assert.equal(server.followed, 0, `the redirect is not followed (${path})`);
      chat.free();
    } finally {
      await server.close();
    }
  });
}

async function main() {
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  await init({ module_or_path: await fs.readFile(wasmUrl) });
  keepOffline();
  const v = await loadVectors();

  const tests = [
    () => featureSwitchesAreNotPublicApi(),
    (server) => aNewChatReadsTheSwitchesOnce(v, server),
    (server) => createChatReadsTheSwitches(v, server),
    (server) => aSendNeverWaitsForTheRequest(v, server),
    (server) => chatsCreatedWhileARequestIsInFlightShareIt(v, server),
    (server) => theAnswerHoldsForTheChatsLifetime(v, server),
    () => anyFailureLeavesSendsOnV0(v),
    (server) => aFailedReadIsRetriedAndTheRetrysAnswerTurnsV1On(v, server),
    () => theFetchReadCapsTheBodyWhileItStreams(v),
    (server) => anUnreachableEndpointLeavesSendsOnV0(v, server),
    (server) => aRequestStillOpenAtItsTimeoutFails(v, server),
    (server) => aRequestEndsSafelyForAFreedChat(v, server),
    (server) => aReadInFlightNeverKeepsNodeRunning(server),
    () => theReadSendsNoCookiesOrCredentials(v),
    () => aRedirectIsNotFollowed(v),
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
