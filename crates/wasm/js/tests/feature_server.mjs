// A local GET /2/chat/features for the tests, and the internal hooks that
// point chats at it. Chats must come from ../pkg, the module the wrapper
// reports feature reads to.
import http from "node:http";

import { Chat, __featureSetDefaultEndpoint } from "../pkg/chat_xdk_wasm.js";
import { ChatWithJuicebox } from "../index.js";

// Nothing listens here: a chat no test points at a server of its own reads its
// feature switches from this endpoint, fails, and stays on v0.
export const OFFLINE = "http://127.0.0.1:9/2/chat/features";

/** Point every chat that does not set its own endpoint at OFFLINE. */
export function keepOffline() {
  __featureSetDefaultEndpoint(OFFLINE);
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function waitFor(what, predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await sleep(20);
  }
  if (!predicate()) throw new Error(`timed out waiting for ${what}`);
}

// Each server gets an endpoint of its own: chats created while a GET for their
// endpoint is in flight share it, and a server can get the port of one that
// came before it.
let lastServerId = 0;

/** A local GET /2/chat/features that records each request's query string. */
export async function featureServer(body = '{"features":{"v1_send":true}}') {
  const state = { status: 200, body, delayMs: 0, queries: [] };
  const server = http.createServer((req, res) => {
    // The answer is fixed before the request is recorded, so a test that
    // sees the request can change the next answer.
    const { status, body, delayMs } = state;
    state.queries.push(new URL(req.url, "http://localhost").search);
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
  state.endpoint = `http://127.0.0.1:${server.address().port}/${++lastServerId}/2/chat/features`;
  state.unref = () => server.unref();
  state.close = () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(resolve);
    });
  return state;
}

/**
 * A wasm Chat that reads its feature switches from `endpoint`, within
 * `timeoutMs`: the wrapper around it starts the read, as createChat's does.
 */
export function reading(endpoint, timeoutMs = 2000) {
  const chat = new Chat();
  chat.__configureFeatures(endpoint, timeoutMs);
  new ChatWithJuicebox(chat, null, undefined, null, null, null);
  return chat;
}

let v1Server;

/**
 * A wasm Chat whose feature switches turn v1_send on, as the X API would: it
 * reads them from a local server that answers so. `waitForV1` waits for the
 * answer.
 */
export async function v1Chat() {
  if (!v1Server) {
    v1Server = await featureServer();
    v1Server.unref();
  }
  return reading(v1Server.endpoint);
}

/** Call `send()` until a send is v1. */
export async function waitForV1(send) {
  await waitFor("v1_send on", () => send().signatureInfo.signatureVersion === "10");
}
