// A local GET /2/chat/features for the tests, and the internal hooks that
// point chats at it. Chats must come from ../pkg, the module the wrapper's
// feature driver serves.
import http from "node:http";

import { Chat, __featureSetDefaultEndpoint } from "../pkg/chat_xdk_wasm.js";
import { ChatWithJuicebox } from "../index.js";

// Nothing listens here: a chat no test points at a server of its own fetches
// from this endpoint, fails, and stays on v0.
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

// Each server gets an endpoint of its own: the core reuses an answer per
// endpoint and bucket for 5 minutes, and a server can get the port of one that
// came before it.
let lastServerId = 0;

/** A local GET /2/chat/features that records each request's bucket. */
export async function featureServer(body = '{"features":{"v1_send":true}}') {
  const state = { status: 200, body, delayMs: 0, buckets: [] };
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
  state.endpoint = `http://127.0.0.1:${server.address().port}/${++lastServerId}/2/chat/features`;
  state.unref = () => server.unref();
  state.close = () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(resolve);
    });
  return state;
}

let v1Server;

/**
 * Turn v1_send on for the wasm `chat` as the X API would: point its feature
 * fetch at a local server that answers it, then `send()` until a send is v1.
 */
export async function enableV1Send(chat, send) {
  if (!v1Server) {
    // Constructing a wrapper is what lets the core start the feature driver.
    new ChatWithJuicebox(new Chat(), null, undefined, null, null, null).free();
    v1Server = await featureServer();
    v1Server.unref();
  }
  chat.__configureFeatures(v1Server.endpoint, 2000, 3_600_000, 50);
  await waitFor("v1_send on", () => send().signatureInfo.signatureVersion === "10");
}
