/**
 * Dev server for the chat-xdk browser example.
 *
 * Responsibilities:
 *   - Serve the static browser app (public/) and the chat-xdk WASM wrapper.
 *   - Proxy X Chat API calls through the XDK using a server-held access token,
 *     so the token never reaches the browser.
 *
 * All encryption/decryption happens in the browser with the WASM binding;
 * this server only relays the encrypted blobs to/from the X API.
 *
 *   X_ACCESS_TOKEN=... node server.mjs
 */
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

import { XChatClient } from "./src/x-api.mjs";

const PORT = Number(process.env.PORT || 8787);
const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = join(ROOT, "public");
// The chat-xdk WASM wrapper + pkg live in the repo; serve them at /chat-xdk/.
const WASM_DIR = join(ROOT, "..", "..", "crates", "wasm");

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".wasm": "application/wasm",
};

const api = process.env.X_ACCESS_TOKEN ? new XChatClient(process.env.X_ACCESS_TOKEN) : null;

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}

async function serveStatic(res, baseDir, relPath) {
  // Prevent path traversal.
  const safe = normalize(relPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(baseDir, safe);
  try {
    const info = await stat(filePath);
    if (info.isDirectory()) return serveStatic(res, baseDir, join(safe, "index.html"));
    res.writeHead(200, { "content-type": MIME[extname(filePath)] || "application/octet-stream" });
    createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("Not found");
  }
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    if (path.startsWith("/api/")) {
      if (!api) return sendJson(res, 500, { error: "X_ACCESS_TOKEN not set on the server" });

      if (path === "/api/me") {
        return sendJson(res, 200, { id: await api.getMyUserId() });
      }
      if (path === "/api/public-keys") {
        const userId = url.searchParams.get("user_id");
        return sendJson(res, 200, { data: await api.getPublicKeys(userId) });
      }
      if (path === "/api/events") {
        const conversationId = url.searchParams.get("conversation_id");
        const paginationToken = url.searchParams.get("pagination_token") || undefined;
        const page = await api.getEvents(conversationId, { maxResults: 50, paginationToken });
        return sendJson(res, 200, page);
      }
      if (path === "/api/send" && req.method === "POST") {
        const body = await readBody(req);
        const result = await api.sendMessage(body.conversation_id, body);
        return sendJson(res, 200, result ?? {});
      }
      return sendJson(res, 404, { error: "unknown route" });
    }

    if (path.startsWith("/chat-xdk/")) {
      return serveStatic(res, WASM_DIR, path.slice("/chat-xdk/".length));
    }

    return serveStatic(res, PUBLIC_DIR, path === "/" ? "index.html" : path);
  } catch (e) {
    sendJson(res, 500, { error: String(e?.message || e) });
  }
});

server.listen(PORT, () => {
  console.log(`chat-xdk browser example on http://localhost:${PORT}`);
  if (!api) console.log("Warning: X_ACCESS_TOKEN not set — /api routes will return 500.");
});
