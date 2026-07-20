/**
 * One-time public-key registration for the JS/WASM example bot.
 *
 * Registering a public key is a rare, rate-limited write (only a few per 24h
 * per user) that establishes the identity every message is signed and
 * encrypted against.
 *
 * JS-specific difference from the other bindings: the browser-safe WASM
 * binding deliberately exposes NO exportKeys/importKeys, so there is no
 * private-key blob to write to disk. Juicebox IS the durable store here, so a
 * PIN is required. The identity is made durable BEFORE the network call:
 * generate, `setup(pin)` (store in Juicebox), record the marker — then POST.
 * An interrupted run is resumed by recovering the same identity with
 * `unlock(pin)` and re-sending the saved registration body, so it never mints
 * a new identity or wastes the strict daily budget. Safety properties:
 *   1. the one-time marker (state/registration.json) — refuse to re-register;
 *   2. resume via unlock(pin) — a run interrupted after setup recovers the same
 *      identity instead of generating a new one;
 *   3. reconcile-before-POST — if our exact public key is already on the
 *      account (a prior POST can apply server-side even after erroring), adopt
 *      it and skip the POST.
 * Stop cleanly on HTTP 429 rather than retrying.
 *
 * Environment (see .env.example):
 *   X_ACCESS_TOKEN     OAuth2 user token for the bot (dm.read + dm.write)
 *   CHAT_PIN           PIN the keys are stored under in Juicebox (required)
 *   CHAT_BOT_USER_ID   the bot's user id (optional; derived from the token)
 *
 * Run:
 *   node src/register.mjs --confirm
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { createChat } from "../../../crates/wasm/js/index.js";
import { XChatClient } from "./x-api.mjs";

const STATE_DIR = new URL("../state/", import.meta.url);
const MARKER_PATH = new URL("../state/registration.json", import.meta.url);

/** Tiny .env loader so the example has no extra dependencies. */
async function loadDotenv() {
  try {
    const text = await readFile(new URL("../.env", import.meta.url), "utf8");
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#") || !t.includes("=")) continue;
      const [k, ...rest] = t.split("=");
      if (process.env[k.trim()] === undefined) process.env[k.trim()] = rest.join("=").trim();
    }
  } catch {
    /* no .env */
  }
}

async function readMarker() {
  try {
    return JSON.parse(await readFile(MARKER_PATH, "utf8"));
  } catch {
    return {};
  }
}

async function writeMarker(marker) {
  await mkdir(STATE_DIR, { recursive: true });
  await writeFile(MARKER_PATH, JSON.stringify(marker, null, 2) + "\n");
}

/**
 * Build the per-realm auth-token callback createChat needs. Realm tokens live
 * in the `token_map` of the X API `juicebox_config`, keyed by hex realm id.
 */
function authTokenGetter(configJson) {
  const parsed = JSON.parse(configJson);
  const tokens = new Map();
  for (const entry of parsed.token_map ?? parsed.tokenMap ?? []) {
    const realm = String(entry?.key ?? "").toLowerCase();
    const token = entry?.value?.token;
    if (realm && typeof token === "string") tokens.set(realm, token);
  }
  return async (realmId) => tokens.get(String(realmId).toLowerCase()) ?? "";
}

async function register({ force }) {
  const token = process.env.X_ACCESS_TOKEN;
  if (!token) {
    console.error("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env");
    process.exit(1);
  }
  const pin = process.env.CHAT_PIN;
  if (!pin) {
    console.error(
      "set CHAT_PIN — the browser-safe binding has no key export, so the JS " +
        "registration persists the identity in Juicebox under this PIN.",
    );
    process.exit(1);
  }

  const marker = await readMarker();
  if (marker.registered && !force) {
    console.error(
      `Already registered (version ${marker.version}). ` +
        "Pass --force only if you intend to create a NEW identity.",
    );
    process.exit(1);
  }

  const api = new XChatClient(token);
  const userId = process.env.CHAT_BOT_USER_ID || (await api.getMyUserId());

  // Juicebox config is needed up front (before generating keys) because it is
  // the only place the identity can be persisted in this binding.
  const { configJson } = await api.getJuiceboxConfig(userId);
  const chat = await createChat({ juiceboxConfig: configJson, getAuthToken: authTokenGetter(configJson) });

  // Resume an interrupted run with the SAME identity: recover it from Juicebox
  // and reuse the saved registration body. Only generate + store a fresh
  // identity when there is no in-progress one. Storing in Juicebox and
  // recording the body BEFORE the POST is what makes a failed POST safe to
  // retry without minting a new identity or wasting the daily budget.
  let body;
  let version;
  if (marker.body && !force) {
    await chat.unlock(pin);
    body = marker.body;
    version = String(marker.version ?? "1");
    console.log("Resuming the saved identity (recovered from Juicebox).");
  } else {
    const reg = chat.generateKeypairs();
    version = String(reg.version ?? "1");
    // Snake_case wire form — the exact body the X API public-key endpoint takes.
    body = {
      public_key: {
        public_key: reg.publicKey.publicKey,
        signing_public_key: reg.publicKey.signingPublicKey,
        identity_public_key_signature: reg.publicKey.identityPublicKeySignature,
        signing_public_key_signature: reg.publicKey.signingPublicKeySignature,
        registration_method: reg.publicKey.registrationMethod,
      },
      version,
      generate_version: Boolean(reg.generateVersion),
    };
    await chat.setup(pin); // durable store BEFORE the POST
    await writeMarker({ registered: false, user_id: userId, version, body });
    console.log("Generated a new identity; stored in Juicebox under your PIN.");
  }
  const ourPublicKey = body.public_key.public_key;

  // Reconcile: if our exact public key is already on the account, adopt it
  // rather than POSTing again (a prior POST may have applied after erroring).
  const existing = await api.getPublicKeys(userId);
  const already = existing.find((k) => (k.publicKey ?? k.public_key) === ourPublicKey);
  if (already) {
    version = String(already.publicKeyVersion ?? already.public_key_version ?? version);
    console.log(`Public key already registered on the account (version ${version}); skipping POST.`);
  } else {
    console.log(`Registering public key version ${version} …`);
    try {
      const resp = await api.addUserPublicKey(userId, body);
      let data = resp.data ?? {};
      if (Array.isArray(data)) data = data[0] ?? {};
      version = String(data.public_key_version ?? version);
    } catch (err) {
      if (err instanceof XChatClient.RateLimited) {
        const when = err.resetEpoch
          ? new Date(err.resetEpoch * 1000).toISOString()
          : "the next window";
        console.error(
          "Registration is rate limited (429). The daily budget is exhausted; " +
            `wait until ${when} and re-run — the saved identity resumes, so no budget is wasted.`,
        );
        process.exit(1);
      }
      throw err;
    }
  }

  // Records the registered key version and the session identity in one call.
  chat.setIdentity(userId, version);

  await writeMarker({
    registered: true,
    user_id: userId,
    version,
    registered_at: new Date().toISOString(),
  });

  console.log();
  console.log("Registration complete. Keys are stored in Juicebox under your PIN.");
  console.log(`  version: ${version}`);
  console.log("Add these to .env to run the bot:");
  console.log("  CHAT_PIN=<your PIN>");
  console.log(`  CHAT_SIGNING_KEY_VERSION=${version}`);
}

async function main() {
  await loadDotenv();
  const args = new Set(process.argv.slice(2));
  const force = args.has("--force");
  if (!args.has("--confirm") && !force) {
    console.log("This registers a bot identity (a rate-limited, one-time action).");
    console.log("Re-run with --confirm when ready:  node src/register.mjs --confirm");
    process.exit(1);
  }
  await register({ force });
}

await main();
