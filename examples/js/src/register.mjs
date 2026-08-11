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
 * PIN is required. The account's `juicebox_config` is created BY the
 * public-key POST, so a brand-new user necessarily runs first boot in this
 * order: create the chat with no config, generate keys, POST the public key,
 * fetch the now-existing `juicebox_config`, then `updateConfig` + `setup(pin)`
 * to make the identity durable. Safety properties:
 *   1. the one-time marker (state/registration.json) — refuse to re-register;
 *   2. the marker (with the public POST body) is written only after a
 *      successful setup(pin), so a marker body always denotes an identity that
 *      is recoverable from Juicebox via unlock(pin) — a run that finds a body
 *      without registered:true recovers that identity and re-sends the saved
 *      body instead of minting a new one;
 *   3. reconcile-before-POST — if our exact public key is already on the
 *      account (a prior POST can apply server-side even after erroring), adopt
 *      it and skip the POST.
 * Stop cleanly on HTTP 429 rather than retrying. A 429 on a freshly minted
 * identity discards it — nothing durable was stored and the failed POST
 * consumed no budget — so the re-run simply mints a new one.
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
 * Realm auth tokens live in the `token_map` of the X API `juicebox_config`,
 * which does not exist until the first public-key POST. The getter handed to
 * createChat therefore reads a mutable map, (re)filled from whichever config
 * is fetched later in the run.
 */
const realmTokens = new Map();

function loadRealmTokens(configJson) {
  const parsed = JSON.parse(configJson);
  realmTokens.clear();
  for (const entry of parsed.token_map ?? parsed.tokenMap ?? []) {
    const realm = String(entry?.key ?? "").toLowerCase();
    const token = entry?.value?.token;
    if (realm && typeof token === "string") realmTokens.set(realm, token);
  }
}

const getAuthToken = async (realmId) => realmTokens.get(String(realmId).toLowerCase()) ?? "";

/**
 * The PIN rules setup() enforces, checked before any budget is spent:
 * setup() can only run after the public-key POST (the config it needs is
 * created by that POST), so a PIN it would reject must fail the run before
 * the POST rather than strand a freshly registered key. Returns the reason
 * the PIN is unacceptable, or null when it is fine.
 */
function weakPinReason(pin) {
  const bytes = new TextEncoder().encode(pin);
  if (bytes.length < 4) return "must be at least 4 characters";
  if (bytes.every((b) => b === bytes[0])) return "must not be a single repeated character";
  const allDigits = bytes.every((b) => b >= 0x30 && b <= 0x39);
  let ascending = true;
  let descending = true;
  for (let i = 1; i < bytes.length; i++) {
    if (bytes[i] !== bytes[i - 1] + 1) ascending = false;
    if (bytes[i] !== bytes[i - 1] - 1) descending = false;
  }
  if (allDigits && (ascending || descending)) return "must not be a sequential run of digits";
  return null;
}

/** Fetch juicebox_config, feed its realm tokens to getAuthToken, and arm the chat with it. */
async function applyJuiceboxConfig(api, chat, userId) {
  const { configJson } = await api.getJuiceboxConfig(userId);
  loadRealmTokens(configJson);
  chat.updateConfig(configJson);
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

  // No juicebox_config yet on first boot (the POST below creates it), so the
  // chat is created without one; crypto and generateKeypairs work regardless.
  const chat = await createChat({ getAuthToken });

  // A marker body without registered:true denotes an identity whose
  // setup(pin) succeeded but whose registration was never confirmed complete:
  // it is durable in Juicebox and juicebox_config exists. Recover that SAME
  // identity and re-send the saved registration body instead of minting a new
  // one (which would waste the strict daily budget). Without a saved body
  // there is nothing to resume — mint a fresh identity.
  let body;
  let version;
  let minted = false;
  if (marker.body && !force) {
    await applyJuiceboxConfig(api, chat, userId);
    await chat.unlock(pin);
    body = marker.body;
    version = String(marker.version ?? "1");
    console.log("Resuming the saved identity (recovered from Juicebox).");
  } else {
    const weak = weakPinReason(pin);
    if (weak) {
      console.error(
        `CHAT_PIN ${weak}. setup(pin) would reject it after the rate-limited ` +
          "POST and strand the new key — pick a stronger PIN and re-run.",
      );
      process.exit(1);
    }
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
    minted = true;
    console.log("Generated a new identity.");
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
            `wait until ${when} and re-run. ` +
            (minted
              ? "The just-minted identity is discarded (nothing durable was stored " +
                "and the failed POST consumed no budget); the re-run mints a new one."
              : "The saved identity resumes, so no budget is wasted."),
        );
        process.exit(1);
      }
      throw err;
    }
  }

  // First boot only: the POST above created juicebox_config, so the identity
  // can now be made durable. The private key exists only in this process
  // until setup() stores it, so a transient failure fetching the just-created
  // config or reaching the realms is retried before declaring the freshly
  // registered key lost. The marker is written only after setup succeeds — it
  // must never point at an identity that cannot be recovered via unlock.
  if (minted) {
    let stored = false;
    let lastErr;
    for (let attempt = 1; attempt <= 3 && !stored; attempt++) {
      try {
        if (attempt > 1) {
          console.log(`Storing keys in Juicebox failed; retrying (attempt ${attempt}/3) …`);
          await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
        }
        await applyJuiceboxConfig(api, chat, userId);
        await chat.setup(pin);
        stored = true;
      } catch (err) {
        lastErr = err;
      }
    }
    if (!stored) {
      console.error(
        `Storing the keys in Juicebox failed AFTER public key version ${version} was ` +
          "registered on the account. This binding has no key export, so that key is " +
          "now unusable; re-run with --force to mint and register a replacement " +
          "(this consumes registration budget).",
      );
      throw lastErr;
    }
    console.log("Keys stored in Juicebox under your PIN.");
  }

  // Records the registered key version and the session identity in one call.
  chat.setIdentity(userId, version);

  await writeMarker({
    registered: true,
    user_id: userId,
    version,
    body,
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
