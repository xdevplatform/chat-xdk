/**
 * X Chat SDK - JavaScript Wrapper
 *
 * Juicebox key-storage lifecycle is handled entirely in this JS layer.
 * The Rust WASM `Chat` is a pure crypto engine that never touches
 * globalThis or module-level singletons.
 *
 * Each `ChatWithJuicebox` instance holds its own Juicebox client, but the
 * juicebox-sdk WASM resolves its auth-token callback through a single
 * process-global (`JuiceboxGetAuthToken`). Every Juicebox operation re-arms
 * that global with its own instance's token getter just before running, so
 * *sequential* use of multiple instances in one runtime is correct.
 * *Concurrent* Juicebox operations across instances in one process are not
 * supported: the last-armed instance's token getter services all in-flight
 * calls.
 */

import {
  __featureComplete,
  __juiceboxClientConfig,
  __juiceboxError,
  __noJuiceboxConfig,
  __setErrorClass,
  __validateNewPin,
} from './pkg/chat_xdk_wasm.js';

function isNodeRuntime() {
  return (
    typeof process !== "undefined" &&
    Boolean(process.versions && process.versions.node)
  );
}

/**
 * The error every SDK call throws. `kind` names the failure the same way in
 * every binding: `invalidInput`, `invalidState`, `parse`, `decryption`,
 * `verification`, `invalidPin`, `juicebox` or `internal`.
 * `guessesRemaining` holds the PIN attempts left after an `invalidPin`
 * failure when Juicebox reports them (0: the stored keys are locked), and
 * is null otherwise.
 */
export class ChatXdkError extends Error {
  constructor(kind, message, guessesRemaining = null) {
    super(message);
    this.name = "ChatXdkError";
    this.kind = kind;
    this.guessesRemaining = guessesRemaining;
  }
}

// The names of the failure reasons juicebox-sdk rejects with, by value.
const REGISTER_REASON_BY_VALUE = {
  0: "InvalidAuth",
  1: "UpgradeRequired",
  2: "RateLimitExceeded",
  3: "Assertion",
  4: "Transient",
};

const RECOVER_REASON_BY_VALUE = {
  0: "InvalidPin",
  1: "NotRegistered",
  2: "InvalidAuth",
  3: "UpgradeRequired",
  4: "RateLimitExceeded",
  5: "Assertion",
  6: "Transient",
};

const DELETE_REASON_BY_VALUE = REGISTER_REASON_BY_VALUE;

function toPinBytes(pin) {
  return typeof pin === 'string' ? new TextEncoder().encode(pin) : pin;
}

/**
 * The ChatXdkError for a failed Juicebox `operation` (`register`, `recover`
 * or `delete`): juicebox-sdk rejects with a reason value, or with an object
 * carrying one and, for a wrong PIN, the attempts left.
 */
function juiceboxError(operation, failure, reasonByValue) {
  const value = typeof failure === "object" && failure !== null ? failure.reason : failure;
  const reason = typeof value === "number" ? reasonByValue[value] : value;
  const guessesRemaining = failure?.guesses_remaining;
  return __juiceboxError(
    operation,
    typeof reason === "string" ? reason : String(failure?.message ?? failure),
    Number.isInteger(guessesRemaining) ? guessesRemaining : undefined,
  );
}

/**
 * The Juicebox client config and PIN guess budget of an X API Juicebox
 * config, as the core reads them: `{ sdkConfig, maxGuessCount }`.
 */
function juiceboxClientConfig(juiceboxConfig) {
  if (typeof juiceboxConfig !== "string") {
    throw new ChatXdkError(
      "invalidInput",
      "juiceboxConfig must be the Juicebox config JSON string from the X API",
    );
  }
  return __juiceboxClientConfig(juiceboxConfig);
}

async function initWasmModule() {
  let wasmModule;
  let init;
  if (isNodeRuntime()) {
    // Node 18 ships WebCrypto but does not expose it on the global scope,
    // and the wasm module's random-byte source requires globalThis.crypto.
    if (typeof globalThis.crypto === "undefined") {
      const { webcrypto } = await import("crypto");
      globalThis.crypto = webcrypto;
    }
    // Dynamic import, not require(): the wasm glue is ESM, and require(esm)
    // only exists on Node >= 20.19 while this package supports Node 18+.
    wasmModule = await import("./pkg/chat_xdk_wasm.js");
    init =
      wasmModule?.default ||
      wasmModule?.init ||
      wasmModule?.__wbindgen_init;
    if (typeof init !== "function") {
      throw new ChatXdkError("internal", "WASM init function not found in chat_xdk_wasm module.");
    }
    const fs = await import("fs");
    const wasmUrl = new URL("./pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
    let wasmBytes;
    try {
      wasmBytes = fs.readFileSync(wasmUrl);
    } catch (err) {
      const { fileURLToPath } = await import("url");
      wasmBytes = fs.readFileSync(fileURLToPath(wasmUrl));
    }
    await init({ module_or_path: wasmBytes });
  } else {
    wasmModule = await import("./pkg/chat_xdk_wasm.js");
    init =
      wasmModule?.default ||
      wasmModule?.init ||
      wasmModule?.__wbindgen_init;
    if (typeof init !== "function") {
      throw new ChatXdkError("internal", "WASM init function not found in chat_xdk_wasm module.");
    }
    await init();
  }
  __setErrorClass(ChatXdkError);
  return wasmModule;
}

// The juicebox-sdk glue module is a process-wide singleton: its JS side keeps
// cached typed-array views of one wasm instance's memory, so binding a second
// instance via __wbg_set_wasm leaves those views pointing at the previous
// memory and later calls (as early as `new Configuration`) read garbage or
// trap. Load once and share the promise across every createChat call;
// concurrent first calls must share the same in-flight load for the same
// reason. A failed load is not cached so a later call can retry (and callers
// get the install guidance each time).
let juiceboxSdkPromise = null;

function loadJuiceboxSdk() {
  if (!juiceboxSdkPromise) {
    juiceboxSdkPromise = loadJuiceboxSdkOnce().catch((err) => {
      juiceboxSdkPromise = null;
      throw err;
    });
  }
  return juiceboxSdkPromise;
}

async function loadJuiceboxSdkOnce() {
  if (isNodeRuntime()) {
    const juiceboxBg = await import("juicebox-sdk/juicebox-sdk_bg.js");
    const { createRequire } = await import("module");
    const require = createRequire(import.meta.url);
    const fs = await import("fs");
    const wasmPath = require.resolve("juicebox-sdk/juicebox-sdk_bg.wasm");
    const wasmBytes = fs.readFileSync(wasmPath);
    const { instance } = await WebAssembly.instantiate(wasmBytes, {
      "./juicebox-sdk_bg.js": juiceboxBg,
    });
    juiceboxBg.__wbg_set_wasm(instance.exports);
    return juiceboxBg;
  }
  return await import("juicebox-sdk");
}

// ChatWithJuicebox — JS wrapper that owns both a WasmChat and a Juicebox client

/**
 * JS wrapper that combines the Rust WASM crypto engine with per-instance
 * Juicebox key storage.  Every crypto method is forwarded transparently;
 * setup/unlock/delete/changePin/updateConfig are handled in pure JS.
 */
export class ChatWithJuicebox {
  /** @type {import('./pkg/chat_xdk_wasm.js').Chat} */
  #inner;
  // Null until a Juicebox config is supplied (createChat or updateConfig):
  // a first-boot instance has no config yet because the account's
  // juicebox_config is only created by the public-key POST. Crypto methods
  // never touch it; the Juicebox lifecycle methods refuse while it is null.
  #juiceboxClient;
  #numGuesses;
  #JuiceboxConfiguration;
  #JuiceboxClient;
  // Points the process-global `JuiceboxGetAuthToken` at this instance's token
  // getter. Called before every Juicebox network operation so sequential use
  // of multiple instances presents the right tokens (last-armed wins).
  #armAuthTokenHook;

  constructor(
    wasmChat,
    juiceboxClient,
    numGuesses,
    JuiceboxConfiguration,
    JuiceboxClientCtor,
    armAuthTokenHook,
  ) {
    __setErrorClass(ChatXdkError);
    this.#inner = wasmChat;
    this.#juiceboxClient = juiceboxClient;
    this.#numGuesses = numGuesses;
    this.#JuiceboxConfiguration = JuiceboxConfiguration;
    this.#JuiceboxClient = JuiceboxClientCtor;
    this.#armAuthTokenHook = armAuthTokenHook ?? (() => {});
    startFeatureFetch(wasmChat);
  }

  // Juicebox lifecycle (handled in this JS layer)

  /** A chat created without `getAuthToken` keeps its keys without Juicebox. */
  #requireJuicebox() {
    if (!this.#JuiceboxConfiguration) {
      throw new ChatXdkError(
        "invalidState",
        "No Juicebox for this chat: pass getAuthToken to createChat() to use " +
          "updateConfig/setup/unlock/changePin/delete.",
      );
    }
  }

  /**
   * Every Juicebox operation needs a client, which exists only once a config
   * has been supplied (to createChat or updateConfig). A first-boot instance
   * created without one gets a deliberate error here instead of a TypeError
   * from calling register/recover/delete on null.
   */
  #requireJuiceboxClient() {
    this.#requireJuicebox();
    if (!this.#juiceboxClient) {
      throw __noJuiceboxConfig();
    }
    return this.#juiceboxClient;
  }

  /**
   * Register existing keys with Juicebox. Call generateKeypairs() first.
   * The PIN must meet minimum strength requirements (4+ characters, not a
   * single repeated character or a sequential digit run). Accepts a string
   * or a Uint8Array; pass a Uint8Array if you want to zero it afterwards.
   * Requires a Juicebox config (from createChat or updateConfig).
   */
  async setup(pin) {
    const pinBytes = toPinBytes(pin);
    try {
      __validateNewPin(pinBytes);
      await this.#register(this.#requireJuiceboxClient(), pinBytes);
    } finally {
      if (typeof pin === 'string') pinBytes.fill(0);
    }
    return this.#inner.getPublicKeys();
  }

  /**
   * Unlock: Recover keys from Juicebox using PIN (string or Uint8Array).
   * No strength validation — existing registrations must stay recoverable.
   * Requires a Juicebox config (from createChat or updateConfig).
   */
  async unlock(pin) {
    const client = this.#requireJuiceboxClient();
    const pinBytes = toPinBytes(pin);
    const ownsPin = typeof pin === 'string';
    let secretBytes;
    try {
      this.#armAuthTokenHook();
      secretBytes = await client.recover(pinBytes, new Uint8Array(0));
    } catch (err) {
      throw juiceboxError("recover", err, RECOVER_REASON_BY_VALUE);
    } finally {
      if (ownsPin) pinBytes.fill(0);
    }
    try {
      this.#inner.importKeys({ keys: secretBytes });
    } finally {
      secretBytes.fill(0);
    }
  }

  /**
   * Delete keys from Juicebox. Warning: Irreversible.
   * Requires a Juicebox config (from createChat or updateConfig).
   */
  async delete() {
    const client = this.#requireJuiceboxClient();
    try {
      this.#armAuthTokenHook();
      await client.delete();
    } catch (err) {
      throw juiceboxError("delete", err, DELETE_REASON_BY_VALUE);
    }
    this.#inner.lock();
  }

  /**
   * Re-register keys with a new PIN. The new PIN must meet strength
   * requirements. Requires a Juicebox config (from createChat or updateConfig).
   */
  async changePin(oldPin, newPin) {
    const newPinBytes = toPinBytes(newPin);
    try {
      __validateNewPin(newPinBytes);
      const client = this.#requireJuiceboxClient();
      await this.unlock(oldPin);
      await this.#register(client, newPinBytes);
    } finally {
      if (typeof newPin === 'string') newPinBytes.fill(0);
    }
  }

  /** Register the loaded keys under `pinBytes`, wiping the exported copy. */
  async #register(client, pinBytes) {
    const secretBytes = this.#inner.exportKeys();
    try {
      this.#armAuthTokenHook();
      await client.register(pinBytes, secretBytes, new Uint8Array(0), this.#numGuesses);
    } catch (err) {
      throw juiceboxError("register", err, REGISTER_REASON_BY_VALUE);
    } finally {
      secretBytes.fill(0);
    }
  }

  /**
   * Update Juicebox config (e.g. to refresh auth tokens): (re-)creates the
   * client, with the PIN guess budget the config sets. On an instance
   * created without a config, this is what enables
   * setup/unlock/changePin/delete — first boot calls it with the
   * `juicebox_config` created by the public-key POST, then `setup(pin)`.
   */
  updateConfig(juiceboxConfig) {
    this.#requireJuicebox();
    const { sdkConfig, maxGuessCount } = juiceboxClientConfig(juiceboxConfig);
    const config = new this.#JuiceboxConfiguration(sdkConfig);
    this.#juiceboxClient = new this.#JuiceboxClient(config, []);
    this.#numGuesses = maxGuessCount;
  }

  // Forwarded crypto methods — delegate to inner WasmChat

  setRejectUnverified(reject) { return this.#inner.setRejectUnverified(reject); }
  generateKeypairs() { return this.#inner.generateKeypairs(); }
  setIdentity(params) { return this.#inner.setIdentity(params); }
  setCacheKeys(enabled) { return this.#inner.setCacheKeys(enabled); }
  setSigningKeys(signingKeys) { return this.#inner.setSigningKeys(signingKeys); }
  importKeys(params) { return this.#inner.importKeys(params); }
  exportKeys() { return this.#inner.exportKeys(); }
  getPublicKeys() { return this.#inner.getPublicKeys(); }
  getPublicKeyFingerprint() { return this.#inner.getPublicKeyFingerprint(); }
  isUnlocked() { return this.#inner.isUnlocked(); }
  hasIdentityKey() { return this.#inner.hasIdentityKey(); }
  lock() { return this.#inner.lock(); }
  decryptConversationKey(b64) { return this.#inner.decryptConversationKey(b64); }
  extractConversationKeys(events) { return this.#inner.extractConversationKeys(events); }
  decryptEvent(params) { return this.#inner.decryptEvent(params); }
  decryptEvents(params) { return this.#inner.decryptEvents(params); }
  sign(data) { return this.#inner.sign(data); }
  verify(publicKeyB64, signature, data) { return this.#inner.verify(publicKeyB64, signature, data); }
  verifyKeyBinding(identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64) {
    return this.#inner.verifyKeyBinding(identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64);
  }
  matchesRegisteredKey(publicKeyB64) { return this.#inner.matchesRegisteredKey(publicKeyB64); }
  encryptMessage(params) { return this.#inner.encryptMessage(params); }
  encryptReply(params) { return this.#inner.encryptReply(params); }
  encryptAddReaction(params) { return this.#inner.encryptAddReaction(params); }
  encryptRemoveReaction(params) { return this.#inner.encryptRemoveReaction(params); }
  encryptEdit(params) { return this.#inner.encryptEdit(params); }
  prepareMessageDelete(params) { return this.#inner.prepareMessageDelete(params); }
  prepareMarkConversationRead(params) { return this.#inner.prepareMarkConversationRead(params); }
  encryptFile(params) { return this.#inner.encryptFile(params); }
  fileEncryptor(params) { return this.#inner.fileEncryptor(params); }
  decryptFile(params) { return this.#inner.decryptFile(params); }
  fileDecryptor(params) { return this.#inner.fileDecryptor(params); }
  decrypt(ciphertext, key) { return this.#inner.decrypt(ciphertext, key); }
  prepareConversationKeyChange(params) { return this.#inner.prepareConversationKeyChange(params); }
  prepareGroupMembersChange(params) { return this.#inner.prepareGroupMembersChange(params); }
  prepareGroupCreate(params) { return this.#inner.prepareGroupCreate(params); }
  prepareGroupMembersRemove(params) { return this.#inner.prepareGroupMembersRemove(params); }
  prepareGroupLeave(params) { return this.#inner.prepareGroupLeave(params); }
  prepareGroupTitleChange(params) { return this.#inner.prepareGroupTitleChange(params); }
  prepareGroupAvatarChange(params) { return this.#inner.prepareGroupAvatarChange(params); }
  prepareGroupDescriptionChange(params) { return this.#inner.prepareGroupDescriptionChange(params); }
  prepareGroupAdminsAdd(params) { return this.#inner.prepareGroupAdminsAdd(params); }
  prepareGroupAdminsRemove(params) { return this.#inner.prepareGroupAdminsRemove(params); }
  prepareGroupInviteEnable(params) { return this.#inner.prepareGroupInviteEnable(params); }
  prepareGroupInviteDisable(params) { return this.#inner.prepareGroupInviteDisable(params); }
  prepareGroupJoinRequest(params) { return this.#inner.prepareGroupJoinRequest(params); }
  prepareGroupJoinReject(params) { return this.#inner.prepareGroupJoinReject(params); }
  prepareMessageTtlChange(params) { return this.#inner.prepareMessageTtlChange(params); }
  prepareMessageTtlRemove(params) { return this.#inner.prepareMessageTtlRemove(params); }
  prepareScreenCapture(params) { return this.#inner.prepareScreenCapture(params); }

  /**
   * Release the WASM-side crypto engine: clears key material (`lock()`) and
   * frees the underlying WASM object. The instance must not be used
   * afterwards. When reusing the instance, `lock()` alone suffices for key
   * hygiene.
   */
  free() {
    this.#inner.lock();
    this.#inner.free();
  }
}

// Feature switches (GET /2/chat/features). A chat reads them once, when it is
// created: the wasm core decides what to fetch and what an answer means, and
// this module performs the GET. Nothing here is API.

/** Start the one read of `wasmChat`'s feature switches. */
function startFeatureFetch(wasmChat) {
  const request = wasmChat.__featureStart();
  if (request === undefined) return;
  getFeatures(request.url, request.timeoutMs, request.maxBytes).then(({ status, body }) =>
    __featureComplete(request.id, status, body),
  );
}

/** In Node, keep a request's timer from holding the process open. */
function unrefTimer(timer) {
  timer?.unref?.();
  return timer;
}

const NO_RESPONSE = { status: 0, body: new Uint8Array(0) };

/**
 * GET `url` within `timeoutMs`: its status and body, read to its end or to
 * one byte past `maxBytes`. Status 0 when no complete response arrived.
 */
function getFeatures(url, timeoutMs, maxBytes) {
  const http = nodeHttpModule(url);
  return http ? getWithNode(http, url, timeoutMs, maxBytes) : getWithFetch(url, timeoutMs, maxBytes);
}

/**
 * Node's own http or https module for `url`, when the runtime hands out
 * builtins without an import (Node 20.16 and later), so bundlers for browsers
 * never see one; undefined anywhere else.
 */
function nodeHttpModule(url) {
  const getBuiltin = globalThis.process?.getBuiltinModule;
  if (typeof getBuiltin !== "function") return undefined;
  try {
    return getBuiltin(new URL(url).protocol === "http:" ? "node:http" : "node:https");
  } catch {
    return undefined;
  }
}

/**
 * GET `url` with Node's http module. Its socket and timer are unref'd, so a
 * request in flight never keeps the process alive.
 */
function getWithNode(http, url, timeoutMs, maxBytes) {
  return new Promise((resolve) => {
    let settled = false;
    let req = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req?.destroy();
      resolve(result);
    };
    const timer = unrefTimer(setTimeout(() => finish(NO_RESPONSE), timeoutMs));
    try {
      req = http.get(url, { headers: { Accept: "application/json" } }, (response) => {
        const chunks = [];
        let size = 0;
        const done = () =>
          finish({ status: response.statusCode, body: new Uint8Array(globalThis.Buffer.concat(chunks)) });
        response.on("data", (chunk) => {
          if (settled) return;
          chunks.push(chunk.subarray(0, maxBytes + 1 - size));
          size += chunk.length;
          if (size > maxBytes) done();
        });
        response.on("end", done);
        response.on("error", () => finish(NO_RESPONSE));
      });
      req.on("socket", (socket) => socket.unref());
      req.on("error", () => finish(NO_RESPONSE));
    } catch {
      finish(NO_RESPONSE);
    }
  });
}

/**
 * GET `url` with `fetch`: the browser's, or Node's where its http module is
 * out of reach. The timeout covers reading the body too.
 */
async function getWithFetch(url, timeoutMs, maxBytes) {
  const request = new AbortController();
  const timer = unrefTimer(setTimeout(() => request.abort(), timeoutMs));
  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: request.signal,
    });
    const body = await readCappedBody(response, maxBytes);
    return body ? { status: response.status, body } : NO_RESPONSE;
  } catch {
    return NO_RESPONSE;
  } finally {
    clearTimeout(timer);
    request.abort();
  }
}

/**
 * The body, read to its end or to one byte past `maxBytes`, or null when
 * the runtime cannot stream it: reading it whole could take any size.
 */
async function readCappedBody(response, maxBytes) {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body?.getReader?.();
  if (!reader) return null;
  const chunks = [];
  let size = 0;
  while (size <= maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.byteLength;
  }
  if (size > maxBytes) reader.cancel().catch(() => {});
  const body = new Uint8Array(Math.min(size, maxBytes + 1));
  let offset = 0;
  for (const chunk of chunks) {
    const part = chunk.subarray(0, body.length - offset);
    body.set(part, offset);
    offset += part.length;
  }
  return body;
}

/**
 * Create a Chat instance, with Juicebox key storage when `getAuthToken` is
 * given.
 *
 * @param {Object} [options] - Configuration options
 * @param {string} [options.juiceboxConfig] - Juicebox configuration JSON from
 *                                            the X API. Omit on first boot —
 *                                            before the first public-key POST
 *                                            the account has no
 *                                            juicebox_config; supply it later
 *                                            via updateConfig()
 * @param {Function} [options.getAuthToken] - Async function to get auth token for a realm,
 *                                            required to use Juicebox
 *                                            Signature: (realmId: string) => Promise<string>
 * @returns {Promise<ChatWithJuicebox>} Initialized chat instance
 *
 * @example
 * // First boot — the account has no juicebox_config yet
 * const chat = await createChat({ getAuthToken });
 * const payload = chat.generateKeypairs();
 * // POST payload to /2/users/:id/public_keys (this creates juicebox_config),
 * // then GET it back and store the keys under a PIN:
 * chat.updateConfig(configFromXApi);
 * await chat.setup("2580");
 *
 * // Subsequent sessions — the account is provisioned
 * const chat = await createChat({
 *   juiceboxConfig: configFromXApi,
 *   getAuthToken: async (realmId) => {
 *     const response = await fetch('/api/juicebox/token?realm=' + realmId);
 *     return response.text();
 *   },
 * });
 * await chat.unlock("2580");
 *
 * // Keys kept elsewhere: no Juicebox, so no juicebox-sdk either
 * const chat = await createChat();
 * chat.importKeys({ keys, signingKeyVersion });
 */
export async function createChat(options = {}) {
  const { juiceboxConfig, getAuthToken } = options;

  if (
    (getAuthToken !== undefined || juiceboxConfig != null) &&
    typeof getAuthToken !== 'function'
  ) {
    throw new ChatXdkError('invalidInput', 'getAuthToken must be an async function');
  }

  const wasmModule = await initWasmModule();
  const juicebox = getAuthToken ? await juiceboxRuntime(options, getAuthToken) : null;

  // First boot has no config yet (the account's juicebox_config is created
  // by the public-key POST), so no Juicebox Configuration/Client is built;
  // updateConfig() constructs them once the real config exists. Crypto
  // methods and generateKeypairs need neither. Only an absent config means
  // first boot — a present-but-empty value is a caller bug and fails here
  // rather than surfacing later as a missing-config error.
  let juiceboxClient = null;
  let numGuesses;
  if (juiceboxConfig != null) {
    const { sdkConfig, maxGuessCount } = juiceboxClientConfig(juiceboxConfig);
    juiceboxClient = new juicebox.Client(new juicebox.Configuration(sdkConfig), []);
    numGuesses = maxGuessCount;
  }

  return new ChatWithJuicebox(
    new wasmModule.Chat(),
    juiceboxClient,
    numGuesses,
    juicebox?.Configuration ?? null,
    juicebox?.Client ?? null,
    juicebox?.armAuthTokenHook ?? null,
  );
}

/**
 * The juicebox-sdk constructors, and the hook that points juicebox-sdk at
 * `getAuthToken`.
 */
async function juiceboxRuntime(options, getAuthToken) {
  // Tests inject stub constructors through the internal `juiceboxModule`
  // option so this flow runs without the juicebox-sdk WASM or network
  // realms; it is not part of the public API.
  let juiceboxModule = options.juiceboxModule;
  if (!juiceboxModule) {
    try {
      juiceboxModule = await loadJuiceboxSdk();
    } catch (e) {
      throw new ChatXdkError(
        "juicebox",
        "Failed to load juicebox-sdk (an optional peer dependency). " +
        "Install it with `npm install juicebox-sdk`, or build it from " +
        "https://github.com/juicebox-systems/juicebox-sdk:\n" +
        "  cd juicebox-sdk/rust/sdk/bridge/wasm && wasm-pack build --target nodejs --out-dir pkg --out-name juicebox-sdk\n" +
        "  npm install /path/to/juicebox-sdk/rust/sdk/bridge/wasm/pkg\n" +
        "Original error: " + e.message
      );
    }
  }
  if (!juiceboxModule.Configuration) {
    throw new ChatXdkError('juicebox', 'juicebox-sdk Configuration export is missing');
  }

  // The juicebox-sdk WASM resolves `JuiceboxGetAuthToken` as a bare-name
  // global on every register/recover/delete call (not just construction).
  // The global is process-wide, so each instance re-arms it with its own
  // token getter immediately before every Juicebox operation; concurrent
  // Juicebox operations across instances are not supported (last-armed wins).
  const authTokenHook = async (realmId) => {
    const realmIdHex =
      typeof realmId === "string"
        ? realmId
        : Array.from(realmId)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    return await getAuthToken(realmIdHex);
  };
  const armAuthTokenHook = () => {
    globalThis.JuiceboxGetAuthToken = authTokenHook;
  };
  armAuthTokenHook();
  return {
    Client: juiceboxModule.Client,
    Configuration: juiceboxModule.Configuration,
    armAuthTokenHook,
  };
}

// Re-export utility functions.
export {
  encryptedFileSize,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  detectMimeType,
  detectImageDimensions,
} from './pkg/chat_xdk_wasm.js';
