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

function isNodeRuntime() {
  return (
    typeof process !== "undefined" &&
    Boolean(process.versions && process.versions.node)
  );
}

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

const MIN_PIN_LENGTH = 4;

function toPinBytes(pin) {
  return typeof pin === 'string' ? new TextEncoder().encode(pin) : pin;
}

/**
 * Validate PIN strength for new registrations: at least MIN_PIN_LENGTH
 * characters, not a single repeated character, not an ascending or
 * descending run of digits. Never applied on unlock.
 */
function validatePinStrength(pinBytes) {
  // Error messages match the native core's weak-PIN errors byte-for-byte so
  // callers can match on them across bindings.
  if (pinBytes.length < MIN_PIN_LENGTH) {
    throw new Error(`PIN must be at least ${MIN_PIN_LENGTH} characters`);
  }
  if (pinBytes.every((b) => b === pinBytes[0])) {
    throw new Error('PIN must not be a single repeated character');
  }
  const allDigits = pinBytes.every((b) => b >= 0x30 && b <= 0x39);
  let ascending = true;
  let descending = true;
  for (let i = 1; i < pinBytes.length; i++) {
    if (pinBytes[i] !== pinBytes[i - 1] + 1) ascending = false;
    if (pinBytes[i] !== pinBytes[i - 1] - 1) descending = false;
  }
  if (allDigits && (ascending || descending)) {
    throw new Error('PIN must not be a sequential run of digits');
  }
}

function formatJuiceboxError(err, reasonMap) {
  if (!err) {
    return "Unknown Juicebox error";
  }
  const reasonValue = err.reason ?? err.reasonCode ?? err.code;
  const reason =
    typeof reasonValue === "number" ? reasonMap[reasonValue] : reasonValue;
  const guessesRemaining =
    err.guesses_remaining ?? err.guessesRemaining ?? err.guesses;
  const parts = [];
  if (reason) {
    parts.push(`reason=${reason}`);
  }
  if (guessesRemaining !== undefined) {
    parts.push(`guesses_remaining=${guessesRemaining}`);
  }
  if (!parts.length) {
    return `Unknown Juicebox error: ${String(err)}`;
  }
  return parts.join(" ");
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
      throw new Error("WASM init function not found in chat_xdk_wasm module.");
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
      throw new Error("WASM init function not found in chat_xdk_wasm module.");
    }
    await init();
  }
  return wasmModule;
}

async function loadJuiceboxSdk() {
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

/**
 * Resolve the PIN guess budget for Juicebox registration, matching the
 * native bindings: a `max_guess_count` that is a non-negative integer
 * (including 0) applies as-is; a fractional, negative, or non-numeric value
 * falls back to the shape default — 20 for the `sdk_config` and
 * `key_store_token_map_json` shapes, 5 otherwise. An explicit
 * `maxGuessCount` option overrides the config under
 * the same integer rule. Exported for tests; `createChat` calls it
 * internally.
 *
 * @param {Object} configValue - Parsed Juicebox config JSON from the X API
 * @param {number} [maxGuessCount] - Explicit override from createChat options
 * @returns {number} The number of PIN guesses to register with
 */
export function resolveMaxGuessCount(configValue, maxGuessCount) {
  if (Number.isSafeInteger(maxGuessCount) && maxGuessCount >= 0) {
    return maxGuessCount;
  }
  const fromConfig = configValue?.max_guess_count;
  if (Number.isSafeInteger(fromConfig) && fromConfig >= 0) {
    return fromConfig;
  }
  return typeof configValue?.sdk_config === "string" ||
    typeof configValue?.key_store_token_map_json === "string"
    ? 20
    : 5;
}

/**
 * Derive the value to hand the Juicebox `Configuration` constructor from a
 * parsed X API config. The `sdk_config` wrapper shape is unwrapped to its
 * embedded SDK config JSON string (which the Juicebox constructor accepts
 * directly); the X API `juicebox_config` object shape is unwrapped to its
 * `key_store_token_map_json` string, which is used **verbatim** because it
 * carries each realm's `public_key` and the server's register/recover
 * thresholds — the realms require both; a raw realms config passes through
 * unchanged; a bare `token_map` shape (an array of
 * `{ key, value: { address } }` entries, no `key_store_token_map_json`) is
 * converted to a realms config with majority recover threshold, the same
 * derivation the native bindings apply. A non-array `token_map` is rejected
 * here, with the same message the core parser uses, rather than handed to
 * the Juicebox constructor to fail obscurely. Realm auth tokens are not
 * taken from the config in this wrapper — they come from the `getAuthToken`
 * callback.
 */
export function juiceboxClientConfig(configValue) {
  if (typeof configValue?.sdk_config === "string") {
    return configValue.sdk_config;
  }
  if (configValue?.key_store_token_map_json !== undefined) {
    if (typeof configValue.key_store_token_map_json !== "string") {
      throw new Error("key_store_token_map_json must be a string");
    }
    // A malformed embedded config is an error rather than a fall-through to
    // the lossy token_map derivation, which would silently drop the realm
    // public keys and produce configs that can never reach the recover
    // threshold. It must parse to a JSON object — merely valid JSON like
    // "42" or "[]" would be handed to the Juicebox constructor to fail
    // obscurely at setup/unlock time.
    let parsed;
    try {
      parsed = JSON.parse(configValue.key_store_token_map_json);
    } catch (e) {
      throw new Error(`Invalid key_store_token_map_json: ${e.message}`);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Invalid key_store_token_map_json: not a JSON object");
    }
    return configValue.key_store_token_map_json;
  }
  if (
    configValue?.token_map !== undefined &&
    configValue?.realms === undefined &&
    !Array.isArray(configValue.token_map)
  ) {
    throw new Error("Missing token_map or sdk_config");
  }
  if (Array.isArray(configValue?.token_map) && configValue?.realms === undefined) {
    const realms = configValue.token_map.map((entry) => {
      const id = entry?.key;
      const address = entry?.value?.address;
      if (typeof id !== "string" || typeof address !== "string") {
        throw new Error(
          "Invalid token_map entry: expected { key, value: { address } }",
        );
      }
      return { id, address };
    });
    return {
      realms,
      register_threshold: realms.length,
      recover_threshold: Math.floor(realms.length / 2) + 1,
      pin_hashing_mode: "Standard2019",
    };
  }
  return configValue;
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
  #juiceboxClient;
  #numGuesses;
  // The raw `maxGuessCount` createChat option (undefined when not provided),
  // kept so updateConfig re-resolves the budget under the same override
  // semantics as construction: an explicit option keeps winning.
  #maxGuessCountOverride;
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
    maxGuessCountOverride,
  ) {
    this.#inner = wasmChat;
    this.#juiceboxClient = juiceboxClient;
    this.#numGuesses = numGuesses;
    this.#maxGuessCountOverride = maxGuessCountOverride;
    this.#JuiceboxConfiguration = JuiceboxConfiguration;
    this.#JuiceboxClient = JuiceboxClientCtor;
    this.#armAuthTokenHook = armAuthTokenHook ?? (() => {});
  }

  // Juicebox lifecycle (handled in this JS layer)

  /**
   * Register existing keys with Juicebox. Call generateKeypairs() first.
   * The PIN must meet minimum strength requirements (4+ characters, not a
   * single repeated character or a sequential digit run). Accepts a string
   * or a Uint8Array; pass a Uint8Array if you want to zero it afterwards.
   */
  async setup(pin) {
    const pinBytes = toPinBytes(pin);
    const ownsPin = typeof pin === 'string';
    validatePinStrength(pinBytes);
    const secretBytes = this.#inner.exportKeys();
    try {
      this.#armAuthTokenHook();
      await this.#juiceboxClient.register(
        pinBytes,
        secretBytes,
        new Uint8Array(0),
        this.#numGuesses,
      );
    } catch (err) {
      throw new Error(`Juicebox register failed: ${formatJuiceboxError(err, REGISTER_REASON_BY_VALUE)}`);
    } finally {
      secretBytes.fill(0);
      if (ownsPin) pinBytes.fill(0);
    }
    return this.#inner.getPublicKeys();
  }

  /**
   * Unlock: Recover keys from Juicebox using PIN (string or Uint8Array).
   * No strength validation — existing registrations must stay recoverable.
   */
  async unlock(pin) {
    const pinBytes = toPinBytes(pin);
    const ownsPin = typeof pin === 'string';
    let secretBytes;
    try {
      this.#armAuthTokenHook();
      secretBytes = await this.#juiceboxClient.recover(pinBytes, new Uint8Array(0));
    } catch (err) {
      throw new Error(`Juicebox recovery failed: ${formatJuiceboxError(err, RECOVER_REASON_BY_VALUE)}`);
    } finally {
      if (ownsPin) pinBytes.fill(0);
    }
    try {
      this.#inner.importKeys(secretBytes);
    } finally {
      secretBytes.fill(0);
    }
  }

  /** Delete keys from Juicebox. Warning: Irreversible. */
  async delete() {
    this.#armAuthTokenHook();
    await this.#juiceboxClient.delete();
    this.#inner.lock();
  }

  /** Re-register keys with a new PIN. The new PIN must meet strength requirements. */
  async changePin(oldPin, newPin) {
    const newPinBytes = toPinBytes(newPin);
    const ownsNewPin = typeof newPin === 'string';
    validatePinStrength(newPinBytes);
    await this.unlock(oldPin);
    const secretBytes = this.#inner.exportKeys();
    try {
      this.#armAuthTokenHook();
      await this.#juiceboxClient.register(
        newPinBytes,
        secretBytes,
        new Uint8Array(0),
        this.#numGuesses,
      );
    } catch (err) {
      throw new Error(`Juicebox re-registration failed: ${formatJuiceboxError(err, REGISTER_REASON_BY_VALUE)}`);
    } finally {
      secretBytes.fill(0);
      if (ownsNewPin) newPinBytes.fill(0);
    }
  }

  /**
   * Update Juicebox config (e.g. to refresh auth tokens). Re-creates the
   * client and re-resolves the PIN guess budget from the new config; an
   * explicit createChat `maxGuessCount` override keeps winning.
   */
  updateConfig(juiceboxConfig) {
    const configValue = JSON.parse(juiceboxConfig);
    const config = new this.#JuiceboxConfiguration(juiceboxClientConfig(configValue));
    this.#juiceboxClient = new this.#JuiceboxClient(config, []);
    this.#numGuesses = resolveMaxGuessCount(configValue, this.#maxGuessCountOverride);
  }

  // Forwarded crypto methods — delegate to inner WasmChat

  setRejectUnverified(reject) { return this.#inner.setRejectUnverified(reject); }
  generateKeypairs() { return this.#inner.generateKeypairs(); }
  setIdentity(userId, signingKeyVersion) { return this.#inner.setIdentity(userId, signingKeyVersion); }
  setCacheKeys(enabled) { return this.#inner.setCacheKeys(enabled); }
  setSigningKeys(signingKeys) { return this.#inner.setSigningKeys(signingKeys); }
  getPublicKeys() { return this.#inner.getPublicKeys(); }
  getPublicKeyFingerprint() { return this.#inner.getPublicKeyFingerprint(); }
  isUnlocked() { return this.#inner.isUnlocked(); }
  hasIdentityKey() { return this.#inner.hasIdentityKey(); }
  lock() { return this.#inner.lock(); }
  decryptConversationKey(b64) { return this.#inner.decryptConversationKey(b64); }
  extractConversationKeys(events) { return this.#inner.extractConversationKeys(events); }
  decryptEvent(eventB64, conversationKeys, signingKeys) {
    return this.#inner.decryptEvent(eventB64, conversationKeys, signingKeys);
  }
  decryptEvents(events, signingKeys) {
    return this.#inner.decryptEvents(events, signingKeys);
  }
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
  encryptStream(plaintext, key) { return this.#inner.encryptStream(plaintext, key); }
  decryptStream(encrypted, key) { return this.#inner.decryptStream(encrypted, key); }
  streamEncryptor(key) { return this.#inner.streamEncryptor(key); }
  streamDecryptor(key) { return this.#inner.streamDecryptor(key); }
  encrypt(plaintext, key) { return this.#inner.encrypt(plaintext, key); }
  decrypt(ciphertext, key) { return this.#inner.decrypt(ciphertext, key); }
  prepareConversationKeyChange(params) { return this.#inner.prepareConversationKeyChange(params); }
  prepareGroupMembersChange(params) { return this.#inner.prepareGroupMembersChange(params); }
  prepareGroupCreate(params) { return this.#inner.prepareGroupCreate(params); }

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

/**
 * Create a Chat instance with integrated Juicebox support.
 * 
 * @param {Object} options - Configuration options
 * @param {string} options.juiceboxConfig - Juicebox configuration JSON from X API
 * @param {Function} options.getAuthToken - Async function to get auth token for a realm
 *                                          Signature: (realmId: string) => Promise<string>
 * @param {number} [options.maxGuessCount] - Optional override for the PIN guess
 *                                           budget (see CreateChatOptions)
 * @returns {Promise<ChatWithJuicebox>} Initialized chat instance
 * 
 * @example
 * const chat = await createChat({
 *   juiceboxConfig: configFromXApi,
 *   getAuthToken: async (realmId) => {
 *     const response = await fetch('/api/juicebox/token?realm=' + realmId);
 *     return response.text();
 *   },
 * });
 * 
 * // First time setup
 * const payload = chat.generateKeypairs();
 * // POST payload to X API, then call setup once you have juiceboxConfig
 * await chat.setup("2580");
 * 
 * // Subsequent sessions
 * await chat.unlock("2580");
 */
export async function createChat(options) {
  const { juiceboxConfig, getAuthToken, maxGuessCount } = options;

  if (!juiceboxConfig) {
    throw new Error('juiceboxConfig is required');
  }
  if (!getAuthToken || typeof getAuthToken !== 'function') {
    throw new Error('getAuthToken must be an async function');
  }

  // Load Juicebox WASM SDK. Tests inject stub constructors through the
  // internal `juiceboxModule` option so this flow runs without the
  // juicebox-sdk WASM or network realms; it is not part of the public API.
  let JuiceboxClientCtor;
  let JuiceboxConfiguration;
  if (options.juiceboxModule) {
    JuiceboxClientCtor = options.juiceboxModule.Client;
    JuiceboxConfiguration = options.juiceboxModule.Configuration;
  } else {
    try {
      const juiceboxModule = await loadJuiceboxSdk();
      JuiceboxClientCtor = juiceboxModule.Client;
      JuiceboxConfiguration = juiceboxModule.Configuration;
    } catch (e) {
      throw new Error(
        "Failed to load juicebox-sdk (an optional peer dependency). " +
        "Install it with `npm install juicebox-sdk`, or build it from " +
        "https://github.com/juicebox-systems/juicebox-sdk:\n" +
        "  cd juicebox-sdk/rust/sdk/bridge/wasm && wasm-pack build --target nodejs --out-dir pkg --out-name juicebox-sdk\n" +
        "  npm install /path/to/juicebox-sdk/rust/sdk/bridge/wasm/pkg\n" +
        "Original error: " + e.message
      );
    }
  }
  if (!JuiceboxConfiguration) {
    throw new Error('juicebox-sdk Configuration export is missing');
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

  const configValue = JSON.parse(juiceboxConfig);
  const config = new JuiceboxConfiguration(juiceboxClientConfig(configValue));
  const juiceboxClient = new JuiceboxClientCtor(config, []);

  const numGuesses = resolveMaxGuessCount(configValue, maxGuessCount);

  // Load Rust WASM crypto engine
  const wasmModule = await initWasmModule();
  const wasmChat = new wasmModule.Chat();

  return new ChatWithJuicebox(
    wasmChat,
    juiceboxClient,
    numGuesses,
    JuiceboxConfiguration,
    JuiceboxClientCtor,
    armAuthTokenHook,
    maxGuessCount,
  );
}

// Re-export utility functions.
export {
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  detectMimeType,
  detectImageDimensions,
} from './pkg/chat_xdk_wasm.js';
