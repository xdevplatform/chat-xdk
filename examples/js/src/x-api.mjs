/**
 * X Chat API access via the X API SDK (XDK).
 *
 * Every REST call goes through the XDK client so request signing, models, and
 * endpoint paths stay in sync with the X API. Authentication is an OAuth2 user
 * access token (scopes dm.read + dm.write).
 */
import { Client } from "@xdevplatform/xdk";

const BASE_URL = "https://api.x.com";

export class XChatClient {
  constructor(accessToken) {
    this.client = new Client({ accessToken });
    this.accessToken = accessToken;
  }

  async getMyUserId() {
    const resp = await this.client.users.getMe();
    return String(resp.data.id);
  }

  /**
   * Fetch a user's registered public keys (for ECIES + verification, or to
   * check your own before registering).
   *
   * Every field of the public_key resource (public_key, signing_public_key,
   * identity_public_key_signature, public_key_version, juicebox_config) is
   * always included; the route takes no public_key.fields parameter.
   */
  async getPublicKeys(userId) {
    const resp = await this.client.users.getPublicKey(userId);
    const data = resp.data ?? [];
    return Array.isArray(data) ? data : [data];
  }

  /**
   * Raised when the public-key write bucket is exhausted (HTTP 429).
   *
   * The endpoint allows only a few writes per 24h; `resetEpoch` is when the
   * window frees up. Retrying before then just fails again.
   */
  static RateLimited = class RateLimited extends Error {
    constructor(resetEpoch) {
      super("public-key registration rate limited (HTTP 429)");
      this.name = "RateLimited";
      this.resetEpoch = resetEpoch;
    }
  };

  /**
   * Register a public key: POST /2/users/{id}/public_keys.
   *
   * `payload` is the registration object from `generateKeypairs` in its
   * snake_case wire form (`public_key` object, `version`, `generate_version`).
   * Sent with a direct fetch — chat auth is a plain OAuth2 bearer token, so
   * this is equivalent to what the XDK would send. Throws `RateLimited` on 429
   * so the caller can stop instead of burning the strict daily budget.
   */
  async addUserPublicKey(userId, payload) {
    const resp = await fetch(`${BASE_URL}/2/users/${encodeURIComponent(userId)}/public_keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (resp.status === 429) {
      const reset = resp.headers.get("x-user-limit-24hour-reset");
      throw new XChatClient.RateLimited(reset ? Number(reset) : null);
    }
    if (!resp.ok) {
      throw new Error(`add public key failed: HTTP ${resp.status} ${await resp.text()}`);
    }
    const text = await resp.text();
    return text ? JSON.parse(text) : {};
  }

  /**
   * Build the Juicebox config JSON + latest key version for `unlock`/`setup`.
   *
   * The browser-safe WASM binding has no key export, so the registration
   * example persists the identity in Juicebox rather than a local blob; this
   * fetches the `juicebox_config` object the SDK needs to reach the realms.
   */
  async getJuiceboxConfig(userId) {
    const resp = await this.client.users.getPublicKey(userId);
    const data = resp.data ?? [];
    const items = Array.isArray(data) ? data : [data];
    const versionOf = (d) => Number(d.publicKeyVersion ?? d.public_key_version ?? 0);
    const latest = items.reduce(
      (best, d) => (versionOf(d) >= versionOf(best) ? d : best),
      items[0] ?? {},
    );
    const config = latest.juiceboxConfig ?? latest.juicebox_config;
    if (!config) {
      throw new Error(
        "no juicebox_config on the account yet. It is created by " +
          "POST /2/users/:id/public_keys, so register a public key first — " +
          "src/register.mjs does this: createChat with no config, " +
          "generateKeypairs, POST, then updateConfig + setup(pin). Once " +
          "provisioned, juicebox_config is always returned.",
      );
    }
    // Passed to the SDK as-is: it reads `key_store_token_map_json` verbatim.
    return {
      configJson: JSON.stringify(config),
      version: String(latest.publicKeyVersion ?? latest.public_key_version ?? "1"),
    };
  }

  /** GET the raw (encrypted) events for a conversation. */
  async getEvents(conversationId, { maxResults = 50, paginationToken } = {}) {
    return this.client.chat.getConversationEvents(conversationId.replaceAll(":", "-"), {
      maxResults,
      paginationToken,
    });
  }

  /** POST an encrypted message produced by ChatCore.encryptReply. */
  async sendMessage(conversationId, body) {
    return this.client.chat.sendMessage(conversationId.replaceAll(":", "-"), {
      messageId: body.message_id,
      encodedMessageCreateEvent: body.encoded_message_create_event,
      encodedMessageEventSignature: body.encoded_message_event_signature,
      conversationToken: body.conversation_token,
    });
  }

  // -- Conversation / key management ----------------------------------------

  /**
   * POST a prepared conversation-key change (initialize or rotate).
   * `body` is the request shape built by `prepToRequest`. For a 1:1,
   * `conversationId` may be the recipient's user ID; the server derives
   * (and returns) the canonical conversation ID.
   */
  async addConversationKeys(conversationId, body) {
    return this.client.chat.initializeConversationKeys(
      conversationId.replaceAll(":", "-"),
      body,
    );
  }

  /** Mint a new group conversation id (`g…`). */
  async initializeGroup() {
    const resp = await this.client.chat.initializeGroup();
    return String(resp.data?.conversationId ?? "");
  }

  /**
   * Create a group conversation. `body` carries `conversationId`,
   * `groupMembers`, `groupAdmins`, and the two-signature key change from
   * `ChatCore.prepareGroupCreate`.
   */
  async createConversation(body) {
    return this.client.chat.createConversation(body);
  }

  /**
   * Add members to a group. `body` carries `userIds` plus the rotated key
   * change from `ChatCore.prepareGroupMembersChange`.
   */
  async addGroupMembers(conversationId, body) {
    return this.client.chat.addGroupMembers(conversationId, body);
  }

  // -- Media (encrypted blobs) ------------------------------------------------

  static UPLOAD_CHUNK = 3 * 1024 * 1024;

  /**
   * Upload an encrypted media blob; returns its `media_hash_key`.
   *
   * Three-step flow: initialize (returns an upload session and the hash
   * key), append (3 MB segments), finalize. The media endpoints take the
   * colon form of the conversation id in the body.
   */
  async uploadMedia(conversationId, ciphertext) {
    const conv = conversationId.replaceAll("-", ":");
    const init = await this.client.chat.mediaUploadInitialize({
      conversationId: conv,
      totalBytes: ciphertext.length,
    });
    const sessionId = init.data?.sessionId ?? init.data?.session_id;
    const mediaHashKey = init.data?.mediaHashKey ?? init.data?.media_hash_key;
    if (!sessionId || !mediaHashKey) {
      throw new Error(`media upload initialize failed: ${JSON.stringify(init)}`);
    }

    let segment = 0;
    for (let offset = 0; offset < ciphertext.length; offset += XChatClient.UPLOAD_CHUNK) {
      const chunk = ciphertext.subarray(offset, offset + XChatClient.UPLOAD_CHUNK);
      await this.client.chat.mediaUploadAppend(sessionId, {
        conversationId: conv,
        mediaHashKey,
        segmentIndex: String(segment),
        media: Buffer.from(chunk).toString("base64"),
      });
      segment++;
    }

    await this.client.chat.mediaUploadFinalize(sessionId, {
      conversationId: conv,
      mediaHashKey,
      numParts: String(segment),
    });
    return String(mediaHashKey);
  }

  /**
   * Download an encrypted media blob as raw bytes.
   *
   * Uses fetch directly: the body is binary ciphertext and must be read as
   * an ArrayBuffer — any text decoding corrupts bytes above 0x7f. The
   * download path takes the hyphen form of the conversation id.
   */
  async downloadMedia(conversationId, mediaHashKey) {
    const conv = encodeURIComponent(conversationId.replaceAll(":", "-"));
    const hashKey = encodeURIComponent(mediaHashKey);
    const resp = await fetch(`${BASE_URL}/2/chat/media/${conv}/${hashKey}`, {
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });
    if (!resp.ok) {
      throw new Error(`media download failed: HTTP ${resp.status}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }
}
