package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.x.chatxdk.Types.*;

import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The main X Chat encryption SDK (JNA &#8594; {@code chat_xdk_dotnet}).
 *
 * <p>Wraps the Rust {@code chat_xdk_core} library and provides the operations exposed by the SDK:
 *
 * <ul>
 *   <li>Key generation and Juicebox-backed storage ({@link #generateKeypairs}, {@link #setup}, {@link #unlock})</li>
 *   <li>Event decryption ({@link #extractConversationKeys}, {@link #decryptEvents}, {@link #decryptEvent})</li>
 *   <li>Signed conversation-key changes ({@link #prepareConversationKeyChange}, {@link #prepareGroupCreate}, {@link #prepareGroupMembersChange})</li>
 *   <li>UTF-8 metadata encryption with the conversation key ({@link #encrypt}, {@link #decrypt})</li>
 *   <li>Message / reaction / reply encryption ({@link #encryptMessage}, etc.)</li>
 *   <li>Media streaming encryption ({@link #encryptStream}, {@link #decryptStream})</li>
 *   <li>Stateless helpers on {@link ChatXdkUtilities} (base64/hex, MIME, image dimensions)</li>
 * </ul>
 *
 * <p>Always {@link #close} the instance when finished to release native resources.
 *
 * <p>Not thread-safe: do not share one instance across threads without external synchronization.
 * Mutating operations ({@link #setup}, {@link #unlock}, {@link #delete}, {@link #changePin},
 * {@link #updateConfig}, {@link #setRejectUnverified},
 * {@link #setIdentity}, {@link #setCacheKeys}, {@link #setSigningKeys}) must not race
 * decrypt or any other call on the same instance.
 */
public final class Chat implements AutoCloseable {

    /**
     * Shared cleaner providing a GC backstop for native handles across the
     * binding ({@link Chat}, {@link StreamEncryptor}, {@link StreamDecryptor}).
     * Explicit {@code close()} remains the primary release mechanism; the
     * cleaner only frees handles whose owner was garbage-collected unclosed.
     */
    static final Cleaner CLEANER = Cleaner.create();

    /**
     * Frees a native Chat handle. Registered with {@link #CLEANER}; the cleaner
     * runs a registered action at most once, so an explicit {@code close()} and
     * the GC backstop can never double-free.
     *
     * <p>An object becomes phantom-reachable as soon as its last use passes —
     * even while one of its methods is still executing native code — so every
     * method that passes {@code handle} to the native library calls
     * {@link Reference#reachabilityFence} on {@code this} in a {@code finally}
     * block, keeping the cleaner from freeing the handle mid-call.
     */
    private static final class FreeHandle implements Runnable {
        private final Pointer handle;

        FreeHandle(Pointer handle) {
            this.handle = handle;
        }

        @Override
        public void run() {
            ChatNative.INSTANCE.chat_xdk_free(handle);
        }
    }

    private Pointer handle;
    private boolean disposed;
    private final Cleaner.Cleanable cleanable;

    /**
     * Create a new Chat SDK instance.
     *
     * @throws IllegalStateException if the native library fails to initialise
     *     (e.g. the shared library is not on {@code jna.library.path}).
     */
    public Chat() {
        handle = ChatNative.INSTANCE.chat_xdk_new();
        if (handle == null) {
            throw new IllegalStateException(
                    "chat_xdk_new() returned null — ensure libchat_xdk_dotnet is on jna.library.path.");
        }
        cleanable = CLEANER.register(this, new FreeHandle(handle));
    }

    /**
     * Free the native handle, releasing all unmanaged resources. Idempotent.
     */
    @Override
    public void close() {
        if (!disposed) {
            disposed = true;
            handle = null;
            cleanable.clean();
        }
    }

    private void throwIfDisposed() {
        if (disposed || handle == null) {
            throw new IllegalStateException("Chat is closed");
        }
    }

    /**
     * @return true when both identity and signing keys are loaded in memory.
     */
    public boolean isUnlocked() {
        throwIfDisposed();
        try {
            return ChatNative.INSTANCE.chat_xdk_is_unlocked(handle) == 1;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * @return true when the identity key is loaded (sufficient for decryption).
     */
    public boolean hasIdentityKey() {
        throwIfDisposed();
        try {
            return ChatNative.INSTANCE.chat_xdk_has_identity_key(handle) == 1;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * When {@code reject} is true — the default — {@link #decryptEvent} throws
     * {@link ChatXdkException} for any signed event whose signature cannot be verified
     * (invalid, missing, or no matching signing key) instead of returning it with
     * {@code verified: false}.
     *
     * @param reject whether to reject events with unverifiable signatures.
     */
    public void setRejectUnverified(boolean reject) {
        throwIfDisposed();
        try {
            ChatNative.INSTANCE.chat_xdk_set_reject_unverified(handle, reject ? 1 : 0);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Set the session identity: the owner's user id and signing-key version, used
     * as the defaults wherever a params class' {@code senderId} / {@code signingKeyVersion}
     * is left null. A resolved default and an explicitly passed value produce
     * byte-identical signed output for the same logical inputs.
     */
    public void setIdentity(String userId, String signingKeyVersion) {
        throwIfDisposed();
        try (Memory user = FfiStrings.utf8(userId);
                Memory ver = FfiStrings.utf8(signingKeyVersion)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_set_identity(handle, user, ver));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Enable or disable the conversation-key cache (off by default). While enabled,
     * {@link #decryptEvents} caches, per conversation, the key whose key change
     * carried a valid signature at the highest version seen, and the encrypt
     * methods resolve a null {@code conversationKey}/{@code conversationKeyVersion}
     * pair from it. Disabling clears the cache.
     */
    public void setCacheKeys(boolean enabled) {
        throwIfDisposed();
        try {
            ChatNative.INSTANCE.chat_xdk_set_cache_keys(handle, enabled ? 1 : 0);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Store signing keys to use when a decrypt call omits its {@code signingKeys}
     * argument. Only this explicit call populates the store — a key carried inside
     * an event is never trusted for verification. Each call replaces the previous set.
     */
    public void setSigningKeys(List<SigningKeyEntry> keys) throws Exception {
        throwIfDisposed();
        String json = ChatJson.MAPPER.writeValueAsString(keys);
        try (Memory j = FfiStrings.utf8(json)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_set_signing_keys(handle, j));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Clear all key material from memory without touching Juicebox. */
    public void lock() {
        throwIfDisposed();
        try {
            ChatNative.INSTANCE.chat_xdk_lock(handle);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Update the Juicebox configuration — call this whenever the X API
     * issues fresh short-lived auth tokens.
     *
     * @param configJson Juicebox configuration JSON from the X API.
     */
    public void updateConfig(String configJson) {
        throwIfDisposed();
        try (Memory cfg = FfiStrings.utf8(configJson)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_update_config(handle, cfg));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Register the SDK's keys with Juicebox (first-time setup).
     * Call {@link #generateKeypairs} and POST the result to the X API first,
     * then call this to persist the keys under the user's PIN.
     *
     * @param pin User-chosen PIN.
     * @param configJson Juicebox configuration JSON from the X API.
     * @return The user's public keys to upload to the X API.
     */
    public PublicKeys setup(String pin, String configJson) throws Exception {
        throwIfDisposed();
        try (Memory pinM = FfiStrings.utf8(pin);
                Memory cfg = FfiStrings.utf8(configJson)) {
            String json = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_setup(handle, pinM, cfg));
            return ChatJson.MAPPER.readValue(json, PublicKeys.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Recover keys from Juicebox and load them into memory.
     * Call on every startup after the user enters their PIN.
     *
     * @param pin The user's PIN.
     * @param configJson Juicebox configuration JSON from the X API.
     */
    public void unlock(String pin, String configJson) {
        throwIfDisposed();
        try (Memory pinM = FfiStrings.utf8(pin);
                Memory cfg = FfiStrings.utf8(configJson)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_unlock(handle, pinM, cfg));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Delete the user's keys from Juicebox and lock the SDK.
     * Irreversible — the user loses access to their encrypted message history.
     */
    public void delete() {
        throwIfDisposed();
        try {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_delete(handle));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Re-register keys under a new PIN. */
    public void changePin(String oldPin, String newPin) {
        throwIfDisposed();
        try (Memory o = FfiStrings.utf8(oldPin);
                Memory n = FfiStrings.utf8(newPin)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_change_pin(handle, o, n));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Generate new identity + signing keypairs and return the registration payload.
     * POST the payload to {@code POST /2/chat/keys} before calling {@link #setup}.
     */
    public PublicKeyRegistrationPayload generateKeypairs() throws Exception {
        throwIfDisposed();
        try {
            String json = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_generate_keypairs(handle));
            return ChatJson.MAPPER.readValue(json, PublicKeyRegistrationPayload.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Get the user's current public keys (requires keys to be loaded). */
    public PublicKeys getPublicKeys() throws Exception {
        throwIfDisposed();
        try {
            String json = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_get_public_keys(handle));
            return ChatJson.MAPPER.readValue(json, PublicKeys.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Get the fingerprint of the loaded identity public key.
     * Returns a URL-safe base64 SHA-256 of the SPKI-encoded key —
     * suitable for out-of-band verification by the user.
     */
    public String getPublicKeyFingerprint() {
        throwIfDisposed();
        try {
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_get_public_key_fingerprint(handle));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Export private keys as raw bytes for a secure backup.
     * Returns {@code null} if the SDK is locked.
     * These are raw secret key bytes — store with extreme care.
     */
    public byte[] exportKeys() {
        throwIfDisposed();
        // Mirrors core's export requirement: identity key present (signing
        // key optional, giving a 32-byte export).
        if (!hasIdentityKey()) {
            return null;
        }
        try {
            String b64 = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_export_keys(handle));
            if (b64.isEmpty()) {
                return null;
            }
            return Base64.getDecoder().decode(b64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Import private keys from a byte array produced by {@link #exportKeys}.
     * Accepts 32 bytes (identity only) or 64 bytes (identity + signing).
     */
    public void importKeys(byte[] keys) {
        throwIfDisposed();
        String b64 = Base64.getEncoder().encodeToString(keys);
        try (Memory b64m = FfiStrings.utf8(b64)) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_import_keys(handle, b64m));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Like {@link #importKeys(byte[])} but also records the public key version
     * the keys were registered under, so participant-key filtering and the
     * session signing-key version are set in one call.
     */
    public void importKeys(byte[] keys, String version) {
        throwIfDisposed();
        Objects.requireNonNull(keys, "keys");
        FfiResult.ByValue r;
        try (Memory ver = FfiStrings.utf8(version)) {
            if (keys.length == 0) {
                // A zero-length Memory cannot be allocated; the native side
                // treats NULL + length 0 as an empty key blob.
                r = ChatNative.INSTANCE.chat_xdk_import_keys_with_version(handle, null, 0, ver);
            } else {
                try (Memory m = new Memory(keys.length)) {
                    m.write(0, keys, 0, keys.length);
                    r = ChatNative.INSTANCE.chat_xdk_import_keys_with_version(handle, m, keys.length, ver);
                }
            }
        } finally {
            Reference.reachabilityFence(this);
        }
        FfiStrings.consume(r);
    }

    /**
     * Extract and decrypt conversation keys from raw {@code KeyChange} event strings.
     *
     * @param events Base64-encoded raw event strings received from the webhook.
     *     Pass only {@code KeyChange} events — other event types are ignored.
     * @return Decrypted keys and {@link ConversationKeyBundle#latestVersion}. Pass
     *     {@link ConversationKeyBundle#keys} (or the whole bundle) to {@link #decryptEvent}.
     */
    public ConversationKeyBundle extractConversationKeys(List<String> events) throws Exception {
        throwIfDisposed();
        String eventsJson = ChatJson.MAPPER.writeValueAsString(events);
        try (Memory ev = FfiStrings.utf8(eventsJson)) {
            String resultJson =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_extract_conversation_keys(handle, ev));
            return parseConversationKeyBundle(ChatJson.MAPPER.readTree(resultJson));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt a webhook event and return it as a {@link JsonNode}.
     *
     * @param eventB64 Base64-encoded raw event from the webhook.
     * @param conversationKeys Map of version &#8594; raw 32-byte key bytes from
     *     {@link #extractConversationKeys} or {@link DecryptEventsResult#conversationKeys}.
     *     Pass {@code null} (or an empty map) for non-message events, or to fall back to
     *     the opt-in key cache ({@link #setCacheKeys}).
     * @param signingKeys Signing keys for the sender. The SDK picks the matching version
     *     automatically. {@code null} (or an empty list) falls back to the keys stored via
     *     {@link #setSigningKeys}; if none are stored either, every signed event throws
     *     under the default reject-unverified policy (only after
     *     {@link #setRejectUnverified}(false) are such events returned with
     *     {@code verified: false}).
     * @return A {@link JsonNode} with a {@code "type"} field indicating the event kind
     *     ({@code "Message"}, {@code "KeyChange"}, {@code "GroupChange"}, etc.).
     */
    public JsonNode decryptEvent(
            String eventB64, Map<String, byte[]> conversationKeys, List<SigningKeyEntry> signingKeys)
            throws Exception {
        throwIfDisposed();
        Map<String, String> convKeysB64 = new LinkedHashMap<>();
        if (conversationKeys != null) {
            for (Map.Entry<String, byte[]> e : conversationKeys.entrySet()) {
                convKeysB64.put(e.getKey(), Base64.getEncoder().encodeToString(e.getValue()));
            }
        }
        String convKeysJson = ChatJson.MAPPER.writeValueAsString(convKeysB64);
        List<SigningKeyEntry> sk = signingKeys == null ? List.of() : signingKeys;
        String signingKeysJson = ChatJson.MAPPER.writeValueAsString(sk);
        try (Memory ev = FfiStrings.utf8(eventB64);
                Memory cj = FfiStrings.utf8(convKeysJson);
                Memory sj = FfiStrings.utf8(signingKeysJson)) {
            String resultJson =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_event(handle, ev, cj, sj));
            return ChatJson.MAPPER.readTree(resultJson);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt a single event using keys from {@link #extractConversationKeys} or
     * {@link DecryptEventsResult#conversationKeys} (uses {@link ConversationKeyBundle#keys}).
     */
    public JsonNode decryptEvent(
            String eventB64, ConversationKeyBundle conversationKeys, List<SigningKeyEntry> signingKeys)
            throws Exception {
        Map<String, byte[]> m = conversationKeys == null ? null : conversationKeys.keys;
        return decryptEvent(eventB64, m, signingKeys);
    }

    /**
     * Decrypt a batch of webhook events in one call. Keys are extracted from {@code KeyChange} events in the batch;
     * failures are recorded in {@link DecryptEventsResult#errors} — this method never throws per-event.
     * Passing {@code null} (or an empty list) for {@code signingKeys} falls back to the keys
     * stored via {@link #setSigningKeys}.
     */
    public DecryptEventsResult decryptEvents(List<String> events, List<SigningKeyEntry> signingKeys)
            throws Exception {
        throwIfDisposed();
        String eventsJson = ChatJson.MAPPER.writeValueAsString(events);
        List<SigningKeyEntry> sk = signingKeys == null ? List.of() : signingKeys;
        String signingKeysJson = ChatJson.MAPPER.writeValueAsString(sk);
        try (Memory ev = FfiStrings.utf8(eventsJson);
                Memory sig = FfiStrings.utf8(signingKeysJson)) {
            String resultJson =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_events(handle, ev, sig));
            JsonNode root = ChatJson.MAPPER.readTree(resultJson);
            DecryptEventsResult out = new DecryptEventsResult();
            List<DecryptedMessage> messages = new ArrayList<>();
            JsonNode arr = root.get("messages");
            if (arr != null && arr.isArray()) {
                for (JsonNode el : arr) {
                    DecryptedMessage dm = new DecryptedMessage();
                    dm.event = el.get("event");
                    if (el.hasNonNull("original_b64")) {
                        dm.originalB64 = el.get("original_b64").asText();
                    }
                    messages.add(dm);
                }
            }
            out.messages = messages;
            out.conversationKeys = parseConversationKeyBundle(root.get("conversation_keys"));
            Map<String, String> errors = new HashMap<>();
            JsonNode errNode = root.get("errors");
            if (errNode != null && errNode.isObject()) {
                errNode.fields().forEachRemaining(e -> errors.put(e.getKey(), e.getValue().asText("")));
            }
            out.errors = errors;
            return out;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Prepare a signed conversation-key change, ready to send to the X API.
     *
     * <p>Use this to start a one-to-one or rotate an existing conversation's key
     * (one-to-one or group). Creating a group or adding members requires a paired
     * group signature as well — use {@link #prepareGroupCreate} or
     * {@link #prepareGroupMembersChange} for those.
     *
     * <p>Leave {@code conversationId} null on a one-to-one to derive the canonical
     * id from the two participants; pass the existing id for a group rotation.
     */
    public PreparedConversationChange prepareConversationKeyChange(ConversationKeyChangeParams parameters)
            throws Exception {
        throwIfDisposed();
        return callPrepare(
                buildPrepareConversationKeyChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_conversation_key_change);
    }

    /**
     * Prepare a signed group member-add change for the updated roster, ready to send to the X API.
     *
     * <p>Use this when adding members to an existing group. Creating the group is
     * {@link #prepareGroupCreate}; a key rotation without a roster change is
     * {@link #prepareConversationKeyChange}.
     *
     * <p>Emits two action signatures: a conversation-key change and the member add.
     */
    public PreparedConversationChange prepareGroupMembersChange(GroupMembersChangeParams parameters)
            throws Exception {
        throwIfDisposed();
        return callPrepare(
                buildPrepareGroupMembersChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_members_change);
    }

    /**
     * Prepare a signed group create for the new roster, ready to send to the X API.
     *
     * <p>Use this once, when creating a group (the conversation id is the g-prefixed
     * id minted by the initialize endpoint). Later key rotations use
     * {@link #prepareConversationKeyChange}; roster additions use
     * {@link #prepareGroupMembersChange}.
     *
     * <p>Emits two action signatures: a conversation-key change and the group create.
     */
    public PreparedConversationChange prepareGroupCreate(GroupCreateParams parameters)
            throws Exception {
        throwIfDisposed();
        return callPrepare(
                buildPrepareGroupCreateJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_create);
    }

    /**
     * Build the signed action for deleting messages from a conversation, ready
     * to submit alongside the delete request.
     *
     * <p>A delete is a signed plaintext event, not an encrypted message, so no
     * conversation key is involved. The SDK generates the action's message id;
     * read it back from the result.
     */
    public ActionSignature prepareMessageDelete(MessageDeleteParams parameters) throws Exception {
        throwIfDisposed();
        try (Memory j = FfiStrings.utf8(buildPrepareMessageDeleteJson(parameters))) {
            String resultJson = FfiStrings.consume(
                    ChatNative.INSTANCE.chat_xdk_prepare_message_delete(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, ActionSignature.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private PreparedConversationChange callPrepare(String paramsJson, ParamsJsonFn fn) throws Exception {
        try (Memory j = FfiStrings.utf8(paramsJson)) {
            String resultJson = FfiStrings.consume(fn.apply(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedConversationChange.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Encrypt a UTF-8 metadata string with the conversation key; returns base64 ciphertext
     * (XSalsa20-Poly1305).
     */
    public String encrypt(String plaintext, byte[] conversationKey) {
        throwIfDisposed();
        Objects.requireNonNull(conversationKey, "conversationKey");
        try (Memory pt = FfiStrings.utf8(plaintext);
                Memory ck = FfiStrings.utf8(Base64.getEncoder().encodeToString(conversationKey))) {
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_encrypt(handle, pt, ck));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt base64 ciphertext (from {@link #encrypt}) to a UTF-8 plaintext string.
     */
    public String decrypt(String ciphertextB64, byte[] conversationKey) {
        throwIfDisposed();
        Objects.requireNonNull(conversationKey, "conversationKey");
        try (Memory ct = FfiStrings.utf8(ciphertextB64);
                Memory ck = FfiStrings.utf8(Base64.getEncoder().encodeToString(conversationKey))) {
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt(handle, ct, ck));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Encrypt a message for the X API.
     * POST the returned {@link SendPayload} fields to
     * {@code POST /2/chat/conversations/{id}/messages}.
     */
    public SendPayload encryptMessage(EncryptMessageParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildEncryptMessageJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_message);
    }

    /**
     * Encrypt a reply message for the X API.
     * Like {@link #encryptMessage} but includes a reply-to preview.
     */
    public SendPayload encryptReply(EncryptReplyParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildEncryptReplyJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_reply);
    }

    /** Encrypt a reaction-add for the X API. */
    public SendPayload encryptAddReaction(EncryptReactionParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildReactionJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_add_reaction);
    }

    /** Encrypt a reaction-remove for the X API. */
    public SendPayload encryptRemoveReaction(EncryptReactionParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildReactionJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_remove_reaction);
    }

    /** Encrypt a message edit for the X API. */
    public SendPayload encryptEdit(EncryptEditParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildEncryptEditJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_edit);
    }

    @FunctionalInterface
    private interface ParamsJsonFn {
        FfiResult.ByValue apply(Pointer h, Pointer json);
    }

    private SendPayload callEncrypt(String paramsJson, ParamsJsonFn fn) throws Exception {
        try (Memory j = FfiStrings.utf8(paramsJson)) {
            String resultJson = FfiStrings.consume(fn.apply(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, SendPayload.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt an ECIES-encrypted conversation key from a {@code KeyChange} event.
     * Call this once per key version and cache the result; pass it to
     * {@link #decryptEvent} for all subsequent messages.
     *
     * @param encryptedKeyB64 Base64-encoded encrypted key from the {@code KeyChange} event
     *     ({@code participant_keys[].encrypted_key}).
     * @return Raw 32-byte decrypted conversation key.
     */
    public byte[] decryptConversationKey(String encryptedKeyB64) {
        throwIfDisposed();
        try (Memory enc = FfiStrings.utf8(encryptedKeyB64)) {
            String b64 = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_conversation_key(handle, enc));
            return Base64.getDecoder().decode(b64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt a streaming-encrypted media payload (e.g. an image or video).
     *
     * @param encrypted Encrypted bytes.
     * @param conversationKey Raw 32-byte conversation key.
     * @return Decrypted bytes.
     */
    public byte[] decryptStream(byte[] encrypted, byte[] conversationKey) {
        throwIfDisposed();
        try (Memory enc = FfiStrings.utf8(Base64.getEncoder().encodeToString(encrypted));
                Memory key = FfiStrings.utf8(Base64.getEncoder().encodeToString(conversationKey))) {
            String resultB64 =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_stream(handle, enc, key));
            return Base64.getDecoder().decode(resultB64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Encrypt a media payload (e.g. an image or video) with a conversation key.
     *
     * @param plaintext Raw bytes to encrypt.
     * @param conversationKey Raw 32-byte conversation key.
     * @return Encrypted bytes.
     */
    public byte[] encryptStream(byte[] plaintext, byte[] conversationKey) {
        throwIfDisposed();
        try (Memory pt = FfiStrings.utf8(Base64.getEncoder().encodeToString(plaintext));
                Memory key = FfiStrings.utf8(Base64.getEncoder().encodeToString(conversationKey))) {
            String resultB64 =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_encrypt_stream(handle, pt, key));
            return Base64.getDecoder().decode(resultB64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Create an incremental stream encryptor for large payloads.
     *
     * @param conversationKey Raw 32-byte conversation key.
     * @return A new {@link StreamEncryptor}; close it when finished.
     */
    public StreamEncryptor streamEncryptor(byte[] conversationKey) {
        throwIfDisposed();
        return StreamEncryptor.create(conversationKey);
    }

    /**
     * Create an incremental stream decryptor for large payloads.
     *
     * @param conversationKey Raw 32-byte conversation key.
     * @return A new {@link StreamDecryptor}; close it when finished.
     */
    public StreamDecryptor streamDecryptor(byte[] conversationKey) {
        throwIfDisposed();
        return StreamDecryptor.create(conversationKey);
    }

    /**
     * Sign arbitrary data with the signing key.
     *
     * @param data Bytes to sign. May be empty but not null.
     * @return 64-byte ECDSA P-256 signature.
     */
    public byte[] sign(byte[] data) {
        throwIfDisposed();
        Objects.requireNonNull(data, "data");
        FfiResult.ByValue r;
        try {
            if (data.length == 0) {
                r = ChatNative.INSTANCE.chat_xdk_sign(handle, null, 0);
            } else {
                try (Memory m = new Memory(data.length)) {
                    m.write(0, data, 0, data.length);
                    r = ChatNative.INSTANCE.chat_xdk_sign(handle, m, data.length);
                }
            }
        } finally {
            Reference.reachabilityFence(this);
        }
        String sigB64 = FfiStrings.consume(r);
        return Base64.getDecoder().decode(sigB64);
    }

    /**
     * Verify an ECDSA signature.
     *
     * @param publicKeyB64 Base64-encoded signing public key (SEC1 or SPKI).
     * @param signature Raw signature bytes from {@link #sign}.
     * @param data The original signed data.
     * @return {@code true} if the signature is valid, {@code false} if invalid.
     * @throws ChatXdkException when the SDK returns an error (e.g. keys not loaded, malformed
     *     public key). An SDK error is always thrown, never returned as a {@code false} result.
     */
    public boolean verify(String publicKeyB64, byte[] signature, byte[] data) {
        throwIfDisposed();
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(data, "data");
        String sigB64 = Base64.getEncoder().encodeToString(signature);
        try (Memory pk = FfiStrings.utf8(publicKeyB64);
                Memory sig = FfiStrings.utf8(sigB64)) {
            int rc;
            if (data.length == 0) {
                rc = ChatNative.INSTANCE.chat_xdk_verify(handle, pk, sig, null, 0);
            } else {
                try (Memory dm = new Memory(data.length)) {
                    dm.write(0, data, 0, data.length);
                    rc = ChatNative.INSTANCE.chat_xdk_verify(handle, pk, sig, dm, data.length);
                }
            }
            return switch (rc) {
                case 1 -> true;
                case 0 -> false;
                default -> throw new ChatXdkException(
                        "Signature verification error — ensure the SDK is unlocked and the public key is valid.");
            };
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Verify that a signing key is authentically bound to an identity key.
     * Call this when you receive another user's public keys from the X API
     * to detect server-side key substitution. All arguments are base64.
     */
    public boolean verifyKeyBinding(String identityPublicKeyB64, String signingPublicKeyB64, String identityPublicKeySignatureB64) {
        throwIfDisposed();
        try (Memory identity = FfiStrings.utf8(identityPublicKeyB64);
                Memory signing = FfiStrings.utf8(signingPublicKeyB64);
                Memory sig = FfiStrings.utf8(identityPublicKeySignatureB64)) {
            int rc = ChatNative.INSTANCE.chat_xdk_verify_key_binding(handle, identity, signing, sig);
            return switch (rc) {
                case 1 -> true;
                case 0 -> false;
                default -> throw new ChatXdkException(
                        "Key binding verification error — ensure the inputs are valid base64.");
            };
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Report whether the loaded identity public key is the key in
     * {@code publicKeyB64}. The X API returns the identity public key in
     * SPKI/DER encoding while getPublicKeys returns the raw SEC1 point;
     * this accepts either encoding, so use it to check whether the keys on
     * this device belong to a key registered to the account.
     */
    public boolean matchesRegisteredKey(String publicKeyB64) {
        throwIfDisposed();
        try (Memory publicKey = FfiStrings.utf8(publicKeyB64)) {
            int rc = ChatNative.INSTANCE.chat_xdk_matches_registered_key(handle, publicKey);
            return switch (rc) {
                case 1 -> true;
                case 0 -> false;
                default -> throw new ChatXdkException(
                        "Registered key match error — ensure keys are loaded and the input is valid base64.");
            };
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private static ConversationKeyBundle parseConversationKeyBundle(JsonNode root) throws Exception {
        ConversationKeyBundle b = new ConversationKeyBundle();
        if (root == null || root.isNull()) {
            b.keys = Map.of();
            return b;
        }
        Map<String, byte[]> keys = new LinkedHashMap<>();
        JsonNode keysEl = root.get("keys");
        if (keysEl != null && keysEl.isObject()) {
            keysEl.fields()
                    .forEachRemaining(
                            e -> keys.put(e.getKey(), Base64.getDecoder().decode(e.getValue().asText())));
        }
        b.keys = keys;
        if (root.hasNonNull("latest_version")) {
            b.latestVersion = root.get("latest_version").asText();
        }
        return b;
    }

    private static Object[][] serializeEntities(List<EntityDescriptor> entities) {
        Object[][] result = new Object[entities.size()][];
        for (int i = 0; i < entities.size(); i++) {
            EntityDescriptor e = entities.get(i);
            result[i] = new Object[] {e.start, e.end, e.entityType};
        }
        return result;
    }

    // An absent optional slot stays out of the document entirely, which the
    // FFI reads as unset — the value then resolves from the session identity /
    // key cache.
    private static void putIdentityAndKey(
            ObjectNode n,
            String senderId,
            String signingKeyVersion,
            byte[] conversationKey,
            String conversationKeyVersion) {
        if (senderId != null) {
            n.put("sender_id", senderId);
        }
        if (signingKeyVersion != null) {
            n.put("signing_key_version", signingKeyVersion);
        }
        if (conversationKey != null) {
            n.put("conversation_key", Base64.getEncoder().encodeToString(conversationKey));
        }
        if (conversationKeyVersion != null) {
            n.put("conversation_key_version", conversationKeyVersion);
        }
    }

    private static String buildEncryptMessageJson(EncryptMessageParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("text", p.text);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        if (p.entities != null) {
            n.set("entities", ChatJson.MAPPER.valueToTree(serializeEntities(p.entities)));
        }
        if (p.attachments != null) {
            n.set("attachments", ChatJson.MAPPER.valueToTree(p.attachments));
        }
        if (p.shouldNotify != null) {
            n.put("should_notify", p.shouldNotify);
        }
        if (p.ttlMsec != null) {
            n.put("ttl_msec", p.ttlMsec);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildEncryptReplyJson(EncryptReplyParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("text", p.text);
        if (p.replyToEvent != null) {
            n.put("reply_to_event", p.replyToEvent);
        }
        if (p.replyToEditEvent != null) {
            n.put("reply_to_edit_event", p.replyToEditEvent);
        }
        if (p.replyToCkces != null) {
            n.set("reply_to_ckces", ChatJson.MAPPER.valueToTree(p.replyToCkces));
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        if (p.replyToSequenceId != null) {
            n.put("reply_to_sequence_id", p.replyToSequenceId);
        }
        if (p.replyToSenderId != null) {
            n.put("reply_to_sender_id", p.replyToSenderId);
        }
        if (p.replyToText != null) {
            n.put("reply_to_text", p.replyToText);
        }
        if (p.entities != null) {
            n.set("entities", ChatJson.MAPPER.valueToTree(serializeEntities(p.entities)));
        }
        if (p.attachments != null) {
            n.set("attachments", ChatJson.MAPPER.valueToTree(p.attachments));
        }
        if (p.replyToEntities != null) {
            n.set("reply_to_entities", ChatJson.MAPPER.valueToTree(serializeEntities(p.replyToEntities)));
        }
        if (p.replyToAttachments != null) {
            n.set("reply_to_attachments", ChatJson.MAPPER.valueToTree(p.replyToAttachments));
        }
        if (p.shouldNotify != null) {
            n.put("should_notify", p.shouldNotify);
        }
        if (p.ttlMsec != null) {
            n.put("ttl_msec", p.ttlMsec);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildReactionJson(EncryptReactionParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("emoji", p.emoji);
        if (p.targetEvent != null) {
            n.put("target_event", p.targetEvent);
        }
        if (p.conversationId != null) {
            n.put("conversation_id", p.conversationId);
        }
        if (p.targetMessageSequenceId != null) {
            n.put("target_message_sequence_id", p.targetMessageSequenceId);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildEncryptEditJson(EncryptEditParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("updated_text", p.updatedText);
        if (p.targetEvent != null) {
            n.put("target_event", p.targetEvent);
        }
        if (p.entities != null) {
            n.set("entities", ChatJson.MAPPER.valueToTree(serializeEntities(p.entities)));
        }
        if (p.conversationId != null) {
            n.put("conversation_id", p.conversationId);
        }
        if (p.targetMessageSequenceId != null) {
            n.put("target_message_sequence_id", p.targetMessageSequenceId);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareMessageDeleteJson(MessageDeleteParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.set("sequence_ids", ChatJson.MAPPER.valueToTree(
                p.sequenceIds == null ? List.of() : p.sequenceIds));
        n.put("delete_for_all", p.deleteForAll);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareConversationKeyChangeJson(ConversationKeyChangeParams p)
            throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.set("public_keys", ChatJson.MAPPER.valueToTree(p.publicKeys));
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        if (p.conversationId != null) {
            n.put("conversation_id", p.conversationId);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupMembersChangeJson(GroupMembersChangeParams p)
            throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.set("public_keys", ChatJson.MAPPER.valueToTree(p.publicKeys));
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        n.put("conversation_id", p.conversationId);
        n.set("new_member_ids", ChatJson.MAPPER.valueToTree(
                p.newMemberIds == null ? List.of() : p.newMemberIds));
        n.set("current_member_ids", ChatJson.MAPPER.valueToTree(
                p.currentMemberIds == null ? List.of() : p.currentMemberIds));
        n.set("current_admin_ids", ChatJson.MAPPER.valueToTree(
                p.currentAdminIds == null ? List.of() : p.currentAdminIds));
        n.set("current_pending_member_ids", ChatJson.MAPPER.valueToTree(
                p.currentPendingMemberIds == null ? List.of() : p.currentPendingMemberIds));
        if (p.currentTitle != null) {
            n.put("current_title", p.currentTitle);
        }
        if (p.currentAvatarUrl != null) {
            n.put("current_avatar_url", p.currentAvatarUrl);
        }
        if (p.currentTtlMsec != null) {
            n.put("current_ttl_msec", p.currentTtlMsec);
        }
        // An unset value stays absent in the document (never a false default),
        // so the core signs the null sentinel.
        if (p.currentScreenCaptureBlockingEnabled != null) {
            n.put("current_screen_capture_blocking_enabled", p.currentScreenCaptureBlockingEnabled);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupCreateJson(GroupCreateParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.set("public_keys", ChatJson.MAPPER.valueToTree(p.publicKeys));
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        n.put("conversation_id", p.conversationId);
        n.set("member_ids", ChatJson.MAPPER.valueToTree(p.memberIds == null ? List.of() : p.memberIds));
        n.set("admin_ids", ChatJson.MAPPER.valueToTree(p.adminIds == null ? List.of() : p.adminIds));
        if (p.title != null) {
            n.put("title", p.title);
        }
        if (p.avatarUrl != null) {
            n.put("avatar_url", p.avatarUrl);
        }
        if (p.ttlMsec != null) {
            n.put("ttl_msec", p.ttlMsec);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }
}
