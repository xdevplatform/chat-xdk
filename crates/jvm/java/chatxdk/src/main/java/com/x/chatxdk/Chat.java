package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.x.chatxdk.Types.*;

import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

/**
 * The main X Chat encryption SDK (JNA &#8594; {@code chat_xdk_ffi}).
 *
 * <p>Wraps the Rust {@code chat_xdk_core} library and provides the operations exposed by the SDK:
 *
 * <ul>
 *   <li>Key generation and Juicebox-backed storage ({@link #generateKeypairs}, {@link #setup}, {@link #unlock})</li>
 *   <li>Event decryption ({@link #extractConversationKeys}, {@link #decryptEvents}, {@link #decryptEvent})</li>
 *   <li>Signed conversation-key changes ({@link #prepareConversationKeyChange}, {@link #prepareGroupCreate}, {@link #prepareGroupMembersChange})</li>
 *   <li>Group metadata decryption with the conversation key ({@link #decrypt})</li>
 *   <li>Message / reaction / reply encryption ({@link #encryptMessage}, etc.)</li>
 *   <li>File encryption ({@link #encryptFile}, {@link #decryptFile}, {@link #fileEncryptor}, {@link #fileDecryptor})</li>
 *   <li>Stateless helpers on {@link ChatXdkUtilities} (base64/hex, MIME, image dimensions)</li>
 * </ul>
 *
 * <p>Always {@link #close} the instance when finished to release native resources.
 *
 * <p>Its methods may be called from several threads at once; {@link #close} must not race them.
 */
public final class Chat implements AutoCloseable {

    /**
     * Shared cleaner providing a GC backstop for native handles across the
     * binding ({@link Chat}, {@link FileEncryptor}, {@link FileDecryptor}).
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
     * Create a Chat SDK instance without a Juicebox config, which manages its keys with
     * {@link #importKeys} and {@link #generateKeypairs} alone or takes its config later from
     * {@link #updateConfig}. Until then {@link #setup}, {@link #unlock}, {@link #changePin} and
     * {@link #delete} throw a {@link ChatXdkException} of kind
     * {@link ChatXdkException.Kind#INVALID_STATE}.
     */
    public Chat() {
        this(null, null, null);
    }

    /**
     * Create a Chat SDK instance that keeps its keys in Juicebox, with the Juicebox configuration
     * JSON the X API returns. {@link #setup}, {@link #unlock}, {@link #changePin} and
     * {@link #delete} use it; {@link #updateConfig} replaces it.
     *
     * @throws ChatXdkException if the configuration is not a Juicebox config (kind
     *     {@code INVALID_INPUT}), or is empty or blank (kind {@code INVALID_STATE}, the error a chat
     *     without a config gives its Juicebox calls).
     */
    public Chat(String juiceboxConfigJson) {
        this(Objects.requireNonNull(juiceboxConfigJson, "juiceboxConfigJson"), null, null);
    }

    /**
     * For this repository's tests: a chat that reads its feature switches from
     * {@code featureEndpoint} within {@code featureTimeout}, or from the default endpoint when
     * it is null.
     */
    Chat(String juiceboxConfigJson, String featureEndpoint, Duration featureTimeout) {
        PointerByReference out = new PointerByReference();
        if (juiceboxConfigJson == null) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_new(null, out));
        } else {
            try (Memory config = FfiStrings.utf8(juiceboxConfigJson)) {
                FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_new(config, out));
            }
        }
        handle = out.getValue();
        cleanable = CLEANER.register(this, new FreeHandle(handle));
        if (featureEndpoint != null) {
            configureFeatures(featureEndpoint, featureTimeout);
        }
        FeatureFetch.start(this);
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
            return FfiStrings.consumeBool(ChatNative.INSTANCE.chat_xdk_is_unlocked(handle));
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
            return FfiStrings.consumeBool(ChatNative.INSTANCE.chat_xdk_has_identity_key(handle));
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
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_set_reject_unverified(handle, reject ? 1 : 0));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Set the session identity: the owner's user id and signing-key version, used
     * as the defaults wherever a params class' {@code senderId} / {@code signingKeyVersion}
     * is left null. A resolved default and an explicitly passed value produce
     * byte-identical signed output for the same logical inputs. The signing-key
     * version is the {@code public_key_version} returned when the keys were
     * registered.
     */
    public void setIdentity(SetIdentityParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("user_id", parameters.userId);
        n.put("signing_key_version", parameters.signingKeyVersion);
        try (Memory j = FfiStrings.utf8(n.toString())) {
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_set_identity(handle, j));
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
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_set_cache_keys(handle, enabled ? 1 : 0));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private void configureFeatures(String endpoint, Duration timeout) {
        try (Memory e = FfiStrings.utf8(endpoint)) {
            FfiStrings.consume(FeatureNative.INSTANCE.chat_xdk_internal_feature_configure(
                    handle, e, timeout.toMillis()));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Start this chat's one read of the feature switches: the GET to perform as JSON, or an empty
     * string when the chat takes the answer of a GET already in flight.
     */
    String startFeatures() {
        try {
            return FfiStrings.consume(FeatureNative.INSTANCE.chat_xdk_internal_feature_start(handle));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Store signing keys to use when a decrypt call's params leave {@code signingKeys}
     * null (or empty). Only this explicit call populates the store — a key carried inside
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
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_lock(handle));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Set or replace the Juicebox configuration: on first boot, for a chat created without one,
     * or whenever the X API issues fresh short-lived auth tokens.
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
     * Pass {@code bytes} to {@code call} in native memory that is wiped once the call returns:
     * the copy of a PIN never outlives the call.
     */
    private static <T> T withSecret(byte[] bytes, Function<Memory, T> call) {
        Objects.requireNonNull(bytes, "pin");
        if (bytes.length == 0) {
            // A zero-length Memory cannot be allocated; the native side treats
            // NULL with length 0 as an empty PIN.
            return call.apply(null);
        }
        try (Memory m = new Memory(bytes.length)) {
            m.write(0, bytes, 0, bytes.length);
            try {
                return call.apply(m);
            } finally {
                m.clear();
            }
        }
    }

    /**
     * Register the SDK's keys with Juicebox under {@code pin} (first-time setup).
     * Call {@link #generateKeypairs} and POST the result to the X API first,
     * then call this to persist the keys under the user's PIN. Needs a chat created
     * with a Juicebox configuration.
     *
     * @param pin The user's PIN as bytes, which you can zero once the call returns.
     * @return The user's public keys to upload to the X API.
     */
    public PublicKeys setup(byte[] pin) throws Exception {
        throwIfDisposed();
        try {
            String json = FfiStrings.consume(withSecret(pin,
                    p -> ChatNative.INSTANCE.chat_xdk_setup(handle, p, pin.length)));
            return ChatJson.MAPPER.readValue(json, PublicKeys.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Recover keys from Juicebox with {@code pin} and load them into memory.
     * Call on every startup after the user enters their PIN. A wrong PIN throws a
     * {@link ChatXdkException} of kind {@link ChatXdkException.Kind#INVALID_PIN}.
     *
     * @param pin The user's PIN as bytes, which you can zero once the call returns.
     */
    public void unlock(byte[] pin) {
        throwIfDisposed();
        try {
            FfiStrings.consume(withSecret(pin,
                    p -> ChatNative.INSTANCE.chat_xdk_unlock(handle, p, pin.length)));
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

    /**
     * Re-register keys under a new PIN, unlocking with the old one first. Both PINs are bytes
     * you can zero once the call returns.
     */
    public void changePin(byte[] oldPin, byte[] newPin) {
        throwIfDisposed();
        Objects.requireNonNull(newPin, "newPin");
        try {
            FfiStrings.consume(withSecret(oldPin, o -> withSecret(newPin,
                    n -> ChatNative.INSTANCE.chat_xdk_change_pin(handle, o, oldPin.length, n, newPin.length))));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** {@link #setup} on the common fork-join pool. */
    public CompletableFuture<PublicKeys> setupAsync(byte[] pin) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return setup(pin);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });
    }

    /** {@link #unlock} on the common fork-join pool. */
    public CompletableFuture<Void> unlockAsync(byte[] pin) {
        return CompletableFuture.runAsync(() -> unlock(pin));
    }

    /** {@link #delete} on the common fork-join pool. */
    public CompletableFuture<Void> deleteAsync() {
        return CompletableFuture.runAsync(this::delete);
    }

    /** {@link #changePin} on the common fork-join pool. */
    public CompletableFuture<Void> changePinAsync(byte[] oldPin, byte[] newPin) {
        return CompletableFuture.runAsync(() -> changePin(oldPin, newPin));
    }

    /**
     * Generate new identity + signing keypairs and return the registration payload.
     * POST the payload to {@code POST /2/users/:id/public_keys} before calling
     * {@link #setup}. No signing-key version is set: after registering the keys,
     * call {@link #setIdentity} with the {@code public_key_version} the
     * registration returns.
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
     * Export private keys as raw bytes for a secure backup: 32 bytes for the identity key, 64 with
     * the signing key. Throws a {@link ChatXdkException} of kind
     * {@link ChatXdkException.Kind#INVALID_STATE} when no identity key is loaded.
     * These are raw secret key bytes — store with extreme care.
     */
    public byte[] exportKeys() {
        throwIfDisposed();
        try {
            String b64 = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_export_keys(handle));
            return Base64.getDecoder().decode(b64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Import private keys from the byte array {@link #exportKeys} produced: 32 bytes (identity
     * only) or 64 bytes (identity + signing). When {@link ImportKeysParams#signingKeyVersion} is
     * set (the {@code public_key_version} returned when the keys were registered), it is recorded
     * as well, so participant-key filtering and the session signing-key version are set in one
     * call. The key bytes are passed to the native side directly, never copied into a string.
     */
    public void importKeys(ImportKeysParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        byte[] keys = parameters.keys == null ? new byte[0] : parameters.keys;
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        if (parameters.signingKeyVersion != null) {
            n.put("signing_key_version", parameters.signingKeyVersion);
        }
        FfiResult.ByValue r;
        try (Memory j = FfiStrings.utf8(n.toString())) {
            if (keys.length == 0) {
                // A zero-length Memory cannot be allocated; the native side
                // treats NULL + length 0 as an empty key blob.
                r = ChatNative.INSTANCE.chat_xdk_import_keys(handle, null, 0, j);
            } else {
                try (Memory m = new Memory(keys.length)) {
                    m.write(0, keys, 0, keys.length);
                    try {
                        r = ChatNative.INSTANCE.chat_xdk_import_keys(handle, m, keys.length, j);
                    } finally {
                        m.clear();
                    }
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
     *     {@link ConversationKeyBundle#keys} to {@link #decryptEvent}.
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
     * <p>Under the default reject-unverified policy, a signed event with no usable signing key
     * (passed or stored via {@link #setSigningKeys}) throws; only after
     * {@link #setRejectUnverified}(false) are such events returned with {@code verified: false}.
     * A member removal's title and description, re-encrypted under the new key, aren't changes:
     * they throw a {@link ChatXdkException} of kind {@code INVALID_INPUT} under either policy.
     *
     * @return A {@link JsonNode} with a {@code "type"} field indicating the event kind
     *     ({@code "Message"}, {@code "KeyChange"}, {@code "GroupChange"}, etc.).
     */
    public JsonNode decryptEvent(DecryptEventParams parameters) throws Exception {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("event_b64", parameters.eventB64);
        n.set("conversation_keys", conversationKeysJson(parameters.conversationKeys));
        if (parameters.signingKeys != null) {
            n.set("signing_keys", ChatJson.MAPPER.valueToTree(parameters.signingKeys));
        }
        try (Memory j = FfiStrings.utf8(ChatJson.MAPPER.writeValueAsString(n))) {
            String resultJson = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_event(handle, j));
            return ChatJson.MAPPER.readTree(resultJson);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt a batch of webhook events in one call. Keys are extracted from {@code KeyChange} events in the batch;
     * failures are recorded in {@link DecryptEventsResult#errors} — this method never throws per-event.
     * A member removal's title and description, re-encrypted under the new key, aren't changes:
     * they are recorded there too.
     */
    public DecryptEventsResult decryptEvents(DecryptEventsParams parameters) throws Exception {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.set("events", ChatJson.MAPPER.valueToTree(parameters.events == null ? List.of() : parameters.events));
        if (parameters.signingKeys != null) {
            n.set("signing_keys", ChatJson.MAPPER.valueToTree(parameters.signingKeys));
        }
        try (Memory j = FfiStrings.utf8(ChatJson.MAPPER.writeValueAsString(n))) {
            String resultJson = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_decrypt_events(handle, j));
            JsonNode root = ChatJson.MAPPER.readTree(resultJson);
            DecryptEventsResult out = new DecryptEventsResult();
            List<DecryptedEvent> events = new ArrayList<>();
            JsonNode arr = root.get("events");
            if (arr != null && arr.isArray()) {
                for (JsonNode el : arr) {
                    DecryptedEvent decrypted = new DecryptedEvent();
                    decrypted.event = el.get("event");
                    if (el.hasNonNull("original_b64")) {
                        decrypted.originalB64 = el.get("original_b64").asText();
                    }
                    events.add(decrypted);
                }
            }
            out.events = events;
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
     * The current title and description are plaintext: the call encrypts each under the
     * new conversation key, signs the ciphertext, and returns it as
     * {@code encryptedTitle} and {@code encryptedDescription}. The current avatar URL is
     * signed as is.
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
     * The title is plaintext: the call encrypts it under the new conversation key,
     * signs the ciphertext, and returns it as {@code encryptedTitle}, the
     * {@code group_name} the create request sends. A create sets no avatar; set it
     * afterwards with {@link #prepareGroupAvatarChange}.
     */
    public PreparedConversationChange prepareGroupCreate(GroupCreateParams parameters)
            throws Exception {
        throwIfDisposed();
        return callPrepare(
                buildPrepareGroupCreateJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_create);
    }

    /**
     * Build the signed action for deleting messages from a conversation: the
     * request's {@code action_signatures}, one entry.
     *
     * <p>A delete is a signed plaintext event, not an encrypted message, so no
     * conversation key is involved. The SDK generates the action's message id;
     * read it back from the entry.
     */
    public PreparedAction prepareMessageDelete(MessageDeleteParams parameters) throws Exception {
        throwIfDisposed();
        try (Memory j = FfiStrings.utf8(buildPrepareMessageDeleteJson(parameters))) {
            String resultJson = FfiStrings.consume(
                    ChatNative.INSTANCE.chat_xdk_prepare_message_delete(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedAction.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Build the signed action for marking a conversation read: the
     * {@code action_signatures} of the mark-read request
     * ({@code POST /2/chat/conversations/{id}/read}), one entry.
     *
     * <p>A read receipt is a signed plaintext event, not an encrypted message,
     * so no conversation key is involved. The SDK generates the action's
     * message id; read it back from the entry.
     */
    public PreparedAction prepareMarkConversationRead(MarkConversationReadParams parameters)
            throws Exception {
        throwIfDisposed();
        try (Memory j = FfiStrings.utf8(buildPrepareMarkConversationReadJson(parameters))) {
            String resultJson = FfiStrings.consume(
                    ChatNative.INSTANCE.chat_xdk_prepare_mark_conversation_read(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedAction.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Sign a group member removal and rotate the conversation key for the members
     * who stay ({@code publicKeys}). The result carries the new key and the action
     * signatures: the removal, a title and a description change for each one the
     * params set, re-encrypted under the new key, and the conversation-key change.
     */
    public PreparedConversationChange prepareGroupMembersRemove(GroupMembersRemoveParams parameters)
            throws Exception {
        throwIfDisposed();
        return callPrepare(
                buildPrepareGroupMembersRemoveJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_members_remove);
    }

    /** Sign leaving a group. Does not rotate the conversation key. */
    public PreparedAction prepareGroupLeave(GroupLeaveParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupLeaveJson(parameters), ChatNative.INSTANCE::chat_xdk_prepare_group_leave);
    }

    /** Encrypt a new group title under the conversation key and sign the change. */
    public PreparedGroupMetadataChange prepareGroupTitleChange(GroupTitleChangeParams parameters)
            throws Exception {
        throwIfDisposed();
        return callMetadataChange(
                buildPrepareGroupTitleChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_title_change);
    }

    /**
     * Sign a group avatar change: the avatar image's media URL, as is, and the version of
     * the key the image is encrypted under.
     */
    public PreparedAction prepareGroupAvatarChange(GroupAvatarChangeParams parameters)
            throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupAvatarChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_avatar_change);
    }

    /** Encrypt a new group description under the conversation key and sign the change. */
    public PreparedGroupMetadataChange prepareGroupDescriptionChange(
            GroupDescriptionChangeParams parameters) throws Exception {
        throwIfDisposed();
        return callMetadataChange(
                buildPrepareGroupDescriptionChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_description_change);
    }

    /** Sign adding group admins. */
    public PreparedAction prepareGroupAdminsAdd(GroupAdminsAddParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupAdminsAddJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_admins_add);
    }

    /** Sign removing group admins. */
    public PreparedAction prepareGroupAdminsRemove(GroupAdminsRemoveParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupAdminsRemoveJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_admins_remove);
    }

    /** Sign enabling a group invite. */
    public PreparedAction prepareGroupInviteEnable(GroupInviteEnableParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupInviteEnableJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_invite_enable);
    }

    /** Sign disabling a group invite. */
    public PreparedAction prepareGroupInviteDisable(GroupInviteDisableParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupInviteDisableJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_invite_disable);
    }

    /** Sign a request to join a group. */
    public PreparedAction prepareGroupJoinRequest(GroupJoinRequestParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupJoinRequestJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_join_request);
    }

    /** Sign rejecting group join requests. */
    public PreparedAction prepareGroupJoinReject(GroupJoinRejectParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareGroupJoinRejectJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_group_join_reject);
    }

    /** Sign a message-TTL change. */
    public PreparedAction prepareMessageTtlChange(MessageTtlChangeParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareMessageTtlChangeJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_message_ttl_change);
    }

    /** Sign clearing a conversation's message TTL. */
    public PreparedAction prepareMessageTtlRemove(MessageTtlRemoveParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareMessageTtlRemoveJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_message_ttl_remove);
    }

    /** Sign one screen-capture setting change. */
    public PreparedAction prepareScreenCapture(ScreenCaptureParams parameters) throws Exception {
        throwIfDisposed();
        return callAction(
                buildPrepareScreenCaptureJson(parameters),
                ChatNative.INSTANCE::chat_xdk_prepare_screen_capture);
    }

    private PreparedConversationChange callPrepare(String paramsJson, ParamsJsonFn fn) throws Exception {
        try (Memory j = FfiStrings.utf8(paramsJson)) {
            String resultJson = FfiStrings.consume(fn.apply(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedConversationChange.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private PreparedGroupMetadataChange callMetadataChange(String paramsJson, ParamsJsonFn fn)
            throws Exception {
        try (Memory j = FfiStrings.utf8(paramsJson)) {
            String resultJson = FfiStrings.consume(fn.apply(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedGroupMetadataChange.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private PreparedAction callAction(String paramsJson, ParamsJsonFn fn) throws Exception {
        try (Memory j = FfiStrings.utf8(paramsJson)) {
            String resultJson = FfiStrings.consume(fn.apply(handle, j));
            return ChatJson.MAPPER.readValue(resultJson, PreparedAction.class);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Decrypt a group title or description the X API returns for a conversation
     * (base64 ciphertext) with the raw 32-byte conversation key. Group changes in
     * events need no call of their own: {@link #decryptEvent} returns them decrypted.
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
     * {@code POST /2/chat/conversations/{id}/messages}. A v1 message with files takes an id
     * derived from its files, so building it again gives the same id; other messages take a random
     * id. Encrypt each file afterwards with {@link #encryptFile} or {@link #fileEncryptor} and the
     * payload's {@link SendPayload#eventB64}.
     */
    public SendPayload encryptMessage(EncryptMessageParams parameters) throws Exception {
        throwIfDisposed();
        return callEncrypt(buildEncryptMessageJson(parameters), ChatNative.INSTANCE::chat_xdk_encrypt_message);
    }

    /**
     * Encrypt a reply message for the X API.
     * Like {@link #encryptMessage} but includes a reply-to preview; the reply's id and files work
     * the same way.
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
     *     ({@code conversation_participant_keys[].encrypted_conversation_key}).
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

    /** Encode a version &#8594; key map as {@code {"version": "base64", ...}}. */
    private static ObjectNode conversationKeysJson(Map<String, byte[]> conversationKeys) {
        ObjectNode json = ChatJson.MAPPER.createObjectNode();
        if (conversationKeys != null) {
            for (Map.Entry<String, byte[]> e : conversationKeys.entrySet()) {
                json.put(e.getKey(), Base64.getEncoder().encodeToString(e.getValue()));
            }
        }
        return json;
    }

    /** Add an optional conversation key (base64) and its version to file params. */
    private static void putConversationKey(ObjectNode n, byte[] conversationKey, String conversationKeyVersion) {
        if (conversationKey != null) {
            n.put("conversation_key", Base64.getEncoder().encodeToString(conversationKey));
        }
        if (conversationKeyVersion != null) {
            n.put("conversation_key_version", conversationKeyVersion);
        }
    }

    private static String fileParamsJson(
            String eventB64, Map<String, byte[]> conversationKeys, String mediaHashKey) {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("event_b64", eventB64);
        n.set("conversation_keys", conversationKeysJson(conversationKeys));
        n.put("media_hash_key", mediaHashKey);
        return n.toString();
    }

    // JsonNode.toString() writes the tree as JSON without a checked exception.
    private byte[] callFile(ObjectNode params, ParamsJsonFn fn) {
        try (Memory j = FfiStrings.utf8(params.toString())) {
            return Base64.getDecoder().decode(FfiStrings.consume(fn.apply(handle, j)));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Encrypt a file of an outgoing message, after the message is built. The SDK finds the
     * attachment that names {@link EncryptFileParams#mediaHashKey} in the message
     * {@link EncryptFileParams#eventB64} carries, and encrypts the file under that attachment's
     * key. Upload the result under the same media hash key; its size is
     * {@link ChatXdkUtilities#encryptedFileSize}.
     *
     * @return Encrypted bytes.
     * @throws ChatXdkException if the event is not a message with this file, or the conversation
     *     key is not the one the message was encrypted under. The message says what to pass instead.
     */
    public byte[] encryptFile(EncryptFileParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("file", Base64.getEncoder().encodeToString(parameters.file == null ? new byte[0] : parameters.file));
        n.put("event_b64", parameters.eventB64);
        n.put("media_hash_key", parameters.mediaHashKey);
        putConversationKey(n, parameters.conversationKey, parameters.conversationKeyVersion);
        return callFile(n, ChatNative.INSTANCE::chat_xdk_encrypt_file);
    }

    /**
     * Decrypt an encrypted file (e.g. an image or video), as downloaded.
     *
     * @return Decrypted bytes.
     * @throws ChatXdkException if the key version is missing, the event is not an encrypted
     *     message with this file, or {@link DecryptFileParams#encrypted} is not the file's
     *     complete encrypted bytes. The message says what to pass instead.
     */
    public byte[] decryptFile(DecryptFileParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("encrypted", Base64.getEncoder().encodeToString(
                parameters.encrypted == null ? new byte[0] : parameters.encrypted));
        n.put("event_b64", parameters.eventB64);
        n.set("conversation_keys", conversationKeysJson(parameters.conversationKeys));
        n.put("media_hash_key", parameters.mediaHashKey);
        return callFile(n, ChatNative.INSTANCE::chat_xdk_decrypt_file);
    }

    /**
     * Create an incremental encryptor for a file too large to hold in memory. Takes the params of
     * {@link #encryptFile} apart from the file, which is fed to the encryptor.
     *
     * @return A new {@link FileEncryptor}; close it when finished.
     * @throws ChatXdkException if the event is not a message with this file, or the conversation
     *     key is not the one the message was encrypted under. The message says what to pass instead.
     */
    public FileEncryptor fileEncryptor(FileEncryptorParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        try {
            ObjectNode n = ChatJson.MAPPER.createObjectNode();
            n.put("event_b64", parameters.eventB64);
            n.put("media_hash_key", parameters.mediaHashKey);
            putConversationKey(n, parameters.conversationKey, parameters.conversationKeyVersion);
            return FileEncryptor.create(handle, n.toString());
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Create an incremental decryptor for an encrypted file too large to hold in memory. Takes the
     * params of {@link #decryptFile} apart from the encrypted bytes, which are fed to the decryptor.
     *
     * @return A new {@link FileDecryptor}; close it when finished.
     * @throws ChatXdkException if the key version is missing, or the event is not an encrypted
     *     message with this file. The message says what to pass instead.
     */
    public FileDecryptor fileDecryptor(FileDecryptorParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        try {
            return FileDecryptor.create(
                    handle, fileParamsJson(parameters.eventB64, parameters.conversationKeys, parameters.mediaHashKey));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Encrypt a file under a key you already hold, rather than from a message: a group's avatar
     * image under the conversation key whose version is signed next to the avatar URL, or an app's
     * own files at rest. The file is encrypted under the key itself, in the format {@link
     * #encryptFile} writes; its size is {@link ChatXdkUtilities#encryptedFileSize}.
     *
     * @return Encrypted bytes.
     * @throws ChatXdkException of kind {@link ChatXdkException.Kind#INVALID_INPUT} if the key is
     *     not 32 bytes.
     */
    public byte[] encryptFileWithKey(EncryptFileWithKeyParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("file", Base64.getEncoder().encodeToString(parameters.file == null ? new byte[0] : parameters.file));
        if (parameters.key != null) {
            n.put("key", Base64.getEncoder().encodeToString(parameters.key));
        }
        return callFile(n, ChatNative.INSTANCE::chat_xdk_encrypt_file_with_key);
    }

    /**
     * Decrypt a file encrypted under a key you already hold, as downloaded, such as a group's
     * avatar image under the conversation key for the version its avatar change names.
     *
     * @return Decrypted bytes.
     * @throws ChatXdkException of kind {@link ChatXdkException.Kind#INVALID_INPUT} if the key is
     *     not 32 bytes, or of kind {@link ChatXdkException.Kind#DECRYPTION} if {@link
     *     DecryptFileWithKeyParams#encrypted} is not the complete file encrypted under the key.
     */
    public byte[] decryptFileWithKey(DecryptFileWithKeyParams parameters) {
        throwIfDisposed();
        Objects.requireNonNull(parameters, "parameters");
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("encrypted", Base64.getEncoder().encodeToString(
                parameters.encrypted == null ? new byte[0] : parameters.encrypted));
        if (parameters.key != null) {
            n.put("key", Base64.getEncoder().encodeToString(parameters.key));
        }
        return callFile(n, ChatNative.INSTANCE::chat_xdk_decrypt_file_with_key);
    }

    /**
     * Sign application data with the signing key. Throws {@link ChatXdkException} for an
     * event signature payload or a public key, which only the SDK signs.
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
     * @throws ChatXdkException of kind {@link ChatXdkException.Kind#INVALID_INPUT} for a malformed
     *     public key or signature, never returned as a {@code false} result. Verifying needs no
     *     loaded keys.
     */
    public boolean verify(String publicKeyB64, byte[] signature, byte[] data) {
        throwIfDisposed();
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(data, "data");
        String sigB64 = Base64.getEncoder().encodeToString(signature);
        try (Memory pk = FfiStrings.utf8(publicKeyB64);
                Memory sig = FfiStrings.utf8(sigB64)) {
            if (data.length == 0) {
                return FfiStrings.consumeBool(ChatNative.INSTANCE.chat_xdk_verify(handle, pk, sig, null, 0));
            }
            try (Memory dm = new Memory(data.length)) {
                dm.write(0, data, 0, data.length);
                return FfiStrings.consumeBool(ChatNative.INSTANCE.chat_xdk_verify(handle, pk, sig, dm, data.length));
            }
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
            return FfiStrings.consumeBool(
                    ChatNative.INSTANCE.chat_xdk_verify_key_binding(handle, identity, signing, sig));
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
            return FfiStrings.consumeBool(ChatNative.INSTANCE.chat_xdk_matches_registered_key(handle, publicKey));
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
        if (p.quickReply != null) {
            n.set("quick_reply", ChatJson.MAPPER.valueToTree(p.quickReply));
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
        if (p.quickReply != null) {
            n.set("quick_reply", ChatJson.MAPPER.valueToTree(p.quickReply));
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

    private static void putIds(ObjectNode n, String field, List<String> ids) {
        n.set(field, ChatJson.MAPPER.valueToTree(ids == null ? List.of() : ids));
    }

    private static String buildPrepareGroupMembersRemoveJson(GroupMembersRemoveParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.set("public_keys", ChatJson.MAPPER.valueToTree(
                p.publicKeys == null ? List.of() : p.publicKeys));
        n.put("conversation_id", p.conversationId);
        putIds(n, "user_ids", p.userIds);
        if (p.title != null) {
            n.put("title", p.title);
        }
        if (p.description != null) {
            n.put("description", p.description);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupLeaveJson(GroupLeaveParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        if (p.promoteAdminId != null) {
            n.put("promote_admin_id", p.promoteAdminId);
        }
        if (p.conversationKeyVersion != null) {
            n.put("conversation_key_version", p.conversationKeyVersion);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupTitleChangeJson(GroupTitleChangeParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("new_title", p.newTitle);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupAvatarChangeJson(GroupAvatarChangeParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("new_avatar_url", p.newAvatarUrl);
        n.put("conversation_key_version", p.conversationKeyVersion);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupDescriptionChangeJson(GroupDescriptionChangeParams p)
            throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("new_description", p.newDescription);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, p.conversationKey, p.conversationKeyVersion);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupAdminsAddJson(GroupAdminsAddParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        putIds(n, "user_ids", p.userIds);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupAdminsRemoveJson(GroupAdminsRemoveParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        putIds(n, "user_ids", p.userIds);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupInviteEnableJson(GroupInviteEnableParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("invite_url", p.inviteUrl);
        if (p.expiresAtMsec != null) {
            n.put("expires_at_msec", p.expiresAtMsec);
        }
        if (p.affiliateId != null) {
            n.put("affiliate_id", p.affiliateId);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupInviteDisableJson(GroupInviteDisableParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        if (p.disabledBy != null) {
            n.put("disabled_by", p.disabledBy);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupJoinRequestJson(GroupJoinRequestParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        if (p.requestingUserId != null) {
            n.put("requesting_user_id", p.requestingUserId);
        }
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareGroupJoinRejectJson(GroupJoinRejectParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        putIds(n, "user_ids", p.userIds);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareMessageTtlChangeJson(MessageTtlChangeParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("ttl_msec", p.ttlMsec);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareMessageTtlRemoveJson(MessageTtlRemoveParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareScreenCaptureJson(ScreenCaptureParams p) throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("change", p.change.name());
        putIdentityAndKey(n, p.senderId, p.signingKeyVersion, null, null);
        return ChatJson.MAPPER.writeValueAsString(n);
    }

    private static String buildPrepareMarkConversationReadJson(MarkConversationReadParams p)
            throws Exception {
        ObjectNode n = ChatJson.MAPPER.createObjectNode();
        n.put("conversation_id", p.conversationId);
        n.put("seen_until_sequence_id", p.seenUntilSequenceId);
        if (p.seenAtMsec != null) {
            n.put("seen_at_msec", p.seenAtMsec);
        }
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
        if (p.currentDescription != null) {
            n.put("current_description", p.currentDescription);
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
        if (p.ttlMsec != null) {
            n.put("ttl_msec", p.ttlMsec);
        }
        return ChatJson.MAPPER.writeValueAsString(n);
    }
}
