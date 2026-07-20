package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Chat;
import com.x.chatxdk.StreamDecryptor;
import com.x.chatxdk.StreamEncryptor;
import com.x.chatxdk.Types.*;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Crypto core for the JVM chat-xdk example bot.
 *
 * <p>A thin, network-free wrapper around the {@link Chat} binding.
 * Everything that touches the SDK lives here so it can be unit-tested directly
 * (see {@code ChatCoreTest}). The four core feature touchpoints are all here:
 *
 * <ul>
 *   <li>key management     -&gt; loadKeys / setIdentity / generateAndRegister</li>
 *   <li>conversation keys  -&gt; prepareConversationKeyChange / decryptConversationKey</li>
 *   <li>message encryption -&gt; encryptReply</li>
 *   <li>event decryption   -&gt; decryptBatch (decryptEvents) and decryptOne (decryptEvent)</li>
 * </ul>
 */
public final class ChatCore implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Chat chat = new Chat();
    private String signingKeyVersion = "1";

    public String signingKeyVersion() {
        return signingKeyVersion;
    }

    // -- Key management -----------------------------------------------------

    /** Import an existing base64 private-key blob (identity[+signing])
     * together with the key version it was registered under. */
    public void loadKeys(String privateKeysB64, String signingKeyVersion) {
        chat.importKeys(Base64.getDecoder().decode(privateKeysB64), signingKeyVersion);
        this.signingKeyVersion = signingKeyVersion;
    }

    /**
     * Set the session identity once; every encrypt/prepare call below then
     * signs as this user without passing a sender id per call.
     */
    public void setIdentity(String userId) {
        chat.setIdentity(userId, signingKeyVersion);
    }

    /** Generated identity: the registration payload + the private blob to persist. */
    public record Generated(PublicKeyRegistrationPayload registration, String privateKeysB64) {}

    /** Generate a fresh identity to register with the X API. */
    public Generated generateAndRegister() throws Exception {
        PublicKeyRegistrationPayload payload = chat.generateKeypairs();
        byte[] exported = chat.exportKeys();
        String blob = exported == null ? "" : Base64.getEncoder().encodeToString(exported);
        return new Generated(payload, blob);
    }

    public PublicKeys publicKeys() throws Exception {
        return chat.getPublicKeys();
    }

    // -- Conversation keys --------------------------------------------------

    public PreparedConversationChange prepareConversationKeyChange(
            List<PublicKeyInput> publicKeys, String conversationId) throws Exception {
        ConversationKeyChangeParams params = new ConversationKeyChangeParams(publicKeys);
        params.conversationId = conversationId;
        return chat.prepareConversationKeyChange(params);
    }

    /** ECIES-decrypt one conversation key -&gt; raw 32-byte key. */
    public byte[] decryptConversationKey(String encryptedKeyB64) {
        return chat.decryptConversationKey(encryptedKeyB64);
    }

    // -- Decryption: the two paths -----------------------------------------

    /** Batch path — used on initial conversation load. */
    public DecryptEventsResult decryptBatch(List<String> eventsB64, List<SigningKeyEntry> signingKeys) throws Exception {
        return chat.decryptEvents(eventsB64, signingKeys);
    }

    /** Single-event path — used for each new event after the initial load. */
    public JsonNode decryptOne(String eventB64, Map<String, byte[]> conversationKeys, List<SigningKeyEntry> signingKeys) throws Exception {
        return chat.decryptEvent(eventB64, conversationKeys, signingKeys);
    }

    // -- Message encryption -------------------------------------------------

    /** Fields the X API expects for an encrypted message send. */
    public record SendBody(String messageId, String encodedMessageCreateEvent, String encodedMessageEventSignature) {}

    /**
     * Encrypt + sign a fresh message ({@code encryptMessage}); returns fields
     * ready for the X API send. The sender comes from {@link #setIdentity}.
     */
    public SendBody encryptReply(String conversationId, String text, byte[] conversationKey, String conversationKeyVersion) throws Exception {
        return encryptReply(conversationId, text, conversationKey, conversationKeyVersion, null, null, null, null, null);
    }

    /**
     * Encrypt + sign a message, returning fields ready for the X API send.
     *
     * <p>Without {@code replyToEvent} this sends a fresh message via
     * {@code encryptMessage}; with it, the SDK's {@code encryptReply} builds a
     * <em>threaded</em> reply whose preview is derived from that raw signed
     * event ({@code replyToCkces} carries the key-change events for the
     * original's key version when it differs from this reply's version).
     * {@code entities} are byte-range descriptors (start, end, type);
     * {@code attachments} are attachment descriptors (e.g. a media reference);
     * {@code ttlMsec} makes the message disappear after the given lifetime.
     */
    public SendBody encryptReply(
            String conversationId,
            String text,
            byte[] conversationKey,
            String conversationKeyVersion,
            String replyToEvent,
            List<EntityDescriptor> entities,
            List<AttachmentDescriptor> attachments,
            Long ttlMsec,
            List<String> replyToCkces)
            throws Exception {
        SendPayload payload;
        if (replyToEvent == null) {
            EncryptMessageParams params = new EncryptMessageParams(conversationId, text);
            params.conversationKey = conversationKey;
            params.conversationKeyVersion = conversationKeyVersion;
            params.entities = entities;
            params.attachments = attachments;
            params.ttlMsec = ttlMsec;
            payload = chat.encryptMessage(params);
        } else {
            EncryptReplyParams params = new EncryptReplyParams(conversationId, text, replyToEvent);
            params.conversationKey = conversationKey;
            params.conversationKeyVersion = conversationKeyVersion;
            params.replyToCkces = replyToCkces;
            params.entities = entities;
            params.attachments = attachments;
            params.ttlMsec = ttlMsec;
            payload = chat.encryptReply(params);
        }
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(payload.messageId, payload.encryptedContent, payload.encodedEventSignature);
    }

    /** Encrypt + sign a reaction add/remove targeting a raw event
     * (the conversation id and target sequence id are derived from it). */
    public SendBody encryptReaction(
            boolean add,
            String targetEventB64,
            String emoji,
            byte[] conversationKey,
            String conversationKeyVersion)
            throws Exception {
        EncryptReactionParams params = new EncryptReactionParams(targetEventB64, emoji);
        params.conversationKey = conversationKey;
        params.conversationKeyVersion = conversationKeyVersion;
        SendPayload payload = add ? chat.encryptAddReaction(params) : chat.encryptRemoveReaction(params);
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(payload.messageId, payload.encryptedContent, payload.encodedEventSignature);
    }

    // -- Group management -----------------------------------------------------

    /** Prepare a group creation: fresh key + the two required signatures. */
    public PreparedConversationChange prepareGroupCreate(
            List<PublicKeyInput> publicKeys,
            String conversationId,
            List<String> memberIds,
            List<String> adminIds)
            throws Exception {
        return chat.prepareGroupCreate(
                new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds));
    }

    /** Prepare a member add: rotated key + the two required signatures. */
    public PreparedConversationChange prepareGroupMembersChange(
            List<PublicKeyInput> publicKeys,
            String conversationId,
            List<String> newMemberIds,
            List<String> currentMemberIds,
            List<String> currentAdminIds)
            throws Exception {
        return chat.prepareGroupMembersChange(new GroupMembersChangeParams(
                publicKeys, conversationId, newMemberIds, currentMemberIds, currentAdminIds, List.of()));
    }

    // -- Media streaming -----------------------------------------------------

    private static final int MEDIA_CHUNK = 1024 * 1024;

    /**
     * Encrypt a media blob with the incremental stream API.
     *
     * <p>Feeding fixed-size chunks through {@code push} keeps memory bounded no
     * matter how large the file is; {@code finish} emits the final frame that
     * seals the stream (decryption fails without it).
     */
    public byte[] encryptMedia(byte[] plaintext, byte[] conversationKey) throws Exception {
        try (StreamEncryptor enc = chat.streamEncryptor(conversationKey)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int offset = 0; offset < plaintext.length; offset += MEDIA_CHUNK) {
                int end = Math.min(offset + MEDIA_CHUNK, plaintext.length);
                out.write(enc.push(Arrays.copyOfRange(plaintext, offset, end)));
            }
            out.write(enc.finish());
            return out.toByteArray();
        }
    }

    /**
     * Decrypt a media blob with the incremental stream API.
     *
     * <p>{@code finish} throws if the stream was truncated, so plaintext from
     * {@code push} must not be treated as complete until it succeeds.
     */
    public byte[] decryptMedia(byte[] ciphertext, byte[] conversationKey) throws Exception {
        try (StreamDecryptor dec = chat.streamDecryptor(conversationKey)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int offset = 0; offset < ciphertext.length; offset += MEDIA_CHUNK) {
                int end = Math.min(offset + MEDIA_CHUNK, ciphertext.length);
                out.write(dec.push(Arrays.copyOfRange(ciphertext, offset, end)));
            }
            out.write(dec.finish());
            return out.toByteArray();
        }
    }

    // -- Generic helpers (handy for metadata + tests) -----------------------

    public String encrypt(String plaintext, byte[] conversationKey) {
        return chat.encrypt(plaintext, conversationKey);
    }

    public String decrypt(String ciphertextB64, byte[] conversationKey) {
        return chat.decrypt(ciphertextB64, conversationKey);
    }

    /** Pull the plain text out of a decrypted Message event, or null. */
    public static String messageText(JsonNode event) {
        if (event == null || !"Message".equals(event.path("type").asText())) {
            return null;
        }
        JsonNode text = event.path("content").path("text");
        return text.isMissingNode() || text.isNull() ? null : text.asText();
    }

    /**
     * Map a prepared conversation change into the X API request shape.
     *
     * <p>Works for 1:1 key changes (one signature) and group create / member add
     * (two signatures). {@code signingPublicKey} is the sender's own signing key,
     * which the API expects alongside each signature. A conversation-key change's
     * {@code signature_payload} is withheld (it embeds the plaintext key), so it
     * is included only when non-empty.
     */
    public static ObjectNode prepToRequest(PreparedConversationChange prep, String signingPublicKey) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("conversation_key_version", prep.conversationKeyVersion);
        ArrayNode participantKeys = body.putArray("conversation_participant_keys");
        for (EncryptedKeyForRecipient pk : prep.participantKeys) {
            ObjectNode entry = participantKeys.addObject();
            entry.put("user_id", pk.userId);
            entry.put("encrypted_conversation_key", pk.encryptedKey);
            entry.put("public_key_version", pk.publicKeyVersion);
        }
        ArrayNode signatures = body.putArray("action_signatures");
        for (ActionSignature sig : prep.actionSignatures) {
            ObjectNode entry = signatures.addObject();
            entry.put("message_id", sig.messageId);
            entry.put("encoded_message_event_detail", sig.encodedMessageEventDetail);
            ObjectNode inner = entry.putObject("message_event_signature");
            inner.put("signature", sig.signature);
            inner.put("signature_version", sig.signatureVersion);
            inner.put("public_key_version", sig.publicKeyVersion);
            inner.put("signing_public_key", signingPublicKey);
            if (sig.signaturePayload != null && !sig.signaturePayload.isEmpty()) {
                entry.put("signature_payload", sig.signaturePayload);
            }
        }
        return body;
    }

    @Override
    public void close() {
        chat.close();
    }
}
