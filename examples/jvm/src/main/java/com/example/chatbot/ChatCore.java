package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Chat;
import com.x.chatxdk.FileDecryptor;
import com.x.chatxdk.FileEncryptor;
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
 *   <li>message encryption -&gt; encryptReply, then encryptMedia for its files</li>
 *   <li>event decryption   -&gt; decryptBatch (decryptEvents) and decryptOne (decryptEvent)</li>
 * </ul>
 */
public final class ChatCore implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Chat chat = new Chat();
    private String signingKeyVersion;

    public String signingKeyVersion() {
        return signingKeyVersion;
    }

    // -- Key management -----------------------------------------------------

    /** Import an existing base64 private-key blob (identity[+signing])
     * together with the public_key_version the X API returned when it was
     * registered. */
    public void loadKeys(String privateKeysB64, String signingKeyVersion) {
        chat.importKeys(new ImportKeysParams(Base64.getDecoder().decode(privateKeysB64), signingKeyVersion));
        this.signingKeyVersion = signingKeyVersion;
    }

    /**
     * Set the session identity once; every encrypt/prepare call below then
     * signs as this user without passing a sender id per call.
     */
    public void setIdentity(String userId) {
        if (signingKeyVersion == null || signingKeyVersion.isEmpty()) {
            throw new IllegalStateException("signing key version unknown: pass loadKeys the "
                    + "public_key_version the X API returned when the keys were registered");
        }
        chat.setIdentity(new SetIdentityParams(userId, signingKeyVersion));
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
        DecryptEventsParams params = new DecryptEventsParams(eventsB64);
        params.signingKeys = signingKeys;
        return chat.decryptEvents(params);
    }

    /** Single-event path — used for each new event after the initial load. */
    public JsonNode decryptOne(String eventB64, Map<String, byte[]> conversationKeys, List<SigningKeyEntry> signingKeys) throws Exception {
        DecryptEventParams params = new DecryptEventParams(eventB64, conversationKeys);
        params.signingKeys = signingKeys;
        return chat.decryptEvent(params);
    }

    // -- Message encryption -------------------------------------------------

    /**
     * Fields the X API expects for an encrypted message send, plus the
     * message's {@code eventB64}, which stays local: the message as recipients
     * receive it, to encrypt the message's files from with {@link #encryptMedia}.
     */
    public record SendBody(
            String messageId,
            String encodedMessageCreateEvent,
            String encodedMessageEventSignature,
            String xdkVersion,
            String eventB64) {}

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
     * {@code attachments} are attachment descriptors, each file naming the
     * media hash key its upload started with (encrypt the files afterwards
     * with {@link #encryptMedia} and the returned body's {@code eventB64});
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
        return encryptReply(conversationId, text, conversationKey, conversationKeyVersion,
                replyToEvent, entities, attachments, ttlMsec, replyToCkces, null);
    }

    /**
     * Like the overload above, plus {@code quickReply}: a quick reply offering
     * selectable options or answering them.
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
            List<String> replyToCkces,
            QuickReply quickReply)
            throws Exception {
        SendPayload payload;
        if (replyToEvent == null) {
            EncryptMessageParams params = new EncryptMessageParams(conversationId, text);
            params.conversationKey = conversationKey;
            params.conversationKeyVersion = conversationKeyVersion;
            params.entities = entities;
            params.attachments = attachments;
            params.quickReply = quickReply;
            params.ttlMsec = ttlMsec;
            payload = chat.encryptMessage(params);
        } else {
            EncryptReplyParams params = new EncryptReplyParams(conversationId, text, replyToEvent);
            params.conversationKey = conversationKey;
            params.conversationKeyVersion = conversationKeyVersion;
            params.replyToCkces = replyToCkces;
            params.entities = entities;
            params.attachments = attachments;
            params.quickReply = quickReply;
            params.ttlMsec = ttlMsec;
            payload = chat.encryptReply(params);
        }
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(
                payload.messageId,
                payload.encodedMessageCreateEvent,
                payload.encodedMessageEventSignature,
                payload.xdkVersion,
                payload.eventB64);
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
        return new SendBody(
                payload.messageId,
                payload.encodedMessageCreateEvent,
                payload.encodedMessageEventSignature,
                payload.xdkVersion,
                payload.eventB64);
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

    /**
     * Prepare a member removal that rotates the key for who stays.
     *
     * <p>{@code publicKeys} are the identity keys of the members who remain.
     */
    public PreparedConversationChange prepareGroupMembersRemove(
            List<PublicKeyInput> publicKeys, String conversationId, List<String> userIds)
            throws Exception {
        return chat.prepareGroupMembersRemove(
                new GroupMembersRemoveParams(publicKeys, conversationId, userIds));
    }

    // -- Media files ----------------------------------------------------------

    private static final int MEDIA_CHUNK = 1024 * 1024;

    /**
     * Encrypt a media file of an outgoing message with the incremental file API.
     *
     * <p>{@code eventB64} is the {@code eventB64} of the body
     * {@link #encryptReply} returned for the message, {@code conversationKey}
     * and {@code conversationKeyVersion} the key the message was encrypted
     * under, and {@code mediaHashKey} the hash key the file's upload started
     * with, as listed in the message's attachments; the SDK encrypts the file
     * under that attachment's key. Feeding fixed-size chunks through
     * {@code push} keeps memory bounded no matter how large the file is;
     * {@code finish} emits the final frame that seals the file (decryption
     * fails without it).
     */
    public byte[] encryptMedia(
            byte[] plaintext,
            String eventB64,
            byte[] conversationKey,
            String conversationKeyVersion,
            String mediaHashKey)
            throws Exception {
        FileEncryptorParams params = new FileEncryptorParams(eventB64, mediaHashKey);
        params.conversationKey = conversationKey;
        params.conversationKeyVersion = conversationKeyVersion;
        try (FileEncryptor enc = chat.fileEncryptor(params)) {
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
     * Decrypt a downloaded media file with the incremental file API.
     *
     * <p>{@code eventB64} is the raw event of the message that carries the
     * media and {@code conversationKeys} its conversation's key map, as passed
     * to {@link #decryptOne}; the SDK finds {@code mediaHashKey} in the event
     * and derives that file's key. {@code finish} throws if the file was
     * truncated, so plaintext from {@code push} must not be treated as complete
     * until it succeeds.
     */
    public byte[] decryptMedia(
            byte[] ciphertext, String eventB64, Map<String, byte[]> conversationKeys, String mediaHashKey)
            throws Exception {
        try (FileDecryptor dec = chat.fileDecryptor(
                new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int offset = 0; offset < ciphertext.length; offset += MEDIA_CHUNK) {
                int end = Math.min(offset + MEDIA_CHUNK, ciphertext.length);
                out.write(dec.push(Arrays.copyOfRange(ciphertext, offset, end)));
            }
            out.write(dec.finish());
            return out.toByteArray();
        }
    }

    // -- Group metadata -------------------------------------------------------

    /**
     * Prepare a group title change: the SDK encrypts the plaintext title under the
     * conversation key and signs it. Send {@code encryptedValue} as the group's name and
     * {@code actionSignatures} on the request.
     */
    public PreparedGroupMetadataChange prepareGroupTitleChange(
            String conversationId, String title, byte[] conversationKey, String conversationKeyVersion)
            throws Exception {
        GroupTitleChangeParams params = new GroupTitleChangeParams(conversationId, title);
        params.conversationKey = conversationKey;
        params.conversationKeyVersion = conversationKeyVersion;
        return chat.prepareGroupTitleChange(params);
    }

    /** Decrypt a group title, avatar URL, or description the X API returns. */
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
     * (two signatures). The participant keys and action signatures already have the
     * request's shape.
     */
    public static ObjectNode prepToRequest(PreparedConversationChange prep) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("conversation_key_version", prep.conversationKeyVersion);
        body.set("conversation_participant_keys", MAPPER.valueToTree(prep.conversationParticipantKeys));
        body.set("action_signatures", MAPPER.valueToTree(prep.actionSignatures));
        return body;
    }

    /**
     * Map a rotating member removal into the members/remove request.
     *
     * <p>Both signatures go in {@code action_signatures}. The new key version and the
     * participant keys for the members who stay go in {@code group_key_rotation_data}.
     */
    public static ObjectNode removalToRequest(List<String> userIds, PreparedConversationChange prep) {
        ObjectNode body = MAPPER.createObjectNode();
        var ids = body.putArray("user_ids");
        userIds.forEach(ids::add);
        body.set("action_signatures", MAPPER.valueToTree(prep.actionSignatures));
        ObjectNode rotation = body.putObject("group_key_rotation_data");
        rotation.put("conversation_key_version", prep.conversationKeyVersion);
        rotation.set(
                "conversation_participant_keys", MAPPER.valueToTree(prep.conversationParticipantKeys));
        return body;
    }

    @Override
    public void close() {
        chat.close();
    }
}
