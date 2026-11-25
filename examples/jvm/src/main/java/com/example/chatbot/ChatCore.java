package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Chat;
import com.x.chatxdk.FileDecryptor;
import com.x.chatxdk.FileEncryptor;
import com.x.chatxdk.PublicKeyResolver;
import com.x.chatxdk.Types.*;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
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
 *
 * <p>Other users' public keys reach the SDK through one hook,
 * {@link #fetchPublicKeysWith}: the SDK calls it for the keys a decrypt or a key
 * change lacks, and stores what it returns.
 */
public final class ChatCore implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Chat chat = new Chat();
    private String signingKeyVersion;

    /**
     * A chat whose conversation-key cache is on: {@link #decryptBatch(List)}
     * fills it from verified key changes, and the encrypt calls take the newest
     * key from it.
     */
    public ChatCore() {
        chat.setCacheKeys(true);
    }

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
        String blob = Base64.getEncoder().encodeToString(chat.exportKeys());
        return new Generated(payload, blob);
    }

    public PublicKeys publicKeys() throws Exception {
        return chat.getPublicKeys();
    }

    // -- Other users' public keys -------------------------------------------

    /**
     * Fetches one user's public keys: the records in the {@code data} array of
     * {@code GET /2/users/{id}/public_keys}.
     */
    @FunctionalInterface
    public interface PublicKeyFetcher {
        List<JsonNode> fetch(String userId) throws Exception;
    }

    /**
     * Have the SDK fetch the public keys it lacks with {@code fetcher}.
     *
     * <p>This sets the SDK's public-key resolver. {@link #decryptBatch(List)}
     * then fetches the signing keys a page's events name and the SDK does not
     * hold, those of the members who made its key changes as well as those of
     * the senders of its messages, and decrypts the page once more. The prepare
     * calls that make a conversation key fetch their members' identity keys
     * when they are passed no public keys. The SDK stores what arrives, and
     * waits a minute before it asks again for a key a lookup did not bring.
     *
     * <p>A user whose fetch fails is logged and left out, so the keys of the
     * other users still arrive.
     */
    public void fetchPublicKeysWith(PublicKeyFetcher fetcher) {
        chat.setResolvePublicKeys(userIds -> {
            Map<String, List<PublicKeyRecord>> records = new LinkedHashMap<>();
            for (String userId : userIds) {
                try {
                    List<PublicKeyRecord> found = new ArrayList<>();
                    for (JsonNode node : fetcher.fetch(userId)) {
                        found.add(MAPPER.treeToValue(node, PublicKeyRecord.class));
                    }
                    records.put(userId, found);
                } catch (Exception e) {
                    System.err.println("public_keys_fetch_failed user=" + userId + " " + e.getMessage());
                }
            }
            return records;
        });
    }

    /**
     * Set the SDK's public-key resolver to {@code resolver} as it is: it takes
     * user ids and returns each user's records, by user id. A process with
     * several signed-in users gives every chat the same resolver, so the chats
     * share its lookups (see {@link SharedPublicKeys} and {@link UserChats}).
     */
    public void resolvePublicKeysWith(PublicKeyResolver resolver) {
        chat.setResolvePublicKeys(resolver);
    }

    // -- Conversation keys --------------------------------------------------

    /**
     * Prepare a conversation-key change: a fresh key encrypted to every
     * participant, and the signature the X API takes with it.
     *
     * <p>{@code publicKeys} are the participants' identity keys. Pass none for
     * a one-to-one that {@code conversationId} names, by its id or by the other
     * user's id alone: the SDK reads both users' keys from the public keys it
     * holds, fetching the ones it lacks through {@link #fetchPublicKeysWith}.
     */
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

    /**
     * Batch path — every page of events goes through it, the key changes and
     * the data events together: it extracts the conversation keys from the
     * KeyChange events, caches those of the key changes that verify, then
     * decrypts every event.
     *
     * <p>Signatures verify with the public keys the SDK holds. The ones the
     * page lacks are fetched through {@link #fetchPublicKeysWith}; the result's
     * {@code missingSigningKeys} lists those that did not arrive.
     */
    public DecryptEventsResult decryptBatch(List<String> eventsB64) throws Exception {
        return chat.decryptEvents(new DecryptEventsParams(eventsB64));
    }

    /**
     * Batch path with the signing keys to verify with passed in the call: the
     * SDK verifies with these keys alone and fetches none. An empty list is
     * read as no keys passed, like {@link #decryptBatch(List)}.
     */
    public DecryptEventsResult decryptBatch(List<String> eventsB64, List<SigningKeyEntry> signingKeys) throws Exception {
        DecryptEventsParams params = new DecryptEventsParams(eventsB64);
        params.signingKeys = signingKeys;
        return chat.decryptEvents(params);
    }

    /**
     * Single-event path — decrypt one event. An empty {@code conversationKeys}
     * takes the keys from the SDK's cache, and no {@code signingKeys} verifies
     * with the public keys the SDK holds. This path fetches none: an event
     * whose sender's keys the SDK may lack goes through
     * {@link #decryptBatch(List)}.
     */
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
     * With {@code conversationKey} and {@code conversationKeyVersion} null, the
     * conversation key comes from the SDK's cache.
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

    /**
     * Prepare a group creation: fresh key + the two required signatures. A plaintext
     * {@code title} (or {@code null}) is encrypted under the new key; send the
     * result's {@code encryptedTitle} as the request's {@code group_name}.
     *
     * <p>Pass no {@code publicKeys} to have the SDK read the identity keys of
     * {@code memberIds} and {@code adminIds} from the public keys it holds,
     * fetching the ones it lacks through {@link #fetchPublicKeysWith}.
     */
    public PreparedConversationChange prepareGroupCreate(
            List<PublicKeyInput> publicKeys,
            String conversationId,
            List<String> memberIds,
            List<String> adminIds,
            String title)
            throws Exception {
        GroupCreateParams params = new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds);
        params.title = title;
        return chat.prepareGroupCreate(params);
    }

    /**
     * Prepare a member add: rotated key + the two required signatures.
     *
     * <p>Pass no {@code publicKeys} to have the SDK read the identity keys of
     * {@code currentMemberIds} and {@code newMemberIds} from the public keys it
     * holds, fetching the ones it lacks through {@link #fetchPublicKeysWith}.
     */
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

    /** Decrypt a group title or description the X API returns. */
    public String decrypt(String ciphertextB64, byte[] conversationKey) {
        return chat.decrypt(ciphertextB64, conversationKey);
    }

    // -- Conversation mute ----------------------------------------------------

    /**
     * Sign muting ({@code muted} true) or unmuting (false) a conversation, group or
     * one-to-one, for this bot alone. The event is signed in the bot's own
     * {@code {userId}:{userId}} conversation and names {@code conversationId} in
     * canonical colon form; send {@code actionSignatures} with a mute or unmute request
     * that names the conversation in that same form. Signed with the session identity.
     */
    public PreparedAction prepareConversationMute(String conversationId, boolean muted) throws Exception {
        return chat.prepareConversationMute(new ConversationMuteParams(conversationId, muted));
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
