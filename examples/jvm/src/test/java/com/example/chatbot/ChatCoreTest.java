package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.ChatXdkException;
import com.x.chatxdk.ChatXdkUtilities;
import com.x.chatxdk.Types.ActionSignature;
import com.x.chatxdk.Types.AttachmentDescriptor;
import com.x.chatxdk.Types.DecryptEventsResult;
import com.x.chatxdk.Types.DecryptedEvent;
import com.x.chatxdk.Types.EntityDescriptor;
import com.x.chatxdk.Types.MessageEventSignature;
import com.x.chatxdk.Types.PreparedAction;
import com.x.chatxdk.Types.PreparedConversationChange;
import com.x.chatxdk.Types.PreparedGroupMetadataChange;
import com.x.chatxdk.Types.PublicKeyInput;
import com.x.chatxdk.Types.PublicKeyRegistration;
import com.x.chatxdk.Types.PublicKeys;
import com.x.chatxdk.Types.SigningKeyEntry;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Offline tests for the JVM example's crypto core.
 *
 * <p>These drive the REAL chatxdk binding through the same {@link ChatCore} the
 * bot uses — no mocking. They prove an actual encrypt -&gt; decrypt round-trip and
 * that the binding reproduces the committed key vectors.
 */
class ChatCoreTest {

    private static JsonNode vectors() throws Exception {
        // Walk up from the working dir until we find the repo's fixtures.
        File dir = new File("").getAbsoluteFile();
        for (File d = dir; d != null; d = d.getParentFile()) {
            File candidate = new File(d, "tests/fixtures/sdk_vectors.json");
            if (candidate.exists()) {
                return new ObjectMapper().readTree(Files.readString(candidate.toPath()));
            }
        }
        throw new IllegalStateException("sdk_vectors.json not found");
    }

    private static ChatCore loadedCore(JsonNode v) {
        ChatCore core = new ChatCore();
        core.loadKeys(v.get("private_keys_concat_b64").asText(), "1");
        return core;
    }

    @Test
    void loadKeysMatchesFixturePublicKeys() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            PublicKeys keys = core.publicKeys();
            assertEquals(v.get("identity_public_b64").asText(), keys.identity);
            assertEquals(v.get("signing_public_b64").asText(), keys.signing);
        }
    }

    @Test
    void setIdentityNeedsTheRegisteredVersion() throws Exception {
        // Freshly generated keys have no registered version yet, so the bot
        // cannot sign as itself until loadKeys provides one.
        try (ChatCore core = new ChatCore()) {
            core.generateAndRegister();
            IllegalStateException err =
                    assertThrows(IllegalStateException.class, () -> core.setIdentity("12345"));
            assertTrue(err.getMessage().contains("signing key version unknown"), err.getMessage());
        }
    }

    @Test
    void groupTitleChangeEncryptsTheTitleItSigns() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("12345");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            String title = "hello from the jvm example";
            PreparedGroupMetadataChange prepared = core.prepareGroupTitleChange("g123", title, key, "1");
            assertNotEquals(title, prepared.encryptedValue);
            assertEquals("1", prepared.conversationKeyVersion);
            assertEquals(title, core.decrypt(prepared.encryptedValue, key));
        }
    }

    @Test
    void conversationKeyPrepareAndDecryptRoundtrip() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("910002");
            PublicKeyInput input = new PublicKeyInput("910002", v.get("identity_public_b64").asText(), "1");
            PreparedConversationChange prepared =
                    core.prepareConversationKeyChange(List.of(input), "conv-1");
            assertEquals(1, prepared.conversationParticipantKeys.size());
            byte[] decrypted = core.decryptConversationKey(prepared.conversationParticipantKeys.get(0).encryptedConversationKey);
            assertArrayEquals(prepared.conversationKey, decrypted);
        }
    }

    @Test
    void encryptReplyProducesSendablePayload() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("12345");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            ChatCore.SendBody body = core.encryptReply("6789:12345", "pong", key, "1710000000000");
            assertFalse(body.encodedMessageCreateEvent().isEmpty());
            assertFalse(body.encodedMessageEventSignature().isEmpty());
            assertFalse(body.messageId().isEmpty());
            assertFalse(body.xdkVersion().isEmpty());
        }
    }

    /** A Thrift string field: its id, then the value's length and bytes. */
    private static void writeString(ByteArrayOutputStream out, int id, String value) {
        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        out.write(11);
        out.write(id >> 8);
        out.write(id);
        out.write(data.length >> 24);
        out.write(data.length >> 16);
        out.write(data.length >> 8);
        out.write(data.length);
        out.writeBytes(data);
    }

    /** The event as delivered: {@code eventB64} with the sequence id the server assigns, prepended as Thrift string field 1. */
    static String delivered(String eventB64, String sequenceId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeString(out, 1, sequenceId);
        out.writeBytes(Base64.getDecoder().decode(eventB64));
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    /**
     * A signed action as delivered: the event the server relays for {@code action}, an entry
     * of a prepared change's action signatures, from {@code senderId} in {@code conversationId},
     * with the sequence id the server assigns.
     */
    static String deliveredAction(
            ActionSignature action, String senderId, String conversationId, String sequenceId) {
        MessageEventSignature signed = action.messageEventSignature;
        ByteArrayOutputStream event = new ByteArrayOutputStream();
        writeString(event, 1, sequenceId);
        writeString(event, 2, action.messageId);
        writeString(event, 3, senderId);
        writeString(event, 4, conversationId);
        event.writeBytes(new byte[] {12, 0, 7});
        event.writeBytes(Base64.getDecoder().decode(action.encodedMessageEventDetail));
        event.writeBytes(new byte[] {12, 0, 9});
        writeString(event, 1, signed.signature);
        writeString(event, 2, signed.publicKeyVersion);
        writeString(event, 3, signed.signatureVersion);
        event.writeBytes(new byte[] {0, 0});
        return Base64.getEncoder().encodeToString(event.toByteArray());
    }

    /** A core with fresh keys as a user, and the keys others hold for it. */
    static final class Party implements AutoCloseable {
        final ChatCore core = new ChatCore();
        final String userId;

        /** The user's private-key blob, which signs the user in to another chat. */
        final String privateKeysB64;

        final SigningKeyEntry signingKey;
        final PublicKeyInput publicKey;

        /** The user's keys as the X API returns them: a record of {@code GET /2/users/{id}/public_keys}. */
        final ObjectNode publicKeyRecord = new ObjectMapper().createObjectNode();

        Party(String userId) throws Exception {
            this.userId = userId;
            ChatCore.Generated generated = core.generateAndRegister();
            privateKeysB64 = generated.privateKeysB64();
            core.loadKeys(privateKeysB64, "1");
            core.setIdentity(userId);
            PublicKeyRegistration registration = generated.registration().publicKey;
            signingKey = new SigningKeyEntry(
                    userId,
                    "1",
                    registration.signingPublicKey,
                    registration.publicKey,
                    registration.identityPublicKeySignature);
            publicKey = new PublicKeyInput(userId, registration.publicKey, "1");
            publicKeyRecord.put("public_key_version", "1");
            publicKeyRecord.put("public_key", registration.publicKey);
            publicKeyRecord.put("signing_public_key", registration.signingPublicKey);
            publicKeyRecord.put("identity_public_key_signature", registration.identityPublicKeySignature);
            publicKeyRecord.putObject("juicebox_config").put("max_guess_count", 20);
        }

        @Override
        public void close() {
            core.close();
        }
    }

    /**
     * A page as the bot receives it: the key change {@code admin} makes in a group for itself,
     * {@code member} and {@code bot}, then a message {@code member} sends under the new key.
     * The admin sends no message.
     */
    private static List<String> keyChangePage(Party admin, Party member, Party bot) throws Exception {
        PreparedConversationChange prepared = admin.core.prepareConversationKeyChange(
                List.of(admin.publicKey, member.publicKey, bot.publicKey), "g900");
        String keyChange =
                deliveredAction(prepared.actionSignatures.get(0), admin.userId, "g900", "2100000000000000000");
        ChatCore.SendBody body = member.core.encryptReply(
                "g900", "hello group", prepared.conversationKey, prepared.conversationKeyVersion);
        return List.of(keyChange, delivered(body.eventB64(), "2100000000000000001"));
    }

    /** The text of each event of a result, null for an event that is not a message. */
    static List<String> texts(DecryptEventsResult result) {
        List<String> texts = new ArrayList<>();
        for (DecryptedEvent decrypted : result.events) {
            texts.add(ChatCore.messageText(decrypted.event));
        }
        return texts;
    }

    /** The users a prepared change encrypted its key to, sorted. */
    private static List<String> recipients(PreparedConversationChange prepared) {
        List<String> userIds = new ArrayList<>();
        prepared.conversationParticipantKeys.forEach(key -> userIds.add(key.userId));
        Collections.sort(userIds);
        return userIds;
    }

    @Test
    void decryptBatchFetchesTheKeysOfTheMemberWhoMadeAKeyChange() throws Exception {
        // An admin rotates a group's key and a member sends a message under
        // it. The admin signed the key change and sent no message.
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party bot = new Party("5003")) {
            List<String> events = keyChangePage(admin, member, bot);

            // Signing keys passed in the call are what it verifies with. With
            // the member's alone the key change does not verify: its key is
            // dropped, the message does not decrypt, and the result names the
            // admin's key as missing.
            DecryptEventsResult unverified = bot.core.decryptBatch(events, List.of(member.signingKey));
            assertTrue(unverified.events.isEmpty());
            assertEquals(Set.of("0"), unverified.missingSigningKeys.keySet());
            assertEquals("5001", unverified.missingSigningKeys.get("0").userId);
            assertEquals("1", unverified.missingSigningKeys.get("0").publicKeyVersion);

            // With no keys passed, the SDK fetches the ones the page lacks: the
            // admin's for the key change and the member's for the message.
            List<String> asked = new ArrayList<>();
            bot.core.fetchPublicKeysWith(userId -> {
                asked.add(userId);
                return List.of(userId.equals(admin.userId) ? admin.publicKeyRecord : member.publicKeyRecord);
            });
            DecryptEventsResult result = bot.core.decryptBatch(events);
            assertEquals(List.of("5001", "5002"), asked);
            assertTrue(result.errors.isEmpty(), result.errors.toString());
            assertTrue(result.missingSigningKeys.isEmpty());
            assertTrue(result.unverifiedKeyChanges.isEmpty());
            assertEquals(Arrays.asList(null, "hello group"), texts(result));

            // The SDK holds the keys it fetched: the next page fetches none.
            result = bot.core.decryptBatch(events);
            assertEquals(Arrays.asList(null, "hello group"), texts(result));
            assertEquals(2, asked.size());
        }
    }

    @Test
    void decryptBatchLeavesOutAUserWhosePublicKeysCannotBeFetched() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party bot = new Party("5003")) {
            List<String> events = keyChangePage(admin, member, bot);
            List<String> asked = new ArrayList<>();
            bot.core.fetchPublicKeysWith(userId -> {
                asked.add(userId);
                if (userId.equals(member.userId)) {
                    throw new IllegalStateException("x api GET public_keys: 503");
                }
                return List.of(admin.publicKeyRecord);
            });

            // The admin's keys arrive, so the key change verifies. The member's
            // do not: the message stays unverified, and the result names the
            // member's key as missing.
            DecryptEventsResult result = bot.core.decryptBatch(events);
            assertEquals(List.of("5001", "5002"), asked);
            assertTrue(result.unverifiedKeyChanges.isEmpty());
            assertEquals(Set.of("1"), result.errors.keySet());
            assertEquals(Set.of("1"), result.missingSigningKeys.keySet());
            assertEquals("5002", result.missingSigningKeys.get("1").userId);

            // The SDK does not ask again at once for a key the fetch did not bring.
            bot.core.decryptBatch(events);
            assertEquals(2, asked.size());
        }
    }

    @Test
    void prepareCallsFetchThePublicKeysTheyAreNotPassed() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002")) {
            List<String> asked = new ArrayList<>();
            admin.core.fetchPublicKeysWith(userId -> {
                asked.add(userId);
                return List.of(userId.equals(admin.userId) ? admin.publicKeyRecord : member.publicKeyRecord);
            });

            PreparedConversationChange created = admin.core.prepareGroupCreate(
                    List.of(), "g900", List.of("5001", "5002"), List.of("5001"), "a group");
            assertEquals(List.of("5001", "5002"), asked);
            assertEquals(List.of("5001", "5002"), recipients(created));

            // A one-to-one names its two users by its id, here the other
            // user's id alone. The SDK holds both users' keys: it fetches none.
            PreparedConversationChange direct = admin.core.prepareConversationKeyChange(List.of(), "5002");
            assertEquals("5001:5002", direct.conversationId);
            assertEquals(List.of("5001", "5002"), recipients(direct));
            assertEquals(2, asked.size());
        }
    }

    @Test
    void decryptBatchEmptyIsSafe() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            var result = core.decryptBatch(List.of(), List.of());
            assertTrue(result.events.isEmpty());
        }
    }

    @Test
    void decryptOneRejectsGarbage() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            assertThrows(Exception.class,
                    () -> core.decryptOne("not-valid-base64!!!", Map.of(), List.of()));
        }
    }

    private static List<PublicKeyInput> fixtureKeys(JsonNode v) {
        PublicKeyInput input = new PublicKeyInput("1000", v.get("identity_public_b64").asText(), "1");
        return List.of(input);
    }

    @Test
    void prepToRequestMapsTheRestShape() throws Exception {
        // The mapper output is exactly what the X API's write endpoints take;
        // a drifted field name here breaks every flow in the live e2e.
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            PreparedConversationChange prep =
                    core.prepareConversationKeyChange(fixtureKeys(v), "1000:2000");
            String signingPub = core.publicKeys().signing;
            ObjectNode body = ChatCore.prepToRequest(prep);

            assertEquals(prep.conversationKeyVersion, body.path("conversation_key_version").asText());
            JsonNode pks = body.path("conversation_participant_keys");
            assertEquals(1, pks.size());
            List<String> fields = new ArrayList<>();
            pks.get(0).fieldNames().forEachRemaining(fields::add);
            Collections.sort(fields);
            assertEquals(
                    List.of("encrypted_conversation_key", "public_key_version", "user_id"), fields);
            JsonNode sigs = body.path("action_signatures");
            assertEquals(1, sigs.size());
            JsonNode sig = sigs.get(0);
            assertEquals(prep.actionSignatures.get(0).messageId, sig.path("message_id").asText());
            assertFalse(sig.path("encoded_message_event_detail").asText().isEmpty());
            JsonNode inner = sig.path("message_event_signature");
            assertEquals(signingPub, inner.path("signing_public_key").asText());
            assertFalse(inner.path("signature").asText().isEmpty());
            assertFalse(inner.path("public_key_version").asText().isEmpty());
        }
    }

    @Test
    void removalToRequestRotatesForMembersWhoStay() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            PreparedConversationChange prep =
                    core.prepareGroupMembersRemove(fixtureKeys(v), "g123", List.of("2000"));
            ObjectNode body = ChatCore.removalToRequest(List.of("2000"), prep);

            assertEquals("2000", body.path("user_ids").get(0).asText());
            assertEquals(2, body.path("action_signatures").size());
            JsonNode rotation = body.path("group_key_rotation_data");
            assertEquals(prep.conversationKeyVersion, rotation.path("conversation_key_version").asText());
            JsonNode pks = rotation.path("conversation_participant_keys");
            assertEquals(1, pks.size());
            assertEquals("1000", pks.get(0).path("user_id").asText());
            List<String> fields = new ArrayList<>();
            pks.get(0).fieldNames().forEachRemaining(fields::add);
            Collections.sort(fields);
            assertEquals(
                    List.of("encrypted_conversation_key", "public_key_version", "user_id"), fields);
            assertTrue(body.path("conversation_key_version").isMissingNode());
            assertTrue(body.path("conversation_participant_keys").isMissingNode());
        }
    }

    @Test
    void prepareGroupCreateYieldsTwoSignatures() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            String title = "hello from the jvm example";
            PreparedConversationChange prep = core.prepareGroupCreate(
                    fixtureKeys(v), "g123", List.of("1000"), List.of("1000"), title);
            assertEquals(2, prep.actionSignatures.size());
            assertNotNull(prep.conversationKey);
            assertEquals(32, prep.conversationKey.length);
            // The title goes out encrypted under the new key: the group_name the
            // create request sends.
            assertEquals(title, core.decrypt(prep.encryptedTitle, prep.conversationKey));
        }
    }

    @Test
    void prepareConversationArchiveSignsArchiveAndUnarchive() throws Exception {
        // Each signed action is sendable as it is, and a recipient verifies it as
        // the setting it signs.
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            List<SigningKeyEntry> signingKeys = List.of(new SigningKeyEntry(
                    "1000",
                    "1",
                    v.get("signing_public_b64").asText(),
                    v.get("identity_public_b64").asText(),
                    v.get("identity_public_key_signature_b64").asText()));
            for (boolean archived : new boolean[] {true, false}) {
                PreparedAction prepared = core.prepareConversationArchive("g123", archived);
                assertEquals(1, prepared.actionSignatures.size());
                ActionSignature sig = prepared.actionSignatures.get(0);
                assertFalse(sig.messageId.isEmpty());
                assertFalse(sig.encodedMessageEventDetail.isEmpty());
                assertFalse(sig.messageEventSignature.signature.isEmpty());

                JsonNode event = core.decryptOne(
                        deliveredAction(sig, "1000", "g123", "2100000000000000000"), Map.of(), signingKeys);
                assertEquals("SettingsChange", event.path("type").asText());
                assertTrue(event.path("verified").asBoolean());
                assertEquals(
                        archived ? "Archived" : "Unarchived",
                        event.path("change").path("setting").asText());
            }
        }
    }

    @Test
    void encryptReactionProducesSendablePayload() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            // React to the fixture raw event: the conversation id and target
            // sequence id are derived from it by the SDK.
            ChatCore.SendBody body = core.encryptReaction(
                    true,
                    v.get("event_message_b64").asText(),
                    "\uD83D\uDC4D",
                    key,
                    v.get("event_conversation_key_version").asText());
            assertFalse(body.messageId().isEmpty());
            assertFalse(body.encodedMessageCreateEvent().isEmpty());
            assertFalse(body.encodedMessageEventSignature().isEmpty());
            assertFalse(body.xdkVersion().isEmpty());
        }
    }

    @Test
    void threadedReplyWithEntitiesAndTtl() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            EntityDescriptor mention = new EntityDescriptor(0, 5, "mention");
            // Reply by raw event: the preview is derived from the fixture event,
            // which was encrypted under the same fixture key + version.
            ChatCore.SendBody body = core.encryptReply(
                    v.get("event_conversation_id").asText(),
                    "@user hello",
                    key,
                    v.get("event_conversation_key_version").asText(),
                    v.get("event_message_b64").asText(),
                    List.of(mention),
                    null,
                    60_000L,
                    null);
            assertFalse(body.encodedMessageCreateEvent().isEmpty());
        }
    }

    @Test
    void mediaEncryptDecryptRoundtrip() throws Exception {
        // The message-first media flow: the message names the file by the
        // media hash key its upload started with, the file is encrypted from
        // the message's eventB64 in chunks, and it decrypts through that
        // event. A truncated file is detected.
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            Map<String, byte[]> convKeys = Map.of("1", key);
            byte[] plaintext = new byte[300_000];
            for (int i = 0; i < plaintext.length; i++) {
                plaintext[i] = (byte) ((i * 31 + 7) % 256);
            }
            ChatCore.SendBody body = core.encryptReply(
                    "1000:2000",
                    "a photo",
                    key,
                    "1",
                    null,
                    null,
                    List.of(AttachmentDescriptor.media(
                            "photo", 4, 3, ChatXdkUtilities.encryptedFileSize(plaintext.length), "photo.bin", 5, null)),
                    null,
                    null);
            assertFalse(body.eventB64().isEmpty());

            byte[] ciphertext = core.encryptMedia(plaintext, body.eventB64(), key, "1", "photo");
            assertEquals(ChatXdkUtilities.encryptedFileSize(plaintext.length), ciphertext.length);
            assertArrayEquals(plaintext, core.decryptMedia(ciphertext, body.eventB64(), convKeys, "photo"));
            byte[] truncated = Arrays.copyOf(ciphertext, ciphertext.length - 4);
            ChatXdkException e = assertThrows(
                    ChatXdkException.class,
                    () -> core.decryptMedia(truncated, body.eventB64(), convKeys, "photo"));
            assertTrue(e.getMessage().contains("truncated"), e.getMessage());
        }
    }

    @Test
    void mediaFromTheFixtureMessageOpens() throws Exception {
        // Media encrypted by another client opens through its message's event.
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            Map<String, byte[]> convKeys = Map.of(
                    v.get("message_key_conversation_key_version").asText(),
                    HexFormat.of().parseHex(v.get("message_key_conversation_key_hex").asText()));
            Base64.Decoder b64 = Base64.getDecoder();
            for (String name : List.of("first", "second")) {
                assertArrayEquals(
                        b64.decode(v.get("media_" + name + "_plaintext_b64").asText()),
                        core.decryptMedia(
                                b64.decode(v.get("media_" + name + "_encrypted_b64").asText()),
                                v.get("event_message_key_b64").asText(),
                                convKeys,
                                v.get("media_" + name + "_hash_key").asText()));
            }
        }
    }
}
