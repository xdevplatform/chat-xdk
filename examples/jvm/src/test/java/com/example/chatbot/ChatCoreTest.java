package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.ChatXdkException;
import com.x.chatxdk.ChatXdkUtilities;
import com.x.chatxdk.Types.AttachmentDescriptor;
import com.x.chatxdk.Types.EntityDescriptor;
import com.x.chatxdk.Types.PreparedConversationChange;
import com.x.chatxdk.Types.PreparedGroupMetadataChange;
import com.x.chatxdk.Types.PublicKeyInput;
import com.x.chatxdk.Types.PublicKeys;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

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
