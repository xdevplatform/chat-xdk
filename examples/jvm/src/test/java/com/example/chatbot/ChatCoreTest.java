package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Types.EntityDescriptor;
import com.x.chatxdk.Types.PreparedConversationChange;
import com.x.chatxdk.Types.PublicKeyInput;
import com.x.chatxdk.Types.PublicKeys;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
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
    void genericEncryptDecryptRoundtrip() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            String plaintext = "hello from the jvm example";
            String ciphertext = core.encrypt(plaintext, key);
            assertNotEquals(plaintext, ciphertext);
            assertEquals(plaintext, core.decrypt(ciphertext, key));
        }
    }

    @Test
    void conversationKeyPrepareAndDecryptRoundtrip() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("me");
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = v.get("identity_public_b64").asText();
            input.keyVersion = "1";
            PreparedConversationChange prepared =
                    core.prepareConversationKeyChange(List.of(input), "conv-1");
            assertEquals(1, prepared.participantKeys.size());
            byte[] decrypted = core.decryptConversationKey(prepared.participantKeys.get(0).encryptedKey);
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
        }
    }

    @Test
    void decryptBatchEmptyIsSafe() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            var result = core.decryptBatch(List.of(), List.of());
            assertTrue(result.messages.isEmpty());
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
        PublicKeyInput input = new PublicKeyInput();
        input.userId = "1000";
        input.publicKey = v.get("identity_public_b64").asText();
        input.keyVersion = "1";
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
            ObjectNode body = ChatCore.prepToRequest(prep, signingPub);

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
            // CKCE signature payloads are withheld (they embed the plaintext key).
            assertFalse(sig.has("signature_payload"));
        }
    }

    @Test
    void prepareGroupCreateYieldsTwoSignatures() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            PreparedConversationChange prep = core.prepareGroupCreate(
                    fixtureKeys(v), "g123", List.of("1000"), List.of("1000"));
            assertEquals(2, prep.actionSignatures.size());
            assertNotNull(prep.conversationKey);
            assertEquals(32, prep.conversationKey.length);
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
        }
    }

    @Test
    void threadedReplyWithEntitiesAndTtl() throws Exception {
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            core.setIdentity("1000");
            byte[] key = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            EntityDescriptor mention = new EntityDescriptor();
            mention.start = 0;
            mention.end = 5;
            mention.entityType = "mention";
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
    void mediaStreamEncryptDecryptRoundtrip() throws Exception {
        // The chunked stream path the media flow uses: multi-chunk payload in,
        // identical bytes out, and truncation is detected.
        JsonNode v = vectors();
        try (ChatCore core = loadedCore(v)) {
            byte[] convKey = Base64.getDecoder().decode(v.get("conversation_key_b64").asText());
            byte[] plaintext = new byte[300_000];
            for (int i = 0; i < plaintext.length; i++) {
                plaintext[i] = (byte) ((i * 31 + 7) % 256);
            }

            byte[] ciphertext = core.encryptMedia(plaintext, convKey);
            assertFalse(Arrays.equals(Arrays.copyOf(ciphertext, plaintext.length), plaintext));
            assertArrayEquals(plaintext, core.decryptMedia(ciphertext, convKey));

            byte[] truncated = Arrays.copyOf(ciphertext, ciphertext.length - 4);
            assertThrows(Exception.class, () -> core.decryptMedia(truncated, convKey));
        }
    }
}
