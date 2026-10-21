package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** JVM binding tests (no network). */
class ChatTest {

    private static Chat createUnlocked() throws Exception {
        Chat chat = new Chat();
        chat.generateKeypairs();
        byte[] exported = chat.exportKeys();
        assertNotNull(exported);
        chat.importKeys(exported);
        return chat;
    }

    /** Deterministic cross-binding vectors from tests/fixtures/sdk_vectors.json. */
    private static JsonNode loadVectors() throws Exception {
        // Walk up from the Maven module dir to the repo root holding the fixture.
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve("tests/fixtures/sdk_vectors.json"))) {
            dir = dir.getParent();
        }
        assertNotNull(dir, "tests/fixtures/sdk_vectors.json not found above " + System.getProperty("user.dir"));
        return new ObjectMapper().readTree(
                Files.readString(dir.resolve("tests/fixtures/sdk_vectors.json"), StandardCharsets.UTF_8));
    }

    private static byte[] b64(JsonNode vectors, String field) {
        return Base64.getDecoder().decode(vectors.get(field).asText());
    }

    /** SigningKeyEntry list matching the fixture's event vectors. */
    private static List<SigningKeyEntry> eventSigningKeys(JsonNode v) {
        return signingKeysFor(v, v.get("event_sender_id").asText());
    }

    /** The fixture signing key, registered to each of {@code userIds}. */
    private static List<SigningKeyEntry> signingKeysFor(JsonNode v, String... userIds) {
        List<SigningKeyEntry> entries = new ArrayList<>();
        for (String userId : userIds) {
            SigningKeyEntry entry = new SigningKeyEntry();
            entry.userId = userId;
            entry.publicKeyVersion = v.get("event_signing_key_version").asText();
            entry.publicKey = v.get("signing_public_b64").asText();
            entry.identityPublicKey = v.get("identity_public_b64").asText();
            entry.identityPublicKeySignature = v.get("identity_public_key_signature_b64").asText();
            entries.add(entry);
        }
        return entries;
    }

    /** The key map of the fixture conversation key, which opens the conversation-key media message and the reply vectors. */
    private static Map<String, byte[]> conversationKeys(JsonNode v) {
        return Map.of(v.get("event_conversation_key_version").asText(), b64(v, "conversation_key_b64"));
    }

    /** The key map that opens the message-key and link-card vectors. */
    private static Map<String, byte[]> messageKeyConversationKeys(JsonNode v) {
        return Map.of(
                v.get("message_key_conversation_key_version").asText(),
                ChatXdkUtilities.hexToBytes(v.get("message_key_conversation_key_hex").asText()));
    }

    /** Decrypt media whole and in 700-byte chunks on a fresh instance, checking both agree. */
    private static byte[] openMedia(
            String eventB64, Map<String, byte[]> keys, String mediaHashKey, byte[] encrypted) throws Exception {
        try (Chat chat = new Chat()) {
            byte[] whole = chat.decryptFile(new DecryptFileParams(encrypted, eventB64, keys, mediaHashKey));
            try (FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(eventB64, keys, mediaHashKey))) {
                ByteArrayOutputStream incremental = new ByteArrayOutputStream();
                for (int i = 0; i < encrypted.length; i += 700) {
                    incremental.write(decryptor.push(
                            Arrays.copyOfRange(encrypted, i, Math.min(i + 700, encrypted.length))));
                }
                incremental.write(decryptor.finish());
                assertArrayEquals(whole, incremental.toByteArray());
            }
            return whole;
        }
    }

    /** {@link #openMedia} on the fixture's {@code media_<name>_*} entries, checked against the plaintext. */
    private static void assertMediaOpens(JsonNode v, String eventField, Map<String, byte[]> keys, String name)
            throws Exception {
        assertArrayEquals(
                b64(v, "media_" + name + "_plaintext_b64"),
                openMedia(
                        v.get(eventField).asText(),
                        keys,
                        v.get("media_" + name + "_hash_key").asText(),
                        b64(v, "media_" + name + "_encrypted_b64")),
                name);
    }

    /** Produce a fresh conversation key via a prepared key change (for crypto tests). */
    private static byte[] newConvKey(Chat chat) throws Exception {
        PublicKeyInput input = new PublicKeyInput();
        input.userId = "me";
        input.publicKey = chat.getPublicKeys().identity;
        input.keyVersion = "1";
        ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(input));
        params.senderId = "me";
        params.signingKeyVersion = "1";
        params.conversationId = "conv-1";
        return chat.prepareConversationKeyChange(params).conversationKey;
    }

    @Test
    void disposeIsIdempotent() {
        Chat chat = new Chat();
        chat.close();
        chat.close();
    }

    @Test
    void throwsAfterClose() {
        Chat chat = new Chat();
        chat.close();
        assertThrows(IllegalStateException.class, chat::isUnlocked);
    }

    @Test
    void updateConfigAcceptsXApiJuiceboxConfigShape() {
        try (Chat chat = new Chat()) {
            // The X API juicebox_config object (key_store_token_map_json +
            // token_map) must be accepted as-is; the embedded config carries
            // realm public keys and server thresholds that the realms require.
            String xApiConfig =
                    """
                    {
                      "key_store_token_map_json": "{\\"realms\\":[{\\"id\\":\\"aa11\\",\\"address\\":\\"https://realm-b.example/\\"},{\\"id\\":\\"bb22\\",\\"address\\":\\"https://realm-east.example/\\",\\"public_key\\":\\"e8b2\\"}],\\"register_threshold\\":2,\\"recover_threshold\\":2,\\"pin_hashing_mode\\":\\"Standard2019\\"}",
                      "max_guess_count": 20,
                      "token_map": [
                        {"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}},
                        {"key": "bb22", "value": {"address": "https://realm-east.example/", "token": "t2"}}
                      ]
                    }
                    """;
            chat.updateConfig(xApiConfig); // must not throw
        }
    }

    @Test
    void updateConfigRejectsMalformedKeyStoreTokenMapJson() {
        try (Chat chat = new Chat()) {
            // A malformed embedded config must error, not silently fall back
            // to the lossy token_map derivation.
            String badConfig =
                    """
                    {
                      "key_store_token_map_json": "not json",
                      "token_map": [
                        {"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}}
                      ]
                    }
                    """;
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.updateConfig(badConfig));
            assertTrue(ex.getMessage().contains("Invalid key_store_token_map_json"), ex.getMessage());
        }
    }

    @Test
    void guessesRemainingParsedFromInvalidPinMessage() {
        // The core's invalid-PIN unlock error carries the stable
        // "guesses_remaining=N" token in the message; 0 means exhausted.
        assertEquals(
                3,
                new ChatXdkException("Juicebox error: Invalid PIN: guesses_remaining=3")
                        .getGuessesRemaining());
        assertEquals(
                0,
                new ChatXdkException("Juicebox error: Invalid PIN: guesses_remaining=0")
                        .getGuessesRemaining());
        assertNull(
                new ChatXdkException("Juicebox error: Invalid PIN").getGuessesRemaining());
        // The count is read only from the invalid-PIN form, not from
        // unrelated messages that happen to contain the token.
        assertNull(
                new ChatXdkException("Delete failed: guesses_remaining=7")
                        .getGuessesRemaining());
    }

    @Test
    void guessesRemainingNullOnNonPinErrors() {
        try (Chat chat = new Chat()) {
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.updateConfig("not json"));
            assertNull(ex.getGuessesRemaining());
        }
    }

    @Test
    void generateKeypairsReturnsValidPayload() throws Exception {
        try (Chat chat = new Chat()) {
            PublicKeyRegistrationPayload payload = chat.generateKeypairs();
            assertFalse(payload.publicKey.publicKey.isEmpty());
            assertFalse(payload.publicKey.signingPublicKey.isEmpty());
            assertFalse(payload.publicKey.identityPublicKeySignature.isEmpty());
            assertEquals("CustomPin", payload.publicKey.registrationMethod);
            assertNotNull(payload.publicKey.publicKeyFingerprint);
            assertEquals(43, payload.publicKey.publicKeyFingerprint.length());
        }
    }

    @Test
    void isUnlockedTrueAfterImport() throws Exception {
        try (Chat chat = createUnlocked()) {
            assertTrue(chat.isUnlocked());
            assertTrue(chat.hasIdentityKey());
        }
    }

    @Test
    void lockClearsKeys() throws Exception {
        try (Chat chat = createUnlocked()) {
            assertTrue(chat.isUnlocked());
            chat.lock();
            assertFalse(chat.isUnlocked());
        }
    }

    @Test
    void getPublicKeysReturnsNonEmpty() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            assertFalse(keys.identity.isEmpty());
            assertFalse(keys.signing.isEmpty());
        }
    }

    @Test
    void getPublicKeyFingerprint43Chars() throws Exception {
        try (Chat chat = createUnlocked()) {
            assertEquals(43, chat.getPublicKeyFingerprint().length());
        }
    }

    @Test
    void encryptDecryptRoundTrip() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] key = newConvKey(chat);
            String ct = chat.encrypt("hello jvm", key);
            assertEquals("hello jvm", chat.decrypt(ct, key));
        }
    }

    @Test
    void utilitiesBase64RoundTrip() {
        byte[] raw = {1, 2, 3, (byte) 0xff};
        assertArrayEquals(raw, ChatXdkUtilities.base64ToBytes(ChatXdkUtilities.bytesToBase64(raw)));
    }

    @Test
    void utilitiesEncryptedFileSize() {
        assertEquals(24, ChatXdkUtilities.encryptedFileSize(0));
        assertEquals(42, ChatXdkUtilities.encryptedFileSize(1));
        assertEquals(1065, ChatXdkUtilities.encryptedFileSize(1024));
        assertEquals(1083, ChatXdkUtilities.encryptedFileSize(1025));
        assertThrows(IllegalArgumentException.class, () -> ChatXdkUtilities.encryptedFileSize(-1));
        assertThrows(
                ArithmeticException.class,
                () -> ChatXdkUtilities.encryptedFileSize(Long.MAX_VALUE));
    }

    @Test
    void exportImportRoundTrip() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys original = chat.getPublicKeys();
            byte[] exported = chat.exportKeys();
            assertNotNull(exported);
            assertEquals(64, exported.length);
            chat.lock();
            assertFalse(chat.isUnlocked());
            chat.importKeys(exported);
            assertTrue(chat.isUnlocked());
            PublicKeys reimported = chat.getPublicKeys();
            assertEquals(original.identity, reimported.identity);
            assertEquals(original.signing, reimported.signing);
        }
    }

    @Test
    void encryptMessageReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "Hello from JVM!");
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("1", payload.conversationKeyVersion);
            assertEquals("7", payload.signatureInfo.signatureVersion);
            assertTrue(payload.shouldNotify);
            // The SDK generates and returns the message id.
            assertFalse(payload.messageId.isEmpty());
        }
    }

    @Test
    void encryptMessageMediaAttachmentMissingRequiredFieldThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "bad attachment");
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            // Core requires the media fields; an attachment missing one is
            // rejected rather than silently defaulted.
            Types.AttachmentDescriptor bad = new Types.AttachmentDescriptor();
            bad.attachmentType = "media";
            bad.mediaHashKey = "h";
            p.attachments = java.util.List.of(bad);
            assertThrows(ChatXdkException.class, () -> chat.encryptMessage(p));
        }
    }

    @Test
    void encryptMessageMixedAttachmentTypesThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "mixed attachments");
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            // Only image/gif/video media may appear in multiples; any other
            // attachment type must be the message's only attachment.
            p.attachments = java.util.List.of(
                    Types.AttachmentDescriptor.media("hash", 100, 100, 1000, "pic.jpg", 1, null),
                    Types.AttachmentDescriptor.urlCard("https://example.com", null));
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.encryptMessage(p));
            assertTrue(ex.getMessage().contains("attachment combination"));
        }
    }

    @Test
    void encryptMessageUrlAttachmentWithBannerImageSucceeds() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity("1001", "s1");
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "Check this out");
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            Types.UrlAttachmentImageDescriptor banner = new Types.UrlAttachmentImageDescriptor();
            banner.mediaHashKey = "banner-hash";
            banner.filesizeBytes = 24_000L;
            banner.filename = "banner.jpg";
            banner.width = 1200L;
            banner.height = 630L;
            Types.AttachmentDescriptor attachment = Types.AttachmentDescriptor.urlCard(
                    "https://example.com/product",
                    "Example Product",
                    banner,
                    Types.UrlAttachmentImageDescriptor.of("favicon-hash", 1_200L, "favicon.ico"));

            // ChatJson.MAPPER is the serializer the FFI uses to build the
            // params JSON, so confirm the banner reaches core under the
            // snake_case keys core deserializes: a @JsonProperty typo would
            // silently drop the image (core ignores unknown keys) yet still
            // encrypt successfully.
            String json = ChatJson.MAPPER.writeValueAsString(attachment);
            for (String key : new String[] {
                "banner_image", "favicon_image", "media_hash_key", "filesize_bytes", "filename"
            }) {
                assertTrue(json.contains("\"" + key + "\""), "attachment JSON missing " + key + ": " + json);
            }

            p.attachments = java.util.List.of(attachment);
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.messageId.isEmpty());
        }
    }

    @Test
    void encryptReplyReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            // Explicit-field form: no raw event in hand, so the preview fields
            // are supplied directly (null reply target).
            EncryptReplyParams p = new EncryptReplyParams("conv-1", "This is a reply", null);
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            p.replyToSequenceId = "seq-42";
            p.replyToSenderId = 12345L;
            p.replyToText = "Original message";
            SendPayload payload = chat.encryptReply(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("1", payload.conversationKeyVersion);
            assertEquals("7", payload.signatureInfo.signatureVersion);
        }
    }

    @Test
    void encryptAddReactionReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            // Explicit-field form: conversation id + target sequence id instead
            // of the raw target event.
            EncryptReactionParams p = new EncryptReactionParams(null, "👍");
            p.conversationId = "conv-1";
            p.targetMessageSequenceId = "seq-99";
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptAddReaction(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("7", payload.signatureInfo.signatureVersion);
        }
    }

    @Test
    void encryptRemoveReactionReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            EncryptReactionParams p = new EncryptReactionParams(null, "👍");
            p.conversationId = "conv-1";
            p.targetMessageSequenceId = "seq-99";
            p.senderId = "1001";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptRemoveReaction(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("7", payload.signatureInfo.signatureVersion);
        }
    }

    @Test
    void encryptEditReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            // Explicit-field form: conversation id + target sequence id instead
            // of the raw target event.
            EncryptEditParams p = new EncryptEditParams(null, "see https://example.com");
            EntityDescriptor url = new EntityDescriptor();
            url.start = 4;
            url.end = 23;
            url.entityType = "url";
            p.entities = List.of(url);
            p.conversationId = "conv-1";
            p.targetMessageSequenceId = "seq-99";
            p.senderId = "111";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptEdit(p);
            assertFalse(payload.messageId.isEmpty());
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
        }
    }

    @Test
    void prepareMessageDeleteSignsCanonicalPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            // A 1:1 id is signed in its canonical colon form; delete-for-all
            // signs the wire action 2.
            MessageDeleteParams p = new MessageDeleteParams("222-111", List.of("seq-10", "seq-11"), true);
            p.senderId = "111";
            p.signingKeyVersion = "1";
            ActionSignature sig = chat.prepareMessageDelete(p);
            assertFalse(sig.messageId.isEmpty());
            assertFalse(sig.encodedMessageEventDetail.isEmpty());
            assertFalse(sig.signature.isEmpty());
            assertEquals(
                    "MessageDeleteEvent," + sig.messageId + ",111,111:222,2,seq-10,seq-11",
                    sig.signaturePayload);
        }
    }

    @Test
    void prepareMessageDeleteForSelf() throws Exception {
        try (Chat chat = createUnlocked()) {
            // Group ids pass through unchanged; delete-for-self signs the wire
            // action 1.
            MessageDeleteParams p = new MessageDeleteParams("g999", List.of("seq-1"), false);
            p.senderId = "111";
            p.signingKeyVersion = "1";
            ActionSignature sig = chat.prepareMessageDelete(p);
            assertEquals(
                    "MessageDeleteEvent," + sig.messageId + ",111,g999,1,seq-1",
                    sig.signaturePayload);
        }
    }

    @Test
    void prepareMarkConversationReadSignsCanonicalPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            // A 1:1 id is signed in its canonical colon form, followed by the
            // read point and its time.
            MarkConversationReadParams p = new MarkConversationReadParams("222-111", "2011626338877079553");
            p.seenAtMsec = 1700000000123L;
            p.senderId = "111";
            p.signingKeyVersion = "1";
            ActionSignature sig = chat.prepareMarkConversationRead(p);
            assertFalse(sig.messageId.isEmpty());
            assertFalse(sig.encodedMessageEventDetail.isEmpty());
            assertEquals("1", sig.publicKeyVersion);
            assertEquals(
                    "MarkConversationReadEvent," + sig.messageId
                            + ",111,111:222,2011626338877079553,1700000000123",
                    sig.signaturePayload);
            assertTrue(chat.verify(
                    chat.getPublicKeys().signing,
                    Base64.getDecoder().decode(sig.signature),
                    sig.signaturePayload.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void prepareMarkConversationReadDefaultsToSessionIdentityAndNow() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity("111", "7");
            long before = System.currentTimeMillis();
            ActionSignature sig = chat.prepareMarkConversationRead(
                    new MarkConversationReadParams("g999", "seq-1"));
            long after = System.currentTimeMillis();

            assertEquals("7", sig.publicKeyVersion);
            String prefix = "MarkConversationReadEvent," + sig.messageId + ",111,g999,seq-1,";
            assertTrue(sig.signaturePayload.startsWith(prefix), sig.signaturePayload);
            long seenAt = Long.parseLong(sig.signaturePayload.substring(prefix.length()));
            assertTrue(seenAt >= before && seenAt <= after, "seen_at " + seenAt);
        }
    }

    @Test
    void prepareMarkConversationReadRejectsEmptySeenUntil() throws Exception {
        try (Chat chat = createUnlocked()) {
            MarkConversationReadParams p = new MarkConversationReadParams("g999", "");
            p.senderId = "111";
            p.signingKeyVersion = "1";
            ChatXdkException e =
                    assertThrows(ChatXdkException.class, () -> chat.prepareMarkConversationRead(p));
            assertTrue(e.getMessage().contains("seen_until_sequence_id is empty"), e.getMessage());
        }
    }

    @Test
    void generatedKeysSignOnlyWithTheRegisteredVersion() throws Exception {
        try (Chat chat = new Chat(); Chat restored = new Chat()) {
            chat.generateKeypairs();
            MessageDeleteParams p = new MessageDeleteParams("1234-5678", List.of("seq-1"), false);
            p.senderId = "1234";
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.prepareMessageDelete(p));
            assertTrue(ex.getMessage().contains("signing_key_version"), ex.getMessage());

            chat.setIdentity("1234", "1700000000123");
            assertEquals("1700000000123", chat.prepareMessageDelete(p).publicKeyVersion);

            // Restored keys carry the version passed to importKeys, and none
            // without it.
            byte[] keys = chat.exportKeys();
            assertNotNull(keys);
            restored.importKeys(keys, "1700000000456");
            assertEquals("1700000000456", restored.prepareMessageDelete(p).publicKeyVersion);
            restored.importKeys(keys);
            assertThrows(ChatXdkException.class, () -> restored.prepareMessageDelete(p));
        }
    }

    @Test
    void utilitiesHexRoundTrip() {
        byte[] raw = {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef};
        String hex = ChatXdkUtilities.bytesToHex(raw);
        assertEquals("deadbeef", hex);
        assertArrayEquals(raw, ChatXdkUtilities.hexToBytes(hex));
    }

    @Test
    void utilitiesDetectMimeTypePng() {
        byte[] png = {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0
        };
        assertEquals("image/png", ChatXdkUtilities.detectMimeType(png));
    }

    @Test
    void utilitiesDetectImageDimensionsPng() throws Exception {
        // Minimal PNG header (magic + IHDR) describing a 100x200 image.
        byte[] png = {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0, 0, 0, 13,
            'I', 'H', 'D', 'R',
            0, 0, 0, 100,
            0, 0, 0, (byte) 200
        };
        ImageDimensions dims = ChatXdkUtilities.detectImageDimensions(png);
        assertNotNull(dims);
        assertEquals(100L, dims.width);
        assertEquals(200L, dims.height);
    }

    @Test
    void prepareConversationKeyChangeReturnsExpectedShape() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(input));
            params.senderId = "me";
            params.signingKeyVersion = "1";
            params.conversationId = "conv-1";
            PreparedConversationChange prepared = chat.prepareConversationKeyChange(params);
            assertNotNull(prepared);
            assertEquals("conv-1", prepared.conversationId);
            byte[] convKey = prepared.conversationKey;
            assertNotNull(convKey);
            assertEquals(32, convKey.length);
            assertEquals(1, prepared.participantKeys.size());
            assertFalse(prepared.participantKeys.get(0).encryptedKey.isEmpty());
            assertEquals(1, prepared.actionSignatures.size());
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            assertTrue(prepared.actionSignatures.get(0).signaturePayload.isEmpty());
        }
    }

    @Test
    void extractConversationKeysEmptyEventsReturnsEmptyBundle() throws Exception {
        try (Chat chat = createUnlocked()) {
            ConversationKeyBundle bundle = chat.extractConversationKeys(List.of());
            assertNotNull(bundle);
            assertTrue(bundle.keys.isEmpty());
            assertNull(bundle.latestVersion);
        }
    }

    @Test
    void prepareGroupMembersChangeReturnsSignedChange() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            GroupMembersChangeParams p = new GroupMembersChangeParams(
                    List.of(input), "g123", List.of("new-1"), List.of("me"), List.of("me"), List.of());
            p.senderId = "me";
            p.signingKeyVersion = "1";
            p.currentTitle = "Test Group";
            PreparedConversationChange prepared = chat.prepareGroupMembersChange(p);
            assertEquals("g123", prepared.conversationId);
            // A member add emits two signed actions: the key change and the add.
            assertEquals(2, prepared.actionSignatures.size());
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            assertTrue(prepared.actionSignatures.get(0).signaturePayload.isEmpty());
            assertFalse(prepared.actionSignatures.get(0).encodedMessageEventDetail.isEmpty());
            assertTrue(prepared.actionSignatures.get(1).signaturePayload.startsWith(
                    "GroupChangeEvent.GroupMemberAddChange,"));
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
            // Unset screen-capture blocking signs as the trailing null sentinel.
            assertTrue(prepared.actionSignatures.get(1).signaturePayload.endsWith(",null"));
        }
    }

    @Test
    void prepareGroupMembersChangeSignsScreenCaptureBlocking() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            GroupMembersChangeParams p = new GroupMembersChangeParams(
                    List.of(input), "g123", List.of("new-1"), List.of("me"), List.of("me"), List.of());
            p.senderId = "me";
            p.signingKeyVersion = "1";
            p.currentScreenCaptureBlockingEnabled = true;
            PreparedConversationChange prepared = chat.prepareGroupMembersChange(p);
            // The group's screen-capture-blocking state fills the trailing signed slot.
            assertTrue(prepared.actionSignatures.get(1).signaturePayload.startsWith(
                    "GroupChangeEvent.GroupMemberAddChange,"));
            assertTrue(prepared.actionSignatures.get(1).signaturePayload.endsWith(",true"));
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
        }
    }

    @Test
    void prepareGroupCreateReturnsSignedChange() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            GroupCreateParams p = new GroupCreateParams(
                    List.of(input), "g123", List.of("me", "friend"), List.of("me"));
            p.senderId = "me";
            p.signingKeyVersion = "1";
            p.title = "Test Group";
            PreparedConversationChange prepared = chat.prepareGroupCreate(p);
            assertEquals("g123", prepared.conversationId);
            // A group create emits two signed actions: the key change and the create.
            assertEquals(2, prepared.actionSignatures.size());
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            assertTrue(prepared.actionSignatures.get(0).signaturePayload.isEmpty());
            assertFalse(prepared.actionSignatures.get(0).encodedMessageEventDetail.isEmpty());
            assertTrue(prepared.actionSignatures.get(1).signaturePayload.startsWith(
                    "GroupChangeEvent.GroupCreate,"));
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
        }
    }

    @Test
    void prepareConversationKeyChangeDerivesOneToOneId() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput a = new PublicKeyInput();
            a.userId = "1491585161162473473";
            a.publicKey = keys.identity;
            a.keyVersion = "1";
            PublicKeyInput b = new PublicKeyInput();
            b.userId = "17380288";
            b.publicKey = keys.identity;
            b.keyVersion = "1";
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(a, b));
            params.senderId = "1491585161162473473";
            params.signingKeyVersion = "1";
            PreparedConversationChange prepared = chat.prepareConversationKeyChange(params);
            assertEquals("17380288:1491585161162473473", prepared.conversationId);
        }
    }

    @Test
    void prepareConversationKeyChangeDeriveAndDecryptRoundTrip() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            // No conversationId set: the canonical one-to-one id is derived from
            // the two participants. Both entries reuse our identity key so every
            // participant key decrypts locally.
            PublicKeyInput a = new PublicKeyInput();
            a.userId = "17380288";
            a.publicKey = keys.identity;
            a.keyVersion = "1";
            PublicKeyInput b = new PublicKeyInput();
            b.userId = "1491585161162473473";
            b.publicKey = keys.identity;
            b.keyVersion = "1";
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(a, b));
            params.senderId = "17380288";
            params.signingKeyVersion = "1";
            PreparedConversationChange prepared = chat.prepareConversationKeyChange(params);
            assertEquals("17380288:1491585161162473473", prepared.conversationId);
            assertEquals(2, prepared.participantKeys.size());
            for (EncryptedKeyForRecipient pk : prepared.participantKeys) {
                assertArrayEquals(
                        prepared.conversationKey,
                        chat.decryptConversationKey(pk.encryptedKey));
            }
        }
    }

    @Test
    void encryptDecryptUnicodeRoundTrip() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] key = newConvKey(chat);
            String plaintext = "metadata payload 🌟 with unicode";
            String ct = chat.encrypt(plaintext, key);
            assertFalse(ct.isEmpty());
            assertNotEquals(plaintext, ct);
            assertEquals(plaintext, chat.decrypt(ct, key));
        }
    }

    @Test
    void decryptEventsEmptyListReturnsNonNullResult() throws Exception {
        try (Chat chat = createUnlocked()) {
            DecryptEventsResult result = chat.decryptEvents(new DecryptEventsParams(List.of()));
            assertNotNull(result);
            assertTrue(result.messages.isEmpty());
            assertTrue(result.errors.isEmpty());
        }
    }

    @Test
    void decryptEventsMalformedSigningKeyEntryThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            // Null fields are omitted from the serialized JSON, so this entry is
            // missing required fields. That must be surfaced rather than silently
            // dropped (which would weaken verification by skipping it).
            SigningKeyEntry malformed = new SigningKeyEntry();
            malformed.publicKeyVersion = "1";
            malformed.publicKey = "AA==";
            DecryptEventsParams params = new DecryptEventsParams(List.of());
            params.signingKeys = List.of(malformed);
            ChatXdkException ex = assertThrows(ChatXdkException.class, () -> chat.decryptEvents(params));
            assertTrue(ex.getMessage().contains("Invalid params JSON: missing field `user_id`"), ex.getMessage());
        }
    }

    // Deterministic cross-binding fixture pins (tests/fixtures/sdk_vectors.json)

    @Test
    void vectorsPublicKeysAndSignatureMatchFixture() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"));
            assertTrue(chat.isUnlocked());

            PublicKeys keys = chat.getPublicKeys();
            assertEquals(v.get("identity_public_b64").asText(), keys.identity);
            assertEquals(v.get("signing_public_b64").asText(), keys.signing);

            // ECDSA here is deterministic (RFC 6979): the signature must match
            // the fixture byte-for-byte, verify, and reject a tampered message.
            byte[] message = v.get("message_utf8").asText().getBytes(StandardCharsets.UTF_8);
            byte[] signature = chat.sign(message);
            assertEquals(v.get("signature_b64").asText(), Base64.getEncoder().encodeToString(signature));
            assertTrue(chat.verify(v.get("signing_public_b64").asText(), signature, message));
            assertFalse(chat.verify(
                    v.get("signing_public_b64").asText(),
                    signature,
                    (v.get("message_utf8").asText() + "!").getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void vectorsDecryptEventsBatchAndSingleEventContracts() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            List<SigningKeyEntry> signingKeys = eventSigningKeys(v);
            String ckVersion = v.get("event_conversation_key_version").asText();

            // Batch path never throws: the garbage event is collected as an
            // indexed error, the signed KeyChange's key is adopted, and the
            // message verifies with the fixture text.
            DecryptEventsParams batch = new DecryptEventsParams(List.of(
                    v.get("event_key_change_b64").asText(),
                    v.get("event_message_b64").asText(),
                    v.get("event_garbage_b64").asText()));
            batch.signingKeys = signingKeys;
            DecryptEventsResult result = chat.decryptEvents(batch);

            assertEquals(1, result.errors.size(), "errors: " + result.errors);
            assertTrue(result.errors.containsKey("2"), "errors: " + result.errors);

            assertEquals(ckVersion, result.conversationKeys.latestVersion);
            assertArrayEquals(
                    b64(v, "conversation_key_b64"),
                    result.conversationKeys.keys.get(ckVersion));

            List<JsonNode> keyChanges = new ArrayList<>();
            List<JsonNode> messages = new ArrayList<>();
            for (DecryptedMessage dm : result.messages) {
                if ("KeyChange".equals(dm.event.path("type").asText())) keyChanges.add(dm.event);
                if ("Message".equals(dm.event.path("type").asText())) messages.add(dm.event);
            }
            assertEquals(1, keyChanges.size());
            assertTrue(keyChanges.get(0).path("verified").asBoolean());
            assertEquals(ckVersion, keyChanges.get(0).path("key_version").asText());

            assertEquals(1, messages.size());
            assertEquals(v.get("event_message_text").asText(),
                    messages.get(0).path("content").path("text").asText());
            assertTrue(messages.get(0).path("verified").asBoolean());

            // Single-event path with pre-cached keys verifies the same message …
            DecryptEventParams cached =
                    new DecryptEventParams(v.get("event_message_b64").asText(), result.conversationKeys.keys);
            cached.signingKeys = signingKeys;
            JsonNode single = chat.decryptEvent(cached);
            assertEquals("Message", single.path("type").asText());
            assertEquals(v.get("event_message_text").asText(),
                    single.path("content").path("text").asText());
            assertTrue(single.path("verified").asBoolean());

            // … and throws on the garbage event.
            DecryptEventParams garbage = new DecryptEventParams(v.get("event_garbage_b64").asText(), Map.of());
            garbage.signingKeys = signingKeys;
            assertThrows(ChatXdkException.class, () -> chat.decryptEvent(garbage));
        }
    }

    // Failure events are unsigned by protocol: the fixture failure decodes
    // with no conversation or signing keys, and the JSON carries the
    // PascalCase discriminator values.
    @Test
    void vectorsFailureEventDecodesTypeAndRateLimitTier() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            JsonNode event = chat.decryptEvent(new DecryptEventParams(v.get("event_failure_b64").asText(), Map.of()));
            assertEquals("Failure", event.path("type").asText());
            assertEquals("RateLimitUpsell", event.path("failure").asText());
            assertEquals("Premium", event.path("rate_limit_tier").asText());
            assertEquals(v.get("event_sender_id").asText(), event.path("sender_id").asText());
        }
    }

    // Session identity: setIdentity supplies senderId and signingKeyVersion;
    // an encrypt with only the conversation key explicit signs with the
    // session values, and without any identity the call fails loudly.
    @Test
    void vectorsSetIdentityResolvesSenderAndSigningVersion() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            String conversationId = v.get("event_conversation_id").asText();

            // No identity set: the error names the missing sender_id.
            EncryptMessageParams withoutIdentity = new EncryptMessageParams(conversationId, "no identity");
            withoutIdentity.conversationKey = b64(v, "conversation_key_b64");
            withoutIdentity.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.encryptMessage(withoutIdentity));
            assertTrue(ex.getMessage().contains("sender_id"), ex.getMessage());

            chat.setIdentity(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText());
            EncryptMessageParams p = new EncryptMessageParams(conversationId, "session identity");
            p.conversationKey = b64(v, "conversation_key_b64");
            p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.messageId.isEmpty());
            assertEquals(v.get("event_signing_key_version").asText(), payload.signatureInfo.publicKeyVersion);
        }
    }

    // Conversation-key cache: after decrypting the verified fixture KeyChange
    // with the cache enabled, an encrypt with no explicit key resolves the
    // cached key; with the cache off the same call fails.
    @Test
    void vectorsSetCacheKeysResolvesConversationKeyFromDecryptedKeyChange() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            chat.setIdentity(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText());
            String conversationId = v.get("event_conversation_id").asText();

            chat.setCacheKeys(true);
            DecryptEventsParams keyChange = new DecryptEventsParams(List.of(v.get("event_key_change_b64").asText()));
            keyChange.signingKeys = eventSigningKeys(v);
            chat.decryptEvents(keyChange);

            // With no conversation keys, decryptEvent takes the key from the cache.
            DecryptEventParams fromCache = new DecryptEventParams(v.get("event_message_b64").asText());
            fromCache.signingKeys = eventSigningKeys(v);
            assertEquals(v.get("event_message_text").asText(),
                    chat.decryptEvent(fromCache).get("content").get("text").asText());

            SendPayload payload =
                    chat.encryptMessage(new EncryptMessageParams(conversationId, "from the key cache"));
            assertEquals(v.get("event_conversation_key_version").asText(), payload.conversationKeyVersion);
            assertFalse(payload.encryptedContent.isEmpty());

            // Disabling clears the cache, so the same short form now fails.
            chat.setCacheKeys(false);
            ChatXdkException ex = assertThrows(ChatXdkException.class, () ->
                    chat.encryptMessage(new EncryptMessageParams(conversationId, "no cache")));
            assertTrue(ex.getMessage().contains("conversation key"), ex.getMessage());
        }
    }

    // Signing-key store: setSigningKeys makes decrypt calls that omit their
    // signingKeys argument verify against the stored keys.
    @Test
    void vectorsSetSigningKeysDecryptWithoutExplicitKeysVerifies() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            chat.setSigningKeys(eventSigningKeys(v));

            DecryptEventsResult result =
                    chat.decryptEvents(new DecryptEventsParams(List.of(v.get("event_key_change_b64").asText())));
            assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

            JsonNode single = chat.decryptEvent(
                    new DecryptEventParams(v.get("event_message_b64").asText(), result.conversationKeys.keys));
            assertEquals("Message", single.path("type").asText());
            assertEquals(v.get("event_message_text").asText(),
                    single.path("content").path("text").asText());
            assertTrue(single.path("verified").asBoolean());
        }
    }

    // Reply preview validation: the genuine embedded original validates,
    // the forged preview is flagged Invalid (both still decrypt).
    @Test
    void vectorsReplyPreviewValidationValidAndForged() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());

            DecryptEventsParams replies = new DecryptEventsParams(List.of(
                    v.get("event_key_change_b64").asText(),
                    v.get("event_reply_valid_b64").asText(),
                    v.get("event_reply_forged_b64").asText()));
            replies.signingKeys = eventSigningKeys(v);
            DecryptEventsResult result = chat.decryptEvents(replies);
            assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

            List<JsonNode> messages = new ArrayList<>();
            for (DecryptedMessage dm : result.messages) {
                if ("Message".equals(dm.event.path("type").asText())) messages.add(dm.event);
            }
            assertEquals(2, messages.size());

            assertEquals(v.get("event_reply_text").asText(),
                    messages.get(0).path("content").path("text").asText());
            assertEquals("Valid", messages.get(0).path("reply_preview_validation").asText());
            assertEquals("Invalid", messages.get(1).path("reply_preview_validation").asText());
        }
    }

    // Reply-by-event: passing the raw original event derives the preview
    // (the SDK decrypts the original with the reply's own key).
    @Test
    void vectorsEncryptReplyByRawEventSucceeds() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            chat.setIdentity(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText());

            EncryptReplyParams p = new EncryptReplyParams(
                    v.get("event_conversation_id").asText(), "a reply", v.get("event_message_b64").asText());
            p.conversationKey = b64(v, "conversation_key_b64");
            p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            SendPayload payload = chat.encryptReply(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.messageId.isEmpty());
        }
    }

    // Message-key vectors: their contents and media are encrypted directly
    // under the known message and attachment keys, so they open only if the
    // SDK derives the same keys from the conversation key.
    @Test
    void vectorsMessageKeyEventDecryptsWithTheConversationKey() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            DecryptEventParams params =
                    new DecryptEventParams(v.get("event_message_key_b64").asText(), messageKeyConversationKeys(v));
            params.signingKeys = signingKeysFor(v, v.get("message_key_sender_id").asText());
            JsonNode event = chat.decryptEvent(params);
            assertEquals("Message", event.path("type").asText());
            assertTrue(event.path("verified").asBoolean());
            assertEquals(v.get("event_message_key_text").asText(), event.path("content").path("text").asText());
            List<String> hashes = new ArrayList<>();
            event.path("media_hashes").forEach(h -> hashes.add(h.path("media_hash_key").asText()));
            assertEquals(
                    List.of(v.get("media_first_hash_key").asText(), v.get("media_second_hash_key").asText()),
                    hashes);
        }
    }

    @Test
    void vectorsSeveralMediaFilesOpenFromTheirMessage() throws Exception {
        JsonNode v = loadVectors();
        assertMediaOpens(v, "event_message_key_b64", messageKeyConversationKeys(v), "first");
        assertMediaOpens(v, "event_message_key_b64", messageKeyConversationKeys(v), "second");
    }

    @Test
    void vectorsOneMediaFileOpensFromItsMessage() throws Exception {
        JsonNode v = loadVectors();
        Map<String, byte[]> keys = Map.of(
                v.get("message_key_short_conversation_key_version").asText(),
                ChatXdkUtilities.hexToBytes(v.get("message_key_short_conversation_key_hex").asText()));
        assertMediaOpens(v, "event_message_key_short_b64", keys, "short");
    }

    @Test
    void vectorsLinkCardImagesOpenFromTheirMessage() throws Exception {
        JsonNode v = loadVectors();
        assertMediaOpens(v, "event_link_card_b64", messageKeyConversationKeys(v), "banner");
        assertMediaOpens(v, "event_link_card_b64", messageKeyConversationKeys(v), "favicon");
    }

    @Test
    void vectorsConversationKeyMediaOpensFromItsMessage() throws Exception {
        JsonNode v = loadVectors();
        assertMediaOpens(v, "event_conversation_key_media_b64", conversationKeys(v), "conversation_key");
    }

    @Test
    void vectorsMediaErrorsSayWhatToPass() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            Map<String, byte[]> mkKeys = messageKeyConversationKeys(v);
            byte[] first = b64(v, "media_first_encrypted_b64");
            byte[] second = b64(v, "media_second_encrypted_b64");
            String firstHash = v.get("media_first_hash_key").asText();
            String mkEvent = v.get("event_message_key_b64").asText();
            String mkVersion = v.get("message_key_conversation_key_version").asText();
            Object[][] cases = {
                {first, mkEvent, conversationKeys(v), firstHash, "no key for version '" + mkVersion + "'"},
                {first, mkEvent, mkKeys, "not-a-hash-key", "is not in the message"},
                {first, v.get("event_key_change_b64").asText(), mkKeys, firstHash, "the event is not a message"},
                {first, v.get("event_message_b64").asText(), conversationKeys(v), firstHash, "the message has no media"},
                {second, mkEvent, mkKeys, firstHash, "encrypted file of media_hash_key '" + firstHash + "'"},
                {Arrays.copyOf(first, first.length / 2), mkEvent, mkKeys, firstHash, "truncated"},
                {first, v.get("event_unencrypted_b64").asText(), mkKeys,
                    v.get("media_unencrypted_hash_key").asText(), "the message is not encrypted"},
                {first, mkEvent, Map.of(mkVersion, new byte[3]), firstHash, "is not 32 bytes"},
            };
            for (Object[] c : cases) {
                @SuppressWarnings("unchecked")
                Map<String, byte[]> keys = (Map<String, byte[]>) c[2];
                ChatXdkException e = assertThrows(
                        ChatXdkException.class,
                        () -> chat.decryptFile(new DecryptFileParams((byte[]) c[0], (String) c[1], keys, (String) c[3])));
                assertTrue(e.getMessage().contains((String) c[4]), e.getMessage() + " lacks " + c[4]);
            }
            ChatXdkException e = assertThrows(
                    ChatXdkException.class,
                    () -> chat.fileDecryptor(new FileDecryptorParams(mkEvent, conversationKeys(v), firstHash)));
            assertTrue(e.getMessage().contains("no key for version"), e.getMessage());
        }
    }

    @Test
    void vectorsMessageKeyEventDecryptsInABatchWithItsKeyChange() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
            DecryptEventsParams batch = new DecryptEventsParams(List.of(
                    v.get("event_key_change_message_key_b64").asText(),
                    v.get("event_message_key_b64").asText()));
            batch.signingKeys =
                    signingKeysFor(v, v.get("event_sender_id").asText(), v.get("message_key_sender_id").asText());
            DecryptEventsResult result = chat.decryptEvents(batch);
            assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

            byte[] key = result.conversationKeys.keys.get(v.get("message_key_conversation_key_version").asText());
            assertArrayEquals(ChatXdkUtilities.hexToBytes(v.get("message_key_conversation_key_hex").asText()), key);
            List<String> texts = new ArrayList<>();
            for (DecryptedMessage dm : result.messages) {
                if ("Message".equals(dm.event.path("type").asText())) {
                    texts.add(dm.event.path("content").path("text").asText());
                }
            }
            assertEquals(List.of(v.get("event_message_key_text").asText()), texts);
            assertMediaOpens(v, "event_message_key_b64", result.conversationKeys.keys, "second");
        }
    }

    @Test
    void vectorsShortSenderMessageKeyEventVerifiesAtV11() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            DecryptEventParams params = new DecryptEventParams(
                    v.get("event_message_key_short_b64").asText(),
                    Map.of(
                            v.get("message_key_short_conversation_key_version").asText(),
                            ChatXdkUtilities.hexToBytes(v.get("message_key_short_conversation_key_hex").asText())));
            params.signingKeys = signingKeysFor(v, v.get("message_key_short_sender_id").asText());
            JsonNode event = chat.decryptEvent(params);
            assertTrue(event.path("verified").asBoolean());
            assertEquals(v.get("event_message_key_short_text").asText(), event.path("content").path("text").asText());
        }
    }

    @Test
    void vectorsReplyCarryingAMessageKeyValidatesAndOpensTheQuotedMedia() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            byte[] key = b64(v, "conversation_key_b64");
            DecryptEventParams params = new DecryptEventParams(
                    v.get("event_reply_message_key_b64").asText(),
                    Map.of(v.get("event_conversation_key_version").asText(), key));
            params.signingKeys =
                    signingKeysFor(v, v.get("event_sender_id").asText(), v.get("message_key_sender_id").asText());
            JsonNode event = chat.decryptEvent(params);
            assertTrue(event.path("verified").asBoolean());
            assertEquals(v.get("event_reply_message_key_text").asText(), event.path("content").path("text").asText());
            assertEquals("Valid", event.path("reply_preview_validation").asText());
            assertMediaOpens(v, "event_reply_message_key_b64", conversationKeys(v), "first");
        }
    }

    @Test
    void vectorsKnownSignatureCoversTheContentsEncryptionVersion() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            String publicKey = v.get("signature_v10_cev1_public_key_b64").asText();
            byte[] signature = b64(v, "signature_v10_cev1_b64");
            assertTrue(chat.verify(
                    publicKey, signature, v.get("payload_message_v10_cev1").asText().getBytes(StandardCharsets.UTF_8)));
            assertFalse(chat.verify(
                    publicKey, signature, v.get("payload_message_v10").asText().getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void signVerifyRoundTripAndTamperReject() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] data = "test data".getBytes(StandardCharsets.UTF_8);
            byte[] signature = chat.sign(data);
            assertEquals(64, signature.length);

            PublicKeys keys = chat.getPublicKeys();
            assertTrue(chat.verify(keys.signing, signature, data));
            assertFalse(chat.verify(keys.signing, signature,
                    "tampered".getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void signVerifyWrongPublicKeyReturnsFalse() throws Exception {
        try (Chat chatA = createUnlocked(); Chat chatB = createUnlocked()) {
            byte[] data = {(byte) 0xAA, (byte) 0xBB};
            byte[] signature = chatA.sign(data);
            // chatB's key doesn't match chatA's signature → false (not throw).
            assertFalse(chatA.verify(chatB.getPublicKeys().signing, signature, data));
        }
    }

    // A message with files is built first; each file is then encrypted from the returned
    // eventB64 and the media hash key its attachment names.

    private static Types.AttachmentDescriptor photo(String mediaHashKey) {
        return Types.AttachmentDescriptor.media(mediaHashKey, 4, 3, 64, mediaHashKey + ".jpg", 1, null);
    }

    /** Send a v1 message carrying {@code attachments}, check it verifies, and return its payload. */
    private static SendPayload sendFiles(Chat chat, JsonNode v, String text, Types.AttachmentDescriptor... attachments)
            throws Exception {
        EncryptMessageParams p = new EncryptMessageParams(v.get("event_conversation_id").asText(), text);
        p.conversationKey = b64(v, "conversation_key_b64");
        p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
        p.attachments = attachments.length == 0 ? null : List.of(attachments);
        chat.applyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.featureBucket());
        SendPayload payload = chat.encryptMessage(p);
        assertEquals("10", payload.signatureInfo.signatureVersion);
        assertEquals(text, decryptOwnContent(chat, v, payload).get("text").asText());
        return payload;
    }

    /** The event as delivered: {@code eventB64} with the sequence id the server assigns, prepended as Thrift string field 1. */
    private static String delivered(String eventB64, String sequenceId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeThriftString(out, 1, sequenceId);
        out.writeBytes(Base64.getDecoder().decode(eventB64));
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    @Test
    void encryptDecryptFileRoundTrip() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v); Chat worker = new Chat()) {
            byte[] plaintext = new byte[1024];
            new java.util.Random(42).nextBytes(plaintext);
            SendPayload payload = sendFiles(chat, v, "a photo", photo("photo"));

            // A chat with no identity encrypts the file from the payload.
            byte[] encrypted = worker.encryptFile(
                    new EncryptFileParams(plaintext, payload.eventB64, conversationKeys(v), "photo"));
            assertFalse(java.util.Arrays.equals(plaintext, encrypted));
            assertEquals(ChatXdkUtilities.encryptedFileSize(plaintext.length), encrypted.length);
            assertArrayEquals(plaintext, chat.decryptFile(
                    new DecryptFileParams(encrypted, payload.eventB64, conversationKeys(v), "photo")));
        }
    }

    @Test
    void decryptFileWrongKeyThrows() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            SendPayload payload = sendFiles(chat, v, "a photo", photo("photo"));
            Map<String, byte[]> wrongKeys =
                    Map.of(v.get("event_conversation_key_version").asText(), newConvKey(chat));
            ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.decryptFile(
                    new DecryptFileParams(new byte[64], payload.eventB64, wrongKeys, "photo")));
            assertTrue(e.getMessage().contains("does not decrypt the message"), e.getMessage());
        }
    }

    @Test
    void incrementalFileRoundTripAndTruncationThrows() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            // A multi-frame file so chunking and re-framing are exercised, sent as the
            // second of two photos.
            byte[] plaintext = new byte[5000];
            java.util.Arrays.fill(plaintext, (byte) 0xAB);
            SendPayload payload = sendFiles(chat, v, "two photos", photo("first"), photo("second"));

            ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
            try (FileEncryptor enc = chat.fileEncryptor(
                    new FileEncryptorParams(payload.eventB64, conversationKeys(v), "second"))) {
                for (int i = 0; i < plaintext.length; i += 700) {
                    int end = Math.min(i + 700, plaintext.length);
                    ciphertext.write(enc.push(java.util.Arrays.copyOfRange(plaintext, i, end)));
                }
                ciphertext.write(enc.finish());
            }
            byte[] ct = ciphertext.toByteArray();

            assertThrows(ChatXdkException.class, () -> chat.decryptFile(
                    new DecryptFileParams(ct, payload.eventB64, conversationKeys(v), "first")));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FileDecryptor dec = chat.fileDecryptor(
                    new FileDecryptorParams(payload.eventB64, conversationKeys(v), "second"))) {
                for (int i = 0; i < ct.length; i += 333) {
                    int end = Math.min(i + 333, ct.length);
                    out.write(dec.push(java.util.Arrays.copyOfRange(ct, i, end)));
                }
                out.write(dec.finish());
            }
            assertArrayEquals(plaintext, out.toByteArray());

            // A truncated file is missing its final frame: finish() throws.
            try (FileDecryptor truncated = chat.fileDecryptor(
                    new FileDecryptorParams(payload.eventB64, conversationKeys(v), "second"))) {
                truncated.push(java.util.Arrays.copyOfRange(ct, 0, ct.length - 4));
                ChatXdkException e = assertThrows(ChatXdkException.class, truncated::finish);
                assertTrue(e.getMessage().contains("truncated"), e.getMessage());
            }
        }
    }

    /** The file calls throw only the unchecked ChatXdkException, so no throws clause is needed. */
    private static byte[] roundTripWithoutThrowsClause(
            Chat chat, SendPayload payload, Map<String, byte[]> keys, String mediaHashKey, byte[] file) {
        byte[] whole = chat.encryptFile(new EncryptFileParams(file, payload.eventB64, keys, mediaHashKey));
        byte[] streamed;
        try (FileEncryptor enc = chat.fileEncryptor(new FileEncryptorParams(payload.eventB64, keys, mediaHashKey))) {
            byte[] head = enc.push(file);
            byte[] tail = enc.finish();
            streamed = java.util.Arrays.copyOf(head, head.length + tail.length);
            System.arraycopy(tail, 0, streamed, head.length, tail.length);
        }
        try (FileDecryptor dec = chat.fileDecryptor(new FileDecryptorParams(payload.eventB64, keys, mediaHashKey))) {
            dec.push(streamed);
            dec.finish();
        }
        return chat.decryptFile(new DecryptFileParams(whole, payload.eventB64, keys, mediaHashKey));
    }

    @Test
    void fileCallsDeclareNoCheckedExceptions() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            SendPayload payload = sendFiles(chat, v, "a photo", photo("only"));
            byte[] file = "photo bytes".getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(file, roundTripWithoutThrowsClause(chat, payload, conversationKeys(v), "only", file));
        }
    }

    @Test
    void linkCardImagesTakeTheCardsKey() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            SendPayload payload = sendFiles(chat, v, "a link", Types.AttachmentDescriptor.urlCard(
                    "https://example.com",
                    null,
                    Types.UrlAttachmentImageDescriptor.of("banner", 12L, "banner.png"),
                    Types.UrlAttachmentImageDescriptor.of("favicon", 13L, "favicon.png")));
            for (String name : new String[] {"banner", "favicon"}) {
                byte[] encrypted = chat.encryptFile(new EncryptFileParams(
                        (name + " bytes").getBytes(StandardCharsets.UTF_8), payload.eventB64, conversationKeys(v), name));
                assertEquals(name + " bytes", new String(chat.decryptFile(
                        new DecryptFileParams(encrypted, payload.eventB64, conversationKeys(v), name)),
                        StandardCharsets.UTF_8));
            }
        }
    }

    @Test
    void aMessageWithFilesTakesTheIdItsFilesDerive() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            SendPayload draft = sendFiles(chat, v, "draft", photo("photo-a"), photo("photo-b"));
            assertTrue(draft.messageId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"),
                    draft.messageId);
            byte[] encrypted = chat.encryptFile(new EncryptFileParams(
                    "photo b".getBytes(StandardCharsets.UTF_8), draft.eventB64, conversationKeys(v), "photo-b"));

            // Building the message again gives the same id, so its encrypted files stay valid.
            SendPayload rebuilt = sendFiles(chat, v, "final text", photo("photo-a"), photo("photo-b"));
            assertEquals(draft.messageId, rebuilt.messageId);
            assertEquals("photo b", new String(chat.decryptFile(
                    new DecryptFileParams(encrypted, rebuilt.eventB64, conversationKeys(v), "photo-b")),
                    StandardCharsets.UTF_8));

            assertNotEquals(draft.messageId, sendFiles(chat, v, "draft", photo("photo-b"), photo("photo-a")).messageId);
            assertNotEquals(sendFiles(chat, v, "no files").messageId, sendFiles(chat, v, "no files").messageId);
        }
    }

    @Test
    void fileSendInputIsChecked() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            byte[] ckey = b64(v, "conversation_key_b64");
            String conversationId = v.get("event_conversation_id").asText();
            String keyVersion = v.get("event_conversation_key_version").asText();

            EncryptMessageParams twice = new EncryptMessageParams(conversationId, "twice");
            twice.conversationKey = ckey;
            twice.conversationKeyVersion = keyVersion;
            twice.attachments = List.of(photo("photo"), photo("photo"));
            ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.encryptMessage(twice));
            assertTrue(e.getMessage().contains("media_hash_key 'photo' is in more than one attachment"), e.getMessage());

            SendPayload payload = sendFiles(chat, v, "a photo", photo("photo"));
            e = assertThrows(ChatXdkException.class, () -> chat.encryptFile(
                    new EncryptFileParams(new byte[] {1}, payload.eventB64, conversationKeys(v), "other")));
            assertTrue(e.getMessage().contains("is not one of the message's files"), e.getMessage());
            e = assertThrows(ChatXdkException.class, () -> chat.encryptFile(
                    new EncryptFileParams(new byte[] {1}, payload.eventB64, Map.of(keyVersion, new byte[3]), "photo")));
            assertTrue(e.getMessage().contains("is not 32 bytes"), e.getMessage());

            // A reply needs the delivered event, which carries the sequence id; the files it
            // quotes belong to the quoted message.
            EncryptReplyParams tooEarly = new EncryptReplyParams(conversationId, "too early", payload.eventB64);
            tooEarly.conversationKey = ckey;
            tooEarly.conversationKeyVersion = keyVersion;
            e = assertThrows(ChatXdkException.class, () -> chat.encryptReply(tooEarly));
            assertTrue(e.getMessage().contains("reply_to_event carries no sequence_id"), e.getMessage());
            EncryptReplyParams replyParams =
                    new EncryptReplyParams(conversationId, "and mine", delivered(payload.eventB64, "100"));
            replyParams.conversationKey = ckey;
            replyParams.conversationKeyVersion = keyVersion;
            replyParams.attachments = List.of(photo("reply-photo"));
            SendPayload reply = chat.encryptReply(replyParams);
            e = assertThrows(ChatXdkException.class, () -> chat.encryptFile(
                    new EncryptFileParams(new byte[] {1}, reply.eventB64, conversationKeys(v), "photo")));
            assertTrue(e.getMessage().contains("is media the reply quotes"), e.getMessage());

            try (Chat noIdentity = new Chat()) {
                noIdentity.importKeys(b64(v, "private_keys_concat_b64"));
                EncryptMessageParams withPhoto = new EncryptMessageParams(conversationId, "a photo");
                withPhoto.conversationKey = ckey;
                withPhoto.conversationKeyVersion = keyVersion;
                withPhoto.attachments = List.of(photo("photo"));
                e = assertThrows(ChatXdkException.class, () -> noIdentity.encryptMessage(withPhoto));
                assertTrue(e.getMessage().contains("set_identity"), e.getMessage());
            }
        }
    }

    @Test
    void verifyKeyBindingValidAndTampered() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = createUnlocked()) {
            assertTrue(chat.verifyKeyBinding(
                    v.get("identity_public_b64").asText(),
                    v.get("signing_public_b64").asText(),
                    v.get("identity_public_key_signature_b64").asText()));

            byte[] tampered = b64(v, "identity_public_key_signature_b64");
            tampered[0] ^= (byte) 0xFF;
            assertFalse(chat.verifyKeyBinding(
                    v.get("identity_public_b64").asText(),
                    v.get("signing_public_b64").asText(),
                    Base64.getEncoder().encodeToString(tampered)));
            // Wrong key in the identity slot: the binding no longer verifies.
            assertFalse(chat.verifyKeyBinding(
                    v.get("signing_public_b64").asText(),
                    v.get("signing_public_b64").asText(),
                    v.get("identity_public_key_signature_b64").asText()));
        }
    }

    @Test
    void matchesRegisteredKeyBothEncodings() throws Exception {
        try (Chat chat = new Chat()) {
            PublicKeyRegistrationPayload payload = chat.generateKeypairs();

            // SPKI/DER form (registration payload) and raw SEC1 form
            // (getPublicKeys) both identify the loaded key.
            assertTrue(chat.matchesRegisteredKey(payload.publicKey.publicKey));
            assertTrue(chat.matchesRegisteredKey(chat.getPublicKeys().identity));

            try (Chat other = new Chat()) {
                PublicKeyRegistrationPayload otherPayload = other.generateKeypairs();
                assertFalse(chat.matchesRegisteredKey(otherPayload.publicKey.publicKey));
            }

            // No identity loaded and invalid base64 throw rather than return false.
            try (Chat locked = new Chat()) {
                assertThrows(
                        ChatXdkException.class,
                        () -> locked.matchesRegisteredKey(payload.publicKey.publicKey));
            }
            assertThrows(ChatXdkException.class, () -> chat.matchesRegisteredKey("not base64!!"));
        }
    }

    @Test
    void importInvalidKeysThrows() {
        try (Chat chat = new Chat()) {
            assertThrows(ChatXdkException.class, () -> chat.importKeys(new byte[16]));
            assertThrows(ChatXdkException.class, () -> chat.importKeys(new byte[0]));
        }
    }

    @Test
    void operationsFailWhenLocked() {
        try (Chat chat = new Chat()) {
            assertThrows(Exception.class, chat::getPublicKeys);
            assertThrows(ChatXdkException.class, () -> chat.sign(new byte[] {1, 2, 3}));
            // exportKeys returns null (not throws) when locked.
            assertNull(chat.exportKeys());
        }
    }

    @Test
    void exportKeysIdentityOnlyReturns32Bytes() throws Exception {
        JsonNode v = loadVectors();
        byte[] full = b64(v, "private_keys_concat_b64");
        byte[] identityOnly = java.util.Arrays.copyOf(full, 32);

        // Identity-only sessions can export (32 bytes), matching core; only
        // a session with no identity key at all returns null.
        try (Chat chat = new Chat()) {
            chat.importKeys(identityOnly);
            byte[] exported = chat.exportKeys();
            assertNotNull(exported);
            assertArrayEquals(identityOnly, exported);
        }
    }

    // JNA plumbing smokes only: the values cross the boundary without a crash.
    // The behaviors themselves are pinned by
    // vectorsDecryptEventsBatchAndSingleEventContracts and the Rust core suite.
    @Test
    void setIdentityAndSetRejectUnverifiedSmoke() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity("user-1", "12345");
            chat.setRejectUnverified(false);
            chat.setRejectUnverified(true);
        }
    }

    // Absent-value normalization: an empty title/avatar is "not set" and
    // signs the null sentinel, exactly like leaving the field null.
    @Test
    void prepareGroupCreateEmptyTitleSignsNullSentinel() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            for (String title : new String[] {"", null}) {
                GroupCreateParams p = new GroupCreateParams(
                        List.of(input), "g123", List.of("me", "friend"), List.of("me"));
                p.senderId = "me";
                p.signingKeyVersion = "1";
                p.title = title;
                p.avatarUrl = title;
                PreparedConversationChange prepared = chat.prepareGroupCreate(p);
                String payload = prepared.actionSignatures.get(1).signaturePayload;
                // Trailing slots: title, avatar_url, ttl — all unset → null sentinels.
                assertTrue(payload.endsWith(",null,null,null"),
                        "title/avatar must sign as the null sentinel, got: " + payload);
            }
        }
    }

    // Comma-injection rejection: the signature payload is comma-joined with
    // no escaping, so a comma-containing title must fail.
    @Test
    void prepareGroupCreateCommaTitleThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput();
            input.userId = "me";
            input.publicKey = keys.identity;
            input.keyVersion = "1";
            GroupCreateParams p = new GroupCreateParams(
                    List.of(input), "g123", List.of("me", "friend"), List.of("me"));
            p.senderId = "me";
            p.signingKeyVersion = "1";
            p.title = "Team, the sequel";
            assertThrows(ChatXdkException.class, () -> chat.prepareGroupCreate(p));
        }
    }

    // Quick replies

    private static QuickReplyOption quickReplyOption(String id, String label, String metadata, String description) {
        QuickReplyOption o = new QuickReplyOption();
        o.id = id;
        o.label = label;
        o.metadata = metadata;
        o.description = description;
        return o;
    }

    private static QuickReply sampleQuickReplyRequest() {
        QuickReplyOptionsRequest options = new QuickReplyOptionsRequest();
        options.id = "qr-1";
        options.options = List.of(
                quickReplyOption("yes", "Yes", "m-yes", "Confirm"),
                quickReplyOption("no", "No", "m-no", "Decline"));
        return QuickReply.request(options);
    }

    private static QuickReply sampleQuickReplyResponse() {
        QuickReplyOptionsResponse options = new QuickReplyOptionsResponse();
        options.requestId = "qr-1";
        options.metadata = "m-yes";
        options.selectedOptionId = "yes";
        return QuickReply.response(options);
    }

    private static void writeThriftString(ByteArrayOutputStream out, int id, String value) {
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

    private static Chat quickReplyChat(JsonNode v) throws Exception {
        Chat chat = new Chat();
        chat.importKeys(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText());
        chat.setIdentity(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText());
        return chat;
    }

    private static JsonNode decryptOwnContent(Chat chat, JsonNode v, SendPayload payload) throws Exception {
        DecryptEventParams params = new DecryptEventParams(
                payload.eventB64,
                Map.of(v.get("event_conversation_key_version").asText(), b64(v, "conversation_key_b64")));
        params.signingKeys = eventSigningKeys(v);
        JsonNode event = chat.decryptEvent(params);
        assertTrue(event.get("verified").asBoolean(), event.toString());
        assertEquals(payload.messageId, event.get("id").asText());
        return event.get("content");
    }

    private static EncryptMessageParams quickReplyMessage(JsonNode v, String text, QuickReply quickReply) {
        EncryptMessageParams p = new EncryptMessageParams(v.get("event_conversation_id").asText(), text);
        p.conversationKey = b64(v, "conversation_key_b64");
        p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
        p.quickReply = quickReply;
        return p;
    }

    @Test
    void encryptMessageQuickReplyRoundTripsThroughDecrypt() throws Exception {
        JsonNode v = loadVectors();
        ObjectMapper mapper = new ObjectMapper();
        try (Chat chat = quickReplyChat(v)) {
            for (QuickReply sent : new QuickReply[] {sampleQuickReplyRequest(), sampleQuickReplyResponse()}) {
                JsonNode expected = mapper.valueToTree(sent);
                JsonNode content = decryptOwnContent(chat, v,
                        chat.encryptMessage(quickReplyMessage(v, "Continue?", sent)));
                assertEquals("Continue?", content.get("text").asText());
                assertEquals(expected, content.get("quick_reply"));

                // A received quick reply can be sent back unchanged.
                QuickReply received = mapper.treeToValue(content.get("quick_reply"), QuickReply.class);
                JsonNode resent = decryptOwnContent(chat, v,
                        chat.encryptMessage(quickReplyMessage(v, "again", received)));
                assertEquals(expected, resent.get("quick_reply"));
            }
        }
    }

    @Test
    void encryptMessageWithoutQuickReplyDecryptsWithoutOne() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            JsonNode content = decryptOwnContent(chat, v, chat.encryptMessage(quickReplyMessage(v, "plain", null)));
            JsonNode quickReply = content.get("quick_reply");
            assertTrue(quickReply == null || quickReply.isNull(), content.toString());
        }
    }

    @Test
    void encryptReplyQuickReplyRoundTripsThroughDecrypt() throws Exception {
        JsonNode v = loadVectors();
        QuickReply sent = sampleQuickReplyResponse();
        try (Chat chat = quickReplyChat(v)) {
            EncryptReplyParams p = new EncryptReplyParams(v.get("event_conversation_id").asText(), "Yes", null);
            p.conversationKey = b64(v, "conversation_key_b64");
            p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            p.replyToSequenceId = "seq-orig";
            p.replyToSenderId = Long.parseLong(v.get("event_sender_id").asText());
            p.replyToText = "Continue?";
            p.quickReply = sent;
            JsonNode content = decryptOwnContent(chat, v, chat.encryptReply(p));
            assertEquals(new ObjectMapper().valueToTree(sent), content.get("quick_reply"));
        }
    }

    @Test
    void encryptMessageInvalidQuickReplyThrows() throws Exception {
        JsonNode v = loadVectors();
        QuickReply both = new QuickReply();
        both.request = sampleQuickReplyRequest().request;
        both.response = sampleQuickReplyResponse().response;
        try (Chat chat = quickReplyChat(v)) {
            for (QuickReply invalid : new QuickReply[] {new QuickReply(), both}) {
                ChatXdkException ex = assertThrows(ChatXdkException.class,
                        () -> chat.encryptMessage(quickReplyMessage(v, "bad", invalid)));
                assertTrue(ex.getMessage().contains("Invalid quick reply"), ex.getMessage());
            }
        }
    }
}
