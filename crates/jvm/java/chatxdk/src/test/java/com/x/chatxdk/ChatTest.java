package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/** JVM binding tests (no network). */
class ChatTest {

    @BeforeAll
    static void keepFeatureFetchesOffline() {
        FeatureServer.keepOffline();
    }

    private static Chat createUnlocked() throws Exception {
        Chat chat = new Chat();
        chat.generateKeypairs();
        byte[] exported = chat.exportKeys();
        assertNotNull(exported);
        chat.importKeys(new ImportKeysParams(exported));
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

    private static JsonNode loadFixture(String name) throws Exception {
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve("tests/fixtures/" + name))) {
            dir = dir.getParent();
        }
        assertNotNull(dir, "tests/fixtures/" + name + " not found above " + System.getProperty("user.dir"));
        return new ObjectMapper().readTree(
                Files.readString(dir.resolve("tests/fixtures/" + name), StandardCharsets.UTF_8));
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
            SigningKeyEntry entry = new SigningKeyEntry(
                    userId,
                    v.get("event_signing_key_version").asText(),
                    v.get("signing_public_b64").asText(),
                    v.get("identity_public_b64").asText(),
                    v.get("identity_public_key_signature_b64").asText());
            entries.add(entry);
        }
        return entries;
    }

    /** The key map of the fixture conversation key, which opens the conversation-key media message and the reply vectors. */
    private static Map<String, byte[]> conversationKeys(JsonNode v) {
        return Map.of(v.get("event_conversation_key_version").asText(), b64(v, "conversation_key_b64"));
    }

    /** The one {@code action_signatures} entry of a prepared delete or read receipt. */
    private static ActionSignature onlyAction(PreparedAction prepared) {
        assertEquals(1, prepared.actionSignatures.size());
        return prepared.actionSignatures.get(0);
    }

    /**
     * Whether {@code sig}'s signature verifies, under the signer's own signing key, over
     * {@code payload}: the comma-joined fields its event signs.
     */
    private static boolean signs(Chat chat, ActionSignature sig, String payload) {
        return chat.verify(
                sig.messageEventSignature.signingPublicKey,
                Base64.getDecoder().decode(sig.messageEventSignature.signature),
                payload.getBytes(StandardCharsets.UTF_8));
    }

    /** File-encryption params under the fixture conversation key. */
    private static EncryptFileParams encryptFileParams(JsonNode v, byte[] file, String eventB64, String mediaHashKey) {
        EncryptFileParams params = new EncryptFileParams(file, eventB64, mediaHashKey);
        params.conversationKey = b64(v, "conversation_key_b64");
        params.conversationKeyVersion = v.get("event_conversation_key_version").asText();
        return params;
    }

    /** File-encryptor params under the fixture conversation key. */
    private static FileEncryptorParams fileEncryptorParams(JsonNode v, String eventB64, String mediaHashKey) {
        FileEncryptorParams params = new FileEncryptorParams(eventB64, mediaHashKey);
        params.conversationKey = b64(v, "conversation_key_b64");
        params.conversationKeyVersion = v.get("event_conversation_key_version").asText();
        return params;
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
        PublicKeyInput input = new PublicKeyInput("910002", chat.getPublicKeys().identity, "1");
        ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(input));
        params.senderId = "910002";
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
    void errorsCarryTheirKind() {
        try (Chat chat = new Chat()) {
            ChatXdkException config =
                    assertThrows(ChatXdkException.class, () -> chat.updateConfig("not json"));
            assertEquals(ChatXdkException.Kind.INVALID_INPUT, config.getKind());
            assertNull(config.getGuessesRemaining());
            assertEquals(ChatXdkException.Kind.INVALID_INPUT, assertThrows(ChatXdkException.class,
                    () -> chat.setup("123".getBytes(StandardCharsets.UTF_8))).getKind());
            assertEquals(ChatXdkException.Kind.PARSE, assertThrows(ChatXdkException.class,
                    () -> chat.decryptEvent(new DecryptEventParams("not base64!"))).getKind());
            assertEquals(ChatXdkException.Kind.INVALID_STATE, assertThrows(ChatXdkException.class,
                    () -> chat.sign(new byte[] {1})).getKind());
        }
        assertThrows(NullPointerException.class, () -> new Chat((String) null));
    }

    @Test
    void juiceboxCallsWithoutAConfigFailWithTheCoresInvalidStateError() throws Exception {
        try (Chat chat = new Chat()) {
            chat.generateKeypairs();
            String want = "Invalid state: no Juicebox config: pass the juicebox_config the X API "
                    + "returns when you create the chat, or call update_config() first";
            byte[] pin = "2580".getBytes(StandardCharsets.UTF_8);
            byte[] newPin = "1359".getBytes(StandardCharsets.UTF_8);
            Throwable async = assertThrows(java.util.concurrent.CompletionException.class,
                    () -> chat.unlockAsync(pin).join()).getCause();
            for (Throwable e : new Throwable[] {
                assertThrows(ChatXdkException.class, () -> chat.setup(pin)),
                assertThrows(ChatXdkException.class, () -> chat.unlock(pin)),
                assertThrows(ChatXdkException.class, () -> chat.changePin(pin, newPin)),
                assertThrows(ChatXdkException.class, chat::delete),
                async,
            }) {
                ChatXdkException error = assertInstanceOf(ChatXdkException.class, e);
                assertEquals(ChatXdkException.Kind.INVALID_STATE, error.getKind());
                assertEquals(want, error.getMessage());
            }
            assertTrue(chat.isUnlocked());
        }
    }

    @Test
    void errorsReadTheInvalidPinCount() {
        ChatXdkException wrongPin = ChatXdkException.fromDocument(
                "{\"kind\":\"invalid_pin\",\"message\":\"Juicebox error: Invalid PIN: guesses_remaining=3\","
                        + "\"guesses_remaining\":3}");
        assertEquals(ChatXdkException.Kind.INVALID_PIN, wrongPin.getKind());
        assertEquals(3, wrongPin.getGuessesRemaining());
        assertEquals("Juicebox error: Invalid PIN: guesses_remaining=3", wrongPin.getMessage());
        assertNull(ChatXdkException.fromDocument(
                "{\"kind\":\"invalid_pin\",\"message\":\"Juicebox error: Invalid PIN\"}").getGuessesRemaining());
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
    void decryptReadsTheTitleATitleChangeSends() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] key = newConvKey(chat);
            assertEquals("hello jvm", chat.decrypt(encryptedTitle(chat, "hello jvm", key), key));
        }
    }

    /** The encrypted title a title change under {@code key} sends. */
    private static String encryptedTitle(Chat chat, String title, byte[] key) throws Exception {
        GroupTitleChangeParams params = new GroupTitleChangeParams("g100", title);
        params.senderId = "910002";
        params.signingKeyVersion = "1";
        params.conversationKey = key;
        params.conversationKeyVersion = "4";
        return chat.prepareGroupTitleChange(params).encryptedValue;
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
            chat.importKeys(new ImportKeysParams(exported));
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
            p.signingKeyVersion = "66";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedMessageEventSignature.isEmpty());
            assertEquals("1", payload.conversationKeyVersion);
            assertEquals("7", payload.signatureInfo.signatureVersion);
            assertTrue(payload.shouldNotify);
            assertFalse(payload.xdkVersion.isEmpty());
            // The SDK generates and returns the message id.
            assertFalse(payload.messageId.isEmpty());
        }
    }

    @Test
    void descriptorsAndKeyEntriesTakeTheirRequiredValuesInConstructors() throws Exception {
        assertEquals(0, Types.AttachmentDescriptor.class.getConstructors().length);
        for (java.lang.reflect.Field field : Types.AttachmentDescriptor.class.getFields()) {
            assertTrue(java.lang.reflect.Modifier.isFinal(field.getModifiers()), field.getName());
        }
        Map<Class<?>, List<String>> required = Map.of(
                EntityDescriptor.class, List.of("start", "end", "entityType"),
                Types.UrlAttachmentImageDescriptor.class, List.of("mediaHashKey", "filesizeBytes", "filename"),
                SigningKeyEntry.class,
                List.of("userId", "publicKeyVersion", "publicKey", "identityPublicKey", "identityPublicKeySignature"),
                PublicKeyInput.class, List.of("userId", "identityPublicKey", "publicKeyVersion"));
        for (Map.Entry<Class<?>, List<String>> type : required.entrySet()) {
            String name = type.getKey().getSimpleName();
            java.lang.reflect.Constructor<?>[] constructors = type.getKey().getConstructors();
            assertEquals(1, constructors.length, name);
            assertEquals(type.getValue().size(), constructors[0].getParameterCount(), name);
            for (String field : type.getValue()) {
                assertTrue(java.lang.reflect.Modifier.isFinal(type.getKey().getField(field).getModifiers()),
                        name + "." + field);
            }
        }
        assertThrows(NullPointerException.class, () -> new SigningKeyEntry(null, "1", "k", "i", "s"));
        assertThrows(NullPointerException.class, () -> new PublicKeyInput("1", null, "1"));
        assertThrows(NullPointerException.class, () -> new Types.UrlAttachmentImageDescriptor("b", 1, null));
        assertThrows(NullPointerException.class, () -> new EntityDescriptor(0, 1, null));
        assertThrows(NullPointerException.class, () -> Types.AttachmentDescriptor.urlCard(null, "Example"));
    }

    @Test
    void aFileWithoutANameOrASizeFailsWithInvalidInput() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("1001", "66"));
            byte[] ckey = newConvKey(chat);
            String noName = "has an empty filename: pass the file's original name";
            String noSize = "has filesize_bytes 0: pass the encrypted file's size, which encrypted_file_size gives";
            for (Map.Entry<Types.AttachmentDescriptor, String> c : List.of(
                    Map.entry(Types.AttachmentDescriptor.media("photo", 100, 100, 1000, "", 1, null),
                            "media_hash_key 'photo' " + noName),
                    Map.entry(Types.AttachmentDescriptor.media("photo", 100, 100, 0, "photo.jpg", 1, null),
                            "media_hash_key 'photo' " + noSize),
                    Map.entry(Types.AttachmentDescriptor.urlCard("https://example.com", "Example",
                                    new Types.UrlAttachmentImageDescriptor("banner", 1000, ""), null),
                            "media_hash_key 'banner' " + noName),
                    Map.entry(Types.AttachmentDescriptor.urlCard("https://example.com", "Example",
                                    null, new Types.UrlAttachmentImageDescriptor("favicon", 0, "favicon.png")),
                            "media_hash_key 'favicon' " + noSize))) {
                EncryptMessageParams p = new EncryptMessageParams("conv-1", "a file");
                p.conversationKey = ckey;
                p.conversationKeyVersion = "1";
                p.attachments = List.of(c.getKey());
                ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.encryptMessage(p));
                assertEquals(ChatXdkException.Kind.INVALID_INPUT, e.getKind());
                assertEquals(c.getValue(), e.getMessage());
            }
        }
    }

    @Test
    void invalidOffsetsLinksPostsAndDimensionsFailWithInvalidInput() throws Exception {
        record Case(List<EntityDescriptor> entities, List<Types.AttachmentDescriptor> attachments, String message) {}
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("1001", "66"));
            byte[] ckey = newConvKey(chat);
            Types.UrlAttachmentImageDescriptor banner = new Types.UrlAttachmentImageDescriptor("banner", 1000, "b.png");
            banner.height = -1L;
            List<Case> cases = List.of(
                    new Case(List.of(new EntityDescriptor(-1, 4, "mention")), null,
                            "Invalid entity offsets -1..4: offsets count bytes of the UTF-8 text, from 0"),
                    new Case(List.of(new EntityDescriptor(5, 3, "mention")), null,
                            "Invalid entity offsets 5..3: end is before start"),
                    new Case(List.of(new EntityDescriptor(3, 8, "mention")), null,
                            "Invalid entity offsets 3..8: end is past the end of the text, which is 7 bytes of UTF-8"),
                    new Case(null, List.of(Types.AttachmentDescriptor.urlCard("", null)),
                            "a URL card's url is empty: pass the link the card shows"),
                    new Case(null, List.of(Types.AttachmentDescriptor.post(null, null)),
                            "a post attachment has neither rest_id nor post_url: pass the post's id or its URL"),
                    new Case(null, List.of(Types.AttachmentDescriptor.media("photo", -1, 100, 1000, "photo.jpg", 1, null)),
                            "media_hash_key 'photo' has width -1: pass the width in pixels, 0 or more"),
                    new Case(null, List.of(Types.AttachmentDescriptor.urlCard("https://example.com", null, banner, null)),
                            "media_hash_key 'banner' has height -1: pass the height in pixels, 0 or more"));
            for (Case c : cases) {
                EncryptMessageParams p = new EncryptMessageParams("conv-1", "hi @bob");
                p.conversationKey = ckey;
                p.conversationKeyVersion = "1";
                p.entities = c.entities();
                p.attachments = c.attachments();
                ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.encryptMessage(p));
                assertEquals(ChatXdkException.Kind.INVALID_INPUT, e.getKind());
                assertEquals(c.message(), e.getMessage());
            }
            // Offsets count UTF-8 bytes: "é @bob" is 7 bytes, and "@bob" is bytes 3..7.
            EncryptMessageParams utf8 = new EncryptMessageParams("conv-1", "é @bob");
            utf8.conversationKey = ckey;
            utf8.conversationKeyVersion = "1";
            utf8.entities = List.of(new EntityDescriptor(3, 7, "mention"));
            chat.encryptMessage(utf8);
        }
    }

    @Test
    void anEmptyJuiceboxConfigFailsWithTheNoConfigError() throws Exception {
        String want = "Invalid state: no Juicebox config: pass the juicebox_config the X API returns "
                + "when you create the chat, or call update_config() first";
        for (String empty : new String[] {"", "  "}) {
            ChatXdkException e = assertThrows(ChatXdkException.class, () -> new Chat(empty));
            assertEquals(ChatXdkException.Kind.INVALID_STATE, e.getKind());
            assertEquals(want, e.getMessage());
        }
        try (Chat chat = new Chat()) {
            ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.updateConfig(""));
            assertEquals(ChatXdkException.Kind.INVALID_STATE, e.getKind());
            assertEquals(want, e.getMessage());
        }
    }

    @Test
    void anUnknownOrEmptyEntityTypeFailsWithInvalidInput() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("1001", "66"));
            byte[] ckey = newConvKey(chat);
            for (String entityType : new String[] {"bogus", ""}) {
                EncryptMessageParams p = new EncryptMessageParams("conv-1", "hi @bob");
                p.conversationKey = ckey;
                p.conversationKeyVersion = "1";
                p.entities = List.of(new EntityDescriptor(3, 7, entityType));
                ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.encryptMessage(p));
                assertEquals(ChatXdkException.Kind.INVALID_INPUT, e.getKind());
                assertEquals("Invalid entity_type '" + entityType + "': pass url, mention, hashtag, cashtag, "
                        + "email, address or phone_number", e.getMessage());
            }
        }
    }

    @Test
    void encryptMessageMixedAttachmentTypesThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "mixed attachments");
            p.senderId = "1001";
            p.signingKeyVersion = "66";
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
            chat.setIdentity(new SetIdentityParams("1001", "66"));
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "Check this out");
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            Types.UrlAttachmentImageDescriptor banner =
                    new Types.UrlAttachmentImageDescriptor("banner-hash", 24_000, "banner.jpg");
            banner.width = 1200L;
            banner.height = 630L;
            Types.AttachmentDescriptor attachment = Types.AttachmentDescriptor.urlCard(
                    "https://example.com/product",
                    "Example Product",
                    banner,
                    new Types.UrlAttachmentImageDescriptor("favicon-hash", 1_200L, "favicon.ico"));

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
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
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
            p.signingKeyVersion = "66";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            p.replyToSequenceId = "seq-42";
            p.replyToSenderId = "12345";
            p.replyToText = "Original message";
            SendPayload payload = chat.encryptReply(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedMessageEventSignature.isEmpty());
            assertEquals("1", payload.conversationKeyVersion);
            assertEquals("7", payload.signatureInfo.signatureVersion);
        }
    }

    @Test
    void userIdsAreDigitStrings() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            ChatXdkException e = assertThrows(ChatXdkException.class,
                    () -> chat.setIdentity(new SetIdentityParams("user-1", "1")));
            assertTrue(e.getMessage().contains("Invalid user_id 'user-1'"), e.getMessage());
            e = assertThrows(ChatXdkException.class,
                    () -> chat.setIdentity(new SetIdentityParams("1001", "v1")));
            assertTrue(e.getMessage().contains("Invalid signing_key_version 'v1'"), e.getMessage());
            EncryptReplyParams p = new EncryptReplyParams("conv-1", "reply", null);
            p.senderId = "1001";
            p.signingKeyVersion = "1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            p.replyToSequenceId = "seq-42";
            p.replyToSenderId = "12x";
            e = assertThrows(ChatXdkException.class, () -> chat.encryptReply(p));
            assertTrue(e.getMessage().contains("Invalid reply_to_sender_id '12x'"), e.getMessage());
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
            p.signingKeyVersion = "66";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptAddReaction(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedMessageEventSignature.isEmpty());
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
            p.signingKeyVersion = "66";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptRemoveReaction(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedMessageEventSignature.isEmpty());
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
            EntityDescriptor url = new EntityDescriptor(4, 23, "url");
            p.entities = List.of(url);
            p.conversationId = "conv-1";
            p.targetMessageSequenceId = "seq-99";
            p.senderId = "111";
            p.signingKeyVersion = "66";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "1";
            SendPayload payload = chat.encryptEdit(p);
            assertFalse(payload.messageId.isEmpty());
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedMessageEventSignature.isEmpty());
        }
    }

    @Test
    void sendPayloadTakesTheRequestFieldNames() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v)) {
            EncryptMessageParams params = new EncryptMessageParams(v.get("event_conversation_id").asText(), "hi");
            params.conversationKey = b64(v, "conversation_key_b64");
            params.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            SendPayload payload = chat.encryptMessage(params);

            JsonNode json = ChatJson.MAPPER.valueToTree(payload);
            assertEquals(payload.encodedMessageCreateEvent, json.get("encoded_message_create_event").asText());
            assertEquals(payload.encodedMessageEventSignature, json.get("encoded_message_event_signature").asText());
            SendPayload roundTrip = ChatJson.MAPPER.treeToValue(json, SendPayload.class);
            assertEquals(payload.encodedMessageCreateEvent, roundTrip.encodedMessageCreateEvent);
            assertEquals(payload.encodedMessageEventSignature, roundTrip.encodedMessageEventSignature);
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
            PreparedAction prepared = chat.prepareMessageDelete(p);
            ActionSignature sig = onlyAction(prepared);
            assertFalse(sig.messageId.isEmpty());
            assertFalse(sig.encodedMessageEventDetail.isEmpty());
            // The signature is nested as the request's action_signatures carry it.
            MessageEventSignature signed = sig.messageEventSignature;
            assertFalse(signed.signature.isEmpty());
            assertEquals("7", signed.signatureVersion);
            assertEquals("1", signed.publicKeyVersion);
            assertEquals(chat.getPublicKeys().signing, signed.signingPublicKey);
            JsonNode entry = ChatJson.MAPPER.<JsonNode>valueToTree(prepared).get("action_signatures").get(0);
            assertFalse(entry.has("signature"), entry.toString());
            assertEquals(signed.signingPublicKey,
                    entry.get("message_event_signature").get("signing_public_key").asText());
            assertTrue(signs(chat, sig, "MessageDeleteEvent," + sig.messageId + ",111,111:222,2,seq-10,seq-11"));
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
            ActionSignature sig = onlyAction(chat.prepareMessageDelete(p));
            assertTrue(signs(chat, sig, "MessageDeleteEvent," + sig.messageId + ",111,g999,1,seq-1"));
        }
    }

    @Test
    void groupActionsSignVerifierPayloads() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeyInput key = new PublicKeyInput("111", chat.getPublicKeys().identity, "1");
            GroupMembersRemoveParams removal =
                    new GroupMembersRemoveParams(List.of(key), "g100", List.of("910007"));
            removal.senderId = "111";
            removal.signingKeyVersion = "1";
            PreparedConversationChange rotated = chat.prepareGroupMembersRemove(removal);
            assertEquals(32, rotated.conversationKey.length);
            assertEquals(1, rotated.conversationParticipantKeys.size());
            assertEquals(2, rotated.actionSignatures.size());
            assertEquals("11", rotated.actionSignatures.get(0).messageEventSignature.signatureVersion);
            ActionSignature removed = rotated.actionSignatures.get(0);
            assertTrue(signs(chat, removed, "GroupChangeEvent.GroupMemberRemoveChange," + removed.messageId
                    + ",111,g100,910007," + rotated.conversationKeyVersion + ",signature_version=11"));

            GroupMembersRemoveParams noKeys =
                    new GroupMembersRemoveParams(List.of(), "g100", List.of("910007"));
            noKeys.senderId = "111";
            noKeys.signingKeyVersion = "1";
            ChatXdkException noKeysError =
                    assertThrows(ChatXdkException.class, () -> chat.prepareGroupMembersRemove(noKeys));
            assertEquals(
                    "public_keys is empty: pass the public keys of the remaining members",
                    noKeysError.getMessage());

            GroupLeaveParams leave = new GroupLeaveParams("g100");
            leave.senderId = "111";
            leave.signingKeyVersion = "1";
            leave.promoteAdminId = "910008";
            leave.conversationKeyVersion = "7";
            PreparedAction left = chat.prepareGroupLeave(leave);
            assertEquals(3, left.actionSignatures.size());
            ActionSignature leaving = left.actionSignatures.get(0);
            ActionSignature promoting = left.actionSignatures.get(1);
            ActionSignature deleting = left.actionSignatures.get(2);
            assertTrue(signs(chat, leaving, "GroupChangeEvent.GroupMemberRemoveChange," + leaving.messageId
                    + ",111,g100,111,7,signature_version=11"));
            assertTrue(signs(chat, promoting,
                    "GroupChangeEvent.GroupAdminAddChange," + promoting.messageId + ",111,g100,910008"));
            assertTrue(signs(chat, deleting, "ConversationDeleteEvent," + deleting.messageId + ",111,g100"));

            GroupTitleChangeParams titleParams = new GroupTitleChangeParams("g100", "Board: layoffs, Q3");
            titleParams.senderId = "111";
            titleParams.signingKeyVersion = "1";
            titleParams.conversationKey = rotated.conversationKey;
            titleParams.conversationKeyVersion = rotated.conversationKeyVersion;
            PreparedGroupMetadataChange title = chat.prepareGroupTitleChange(titleParams);
            assertEquals(rotated.conversationKeyVersion, title.conversationKeyVersion);
            assertEquals(1, title.actionSignatures.size());
            ActionSignature titleSig = title.actionSignatures.get(0);
            assertTrue(signs(chat, titleSig, "GroupChangeEvent.GroupTitleChange," + titleSig.messageId
                    + ",111,g100," + title.conversationKeyVersion + "," + title.encryptedValue));
            assertEquals("Board: layoffs, Q3", chat.decrypt(title.encryptedValue, rotated.conversationKey));

            String avatarUrl = "https://ton.x.com/xchat_media/g100/avatar";
            GroupAvatarChangeParams avatarParams =
                    new GroupAvatarChangeParams("g100", avatarUrl, rotated.conversationKeyVersion);
            avatarParams.senderId = "111";
            avatarParams.signingKeyVersion = "1";
            PreparedAction avatar = chat.prepareGroupAvatarChange(avatarParams);
            assertEquals(1, avatar.actionSignatures.size());
            ActionSignature avatarSig = avatar.actionSignatures.get(0);
            assertTrue(signs(chat, avatarSig, "GroupChangeEvent.GroupAvatarUrlChange," + avatarSig.messageId
                    + ",111,g100," + rotated.conversationKeyVersion + "," + avatarUrl));

            GroupDescriptionChangeParams descriptionParams =
                    new GroupDescriptionChangeParams("g100", "Rules: be kind");
            descriptionParams.senderId = "111";
            descriptionParams.signingKeyVersion = "1";
            descriptionParams.conversationKey = rotated.conversationKey;
            descriptionParams.conversationKeyVersion = rotated.conversationKeyVersion;
            PreparedGroupMetadataChange description = chat.prepareGroupDescriptionChange(descriptionParams);
            ActionSignature descriptionSig = description.actionSignatures.get(0);
            assertTrue(signs(chat, descriptionSig, "GroupChangeEvent.GroupDescriptionChange,"
                    + descriptionSig.messageId + ",111,g100," + description.conversationKeyVersion + ","
                    + description.encryptedValue));
            assertEquals("Rules: be kind", chat.decrypt(description.encryptedValue, rotated.conversationKey));

            GroupTitleChangeParams uncached = new GroupTitleChangeParams("g100", "Board");
            uncached.senderId = "111";
            uncached.signingKeyVersion = "1";
            ChatXdkException uncachedError =
                    assertThrows(ChatXdkException.class, () -> chat.prepareGroupTitleChange(uncached));
            assertTrue(uncachedError.getMessage().contains("no cached conversation key for 'g100'"),
                    uncachedError.getMessage());

            GroupMembersRemoveParams withTitle =
                    new GroupMembersRemoveParams(List.of(key), "g100", List.of("910007"));
            withTitle.senderId = "111";
            withTitle.signingKeyVersion = "1";
            withTitle.title = "Board";
            PreparedConversationChange removedWithTitle = chat.prepareGroupMembersRemove(withTitle);
            assertEquals(3, removedWithTitle.actionSignatures.size());
            ActionSignature rotatedTitle = removedWithTitle.actionSignatures.get(1);
            assertEquals("7", rotatedTitle.messageEventSignature.signatureVersion);
            assertFalse(rotatedTitle.encodedMessageEventDetail.isEmpty());

            ScreenCaptureParams capture = new ScreenCaptureParams("g100", ScreenCaptureChange.BlockingEnabled);
            capture.senderId = "111";
            capture.signingKeyVersion = "1";
            ActionSignature blocking = onlyAction(chat.prepareScreenCapture(capture));
            assertTrue(signs(chat, blocking,
                    "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking," + blocking.messageId + ",111,g100"));
        }
    }

    /** One signed action and the fields it signs after the sender. */
    private record SignedAction(ActionSignature action, String fields) {}

    /** One signed action: the event its payload names and the prepare call. */
    private record GroupActionCase(String event, Callable<SignedAction> prepare) {}

    // The group and conversation-metadata actions each sign one action at signature version 7 over
    // the event name, the action's message id, the sender, the conversation and the signed fields,
    // and the signature verifies with the signer's signing key.
    @Test
    void groupActionsSignEachAction() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("111", "1"));
            String signingKey = chat.getPublicKeys().signing;
            GroupDescriptionChangeParams description = new GroupDescriptionChangeParams("g100", "Ships the app");
            description.conversationKey = new byte[32];
            description.conversationKeyVersion = "4";
            Map<String, GroupActionCase> cases = new LinkedHashMap<>();
            cases.put("avatar", new GroupActionCase("GroupChangeEvent.GroupAvatarUrlChange",
                    () -> new SignedAction(onlyAction(chat.prepareGroupAvatarChange(
                            new GroupAvatarChangeParams("g100", "https://img/a.png", "4"))), ",g100,4,https://img/a.png")));
            cases.put("description", new GroupActionCase("GroupChangeEvent.GroupDescriptionChange", () -> {
                PreparedGroupMetadataChange changed = chat.prepareGroupDescriptionChange(description);
                assertEquals(1, changed.actionSignatures.size());
                return new SignedAction(changed.actionSignatures.get(0), ",g100,4," + changed.encryptedValue);
            }));
            cases.put("admins add", new GroupActionCase("GroupChangeEvent.GroupAdminAddChange",
                    () -> new SignedAction(onlyAction(chat.prepareGroupAdminsAdd(
                            new GroupAdminsAddParams("g100", List.of("910008", "910009")))), ",g100,910008,910009")));
            cases.put("admins remove", new GroupActionCase("GroupChangeEvent.GroupAdminRemoveChange",
                    () -> new SignedAction(onlyAction(chat.prepareGroupAdminsRemove(
                            new GroupAdminsRemoveParams("g100", List.of("910008")))), ",g100,910008")));
            cases.put("invite enable", new GroupActionCase("GroupChangeEvent.GroupInviteEnable",
                    () -> new SignedAction(onlyAction(chat.prepareGroupInviteEnable(
                            new GroupInviteEnableParams("g100", "https://x.com/i/invite/abc"))),
                            ",g100,https://x.com/i/invite/abc,null,null")));
            cases.put("invite disable", new GroupActionCase("GroupChangeEvent.GroupInviteDisable",
                    () -> new SignedAction(onlyAction(chat.prepareGroupInviteDisable(
                            new GroupInviteDisableParams("g100"))), ",g100,111")));
            cases.put("join request", new GroupActionCase("GroupChangeEvent.GroupJoinRequest",
                    () -> new SignedAction(onlyAction(chat.prepareGroupJoinRequest(
                            new GroupJoinRequestParams("g100"))), ",g100,111")));
            cases.put("join reject", new GroupActionCase("GroupChangeEvent.GroupJoinReject",
                    () -> new SignedAction(onlyAction(chat.prepareGroupJoinReject(
                            new GroupJoinRejectParams("g100", List.of("910010")))), ",g100,910010")));
            cases.put("ttl change", new GroupActionCase("ConversationMetadataChangeEvent.MessageDurationChange",
                    () -> new SignedAction(onlyAction(chat.prepareMessageTtlChange(
                            new MessageTtlChangeParams("g100", 86400000L))), ",g100,86400000")));
            cases.put("ttl remove", new GroupActionCase("ConversationMetadataChangeEvent.MessageDurationRemove",
                    () -> new SignedAction(onlyAction(chat.prepareMessageTtlRemove(
                            new MessageTtlRemoveParams("g100"))), ",g100")));
            for (Map.Entry<String, GroupActionCase> entry : cases.entrySet()) {
                String name = entry.getKey();
                GroupActionCase c = entry.getValue();
                SignedAction signed = c.prepare().call();
                MessageEventSignature sig = signed.action().messageEventSignature;
                assertEquals("7", sig.signatureVersion, name);
                assertEquals(signingKey, sig.signingPublicKey, name);
                String payload = c.event() + "," + signed.action().messageId + ",111" + signed.fields();
                assertTrue(signs(chat, signed.action(), payload), name + ": " + payload);
            }
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
            ActionSignature sig = onlyAction(chat.prepareMarkConversationRead(p));
            assertFalse(sig.messageId.isEmpty());
            assertFalse(sig.encodedMessageEventDetail.isEmpty());
            assertEquals("1", sig.messageEventSignature.publicKeyVersion);
            assertEquals(chat.getPublicKeys().signing, sig.messageEventSignature.signingPublicKey);
            assertTrue(signs(chat, sig, "MarkConversationReadEvent," + sig.messageId
                    + ",111,111:222,2011626338877079553,1700000000123"));
        }
    }

    @Test
    void prepareMarkConversationReadDefaultsToSessionIdentityAndNow() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("111", "7"));
            long before = System.currentTimeMillis();
            ActionSignature sig = onlyAction(chat.prepareMarkConversationRead(
                    new MarkConversationReadParams("g999", "seq-1")));
            long after = System.currentTimeMillis();

            assertEquals("7", sig.messageEventSignature.publicKeyVersion);
            String prefix = "MarkConversationReadEvent," + sig.messageId + ",111,g999,seq-1,";
            boolean signedNow = false;
            for (long seenAt = before; seenAt <= after && !signedNow; seenAt++) {
                signedNow = signs(chat, sig, prefix + seenAt);
            }
            assertTrue(signedNow, "seen_at in [" + before + ", " + after + "]");
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

            chat.setIdentity(new SetIdentityParams("1234", "1700000000123"));
            assertEquals("1700000000123",
                    onlyAction(chat.prepareMessageDelete(p)).messageEventSignature.publicKeyVersion);

            // Restored keys carry the version passed to importKeys, and none
            // without it.
            byte[] keys = chat.exportKeys();
            assertNotNull(keys);
            restored.importKeys(new ImportKeysParams(keys, "1700000000456"));
            assertEquals("1700000000456",
                    onlyAction(restored.prepareMessageDelete(p)).messageEventSignature.publicKeyVersion);
            restored.importKeys(new ImportKeysParams(keys));
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
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(input));
            params.senderId = "910002";
            params.signingKeyVersion = "1";
            params.conversationId = "conv-1";
            PreparedConversationChange prepared = chat.prepareConversationKeyChange(params);
            assertNotNull(prepared);
            assertEquals("conv-1", prepared.conversationId);
            byte[] convKey = prepared.conversationKey;
            assertNotNull(convKey);
            assertEquals(32, convKey.length);
            assertEquals(1, prepared.conversationParticipantKeys.size());
            assertFalse(prepared.conversationParticipantKeys.get(0).encryptedConversationKey.isEmpty());
            assertEquals(1, prepared.actionSignatures.size());
            // The participant keys serialize under the request's field names.
            JsonNode entry = ChatJson.MAPPER.valueToTree(prepared).get("conversation_participant_keys").get(0);
            assertEquals(
                    prepared.conversationParticipantKeys.get(0).encryptedConversationKey,
                    entry.get("encrypted_conversation_key").asText());
        }
    }

    // The conversation key is secret: a prepared change carries it, but its JSON,
    // the shape a request body is built from, never does.
    @Test
    void preparedChangeJsonLeavesOutTheConversationKey() throws Exception {
        try (Chat chat = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("910002", "1"));
            List<PublicKeyInput> publicKeys =
                    List.of(new PublicKeyInput("910002", chat.getPublicKeys().identity, "1"));

            ConversationKeyChangeParams keyChange = new ConversationKeyChangeParams(publicKeys);
            keyChange.conversationId = "910002:910005";
            GroupMembersRemoveParams removal = new GroupMembersRemoveParams(publicKeys, "g123", List.of("910005"));
            List<PreparedConversationChange> prepared = List.of(
                    chat.prepareConversationKeyChange(keyChange),
                    chat.prepareGroupCreate(new GroupCreateParams(
                            publicKeys, "g123", List.of("910002", "910005"), List.of("910002"))),
                    chat.prepareGroupMembersRemove(removal));

            for (PreparedConversationChange change : prepared) {
                assertEquals(32, change.conversationKey.length);
                for (ObjectMapper mapper : List.of(ChatJson.MAPPER, new ObjectMapper())) {
                    JsonNode json = mapper.readTree(mapper.writeValueAsString(change));
                    assertFalse(json.has("conversation_key"), "JSON carries the key: " + json);
                    List<String> fields = new ArrayList<>();
                    json.fieldNames().forEachRemaining(fields::add);
                    assertEquals(
                            List.of("conversation_id", "conversation_key_version",
                                    "conversation_participant_keys", "action_signatures"),
                            fields);
                }
            }
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
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            GroupMembersChangeParams p = new GroupMembersChangeParams(
                    List.of(input), "g123", List.of("910006"), List.of("910002"), List.of("910002"), List.of());
            p.senderId = "910002";
            p.signingKeyVersion = "1";
            p.currentTitle = "Test Group";
            PreparedConversationChange prepared = chat.prepareGroupMembersChange(p);
            assertEquals("g123", prepared.conversationId);
            // A member add emits two signed actions: the key change and the add.
            assertEquals(2, prepared.actionSignatures.size());
            assertFalse(prepared.actionSignatures.get(0).encodedMessageEventDetail.isEmpty());
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
            // The title goes out encrypted under the new key, the value the request
            // sends as encrypted_title; the signature covers the ciphertext. Unset
            // screen-capture blocking signs as the trailing null sentinel.
            ActionSignature add = prepared.actionSignatures.get(1);
            assertTrue(signs(chat, add, "GroupChangeEvent.GroupMemberAddChange," + add.messageId
                    + ",910002,g123,910006,910002,910002," + prepared.encryptedTitle + ",null,null,"
                    + prepared.conversationKeyVersion + ",null"));
            assertEquals("Test Group", chat.decrypt(prepared.encryptedTitle, prepared.conversationKey));
            assertNull(prepared.encryptedDescription);
            assertEquals("7", prepared.actionSignatures.get(1).messageEventSignature.signatureVersion);
        }
    }

    @Test
    void prepareGroupMembersChangeEncryptsTheDescription() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            String avatarUrl = "https://ton.x.com/xchat_media/g123/avatar";
            GroupMembersChangeParams p = new GroupMembersChangeParams(
                    List.of(input), "g123", List.of("910006"), List.of("910002"), List.of("910002"), List.of());
            p.senderId = "910002";
            p.signingKeyVersion = "1";
            p.currentTitle = "Test Group";
            p.currentDescription = "Ships the app";
            p.currentAvatarUrl = avatarUrl;
            PreparedConversationChange prepared = chat.prepareGroupMembersChange(p);
            assertEquals("Ships the app", chat.decrypt(prepared.encryptedDescription, prepared.conversationKey));
            // The description is signed at version 8, after the screen-capture slot;
            // the avatar URL is signed as passed.
            ActionSignature add = prepared.actionSignatures.get(1);
            assertEquals("8", add.messageEventSignature.signatureVersion);
            assertTrue(signs(chat, add, "GroupChangeEvent.GroupMemberAddChange," + add.messageId
                    + ",910002,g123,910006,910002,910002," + prepared.encryptedTitle + "," + avatarUrl
                    + ",null," + prepared.conversationKeyVersion + ",null," + prepared.encryptedDescription));
        }
    }

    @Test
    void prepareGroupMembersChangeSignsScreenCaptureBlocking() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            GroupMembersChangeParams p = new GroupMembersChangeParams(
                    List.of(input), "g123", List.of("910006"), List.of("910002"), List.of("910002"), List.of());
            p.senderId = "910002";
            p.signingKeyVersion = "1";
            p.currentScreenCaptureBlockingEnabled = true;
            PreparedConversationChange prepared = chat.prepareGroupMembersChange(p);
            // The group's screen-capture-blocking state fills the trailing signed slot.
            ActionSignature add = prepared.actionSignatures.get(1);
            assertTrue(signs(chat, add, "GroupChangeEvent.GroupMemberAddChange," + add.messageId
                    + ",910002,g123,910006,910002,910002,null,null,null," + prepared.conversationKeyVersion
                    + ",true"));
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
        }
    }

    @Test
    void prepareGroupCreateReturnsSignedChange() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            GroupCreateParams p = new GroupCreateParams(
                    List.of(input), "g123", List.of("910002", "910005"), List.of("910002"));
            p.senderId = "910002";
            p.signingKeyVersion = "1";
            p.title = "Test Group";
            PreparedConversationChange prepared = chat.prepareGroupCreate(p);
            assertEquals("g123", prepared.conversationId);
            // A group create emits two signed actions: the key change and the create.
            assertEquals(2, prepared.actionSignatures.size());
            assertFalse(prepared.actionSignatures.get(0).encodedMessageEventDetail.isEmpty());
            assertFalse(prepared.actionSignatures.get(1).encodedMessageEventDetail.isEmpty());
            // The title goes out encrypted under the new key, the value the request
            // sends as group_name; the signature covers the ciphertext.
            ActionSignature create = prepared.actionSignatures.get(1);
            assertTrue(signs(chat, create, "GroupChangeEvent.GroupCreate," + create.messageId + ",910002,"
                    + prepared.conversationKeyVersion + ",910002,910005,null," + prepared.encryptedTitle + ",null"));
            assertEquals("Test Group", chat.decrypt(prepared.encryptedTitle, prepared.conversationKey));
            assertNull(prepared.encryptedDescription);
        }
    }

    @Test
    void prepareConversationKeyChangeDerivesOneToOneId() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput a = new PublicKeyInput("1491585161162473473", keys.identity, "1");
            PublicKeyInput b = new PublicKeyInput("17380288", keys.identity, "1");
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
            PublicKeyInput a = new PublicKeyInput("17380288", keys.identity, "1");
            PublicKeyInput b = new PublicKeyInput("1491585161162473473", keys.identity, "1");
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(List.of(a, b));
            params.senderId = "17380288";
            params.signingKeyVersion = "1";
            PreparedConversationChange prepared = chat.prepareConversationKeyChange(params);
            assertEquals("17380288:1491585161162473473", prepared.conversationId);
            assertEquals(2, prepared.conversationParticipantKeys.size());
            for (ConversationParticipantKey pk : prepared.conversationParticipantKeys) {
                assertArrayEquals(
                        prepared.conversationKey,
                        chat.decryptConversationKey(pk.encryptedConversationKey));
            }
        }
    }

    @Test
    void decryptReadsAUnicodeTitle() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] key = newConvKey(chat);
            String plaintext = "metadata payload 🌟 with unicode";
            String ct = encryptedTitle(chat, plaintext, key);
            assertFalse(ct.isEmpty());
            assertNotEquals(plaintext, ct);
            assertNotEquals(ct, encryptedTitle(chat, plaintext, key));
            assertEquals(plaintext, chat.decrypt(ct, key));
        }
    }

    @Test
    void decryptEventsEmptyListReturnsNonNullResult() throws Exception {
        try (Chat chat = createUnlocked()) {
            DecryptEventsResult result = chat.decryptEvents(new DecryptEventsParams(List.of()));
            assertNotNull(result);
            assertTrue(result.events.isEmpty());
            assertTrue(result.errors.isEmpty());
        }
    }

    // Deterministic cross-binding fixture pins (tests/fixtures/sdk_vectors.json)

    @Test
    void vectorsPublicKeysAndSignatureMatchFixture() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64")));
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

    // sign refuses data only the SDK signs: an event signature payload and a public key.
    // Data that only resembles a payload is application data.
    @Test
    void signRefusesDataOnlyTheSdkSigns() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64")));
            String keyChange = "ConversationKeyChangeEvent,mk1,1001,1001:1002,1800000000000,a2V5";
            for (byte[] data : List.of(keyChange.getBytes(StandardCharsets.UTF_8), b64(v, "identity_public_b64"))) {
                ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.sign(data));
                assertTrue(e.getMessage().contains("only the SDK signs"), e.getMessage());
            }
            assertEquals(64, chat.sign((" " + keyChange).getBytes(StandardCharsets.UTF_8)).length);
        }
    }

    @Test
    void vectorsDecryptEventsBatchAndSingleEventContracts() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
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
            for (DecryptedEvent dm : result.events) {
                if ("KeyChange".equals(dm.event.path("type").asText())) keyChanges.add(dm.event);
                if ("Message".equals(dm.event.path("type").asText())) messages.add(dm.event);
            }
            assertEquals(1, keyChanges.size());
            assertTrue(keyChanges.get(0).path("verified").asBoolean());
            assertEquals(ckVersion, keyChanges.get(0).path("conversation_key_version").asText());
            // The received participant keys read into the type a prepared change carries.
            JsonNode received = keyChanges.get(0).path("conversation_participant_keys");
            assertTrue(received.isArray() && received.size() > 0, received.toString());
            for (JsonNode node : received) {
                ConversationParticipantKey key = ChatJson.MAPPER.treeToValue(node, ConversationParticipantKey.class);
                assertFalse(key.userId.isEmpty() || key.encryptedConversationKey.isEmpty()
                        || key.publicKeyVersion.isEmpty(), node.toString());
            }

            assertEquals(1, messages.size());
            assertEquals(v.get("event_message_text").asText(),
                    messages.get(0).path("content").path("text").asText());
            assertTrue(messages.get(0).path("verified").asBoolean());
            assertEquals(ckVersion, messages.get(0).path("conversation_key_version").asText());

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
    // Reactions and edits name their target by its sequence id; a v0 edit
    // carries no target message id.
    @Test
    void vectorsReactionsAndEditsNameTheirTargetBySequenceId() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64")));
            chat.setIdentity(new SetIdentityParams(
                    v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText()));
            byte[] key = b64(v, "conversation_key_b64");
            String version = v.get("event_conversation_key_version").asText();
            String target = v.get("event_message_b64").asText();

            EncryptReactionParams reaction = new EncryptReactionParams(target, "👍");
            reaction.conversationKey = key;
            reaction.conversationKeyVersion = version;
            JsonNode added = decryptedContent(chat, v, chat.encryptAddReaction(reaction).eventB64);
            assertEquals("Reaction", added.path("content_type").asText());
            assertEquals("1", added.path("target_message_sequence_id").asText());
            JsonNode removed = decryptedContent(chat, v, chat.encryptRemoveReaction(reaction).eventB64);
            assertEquals("ReactionRemoved", removed.path("content_type").asText());
            assertEquals("1", removed.path("target_message_sequence_id").asText());

            EncryptEditParams edit = new EncryptEditParams(target, "fixed");
            edit.conversationKey = key;
            edit.conversationKeyVersion = version;
            JsonNode edited = decryptedContent(chat, v, chat.encryptEdit(edit).eventB64);
            assertEquals("Edit", edited.path("content_type").asText());
            assertEquals("1", edited.path("target_message_sequence_id").asText());
            assertEquals("fixed", edited.path("updated_text").asText());
            assertTrue(edited.path("target_message_id").isMissingNode());
        }
    }

    /** The content of a message this chat sent, decrypted and verified. */
    private static JsonNode decryptedContent(Chat chat, JsonNode v, String eventB64) throws Exception {
        DecryptEventParams params = new DecryptEventParams(eventB64, conversationKeys(v));
        params.signingKeys = eventSigningKeys(v);
        JsonNode event = chat.decryptEvent(params);
        assertTrue(event.path("verified").asBoolean());
        return event.path("content");
    }

    @Test
    void vectorsGroupDescriptionChangeDecryptsOnReceive() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            DecryptEventParams params =
                    new DecryptEventParams(v.get("event_group_description_b64").asText(), conversationKeys(v));
            params.signingKeys = eventSigningKeys(v);
            JsonNode event = chat.decryptEvent(params);
            assertEquals("GroupChange", event.path("type").asText());
            assertTrue(event.path("verified").asBoolean());
            assertEquals(v.get("event_group_id").asText(), event.path("conversation_id").asText());
            assertEquals("DescriptionChanged", event.path("change").path("change_type").asText());
            ObjectMapper mapper = new ObjectMapper();
            GroupText description =
                    mapper.treeToValue(event.path("change").path("new_description"), GroupText.class);
            assertEquals("Text", description.kind);
            assertEquals(v.get("event_group_description").asText(), description.text);

            // Without the key the description was encrypted under, the change
            // still decrypts, with the description unavailable.
            DecryptEventParams keyless =
                    new DecryptEventParams(v.get("event_group_description_b64").asText(), Map.of());
            keyless.signingKeys = eventSigningKeys(v);
            GroupText unavailable = mapper.treeToValue(
                    chat.decryptEvent(keyless).path("change").path("new_description"), GroupText.class);
            assertEquals("Unavailable", unavailable.kind);
            assertFalse(unavailable.raw.isEmpty());
            assertNotEquals(v.get("event_group_description").asText(), unavailable.raw);
        }
    }

    @Test
    void vectorsGroupAvatarChangeCarriesTheMediaUrl() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            // The avatar URL is not encrypted, so the change reads without any key.
            DecryptEventParams params =
                    new DecryptEventParams(v.get("event_group_avatar_change_b64").asText(), Map.of());
            params.signingKeys = eventSigningKeys(v);
            JsonNode event = chat.decryptEvent(params);
            assertTrue(event.path("verified").asBoolean());
            JsonNode change = event.path("change");
            assertEquals("AvatarChanged", change.path("change_type").asText());
            assertEquals(v.get("event_group_avatar_url").asText(), change.path("new_avatar_url").asText());
            assertEquals(
                    v.get("event_conversation_key_version").asText(),
                    change.path("conversation_key_version").asText());
        }
    }

    @Test
    void vectorsGroupRemovalDropsTheTitleAndDescriptionReencryptions() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
            List<String> flow = new ArrayList<>();
            v.get("event_group_removal_flow_b64").forEach(event -> flow.add(event.asText()));
            List<String> dropped = new ArrayList<>();
            v.get("event_group_removal_dropped_indices").forEach(index -> dropped.add(index.asText()));
            String version = v.get("event_group_removal_conversation_key_version").asText();

            // Decrypt keeps the removal, its key change and a later rename, and
            // drops the title and description the removal re-encrypts.
            DecryptEventsParams batch = new DecryptEventsParams(flow);
            batch.signingKeys = eventSigningKeys(v);
            DecryptEventsResult result = chat.decryptEvents(batch);
            List<String> errors = new ArrayList<>(result.errors.keySet());
            errors.sort(null);
            assertEquals(dropped, errors);
            assertEquals(version, result.conversationKeys.latestVersion);
            assertEquals(3, result.events.size());
            for (DecryptedEvent kept : result.events) {
                assertTrue(kept.event.path("verified").asBoolean(), kept.event.toString());
            }
            JsonNode removal = result.events.get(0).event.path("change");
            assertEquals("MembersRemoved", removal.path("change_type").asText());
            assertEquals(1, removal.path("member_ids").size());
            assertEquals(v.get("event_group_removed_member_id").asText(), removal.path("member_ids").get(0).asText());
            JsonNode keyChange = result.events.get(1).event;
            assertEquals("KeyChange", keyChange.path("type").asText());
            assertEquals(version, keyChange.path("conversation_key_version").asText());
            JsonNode rename = result.events.get(2).event.path("change");
            assertEquals("TitleChanged", rename.path("change_type").asText());
            GroupText title = new ObjectMapper().treeToValue(rename.path("new_title"), GroupText.class);
            assertEquals("Text", title.kind);
            assertEquals(v.get("event_group_renamed_title").asText(), title.text);

            // The single-event path drops the same events, as invalid input.
            for (String index : dropped) {
                DecryptEventParams single =
                        new DecryptEventParams(flow.get(Integer.parseInt(index)), result.conversationKeys.keys);
                single.signingKeys = eventSigningKeys(v);
                ChatXdkException e = assertThrows(ChatXdkException.class, () -> chat.decryptEvent(single));
                assertEquals(ChatXdkException.Kind.INVALID_INPUT, e.getKind());
                assertEquals(result.errors.get(index), e.getMessage());
            }
        }
    }

    @Test
    void vectorsGroupCreateDecryptsItsTitleOnReceive() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) {
            Map<String, byte[]> createKeys = Map.of(
                    v.get("event_group_create_conversation_key_version").asText(),
                    Base64.getDecoder().decode(v.get("event_group_create_conversation_key_b64").asText()));
            DecryptEventParams params =
                    new DecryptEventParams(v.get("event_group_create_b64").asText(), createKeys);
            params.signingKeys = eventSigningKeys(v);
            JsonNode event = chat.decryptEvent(params);
            assertEquals("GroupChange", event.path("type").asText());
            assertTrue(event.path("verified").asBoolean());
            JsonNode change = event.path("change");
            assertEquals("Created", change.path("change_type").asText());
            ObjectMapper mapper = new ObjectMapper();
            GroupText title = mapper.treeToValue(change.path("title"), GroupText.class);
            assertEquals("Text", title.kind);
            assertEquals(v.get("event_group_title").asText(), title.text);
            assertTrue(change.path("avatar_url").isNull());
            assertEquals(
                    v.get("event_group_create_conversation_key_version").asText(),
                    change.path("conversation_key_version").asText());

            // Without the key the create seeded, the create still decrypts, on both
            // paths, with its title unavailable as the ciphertext it carries.
            String ciphertext = v.get("event_group_create_encrypted_title").asText();
            DecryptEventParams keyless =
                    new DecryptEventParams(v.get("event_group_create_b64").asText(), Map.of());
            keyless.signingKeys = eventSigningKeys(v);
            JsonNode keylessChange = chat.decryptEvent(keyless).path("change");
            assertEquals(v.get("event_sender_id").asText(), keylessChange.path("member_ids").path(0).asText());
            GroupText unavailable = mapper.treeToValue(keylessChange.path("title"), GroupText.class);
            assertEquals("Unavailable", unavailable.kind);
            assertEquals(ciphertext, unavailable.raw);
            DecryptEventsParams batch =
                    new DecryptEventsParams(List.of(v.get("event_group_create_b64").asText()));
            batch.signingKeys = eventSigningKeys(v);
            DecryptEventsResult result = chat.decryptEvents(batch);
            assertTrue(result.errors.isEmpty(), result.errors.toString());
            GroupText batched = mapper.treeToValue(
                    result.events.get(0).event.path("change").path("title"), GroupText.class);
            assertEquals("Unavailable", batched.kind);
            assertEquals(ciphertext, batched.raw);
        }
    }

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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
            String conversationId = v.get("event_conversation_id").asText();

            // No identity set: the error names the missing sender_id.
            EncryptMessageParams withoutIdentity = new EncryptMessageParams(conversationId, "no identity");
            withoutIdentity.conversationKey = b64(v, "conversation_key_b64");
            withoutIdentity.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            ChatXdkException ex =
                    assertThrows(ChatXdkException.class, () -> chat.encryptMessage(withoutIdentity));
            assertTrue(ex.getMessage().contains("sender_id"), ex.getMessage());

            chat.setIdentity(new SetIdentityParams(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText()));
            EncryptMessageParams p = new EncryptMessageParams(conversationId, "session identity");
            p.conversationKey = b64(v, "conversation_key_b64");
            p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
            chat.setIdentity(new SetIdentityParams(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText()));
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
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());

            // A file of a message sent from the cache encrypts under the same cached key.
            EncryptMessageParams withPhoto = new EncryptMessageParams(conversationId, "a photo");
            withPhoto.attachments = List.of(photo("photo"));
            SendPayload photoPayload = chat.encryptMessage(withPhoto);
            byte[] file = "photo bytes".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = chat.encryptFile(new EncryptFileParams(file, photoPayload.eventB64, "photo"));
            assertArrayEquals(file, chat.decryptFile(
                    new DecryptFileParams(encrypted, photoPayload.eventB64, conversationKeys(v), "photo")));

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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));

            DecryptEventsParams replies = new DecryptEventsParams(List.of(
                    v.get("event_key_change_b64").asText(),
                    v.get("event_reply_valid_b64").asText(),
                    v.get("event_reply_forged_b64").asText()));
            replies.signingKeys = eventSigningKeys(v);
            DecryptEventsResult result = chat.decryptEvents(replies);
            assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

            List<JsonNode> messages = new ArrayList<>();
            for (DecryptedEvent dm : result.events) {
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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
            chat.setIdentity(new SetIdentityParams(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText()));

            EncryptReplyParams p = new EncryptReplyParams(
                    v.get("event_conversation_id").asText(), "a reply", v.get("event_message_b64").asText());
            p.conversationKey = b64(v, "conversation_key_b64");
            p.conversationKeyVersion = v.get("event_conversation_key_version").asText();
            SendPayload payload = chat.encryptReply(p);
            assertFalse(payload.encodedMessageCreateEvent.isEmpty());
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
            chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
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
            for (DecryptedEvent dm : result.events) {
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

    // Verifying needs no loaded keys, and its error names the input, not the lock state.
    @Test
    void verifyNeedsNoLoadedKeys() throws Exception {
        try (Chat signer = createUnlocked(); Chat verifier = new Chat()) {
            byte[] data = {(byte) 0xAA, (byte) 0xBB};
            byte[] signature = signer.sign(data);
            assertTrue(verifier.verify(signer.getPublicKeys().signing, signature, data));
            ChatXdkException e =
                    assertThrows(ChatXdkException.class, () -> verifier.verify("notAPublicKey", signature, data));
            assertTrue(e.getMessage().contains("public key"), e.getMessage());
            assertFalse(e.getMessage().contains("unlocked"), e.getMessage());
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
        FeatureServer.waitForV1(chat);
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
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat()); Chat worker = new Chat()) {
            byte[] plaintext = new byte[1024];
            new java.util.Random(42).nextBytes(plaintext);
            SendPayload payload = sendFiles(chat, v, "a photo", photo("photo"));

            // A chat with no identity encrypts the file from the payload.
            byte[] encrypted = worker.encryptFile(encryptFileParams(v, plaintext, payload.eventB64, "photo"));
            assertFalse(java.util.Arrays.equals(plaintext, encrypted));
            assertEquals(ChatXdkUtilities.encryptedFileSize(plaintext.length), encrypted.length);
            assertArrayEquals(plaintext, chat.decryptFile(
                    new DecryptFileParams(encrypted, payload.eventB64, conversationKeys(v), "photo")));
        }
    }

    @Test
    void decryptFileWrongKeyThrows() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
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
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
            // A multi-frame file so chunking and re-framing are exercised, sent as the
            // second of two photos.
            byte[] plaintext = new byte[5000];
            java.util.Arrays.fill(plaintext, (byte) 0xAB);
            SendPayload payload = sendFiles(chat, v, "two photos", photo("first"), photo("second"));

            ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
            try (FileEncryptor enc = chat.fileEncryptor(fileEncryptorParams(v, payload.eventB64, "second"))) {
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

    @Test
    void fileWithKeyRoundTripsAtEveryFrameCount() throws Exception {
        byte[] key = b64(loadVectors(), "conversation_key_b64");
        try (Chat chat = new Chat()) {
            for (int size : new int[] {0, 1, 1023, 1024, 1025, 3050}) {
                byte[] file = new byte[size];
                for (int i = 0; i < size; i++) {
                    file[i] = (byte) (i % 251);
                }
                byte[] encrypted = chat.encryptFileWithKey(new EncryptFileWithKeyParams(file, key));
                assertEquals(ChatXdkUtilities.encryptedFileSize(size), encrypted.length);
                assertArrayEquals(file, chat.decryptFileWithKey(new DecryptFileWithKeyParams(encrypted, key)));
            }
        }
    }

    @Test
    void fileWithKeyOpensTheFiles05EncryptStreamEncrypted() throws Exception {
        try (Chat chat = new Chat()) {
            for (String version : new String[] {"0_5_0", "0_5_2"}) {
                JsonNode fixture = loadFixture("compat_v" + version + ".json");
                byte[] key = b64(fixture, "conversation_key_b64");
                for (String name : new String[] {"file", "avatar_file", "empty_file"}) {
                    JsonNode entry = fixture.get(name);
                    assertArrayEquals(
                            b64(entry, "plaintext_b64"),
                            chat.decryptFileWithKey(new DecryptFileWithKeyParams(b64(entry, "ciphertext_b64"), key)),
                            version + " " + name);
                }
            }
        }
    }

    @Test
    void fileWithKeyErrorsCarryTheirKind() throws Exception {
        byte[] key = b64(loadVectors(), "conversation_key_b64");
        try (Chat chat = new Chat()) {
            byte[] encrypted = chat.encryptFileWithKey(new EncryptFileWithKeyParams(new byte[1800], key));

            ChatXdkException shortKey = assertThrows(ChatXdkException.class, () -> chat.encryptFileWithKey(
                    new EncryptFileWithKeyParams(new byte[] {1}, Arrays.copyOf(key, 31))));
            assertEquals(ChatXdkException.Kind.INVALID_INPUT, shortKey.getKind());
            assertTrue(shortKey.getMessage().contains("expected 32 bytes, got 31"), shortKey.getMessage());
            assertEquals(ChatXdkException.Kind.INVALID_INPUT, assertThrows(ChatXdkException.class,
                    () -> chat.decryptFileWithKey(new DecryptFileWithKeyParams(encrypted, null))).getKind());

            for (byte[] bad : new byte[][] {
                    Arrays.copyOf(encrypted, encrypted.length - 1),
                    Arrays.copyOf(encrypted, 24 + 1041),
                    Arrays.copyOf(encrypted, 10)}) {
                assertEquals(ChatXdkException.Kind.DECRYPTION, assertThrows(ChatXdkException.class,
                        () -> chat.decryptFileWithKey(new DecryptFileWithKeyParams(bad, key))).getKind());
            }
            assertEquals(ChatXdkException.Kind.DECRYPTION, assertThrows(ChatXdkException.class,
                    () -> chat.decryptFileWithKey(new DecryptFileWithKeyParams(encrypted, new byte[32]))).getKind());
        }
    }

    /** The file calls throw only the unchecked ChatXdkException, so no throws clause is needed. */
    private static byte[] roundTripWithoutThrowsClause(
            Chat chat, JsonNode v, SendPayload payload, String mediaHashKey, byte[] file) {
        Map<String, byte[]> keys = conversationKeys(v);
        byte[] whole = chat.encryptFile(encryptFileParams(v, file, payload.eventB64, mediaHashKey));
        byte[] streamed;
        try (FileEncryptor enc = chat.fileEncryptor(fileEncryptorParams(v, payload.eventB64, mediaHashKey))) {
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
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
            SendPayload payload = sendFiles(chat, v, "a photo", photo("only"));
            byte[] file = "photo bytes".getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(file, roundTripWithoutThrowsClause(chat, v, payload, "only", file));
        }
    }

    @Test
    void linkCardImagesTakeTheCardsKey() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
            SendPayload payload = sendFiles(chat, v, "a link", Types.AttachmentDescriptor.urlCard(
                    "https://example.com",
                    null,
                    new Types.UrlAttachmentImageDescriptor("banner", 12L, "banner.png"),
                    new Types.UrlAttachmentImageDescriptor("favicon", 13L, "favicon.png")));
            for (String name : new String[] {"banner", "favicon"}) {
                byte[] encrypted = chat.encryptFile(encryptFileParams(
                        v, (name + " bytes").getBytes(StandardCharsets.UTF_8), payload.eventB64, name));
                assertEquals(name + " bytes", new String(chat.decryptFile(
                        new DecryptFileParams(encrypted, payload.eventB64, conversationKeys(v), name)),
                        StandardCharsets.UTF_8));
            }
        }
    }

    @Test
    void aMessageWithFilesTakesTheIdItsFilesDerive() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
            SendPayload draft = sendFiles(chat, v, "draft", photo("photo-a"), photo("photo-b"));
            assertTrue(draft.messageId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"),
                    draft.messageId);
            byte[] encrypted = chat.encryptFile(encryptFileParams(
                    v, "photo b".getBytes(StandardCharsets.UTF_8), draft.eventB64, "photo-b"));

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
        try (Chat chat = quickReplyChat(v, FeatureServer.v1Chat())) {
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
                    encryptFileParams(v, new byte[] {1}, payload.eventB64, "other")));
            assertTrue(e.getMessage().contains("is not one of the message's files"), e.getMessage());
            EncryptFileParams shortKey = new EncryptFileParams(new byte[] {1}, payload.eventB64, "photo");
            shortKey.conversationKey = new byte[3];
            shortKey.conversationKeyVersion = keyVersion;
            e = assertThrows(ChatXdkException.class, () -> chat.encryptFile(shortKey));
            assertTrue(e.getMessage().contains("expected 32 bytes"), e.getMessage());
            EncryptFileParams otherVersion = encryptFileParams(v, new byte[] {1}, payload.eventB64, "photo");
            otherVersion.conversationKeyVersion = "9";
            e = assertThrows(ChatXdkException.class, () -> chat.encryptFile(otherVersion));
            assertTrue(e.getMessage().contains(
                    "conversation_key_version '9' is not the message's key version '" + keyVersion + "'"), e.getMessage());

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
                    encryptFileParams(v, new byte[] {1}, reply.eventB64, "photo")));
            assertTrue(e.getMessage().contains("is media the reply quotes"), e.getMessage());

            try (Chat noIdentity = new Chat()) {
                noIdentity.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64")));
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
            assertThrows(ChatXdkException.class, () -> chat.importKeys(new ImportKeysParams(new byte[16])));
            assertThrows(ChatXdkException.class, () -> chat.importKeys(new ImportKeysParams(new byte[0])));
        }
    }

    @Test
    void operationsFailWhenLocked() {
        try (Chat chat = new Chat()) {
            assertThrows(Exception.class, chat::getPublicKeys);
            assertThrows(ChatXdkException.class, () -> chat.sign(new byte[] {1, 2, 3}));
            assertEquals(ChatXdkException.Kind.INVALID_STATE,
                    assertThrows(ChatXdkException.class, chat::exportKeys).getKind());
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
            chat.importKeys(new ImportKeysParams(identityOnly));
            byte[] exported = chat.exportKeys();
            assertNotNull(exported);
            assertArrayEquals(identityOnly, exported);
        }
    }

    // The session identity signs a call that names no identity of its own, and
    // setRejectUnverified decides whether a message from a sender whose signing
    // key the chat lacks is rejected or returned unverified.
    @Test
    void setIdentityAndSetRejectUnverifiedTakeEffect() throws Exception {
        try (Chat chat = createUnlocked(); Chat sender = createUnlocked()) {
            chat.setIdentity(new SetIdentityParams("910004", "12345"));
            ActionSignature action = onlyAction(chat.prepareMessageTtlRemove(new MessageTtlRemoveParams("g100")));
            assertTrue(signs(chat, action,
                    "ConversationMetadataChangeEvent.MessageDurationRemove," + action.messageId + ",910004,g100"));
            assertEquals("12345", action.messageEventSignature.publicKeyVersion);

            byte[] conversationKey = new byte[32];
            EncryptMessageParams send = new EncryptMessageParams("910004:910005", "hi");
            send.senderId = "910005";
            send.signingKeyVersion = "1";
            send.conversationKey = conversationKey;
            send.conversationKeyVersion = "1";
            DecryptEventParams received =
                    new DecryptEventParams(sender.encryptMessage(send).eventB64, Map.of("1", conversationKey));
            assertThrows(ChatXdkException.class, () -> chat.decryptEvent(received));
            chat.setRejectUnverified(false);
            JsonNode unverified = chat.decryptEvent(received);
            assertEquals("hi", unverified.path("content").path("text").asText());
            assertFalse(unverified.path("verified").asBoolean());
            chat.setRejectUnverified(true);
            assertThrows(ChatXdkException.class, () -> chat.decryptEvent(received));
        }
    }

    // Absent-value normalization: an empty title is "not set" and signs the
    // null sentinel, exactly like leaving the field null.
    @Test
    void prepareGroupCreateEmptyTitleSignsNullSentinel() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            for (String title : new String[] {"", null}) {
                GroupCreateParams p = new GroupCreateParams(
                        List.of(input), "g123", List.of("910002", "910005"), List.of("910002"));
                p.senderId = "910002";
                p.signingKeyVersion = "1";
                p.title = title;
                PreparedConversationChange prepared = chat.prepareGroupCreate(p);
                // Trailing slots: legacy upgrade, title, avatar_url — all unset → null
                // sentinels.
                ActionSignature create = prepared.actionSignatures.get(1);
                assertTrue(signs(chat, create, "GroupChangeEvent.GroupCreate," + create.messageId + ",910002,"
                        + prepared.conversationKeyVersion + ",910002,910005,null,null,null"),
                        "the title and avatar must sign as the null sentinel");
                assertNull(prepared.encryptedTitle);
            }
        }
    }

    // The plaintext never enters the comma-joined signature payload, only its
    // base64 ciphertext does, so a title with a comma encrypts.
    @Test
    void prepareGroupCreateEncryptsACommaTitle() throws Exception {
        try (Chat chat = createUnlocked()) {
            PublicKeys keys = chat.getPublicKeys();
            PublicKeyInput input = new PublicKeyInput("910002", keys.identity, "1");
            GroupCreateParams p = new GroupCreateParams(
                    List.of(input), "g123", List.of("910002", "910005"), List.of("910002"));
            p.senderId = "910002";
            p.signingKeyVersion = "1";
            p.title = "Team, the sequel";
            PreparedConversationChange prepared = chat.prepareGroupCreate(p);
            assertEquals("Team, the sequel", chat.decrypt(prepared.encryptedTitle, prepared.conversationKey));
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
        return quickReplyChat(v, new Chat());
    }

    private static Chat quickReplyChat(JsonNode v, Chat chat) throws Exception {
        chat.importKeys(new ImportKeysParams(b64(v, "private_keys_concat_b64"), v.get("event_recipient_key_version").asText()));
        chat.setIdentity(new SetIdentityParams(v.get("event_sender_id").asText(), v.get("event_signing_key_version").asText()));
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
            p.replyToSenderId = v.get("event_sender_id").asText();
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
