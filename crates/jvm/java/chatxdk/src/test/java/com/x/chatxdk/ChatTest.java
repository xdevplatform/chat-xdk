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
import java.util.Base64;
import java.util.List;

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
        SigningKeyEntry entry = new SigningKeyEntry();
        entry.userId = v.get("event_sender_id").asText();
        entry.publicKeyVersion = v.get("event_signing_key_version").asText();
        entry.publicKey = v.get("signing_public_b64").asText();
        entry.identityPublicKey = v.get("identity_public_b64").asText();
        entry.identityPublicKeySignature = v.get("identity_public_key_signature_b64").asText();
        return List.of(entry);
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
    void generateKeypairsReturnsValidPayload() throws Exception {
        try (Chat chat = new Chat()) {
            PublicKeyRegistrationPayload payload = chat.generateKeypairs();
            assertFalse(payload.publicKey.publicKey.isEmpty());
            assertFalse(payload.publicKey.signingPublicKey.isEmpty());
            assertFalse(payload.publicKey.identityPublicKeySignature.isEmpty());
            assertEquals("CustomPin", payload.publicKey.registrationMethod);
            assertTrue(payload.generateVersion);
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
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
            SendPayload payload = chat.encryptMessage(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("v1", payload.conversationKeyVersion);
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
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
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
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
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
            byte[] ckey = newConvKey(chat);
            EncryptMessageParams p = new EncryptMessageParams("conv-1", "Check this out");
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
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
        }
    }

    @Test
    void encryptReplyReturnsValidPayload() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            // Explicit-field form: no raw event in hand, so the preview fields
            // are supplied directly (null reply target).
            EncryptReplyParams p = new EncryptReplyParams("conv-1", "This is a reply", null);
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
            p.replyToSequenceId = "seq-42";
            p.replyToSenderId = 12345L;
            p.replyToText = "Original message";
            SendPayload payload = chat.encryptReply(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("v1", payload.conversationKeyVersion);
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
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
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
            p.senderId = "user-1";
            p.signingKeyVersion = "s1";
            p.conversationKey = ckey;
            p.conversationKeyVersion = "v1";
            SendPayload payload = chat.encryptRemoveReaction(p);
            assertFalse(payload.encryptedContent.isEmpty());
            assertFalse(payload.signature.isEmpty());
            assertFalse(payload.encodedEventSignature.isEmpty());
            assertEquals("7", payload.signatureInfo.signatureVersion);
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
            DecryptEventsResult result = chat.decryptEvents(List.of(), List.of());
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
            ChatXdkException ex =
                    assertThrows(
                            ChatXdkException.class,
                            () -> chat.decryptEvents(List.of(), List.of(malformed)));
            assertTrue(ex.getMessage().contains("Invalid signing keys JSON"));
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
            DecryptEventsResult result = chat.decryptEvents(
                    List.of(
                            v.get("event_key_change_b64").asText(),
                            v.get("event_message_b64").asText(),
                            v.get("event_garbage_b64").asText()),
                    signingKeys);

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
            JsonNode single = chat.decryptEvent(
                    v.get("event_message_b64").asText(), result.conversationKeys, signingKeys);
            assertEquals("Message", single.path("type").asText());
            assertEquals(v.get("event_message_text").asText(),
                    single.path("content").path("text").asText());
            assertTrue(single.path("verified").asBoolean());

            // … and throws on the garbage event.
            assertThrows(ChatXdkException.class, () -> chat.decryptEvent(
                    v.get("event_garbage_b64").asText(), (ConversationKeyBundle) null, signingKeys));
        }
    }

    // Failure events are unsigned by protocol: the fixture failure decodes
    // with no conversation or signing keys, and the JSON carries the
    // PascalCase discriminator values.
    @Test
    void vectorsFailureEventDecodesTypeAndRateLimitTier() throws Exception {
        JsonNode v = loadVectors();
        try (Chat chat = new Chat()) { // default reject-unverified policy
            JsonNode event = chat.decryptEvent(
                    v.get("event_failure_b64").asText(), (ConversationKeyBundle) null, List.of());
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
            chat.decryptEvents(List.of(v.get("event_key_change_b64").asText()), eventSigningKeys(v));

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
                    chat.decryptEvents(List.of(v.get("event_key_change_b64").asText()), null);
            assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

            JsonNode single = chat.decryptEvent(
                    v.get("event_message_b64").asText(), result.conversationKeys, null);
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

            DecryptEventsResult result = chat.decryptEvents(
                    List.of(
                            v.get("event_key_change_b64").asText(),
                            v.get("event_reply_valid_b64").asText(),
                            v.get("event_reply_forged_b64").asText()),
                    eventSigningKeys(v));
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

    @Test
    void encryptDecryptStreamRoundTrip() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            byte[] plaintext = new byte[1024];
            new java.util.Random(42).nextBytes(plaintext);

            byte[] encrypted = chat.encryptStream(plaintext, ckey);
            assertFalse(java.util.Arrays.equals(plaintext, encrypted));
            assertArrayEquals(plaintext, chat.decryptStream(encrypted, ckey));
        }
    }

    @Test
    void decryptStreamWrongKeyThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey1 = newConvKey(chat);
            byte[] ckey2 = newConvKey(chat);
            byte[] encrypted = chat.encryptStream("secret content".getBytes(StandardCharsets.UTF_8), ckey1);
            assertThrows(ChatXdkException.class, () -> chat.decryptStream(encrypted, ckey2));
        }
    }

    @Test
    void incrementalStreamRoundTripAndTruncationThrows() throws Exception {
        try (Chat chat = createUnlocked()) {
            byte[] ckey = newConvKey(chat);
            // A multi-frame payload so chunking and re-framing are exercised.
            byte[] plaintext = new byte[5000];
            java.util.Arrays.fill(plaintext, (byte) 0xAB);

            ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
            try (StreamEncryptor enc = chat.streamEncryptor(ckey)) {
                for (int i = 0; i < plaintext.length; i += 700) {
                    int end = Math.min(i + 700, plaintext.length);
                    ciphertext.write(enc.push(java.util.Arrays.copyOfRange(plaintext, i, end)));
                }
                ciphertext.write(enc.finish());
            }
            byte[] ct = ciphertext.toByteArray();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (StreamDecryptor dec = chat.streamDecryptor(ckey)) {
                for (int i = 0; i < ct.length; i += 333) {
                    int end = Math.min(i + 333, ct.length);
                    out.write(dec.push(java.util.Arrays.copyOfRange(ct, i, end)));
                }
                out.write(dec.finish());
            }
            assertArrayEquals(plaintext, out.toByteArray());

            // A truncated stream is missing its final frame: finish() throws.
            try (StreamDecryptor truncated = chat.streamDecryptor(ckey)) {
                truncated.push(java.util.Arrays.copyOfRange(ct, 0, ct.length - 4));
                assertThrows(ChatXdkException.class, truncated::finish);
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
}
