package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.KeyChangeSignerTest.KeyChange;
import com.x.chatxdk.KeyChangeSignerTest.Party;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static com.x.chatxdk.KeyChangeSignerTest.GROUP;
import static com.x.chatxdk.KeyChangeSignerTest.KEY_VERSION;
import static com.x.chatxdk.KeyChangeSignerTest.sentMessage;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The conversation-key cache and the signing-key store: what fills them and which calls read
 * them.
 */
class KeyCacheTest {

    private static final String AVATAR_URL = "https://ton.x.com/xchat_media/g900/avatar";

    @BeforeAll
    static void keepFeatureFetchesOffline() {
        FeatureServer.keepOffline();
    }

    /** A party whose chat has its user as session identity. */
    private static Party session(String userId) throws Exception {
        Party party = new Party(userId);
        party.chat.setIdentity(new SetIdentityParams(userId, KEY_VERSION));
        return party;
    }

    /** A party with a session identity whose key cache is on. */
    private static Party caching(String userId) throws Exception {
        Party party = session(userId);
        party.chat.setCacheKeys(true);
        return party;
    }

    /** The key version {@code party} encrypts under in the group when the call passes no key. */
    private static String sendVersion(Party party) throws Exception {
        return party.chat.encryptMessage(new EncryptMessageParams(GROUP, "hello")).conversationKeyVersion;
    }

    /** Asserts that a send from {@code party} that passes no key fails because no key is cached. */
    private static void assertNoCachedKey(Party party) {
        ChatXdkException e = assertThrows(ChatXdkException.class, () -> sendVersion(party));
        assertEquals(ChatXdkException.Kind.INVALID_STATE, e.getKind());
        assertTrue(e.getMessage().contains("no cached conversation key for '" + GROUP + "'"), e.getMessage());
    }

    /**
     * Whether {@code change} verifies as {@code party} decrypts it on its own, with the signing
     * keys of {@code signers}.
     */
    private static boolean verifiesKeyChange(Party party, KeyChange change, Party... signers) throws Exception {
        List<SigningKeyEntry> signingKeys = new ArrayList<>();
        for (Party signer : signers) {
            signingKeys.add(signer.signingKey);
        }
        DecryptEventParams params = new DecryptEventParams(change.eventB64);
        params.signingKeys = signingKeys;
        JsonNode decrypted = party.chat.decryptEvent(params);
        assertEquals("KeyChange", decrypted.path("type").asText());
        return decrypted.path("verified").asBoolean();
    }

    /**
     * The text of {@code message} from {@code author}, as {@code reader} decrypts and verifies it
     * on its own with no key map.
     */
    private static String read(Party reader, String message, Party author) throws Exception {
        DecryptEventParams params = new DecryptEventParams(message);
        params.signingKeys = List.of(author.signingKey);
        JsonNode decrypted = reader.chat.decryptEvent(params);
        assertEquals("Message", decrypted.path("type").asText());
        assertTrue(decrypted.path("verified").asBoolean());
        return decrypted.path("content").path("text").asText();
    }

    /**
     * A key change {@code signer} makes in the group for {@code members} at a later key version
     * than {@code older}'s.
     */
    private static KeyChange newerKeyChange(Party signer, List<Party> members, KeyChange older) throws Exception {
        KeyChange change = new KeyChange(signer, members, GROUP);
        while (Long.parseLong(change.version) <= Long.parseLong(older.version)) {
            change = new KeyChange(signer, members, GROUP);
        }
        return change;
    }

    /**
     * Whether {@code signed}'s signature verifies, under the signer's own signing key, over
     * {@code payload}: the comma-joined fields its event signs.
     */
    private static boolean signs(Chat chat, ActionSignature signed, String payload) {
        return chat.verify(
                signed.messageEventSignature.signingPublicKey,
                Base64.getDecoder().decode(signed.messageEventSignature.signature),
                payload.getBytes(StandardCharsets.UTF_8));
    }

    /** Whether the avatar change {@code admin} prepares with {@code params} signs {@code version}. */
    private static boolean signsVersion(Party admin, GroupAvatarChangeParams params, String version)
            throws Exception {
        PreparedAction prepared = admin.chat.prepareGroupAvatarChange(params);
        assertEquals(1, prepared.actionSignatures.size());
        ActionSignature signed = prepared.actionSignatures.get(0);
        return signs(admin.chat, signed, "GroupChangeEvent.GroupAvatarUrlChange," + signed.messageId
                + "," + admin.userId + "," + GROUP + "," + version + "," + params.newAvatarUrl);
    }

    /**
     * The four calls that make a conversation key, as {@code maker} makes them in the group it
     * shares with {@code member}: the create, adding {@code joiner}, removing {@code joiner}, and
     * a key rotation.
     */
    private static List<Callable<PreparedConversationChange>> prepares(Party maker, Party member, Party joiner) {
        List<PublicKeyInput> both = List.of(maker.publicKey, member.publicKey);
        ConversationKeyChangeParams rotation = new ConversationKeyChangeParams(both);
        rotation.conversationId = GROUP;
        return List.<Callable<PreparedConversationChange>>of(
                () -> maker.chat.prepareGroupCreate(new GroupCreateParams(
                        both, GROUP, List.of(maker.userId, member.userId), List.of(maker.userId))),
                () -> maker.chat.prepareGroupMembersChange(new GroupMembersChangeParams(
                        List.of(maker.publicKey, member.publicKey, joiner.publicKey),
                        GROUP,
                        List.of(joiner.userId),
                        List.of(maker.userId, member.userId),
                        List.of(maker.userId),
                        List.of())),
                () -> maker.chat.prepareGroupMembersRemove(
                        new GroupMembersRemoveParams(both, GROUP, List.of(joiner.userId))),
                () -> maker.chat.prepareConversationKeyChange(rotation));
    }

    /**
     * Whether {@code reader} decrypts a message {@code author} sends under the key of
     * {@code change}, passed in the call, and verifies it with the signing keys it stores.
     */
    private static boolean reads(Party reader, Party author, KeyChange change) throws Exception {
        String message = sentMessage(author, GROUP, change, "hi");
        try {
            JsonNode decrypted =
                    reader.chat.decryptEvent(new DecryptEventParams(message, Map.of(change.version, change.key)));
            return decrypted.path("verified").asBoolean();
        } catch (ChatXdkException e) {
            return false;
        }
    }

    @Test
    void decryptEventCachesTheKeyOfAKeyChangeThatVerifies() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party bot = caching("5003")) {
            KeyChange change = new KeyChange(admin, List.of(admin, member, bot), GROUP);
            String message = sentMessage(member, GROUP, change, "hello group");

            // Nothing is cached yet.
            assertNoCachedKey(bot);

            assertTrue(verifiesKeyChange(bot, change, admin));

            assertEquals(change.version, sendVersion(bot));
            assertEquals("hello group", read(bot, message, member));
        }
    }

    @Test
    void decryptEventDoesNotCacheAKeyChangeThatDoesNotVerify() throws Exception {
        try (Party admin = new Party("5001");
                Party bot = caching("5003")) {
            bot.chat.setRejectUnverified(false);
            KeyChange change = new KeyChange(admin, List.of(admin, bot), GROUP);

            // Without the admin's signing keys the key change is returned unverified.
            assertFalse(verifiesKeyChange(bot, change));
            assertNoCachedKey(bot);
        }
    }

    @Test
    void prepareCallsCacheTheKeyTheyMake() throws Exception {
        try (Party member = new Party("5002");
                Party joiner = new Party("5004");
                Party admin = caching("5001");
                Party uncached = session("5001")) {
            // With the cache on, a send that passes no key uses the key each call made.
            for (Callable<PreparedConversationChange> prepare : prepares(admin, member, joiner)) {
                assertEquals(prepare.call().conversationKeyVersion, sendVersion(admin));
            }

            // With the cache off, the keys are not kept.
            for (Callable<PreparedConversationChange> prepare : prepares(uncached, member, joiner)) {
                prepare.call();
                assertNoCachedKey(uncached);
            }
        }
    }

    @Test
    void keyCacheKeepsEveryVersionAndSendsUseTheNewest() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party bot = caching("5003")) {
            List<Party> members = List.of(admin, member, bot);
            KeyChange first = new KeyChange(admin, members, GROUP);
            KeyChange second = newerKeyChange(admin, members, first);

            // The older key change arrives last: it is kept for decryption and does not become
            // the key sends use.
            assertTrue(verifiesKeyChange(bot, second, admin));
            assertTrue(verifiesKeyChange(bot, first, admin));
            assertEquals(second.version, sendVersion(bot));

            for (KeyChange change : List.of(first, second)) {
                String text = "under " + change.version;
                assertEquals(text, read(bot, sentMessage(member, GROUP, change, text), member));
            }
        }
    }

    @Test
    void fileDecryptionReadsTheKeyCache() throws Exception {
        try (Party sender = caching("5001")) {
            KeyChange change = new KeyChange(sender, List.of(sender), GROUP);

            // A message and its file, encrypted under the cached key.
            EncryptMessageParams message = new EncryptMessageParams(GROUP, "a photo");
            message.attachments = List.of(AttachmentDescriptor.media("photo", 4, 3, 64, "photo.jpg", 1, null));
            SendPayload payload = sender.chat.encryptMessage(message);
            assertEquals(change.version, payload.conversationKeyVersion);
            byte[] file = "photo bytes".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = sender.chat.encryptFile(new EncryptFileParams(file, payload.eventB64, "photo"));

            // No key map: the keys come from the cache.
            assertArrayEquals(
                    file, sender.chat.decryptFile(new DecryptFileParams(encrypted, payload.eventB64, "photo")));
            assertArrayEquals(
                    file, sender.chat.decryptFile(new DecryptFileParams(encrypted, payload.eventB64, null, "photo")));
            assertArrayEquals(
                    file,
                    sender.chat.decryptFile(new DecryptFileParams(encrypted, payload.eventB64, Map.of(), "photo")));
            try (FileDecryptor decryptor =
                    sender.chat.fileDecryptor(new FileDecryptorParams(payload.eventB64, "photo"))) {
                ByteArrayOutputStream streamed = new ByteArrayOutputStream();
                streamed.write(decryptor.push(encrypted));
                streamed.write(decryptor.finish());
                assertArrayEquals(file, streamed.toByteArray());
            }

            // A key map that is passed is the only source: one without the message's version
            // fails though the cache holds that version.
            byte[] otherKey = new byte[32];
            Arrays.fill(otherKey, (byte) 7);
            Map<String, byte[]> otherVersion = Map.of("9", otherKey);
            String noKey = "conversation_keys has no key for version '" + change.version + "'";
            ChatXdkException whole = assertThrows(ChatXdkException.class, () -> sender.chat.decryptFile(
                    new DecryptFileParams(encrypted, payload.eventB64, otherVersion, "photo")));
            assertTrue(whole.getMessage().contains(noKey), whole.getMessage());
            ChatXdkException chunked = assertThrows(ChatXdkException.class, () -> sender.chat.fileDecryptor(
                    new FileDecryptorParams(payload.eventB64, otherVersion, "photo")));
            assertTrue(chunked.getMessage().contains(noKey), chunked.getMessage());
        }
    }

    @Test
    void prepareGroupAvatarChangeWithNoKeyVersionSignsTheNewestCachedVersion() throws Exception {
        try (Party admin = caching("5001")) {
            // With no key cached there is no version to sign.
            ChatXdkException e = assertThrows(
                    ChatXdkException.class,
                    () -> admin.chat.prepareGroupAvatarChange(new GroupAvatarChangeParams(GROUP, AVATAR_URL)));
            assertEquals(ChatXdkException.Kind.INVALID_STATE, e.getKind());
            assertTrue(
                    e.getMessage()
                            .contains("conversation_key_version is not set and no conversation key is cached for '"
                                    + GROUP + "'"),
                    e.getMessage());

            KeyChange first = new KeyChange(admin, List.of(admin), GROUP);
            KeyChange second = newerKeyChange(admin, List.of(admin), first);
            assertTrue(signsVersion(admin, new GroupAvatarChangeParams(GROUP, AVATAR_URL), second.version));
            assertTrue(signsVersion(admin, new GroupAvatarChangeParams(GROUP, AVATAR_URL, null), second.version));
            assertTrue(signsVersion(admin, new GroupAvatarChangeParams(GROUP, AVATAR_URL, ""), second.version));

            // A version that is passed is signed as is.
            assertTrue(signsVersion(
                    admin, new GroupAvatarChangeParams(GROUP, AVATAR_URL, first.version), first.version));
        }
    }

    @Test
    void addSigningKeysAddsToTheStoredKeysAndSetSigningKeysReplacesThem() throws Exception {
        try (Party alice = new Party("5001");
                Party bob = new Party("5002");
                Party reader = new Party("5003")) {
            KeyChange change = new KeyChange(alice, List.of(alice), GROUP);

            reader.chat.setSigningKeys(List.of(alice.signingKey));
            assertTrue(reads(reader, alice, change));
            assertFalse(reads(reader, bob, change));

            // Adding keeps what is stored.
            reader.chat.addSigningKeys(List.of(bob.signingKey));
            assertTrue(reads(reader, alice, change));
            assertTrue(reads(reader, bob, change));

            // An entry for a stored user and key version replaces that entry alone.
            SigningKeyEntry wrong = new SigningKeyEntry(
                    alice.userId,
                    bob.signingKey.publicKeyVersion,
                    bob.signingKey.publicKey,
                    bob.signingKey.identityPublicKey,
                    bob.signingKey.identityPublicKeySignature);
            reader.chat.addSigningKeys(List.of(wrong));
            assertFalse(reads(reader, alice, change));
            assertTrue(reads(reader, bob, change));

            // Setting replaces the whole set.
            reader.chat.setSigningKeys(List.of(bob.signingKey));
            assertFalse(reads(reader, alice, change));
            assertTrue(reads(reader, bob, change));
        }
    }
}
