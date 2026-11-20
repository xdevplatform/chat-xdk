package com.x.chatxdk;

import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Chat#decryptEvents} and the key changes of a batch: a key change needs its signer's
 * keys to verify, the result says which key changes did not verify or could not be decrypted and
 * why, and keys and the version to encrypt with are reported per conversation.
 */
class KeyChangeSignerTest {

    /** A sequence id past the cut-over, where a key change that does not verify has its key dropped. */
    private static final String ENFORCED_SEQUENCE = "2100000000000000000";

    /** A sequence id before the cut-over, where the key is kept. */
    private static final String UNENFORCED_SEQUENCE = "100";

    private static final String GROUP = "g900";
    private static final String OTHER_GROUP = "g901";
    private static final String THIRD_GROUP = "g902";
    private static final String KEY_VERSION = "1";

    @BeforeAll
    static void keepFeatureFetchesOffline() {
        FeatureServer.keepOffline();
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

    /** A Thrift struct field: its id, then the struct as already serialized. */
    private static void writeStruct(ByteArrayOutputStream out, int id, byte[] struct) {
        out.write(12);
        out.write(id >> 8);
        out.write(id);
        out.writeBytes(struct);
    }

    /** The event as delivered: {@code eventB64} with the sequence id the server assigns, prepended as Thrift string field 1. */
    private static String delivered(String eventB64, String sequenceId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeString(out, 1, sequenceId);
        out.writeBytes(Base64.getDecoder().decode(eventB64));
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    /**
     * A signed action as delivered: the event the server relays for {@code action}, an entry of a
     * prepared change's action signatures, from {@code senderId} in {@code conversationId}, with
     * the sequence id the server assigns.
     */
    private static String deliveredAction(
            ActionSignature action, String senderId, String conversationId, String sequenceId) {
        MessageEventSignature signed = action.messageEventSignature;
        ByteArrayOutputStream signature = new ByteArrayOutputStream();
        writeString(signature, 1, signed.signature);
        writeString(signature, 2, signed.publicKeyVersion);
        writeString(signature, 3, signed.signatureVersion);
        signature.write(0);
        ByteArrayOutputStream event = new ByteArrayOutputStream();
        writeString(event, 1, sequenceId);
        writeString(event, 2, action.messageId);
        writeString(event, 3, senderId);
        writeString(event, 4, conversationId);
        writeStruct(event, 7, Base64.getDecoder().decode(action.encodedMessageEventDetail));
        writeStruct(event, 9, signature.toByteArray());
        event.write(0);
        return Base64.getEncoder().encodeToString(event.toByteArray());
    }

    /** A chat with fresh keys as a user, and the keys others hold for it. */
    private static final class Party implements AutoCloseable {
        final Chat chat = new Chat();
        final String userId;
        final SigningKeyEntry signingKey;
        final PublicKeyInput publicKey;

        Party(String userId) throws Exception {
            this.userId = userId;
            PublicKeyRegistration registration = chat.generateKeypairs().publicKey;
            signingKey = new SigningKeyEntry(
                    userId,
                    KEY_VERSION,
                    registration.signingPublicKey,
                    registration.publicKey,
                    registration.identityPublicKeySignature);
            publicKey = new PublicKeyInput(userId, registration.publicKey, KEY_VERSION);
        }

        @Override
        public void close() {
            chat.close();
        }
    }

    /** The key change a signer makes in a conversation for its members, as delivered, with its key. */
    private static final class KeyChange {
        final ActionSignature action;
        final String signerId;
        final String conversationId;
        final String eventB64;
        final byte[] key;
        final String version;

        KeyChange(Party signer, List<Party> members, String conversationId) throws Exception {
            List<PublicKeyInput> publicKeys = new ArrayList<>();
            for (Party member : members) {
                publicKeys.add(member.publicKey);
            }
            ConversationKeyChangeParams params = new ConversationKeyChangeParams(publicKeys);
            params.senderId = signer.userId;
            params.signingKeyVersion = KEY_VERSION;
            params.conversationId = conversationId;
            PreparedConversationChange prepared = signer.chat.prepareConversationKeyChange(params);
            action = prepared.actionSignatures.get(0);
            signerId = signer.userId;
            this.conversationId = conversationId;
            eventB64 = deliveredAction(action, signerId, conversationId, ENFORCED_SEQUENCE);
            key = prepared.conversationKey;
            version = prepared.conversationKeyVersion;
        }

        private KeyChange(KeyChange change, String eventB64, String version) {
            action = change.action;
            signerId = change.signerId;
            conversationId = change.conversationId;
            this.eventB64 = eventB64;
            key = change.key;
            this.version = version;
        }

        /**
         * This key change as delivered before the cut-over with its key version rewritten to
         * {@code version}. The signature no longer verifies, and the key is kept.
         */
        KeyChange atVersion(String version) {
            assertEquals(this.version.length(), version.length());
            String detail = new String(
                    Base64.getDecoder().decode(action.encodedMessageEventDetail), StandardCharsets.ISO_8859_1);
            assertTrue(detail.contains(this.version));
            ActionSignature rewritten = new ActionSignature();
            rewritten.messageId = action.messageId;
            rewritten.encodedMessageEventDetail = Base64.getEncoder()
                    .encodeToString(detail.replaceFirst(this.version, version).getBytes(StandardCharsets.ISO_8859_1));
            rewritten.messageEventSignature = action.messageEventSignature;
            return new KeyChange(
                    this, deliveredAction(rewritten, signerId, conversationId, UNENFORCED_SEQUENCE), version);
        }
    }

    /** The message {@code author} sends in {@code conversationId} under the key of {@code change}, as delivered. */
    private static String sentMessage(Party author, String conversationId, KeyChange change, String text)
            throws Exception {
        EncryptMessageParams params = new EncryptMessageParams(conversationId, text);
        params.senderId = author.userId;
        params.signingKeyVersion = KEY_VERSION;
        params.conversationKey = change.key;
        params.conversationKeyVersion = change.version;
        return delivered(author.chat.encryptMessage(params).eventB64, "2100000000000000001");
    }

    /**
     * An admin who rotates a group's key, a member who sends a message under it, and the bot that
     * receives both events.
     */
    private static final class Page implements AutoCloseable {
        final Party admin = new Party("5001");
        final Party member = new Party("5002");
        final Party bot = new Party("5003");
        final KeyChange change;
        final List<String> events;

        Page() throws Exception {
            change = new KeyChange(admin, List.of(admin, member, bot), GROUP);
            events = List.of(change.eventB64, sentMessage(member, GROUP, change, "hello group"));
        }

        /** The bot's decryptEvents of {@code events} with the signing keys of {@code signers}. */
        DecryptEventsResult decrypt(List<String> events, Party... signers) throws Exception {
            List<SigningKeyEntry> signingKeys = new ArrayList<>();
            for (Party signer : signers) {
                signingKeys.add(signer.signingKey);
            }
            return decryptWith(bot.chat, events, signingKeys);
        }

        /**
         * A key change the admin makes for itself and the bot in the other group, at another key
         * version than the page's.
         */
        KeyChange otherKeyChange() throws Exception {
            List<Party> members = List.of(admin, bot);
            KeyChange other = new KeyChange(admin, members, OTHER_GROUP);
            while (other.version.equals(change.version)) {
                other = new KeyChange(admin, members, OTHER_GROUP);
            }
            return other;
        }

        /**
         * Asserts that the page's key change, and no other, did not verify for {@code reason} and
         * lost its key.
         */
        void assertUnverified(DecryptEventsResult result, UnverifiedKeyChangeReason reason) {
            assertEquals(Set.of("0"), result.unverifiedKeyChanges.keySet());
            UnverifiedKeyChange unverified = result.unverifiedKeyChanges.get("0");
            assertEquals(reason, unverified.reason);
            assertTrue(unverified.keyDropped);
            assertEquals(GROUP, unverified.conversationId);
            assertEquals(change.version, unverified.conversationKeyVersion);
            assertEquals("5001", unverified.senderId);
            assertEquals(KEY_VERSION, unverified.publicKeyVersion);
        }

        @Override
        public void close() {
            admin.close();
            member.close();
            bot.close();
        }
    }

    private static DecryptEventsResult decryptWith(Chat chat, List<String> events, List<SigningKeyEntry> signingKeys)
            throws Exception {
        DecryptEventsParams params = new DecryptEventsParams(events);
        params.signingKeys = signingKeys;
        return chat.decryptEvents(params);
    }

    /** The text of each message among a result's events. */
    private static List<String> texts(DecryptEventsResult result) {
        List<String> texts = new ArrayList<>();
        for (DecryptedEvent decrypted : result.events) {
            if ("Message".equals(decrypted.event.path("type").asText())) {
                texts.add(decrypted.event.path("content").path("text").asText());
            }
        }
        return texts;
    }

    /** Asserts that {@code actual} holds the keys of {@code expected}, version by version, and no other. */
    private static void assertKeys(Map<String, byte[]> expected, Map<String, byte[]> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        for (Map.Entry<String, byte[]> key : expected.entrySet()) {
            assertArrayEquals(key.getValue(), actual.get(key.getKey()));
        }
    }

    /**
     * Asserts that {@code actual} holds the keys of {@code expected}, conversation by conversation,
     * and no other.
     */
    private static void assertKeysByConversation(
            Map<String, Map<String, byte[]>> expected, Map<String, Map<String, byte[]>> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        for (Map.Entry<String, Map<String, byte[]>> keys : expected.entrySet()) {
            assertKeys(keys.getValue(), actual.get(keys.getKey()));
        }
    }

    @Test
    void keyChangeWithoutItsSignersKeysIsReportedAndItsKeyDropped() throws Exception {
        try (Page page = new Page()) {
            // The bot holds the keys of the member who wrote the message, not of the admin who
            // made the key change.
            DecryptEventsResult result = page.decrypt(page.events, page.member);

            assertTrue(result.events.isEmpty());
            assertTrue(result.conversationKeys.keys.isEmpty());
            assertTrue(result.conversationKeys.keysByConversation.isEmpty());
            assertNull(result.conversationKeys.latestVersion);
            assertTrue(result.conversationKeys.latestVersions.isEmpty());
            page.assertUnverified(result, UnverifiedKeyChangeReason.MissingSigningKey);
            assertTrue(result.undecryptableKeyChanges.isEmpty());
            assertTrue(result.rejectedSigningKeys.isEmpty());
            assertTrue(
                    result.errors.get("0").contains("no signing key for sender 5001 at public_key_version 1"),
                    result.errors.get("0"));
            assertTrue(
                    result.errors
                            .get("1")
                            .contains(
                                    "no matching key found: the key change for that version, event 0 of"
                                            + " the batch, did not verify"),
                    result.errors.get("1"));
        }
    }

    @Test
    void keyChangeCheckedWithAnotherKeyIsReportedInvalid() throws Exception {
        // A signing key under the admin's user id and key version that is not the key the admin
        // signed with.
        try (Page page = new Page();
                Party otherKey = new Party(page.admin.userId)) {
            DecryptEventsResult result = page.decrypt(page.events, page.member, otherKey);

            assertTrue(result.events.isEmpty());
            page.assertUnverified(result, UnverifiedKeyChangeReason.InvalidSignature);
            assertTrue(result.errors.get("0").contains("ECDSA mismatch"), result.errors.get("0"));
        }
    }

    @Test
    void signingKeyWithAnInvalidBindingIsReportedRejected() throws Exception {
        try (Page page = new Page()) {
            // The admin's signing key with a binding signature that is not its signature over the
            // identity key.
            SigningKeyEntry admin = page.admin.signingKey;
            SigningKeyEntry unbound = new SigningKeyEntry(
                    admin.userId,
                    admin.publicKeyVersion,
                    admin.publicKey,
                    admin.identityPublicKey,
                    page.member.signingKey.identityPublicKeySignature);
            DecryptEventsResult result =
                    decryptWith(page.bot.chat, page.events, List.of(page.member.signingKey, unbound));

            assertTrue(result.events.isEmpty());
            assertEquals(Set.of("1"), result.rejectedSigningKeys.keySet());
            RejectedSigningKey rejected = result.rejectedSigningKeys.get("1");
            assertEquals("5001", rejected.userId);
            assertEquals(KEY_VERSION, rejected.publicKeyVersion);
            page.assertUnverified(result, UnverifiedKeyChangeReason.RejectedSigningKey);
            assertTrue(
                    result.errors
                            .get("0")
                            .contains(
                                    "the signing key given for sender 5001 at public_key_version 1 was"
                                            + " rejected: its identity binding does not verify"),
                    result.errors.get("0"));
        }
    }

    @Test
    void keyChangeWithItsSignersKeysVerifiesAndItsMessagesDecrypt() throws Exception {
        try (Page page = new Page()) {
            DecryptEventsResult result = page.decrypt(page.events, page.member, page.admin);

            assertTrue(result.errors.isEmpty(), result.errors.toString());
            assertTrue(result.unverifiedKeyChanges.isEmpty());
            assertTrue(result.undecryptableKeyChanges.isEmpty());
            assertTrue(result.rejectedSigningKeys.isEmpty());
            assertEquals(2, result.events.size());
            assertEquals("KeyChange", result.events.get(0).event.path("type").asText());
            assertEquals(List.of("hello group"), texts(result));
            ConversationKeyBundle keys = result.conversationKeys;
            assertEquals(page.change.version, keys.latestVersion);
            assertEquals(Map.of(GROUP, page.change.version), keys.latestVersions);
            Map<String, byte[]> groupKeys = Map.of(page.change.version, page.change.key);
            assertKeys(groupKeys, keys.keys);
            assertKeysByConversation(Map.of(GROUP, groupKeys), keys.keysByConversation);
        }
    }

    @Test
    void keyChangeThisChatCannotDecryptIsReportedWithWhy() throws Exception {
        // A key change made for the admin and the member only: a chat whose identity is the
        // bot's finds no key for its user in it.
        try (Page page = new Page();
                Party outsider = new Party(page.bot.userId)) {
            outsider.chat.setIdentity(new SetIdentityParams(page.bot.userId, KEY_VERSION));
            KeyChange change = new KeyChange(page.admin, List.of(page.admin, page.member), GROUP);
            List<String> events =
                    List.of(change.eventB64, sentMessage(page.member, GROUP, change, "not for the bot"));
            DecryptEventsResult result = decryptWith(
                    outsider.chat, events, List.of(page.member.signingKey, page.admin.signingKey));

            assertTrue(result.events.isEmpty());
            assertTrue(result.unverifiedKeyChanges.isEmpty());
            assertEquals(Set.of("0"), result.undecryptableKeyChanges.keySet());
            UndecryptableKeyChange undecryptable = result.undecryptableKeyChanges.get("0");
            assertEquals(UndecryptableKeyChangeReason.NotARecipient, undecryptable.reason);
            assertEquals(GROUP, undecryptable.conversationId);
            assertEquals(change.version, undecryptable.conversationKeyVersion);
            assertEquals("5001", undecryptable.senderId);
            assertTrue(
                    result.errors
                            .get("1")
                            .contains(
                                    "event 0 of the batch, holds no key this chat can decrypt: it holds no"
                                            + " key for this chat's user"),
                    result.errors.get("1"));
        }
    }

    @Test
    void keysAndLatestVersionsAreReportedPerConversation() throws Exception {
        try (Page page = new Page()) {
            KeyChange other = page.otherKeyChange();
            List<String> events = List.of(page.change.eventB64, other.eventB64);
            Map<String, String> versions = Map.of(GROUP, page.change.version, OTHER_GROUP, other.version);
            Map<String, Map<String, byte[]>> keysByConversation = Map.of(
                    GROUP, Map.of(page.change.version, page.change.key),
                    OTHER_GROUP, Map.of(other.version, other.key));

            // Each conversation has its own keys and its own version to encrypt with, and no
            // single version stands for both.
            ConversationKeyBundle keys = page.decrypt(events, page.admin).conversationKeys;
            assertEquals(versions, keys.latestVersions);
            assertNull(keys.latestVersion);
            assertKeysByConversation(keysByConversation, keys.keysByConversation);
            assertKeys(Map.of(page.change.version, page.change.key, other.version, other.key), keys.keys);

            keys = page.decrypt(List.of(other.eventB64), page.admin).conversationKeys;
            assertEquals(other.version, keys.latestVersion);
            assertEquals(Map.of(OTHER_GROUP, other.version), keys.latestVersions);

            // A batch of two conversations has no single version even when only one of them has
            // a verified key change.
            String stray = sentMessage(page.admin, THIRD_GROUP, other, "hello third group");
            keys = page.decrypt(List.of(page.change.eventB64, stray), page.admin).conversationKeys;
            assertNull(keys.latestVersion);
            assertEquals(Map.of(GROUP, page.change.version), keys.latestVersions);

            // extractConversationKeys checks no signature, and reports the same way.
            ConversationKeyBundle extracted = page.bot.chat.extractConversationKeys(events);
            assertEquals(versions, extracted.latestVersions);
            assertNull(extracted.latestVersion);
            assertKeysByConversation(keysByConversation, extracted.keysByConversation);
            extracted = page.bot.chat.extractConversationKeys(List.of(other.eventB64));
            assertEquals(other.version, extracted.latestVersion);
        }
    }

    @Test
    void keysOfTwoConversationsAtOneVersionStayApart() throws Exception {
        try (Page page = new Page()) {
            KeyChange other = page.otherKeyChange();
            KeyChange sameVersion = other.atVersion(page.change.version);
            List<String> events = List.of(
                    page.change.eventB64,
                    sameVersion.eventB64,
                    sentMessage(page.admin, GROUP, page.change, "hello group"),
                    sentMessage(page.admin, OTHER_GROUP, sameVersion, "hello other group"));

            // Each message decrypts under its own conversation's key, and a lookup by version
            // alone finds neither.
            DecryptEventsResult result = page.decrypt(events, page.admin);
            assertEquals(List.of("hello group", "hello other group"), texts(result));
            assertEquals(Set.of("1"), result.errors.keySet());
            assertKeysByConversation(
                    Map.of(
                            GROUP, Map.of(page.change.version, page.change.key),
                            OTHER_GROUP, Map.of(page.change.version, other.key)),
                    result.conversationKeys.keysByConversation);
            assertTrue(result.conversationKeys.keys.isEmpty());
            UnverifiedKeyChange unverified = result.unverifiedKeyChanges.get("1");
            assertEquals(UnverifiedKeyChangeReason.InvalidSignature, unverified.reason);
            assertFalse(unverified.keyDropped);
        }
    }
}
