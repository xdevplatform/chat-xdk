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

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Chat#decryptEvents} and the members who sign a batch's key changes: a key change needs
 * its signer's keys to verify, the result says which key changes did not verify and why, and the
 * version to encrypt with is reported per conversation.
 */
class KeyChangeSignerTest {

    /** A sequence id past the cut-over, where a key change that does not verify has its key dropped. */
    private static final String ENFORCED_SEQUENCE = "2100000000000000000";

    private static final String GROUP = "g900";
    private static final String OTHER_GROUP = "g901";
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
            eventB64 = deliveredAction(
                    prepared.actionSignatures.get(0), signer.userId, conversationId, ENFORCED_SEQUENCE);
            key = prepared.conversationKey;
            version = prepared.conversationKeyVersion;
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
            DecryptEventsParams params = new DecryptEventsParams(events);
            List<SigningKeyEntry> signingKeys = new ArrayList<>();
            for (Party signer : signers) {
                signingKeys.add(signer.signingKey);
            }
            params.signingKeys = signingKeys;
            return bot.chat.decryptEvents(params);
        }

        @Override
        public void close() {
            admin.close();
            member.close();
            bot.close();
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
            assertNull(result.conversationKeys.latestVersion);
            assertTrue(result.conversationKeys.latestVersions.isEmpty());
            assertEquals(1, result.unverifiedKeyChanges.size());
            UnverifiedKeyChange unverified = result.unverifiedKeyChanges.get(0);
            assertEquals(0, unverified.index);
            assertEquals(UnverifiedKeyChangeReason.MissingSigningKey, unverified.reason);
            assertTrue(unverified.keyDropped);
            assertEquals(GROUP, unverified.conversationId);
            assertEquals(page.change.version, unverified.conversationKeyVersion);
            assertEquals("5001", unverified.senderId);
            assertEquals(KEY_VERSION, unverified.publicKeyVersion);
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
            assertEquals(1, result.unverifiedKeyChanges.size());
            UnverifiedKeyChange unverified = result.unverifiedKeyChanges.get(0);
            assertEquals(UnverifiedKeyChangeReason.InvalidSignature, unverified.reason);
            assertTrue(unverified.keyDropped);
            assertTrue(result.errors.get("0").contains("ECDSA mismatch"), result.errors.get("0"));
        }
    }

    @Test
    void keyChangeWithItsSignersKeysVerifiesAndItsMessagesDecrypt() throws Exception {
        try (Page page = new Page()) {
            DecryptEventsResult result = page.decrypt(page.events, page.member, page.admin);

            assertTrue(result.errors.isEmpty(), result.errors.toString());
            assertTrue(result.unverifiedKeyChanges.isEmpty());
            assertEquals(2, result.events.size());
            assertEquals("KeyChange", result.events.get(0).event.path("type").asText());
            assertEquals("Message", result.events.get(1).event.path("type").asText());
            assertEquals("hello group", result.events.get(1).event.path("content").path("text").asText());
            assertEquals(page.change.version, result.conversationKeys.latestVersion);
            assertEquals(Map.of(GROUP, page.change.version), result.conversationKeys.latestVersions);
        }
    }

    @Test
    void latestVersionsAreReportedPerConversation() throws Exception {
        try (Page page = new Page()) {
            List<Party> members = List.of(page.admin, page.bot);
            KeyChange other = new KeyChange(page.admin, members, OTHER_GROUP);
            while (other.version.equals(page.change.version)) {
                other = new KeyChange(page.admin, members, OTHER_GROUP);
            }
            List<String> events = List.of(page.change.eventB64, other.eventB64);
            Map<String, String> versions = Map.of(GROUP, page.change.version, OTHER_GROUP, other.version);

            // Each conversation has its own version to encrypt with, and no single one stands for
            // both.
            DecryptEventsResult result = page.decrypt(events, page.admin);
            assertTrue(result.errors.isEmpty(), result.errors.toString());
            assertEquals(versions, result.conversationKeys.latestVersions);
            assertNull(result.conversationKeys.latestVersion);

            result = page.decrypt(List.of(other.eventB64), page.admin);
            assertEquals(other.version, result.conversationKeys.latestVersion);
            assertEquals(Map.of(OTHER_GROUP, other.version), result.conversationKeys.latestVersions);

            // extractConversationKeys checks no signature: its latestVersion is the batch's
            // highest, and latestVersions each conversation's.
            ConversationKeyBundle extracted = page.bot.chat.extractConversationKeys(events);
            assertEquals(versions, extracted.latestVersions);
            long highest = Math.max(Long.parseLong(page.change.version), Long.parseLong(other.version));
            assertEquals(String.valueOf(highest), extracted.latestVersion);
        }
    }
}
