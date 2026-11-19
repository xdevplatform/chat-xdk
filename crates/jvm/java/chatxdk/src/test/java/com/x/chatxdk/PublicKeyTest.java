package com.x.chatxdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.x.chatxdk.KeyChangeSignerTest.KeyChange;
import com.x.chatxdk.KeyChangeSignerTest.Party;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.x.chatxdk.KeyChangeSignerTest.GROUP;
import static com.x.chatxdk.KeyChangeSignerTest.KEY_VERSION;
import static com.x.chatxdk.KeyChangeSignerTest.sentMessage;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Other users' public keys: the signing keys a batch reports missing, the records
 * {@link Chat#addPublicKeys} stores, the lookups that are not repeated at once, the keys the
 * prepare calls read from the store, and the resolver that fetches what is missing.
 */
class PublicKeyTest {

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

    /** The record the X API returns for {@code party}'s keys. */
    private static PublicKeyRecord recordOf(Party party) {
        SigningKeyEntry key = party.signingKey;
        return new PublicKeyRecord(
                key.publicKeyVersion, key.identityPublicKey, key.publicKey, key.identityPublicKeySignature);
    }

    /** The records of {@code parties}, by user id. */
    private static Map<String, List<PublicKeyRecord>> recordsOf(Party... parties) {
        Map<String, List<PublicKeyRecord>> records = new LinkedHashMap<>();
        for (Party party : parties) {
            records.put(party.userId, List.of(recordOf(party)));
        }
        return records;
    }

    /**
     * The record of {@code party}'s keys as the X API's JSON: the key version written as
     * {@code version}, and fields the SDK does not read.
     */
    private static String apiRecord(Party party, String version) {
        SigningKeyEntry key = party.signingKey;
        return """
                {
                  "public_key_version": %s,
                  "public_key": "%s",
                  "signing_public_key": "%s",
                  "identity_public_key_signature": "%s",
                  "juicebox_config": {"max_guess_count": 20, "token_map": []},
                  "public_key_fingerprint": null
                }
                """
                .formatted(version, key.identityPublicKey, key.publicKey, key.identityPublicKeySignature);
    }

    /** A resolver that answers from the records of the parties it knows, and the user ids of each call it gets. */
    private static final class Directory implements PublicKeyResolver {
        final List<List<String>> calls = new ArrayList<>();
        private final Map<String, List<PublicKeyRecord>> known;

        Directory(Party... parties) {
            known = recordsOf(parties);
        }

        @Override
        public Map<String, List<PublicKeyRecord>> resolve(List<String> userIds) {
            calls.add(List.copyOf(userIds));
            Map<String, List<PublicKeyRecord>> found = new LinkedHashMap<>();
            for (String userId : userIds) {
                if (known.containsKey(userId)) {
                    found.put(userId, known.get(userId));
                }
            }
            return found;
        }
    }

    /**
     * An admin who rotates a group's key and sends no message, a member who sends a message under
     * that key, and the bot that receives both events.
     */
    private static final class Page implements AutoCloseable {
        final Party admin = new Party("5001");
        final Party member = new Party("5002");
        final Party bot = session("5003");
        final KeyChange change;
        final List<String> events;

        Page() throws Exception {
            change = new KeyChange(admin, List.of(admin, member, bot), GROUP);
            events = List.of(change.eventB64, sentMessage(member, GROUP, change, "hello group"));
        }

        /** The bot's decryptEvents of the page with no signing keys passed. */
        DecryptEventsResult decrypt() throws Exception {
            return bot.chat.decryptEvents(new DecryptEventsParams(events));
        }

        /** The key version the bot encrypts under in the group when the call passes no key. */
        String sendVersion() throws Exception {
            return bot.chat.encryptMessage(new EncryptMessageParams(GROUP, "hi")).conversationKeyVersion;
        }

        @Override
        public void close() {
            admin.close();
            member.close();
            bot.close();
        }
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

    /** Asserts that {@code missing} names the signing key {@code userId} signs with. */
    private static void assertMissing(MissingSigningKey missing, String userId) {
        assertEquals(userId, missing.userId);
        assertEquals(KEY_VERSION, missing.publicKeyVersion);
    }

    /** Asserts that the page decrypted: no error, no missing key, and the member's message. */
    private static void assertDecrypted(DecryptEventsResult result) {
        assertTrue(result.errors.isEmpty(), result.errors.toString());
        assertTrue(result.missingSigningKeys.isEmpty());
        assertEquals(List.of("hello group"), texts(result));
    }

    /** The users a prepared change encrypted its key to, sorted. */
    private static List<String> recipients(PreparedConversationChange prepared) {
        List<String> userIds = new ArrayList<>();
        for (ConversationParticipantKey key : prepared.conversationParticipantKeys) {
            userIds.add(key.userId);
        }
        Collections.sort(userIds);
        return userIds;
    }

    /** A prepare call made on a chat. */
    @FunctionalInterface
    private interface Prepare {
        PreparedConversationChange on(Chat chat) throws Exception;
    }

    /**
     * A prepare call of user 5001 that passes no public keys: the conversation id its result
     * carries, and the users it encrypts its key to, in the order the call names them.
     */
    private record Keyless(String name, String conversationId, List<String> members, Prepare prepare) {}

    /**
     * The four calls that make a conversation key, as user 5001 makes them with no public keys
     * in the group it shares with 5002: the create, adding 5004, removing 5004, and a key
     * rotation; then a key change in the one-to-one with 5002.
     */
    private static List<Keyless> keylessPrepares() {
        List<String> both = List.of("5001", "5002");
        GroupMembersRemoveParams removal = new GroupMembersRemoveParams(GROUP, List.of("5004"));
        removal.remainingMemberIds = both;
        ConversationKeyChangeParams rotation = new ConversationKeyChangeParams();
        rotation.conversationId = GROUP;
        rotation.memberIds = both;
        // A one-to-one names its two users by its id: here the other user's id alone.
        ConversationKeyChangeParams direct = new ConversationKeyChangeParams();
        direct.conversationId = "5002";
        return List.of(
                new Keyless(
                        "group create",
                        GROUP,
                        both,
                        chat -> chat.prepareGroupCreate(new GroupCreateParams(GROUP, both, List.of("5001")))),
                new Keyless(
                        "group members change",
                        GROUP,
                        List.of("5001", "5002", "5004"),
                        chat -> chat.prepareGroupMembersChange(new GroupMembersChangeParams(
                                GROUP, List.of("5004"), both, List.of("5001"), List.of()))),
                new Keyless("group members remove", GROUP, both, chat -> chat.prepareGroupMembersRemove(removal)),
                new Keyless("key change", GROUP, both, chat -> chat.prepareConversationKeyChange(rotation)),
                new Keyless(
                        "one-to-one key change",
                        "5001:5002",
                        both,
                        chat -> chat.prepareConversationKeyChange(direct)));
    }

    @Test
    void decryptEventsReportsTheSigningKeysItWasMissing() throws Exception {
        try (Page page = new Page()) {
            DecryptEventsResult result = page.decrypt();

            assertTrue(result.events.isEmpty());
            assertEquals(Set.of("0", "1"), result.missingSigningKeys.keySet());
            assertMissing(result.missingSigningKeys.get("0"), "5001");
            assertMissing(result.missingSigningKeys.get("1"), "5002");
            assertEquals(List.of("5001", "5002"), page.bot.chat.missingPublicKeys(result));

            // Nothing was added: neither key is asked for again at once.
            assertTrue(page.bot.chat.missingPublicKeys(result).isEmpty());

            // With the member's keys given, only the admin's is missing.
            DecryptEventsParams params = new DecryptEventsParams(page.events);
            params.signingKeys = List.of(page.member.signingKey);
            result = page.bot.chat.decryptEvents(params);
            assertEquals(Set.of("0"), result.missingSigningKeys.keySet());
            assertMissing(result.missingSigningKeys.get("0"), "5001");
        }
    }

    @Test
    void addPublicKeysStoresTheRecordsTheApiReturns() throws Exception {
        try (Page page = new Page()) {
            // The admin's key version is written as a string and the member's as a number.
            ObjectMapper mapper = new ObjectMapper();
            PublicKeyRecord admin =
                    mapper.readValue(apiRecord(page.admin, "\"" + KEY_VERSION + "\""), PublicKeyRecord.class);
            PublicKeyRecord member = mapper.readValue(apiRecord(page.member, KEY_VERSION), PublicKeyRecord.class);
            assertEquals(KEY_VERSION, admin.publicKeyVersion);
            assertEquals(KEY_VERSION, member.publicKeyVersion);
            assertEquals(page.member.signingKey.identityPublicKey, member.publicKey);
            assertEquals(page.member.signingKey.publicKey, member.signingPublicKey);
            assertEquals(page.member.signingKey.identityPublicKeySignature, member.identityPublicKeySignature);

            // No records add nothing.
            page.bot.chat.addPublicKeys(null);
            page.bot.chat.addPublicKeys(Map.of());
            assertTrue(page.decrypt().events.isEmpty());

            // A record without its signing key is left out.
            PublicKeyRecord partial = recordOf(page.admin);
            partial.signingPublicKey = "";
            page.bot.chat.addPublicKeys(Map.of("5001", List.of(partial)));
            assertTrue(page.decrypt().events.isEmpty());

            page.bot.chat.addPublicKeys(Map.of("5001", List.of(admin), "5002", List.of(member)));
            assertDecrypted(page.decrypt());
        }
    }

    @Test
    void decryptEventsFetchesMissingKeysThroughTheResolverAndDecryptsOnceMore() throws Exception {
        try (Page page = new Page()) {
            Directory directory = new Directory(page.admin, page.member);
            page.bot.chat.setResolvePublicKeys(directory);

            // Signing keys that are passed are what the call verifies with.
            DecryptEventsParams passed = new DecryptEventsParams(page.events);
            passed.signingKeys = List.of(page.member.signingKey);
            DecryptEventsResult result = page.bot.chat.decryptEvents(passed);
            assertEquals(Set.of("0"), result.missingSigningKeys.keySet());
            assertTrue(directory.calls.isEmpty());

            assertDecrypted(page.decrypt());
            assertEquals(List.of(List.of("5001", "5002")), directory.calls);

            // Setting a resolver turned the key cache on: a send that passes no key finds the
            // verified key.
            assertEquals(page.change.version, page.sendVersion());

            // The keys are stored: the next page needs no lookup.
            assertDecrypted(page.decrypt());
            assertEquals(1, directory.calls.size());

            // Removing the resolver leaves the key cache on.
            page.bot.chat.setResolvePublicKeys(null);
            assertEquals(page.change.version, page.sendVersion());
        }
    }

    @Test
    void theResolverIsNotCalledAgainForAKeyItCouldNotFind() throws Exception {
        try (Page page = new Page()) {
            // The resolver knows the admin alone.
            Directory directory = new Directory(page.admin);
            page.bot.chat.setResolvePublicKeys(directory);

            // The member's keys are not found, and the result says so.
            DecryptEventsResult result = page.decrypt();
            assertEquals(Set.of("1"), result.missingSigningKeys.keySet());
            assertMissing(result.missingSigningKeys.get("1"), "5002");
            assertEquals(List.of(List.of("5001", "5002")), directory.calls);

            // The next call does not ask again.
            result = page.decrypt();
            assertEquals(Set.of("1"), result.missingSigningKeys.keySet());
            assertEquals(1, directory.calls.size());
        }
    }

    @Test
    void aResolverThatReturnsNoRecordsLeavesTheKeysMissing() throws Exception {
        try (Page page = new Page()) {
            page.bot.chat.setResolvePublicKeys(userIds -> null);

            DecryptEventsResult result = page.decrypt();
            assertTrue(result.events.isEmpty());
            assertEquals(Set.of("0", "1"), result.missingSigningKeys.keySet());
        }
    }

    @Test
    void anExceptionTheResolverThrowsReachesTheCaller() throws Exception {
        IOException failure = new IOException("the directory is down");
        PublicKeyResolver failing = userIds -> {
            throw failure;
        };
        try (Page page = new Page()) {
            page.bot.chat.setResolvePublicKeys(failing);
            assertSame(failure, assertThrows(IOException.class, page::decrypt));
        }
        for (Keyless call : keylessPrepares()) {
            try (Party admin = session("5001")) {
                admin.chat.setResolvePublicKeys(failing);
                assertSame(
                        failure,
                        assertThrows(IOException.class, () -> call.prepare().on(admin.chat), call.name()),
                        call.name());
            }
        }
    }

    @Test
    void prepareCallsTakePublicKeysFromTheStoreWhenNoneArePassed() throws Exception {
        try (Party admin = session("5001");
                Party member = new Party("5002");
                Party joiner = new Party("5004")) {
            admin.chat.addPublicKeys(recordsOf(admin, member, joiner));

            for (Keyless call : keylessPrepares()) {
                PreparedConversationChange prepared = call.prepare().on(admin.chat);
                assertEquals(call.conversationId(), prepared.conversationId, call.name());
                assertEquals(call.members(), recipients(prepared), call.name());
            }

            // Public keys passed as null or as an empty list are read from the store too.
            List<String> both = List.of("5001", "5002");
            assertEquals(
                    both,
                    recipients(admin.chat.prepareGroupCreate(
                            new GroupCreateParams(null, GROUP, both, List.of("5001")))));
            assertEquals(
                    both,
                    recipients(admin.chat.prepareGroupCreate(
                            new GroupCreateParams(List.of(), GROUP, both, List.of("5001")))));
        }
    }

    @Test
    void prepareCallsSayWhosePublicKeysTheStoreLacks() throws Exception {
        try (Party admin = session("5001")) {
            admin.chat.addPublicKeys(recordsOf(admin));

            for (Keyless call : keylessPrepares()) {
                ChatXdkException e =
                        assertThrows(ChatXdkException.class, () -> call.prepare().on(admin.chat), call.name());
                assertEquals(ChatXdkException.Kind.INVALID_INPUT, e.getKind(), call.name());
                assertTrue(
                        e.getMessage().contains("no public keys are stored for user(s) 5002"),
                        call.name() + ": " + e.getMessage());
            }
        }
    }

    @Test
    void theResolverSuppliesThePublicKeysOfPrepareCallsThatPassNone() throws Exception {
        try (Party member = new Party("5002");
                Party joiner = new Party("5004")) {
            for (Keyless call : keylessPrepares()) {
                try (Party admin = session("5001")) {
                    Directory directory = new Directory(admin, member, joiner);
                    admin.chat.setResolvePublicKeys(directory);

                    PreparedConversationChange prepared = call.prepare().on(admin.chat);
                    assertEquals(call.members(), recipients(prepared), call.name());
                    assertEquals(List.of(call.members()), directory.calls, call.name());

                    // The keys are stored: the next call needs no lookup.
                    call.prepare().on(admin.chat);
                    assertEquals(1, directory.calls.size(), call.name());
                }
            }
        }
    }

    @Test
    void theResolverIsNotCalledForPrepareCallsThatPassTheirPublicKeys() throws Exception {
        try (Party admin = session("5001");
                Party member = new Party("5002");
                Party joiner = new Party("5004")) {
            Directory directory = new Directory(admin, member, joiner);
            admin.chat.setResolvePublicKeys(directory);
            List<PublicKeyInput> both = List.of(admin.publicKey, member.publicKey);
            ConversationKeyChangeParams rotation = new ConversationKeyChangeParams(both);
            rotation.conversationId = GROUP;

            // Public keys that are passed are used as they are.
            PreparedConversationChange created = admin.chat.prepareGroupCreate(
                    new GroupCreateParams(both, GROUP, List.of("5001", "5002"), List.of("5001")));
            assertEquals(List.of("5001", "5002"), recipients(created));
            admin.chat.prepareGroupMembersChange(new GroupMembersChangeParams(
                    List.of(admin.publicKey, member.publicKey, joiner.publicKey),
                    GROUP,
                    List.of("5004"),
                    List.of("5001", "5002"),
                    List.of("5001"),
                    List.of()));
            admin.chat.prepareGroupMembersRemove(new GroupMembersRemoveParams(both, GROUP, List.of("5004")));
            admin.chat.prepareConversationKeyChange(rotation);

            assertTrue(directory.calls.isEmpty());
        }
    }
}
