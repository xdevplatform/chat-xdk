package com.example.chatbot;

import com.example.chatbot.ChatCoreTest.Party;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.x.chatxdk.ChatXdkException;
import com.x.chatxdk.Types.DecryptEventsResult;
import com.x.chatxdk.Types.PreparedConversationChange;
import com.x.chatxdk.Types.PublicKeyInput;
import com.x.chatxdk.Types.PublicKeyRecord;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Offline tests for the JVM example's multi-user helpers: one chat per
 * signed-in user, all fetching public keys with one resolver over one cache.
 *
 * <p>Like {@link ChatCoreTest}, these drive the real chatxdk binding.
 */
class MultiUserTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** How long a test waits for another thread before it fails. */
    private static final long WAIT_SECONDS = 30;

    /**
     * The page each of {@code readers} receives after {@code admin} rotates the key of the group
     * {@code conversationId}, which they and {@code member} are in, and {@code member} sends
     * {@code text} under it: the key change, then the message.
     */
    private static List<String> groupPage(
            Party admin, Party member, List<Party> readers, String conversationId, String text)
            throws Exception {
        List<PublicKeyInput> publicKeys = new ArrayList<>(List.of(admin.publicKey, member.publicKey));
        readers.forEach(reader -> publicKeys.add(reader.publicKey));
        PreparedConversationChange prepared =
                admin.core.prepareConversationKeyChange(publicKeys, conversationId);
        String keyChange = ChatCoreTest.deliveredAction(
                prepared.actionSignatures.get(0), admin.userId, conversationId, "2100000000000000000");
        ChatCore.SendBody body = member.core.encryptReply(
                conversationId, text, prepared.conversationKey, prepared.conversationKeyVersion);
        return List.of(keyChange, ChatCoreTest.delivered(body.eventB64(), "2100000000000000001"));
    }

    /** One user's records as a fake fetch returns them: one record, of key version {@code version}. */
    private static List<JsonNode> recordsOfVersion(String version) {
        return List.of(MAPPER.createObjectNode().put("public_key_version", version));
    }

    /** The key versions of the records a resolver returned, by user id. */
    private static Map<String, List<String>> versions(Map<String, List<PublicKeyRecord>> resolved) {
        Map<String, List<String>> byUser = new HashMap<>();
        resolved.forEach((userId, records) -> {
            List<String> ofUser = new ArrayList<>();
            records.forEach(key -> ofUser.add(key.publicKeyVersion));
            byUser.put(userId, ofUser);
        });
        return byUser;
    }

    @Test
    void chatsOfTwoSignedInUsersFetchTheKeysOfAUserTheyBothMeetOnce() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party alice = new Party("5003");
                Party bob = new Party("5004")) {
            List<String> asked = new ArrayList<>();
            UserChats chats = new UserChats(new SharedPublicKeys(userId -> {
                asked.add(userId);
                return List.of(userId.equals(admin.userId) ? admin.publicKeyRecord : member.publicKeyRecord);
            }));
            List<String> events = groupPage(admin, member, List.of(alice, bob), "g900", "hello group");

            try {
                for (Party signedIn : List.of(alice, bob)) {
                    ChatCore chat = chats.chatFor(signedIn.userId, signedIn.privateKeysB64, "1");
                    DecryptEventsResult page = chat.decryptBatch(events);
                    assertTrue(page.errors.isEmpty(), page.errors.toString());
                    assertTrue(page.missingSigningKeys.isEmpty());
                    assertEquals(Arrays.asList(null, "hello group"), ChatCoreTest.texts(page));
                }
                // Each chat needed the keys of the admin and the member: the
                // second chat took them from the cache the first one filled.
                assertEquals(List.of("5001", "5002"), asked);
            } finally {
                chats.close(alice.userId);
                chats.close(bob.userId);
            }
        }
    }

    @Test
    void aSignedInUserHasOneChatWhichServesEveryConversationOfTheUser() throws Exception {
        try (Party admin = new Party("5001");
                Party member = new Party("5002");
                Party alice = new Party("5003");
                Party bob = new Party("5004")) {
            UserChats chats = new UserChats(new SharedPublicKeys(userId ->
                    List.of(userId.equals(admin.userId) ? admin.publicKeyRecord : member.publicKeyRecord)));
            try {
                ChatCore chat = chats.chatFor(alice.userId, alice.privateKeysB64, "1");
                assertSame(chat, chats.chatFor(alice.userId, alice.privateKeysB64, "1"));
                assertNotSame(chat, chats.chatFor(bob.userId, bob.privateKeysB64, "1"));

                for (String conversationId : List.of("g900", "g901")) {
                    String text = "hello " + conversationId;
                    DecryptEventsResult page =
                            chat.decryptBatch(groupPage(admin, member, List.of(alice), conversationId, text));
                    assertTrue(page.errors.isEmpty(), page.errors.toString());
                    assertEquals(Arrays.asList(null, text), ChatCoreTest.texts(page));
                    // The reply takes the conversation's key from the chat's key cache.
                    ChatCore.SendBody body = chat.encryptReply(conversationId, "hi", null, null);
                    assertFalse(body.encodedMessageCreateEvent().isEmpty());
                }
                // The chat holds no key for a conversation it has not read.
                ChatXdkException noKey = assertThrows(
                        ChatXdkException.class, () -> chat.encryptReply("g902", "hi", null, null));
                assertEquals(ChatXdkException.Kind.INVALID_STATE, noKey.getKind());

                // After a sign-out, the next sign-in makes another chat.
                chats.close(alice.userId);
                assertNotSame(chat, chats.chatFor(alice.userId, alice.privateKeysB64, "1"));
            } finally {
                chats.close(alice.userId);
                chats.close(bob.userId);
            }
        }
    }

    @Test
    void sharedPublicKeysRetriesAFailedLookupAndFetchesAgainAfterTheTtl() {
        AtomicLong time = new AtomicLong(1_000);
        AtomicBoolean failing = new AtomicBoolean(true);
        List<String> asked = new ArrayList<>();
        SharedPublicKeys shared = new SharedPublicKeys(
                userId -> {
                    asked.add(userId);
                    if (userId.equals("7") && failing.get()) {
                        throw new IllegalStateException("x api GET public_keys: 503");
                    }
                    // The key version of an answer is the number of the fetch that brought it.
                    return recordsOfVersion(String.valueOf(asked.size()));
                },
                Duration.ofMillis(100),
                time::get);

        // A lookup that fails leaves its user out and the other user in, and
        // is not kept: the next call fetches again.
        assertEquals(Map.of("5", List.of("1")), versions(shared.resolve(List.of("5", "7"))));
        failing.set(false);
        assertEquals(Map.of("7", List.of("3")), versions(shared.resolve(List.of("7"))));
        assertEquals(List.of("5", "7", "7"), asked);

        // An answer is served until its time is up, then fetched again.
        time.addAndGet(99);
        assertEquals(Map.of("5", List.of("1")), versions(shared.resolve(List.of("5"))));
        assertEquals(3, asked.size());
        time.addAndGet(1);
        assertEquals(Map.of("5", List.of("4")), versions(shared.resolve(List.of("5"))));
        assertEquals(4, asked.size());
    }

    @Test
    void sharedPublicKeysSharesALookupUnderWay() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // Each lookup reads the clock once, before it looks in the cache.
        CountDownLatch lookedUp = new CountDownLatch(2);
        AtomicInteger fetches = new AtomicInteger();
        SharedPublicKeys shared = new SharedPublicKeys(
                userId -> {
                    fetches.incrementAndGet();
                    started.countDown();
                    release.await();
                    return recordsOfVersion("1");
                },
                Duration.ofMillis(100),
                () -> {
                    lookedUp.countDown();
                    return 1_000;
                });

        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<Map<String, List<PublicKeyRecord>>> first =
                    callers.submit(() -> shared.resolve(List.of("5")));
            // The second caller asks while the first caller's fetch is held.
            assertTrue(started.await(WAIT_SECONDS, TimeUnit.SECONDS));
            Future<Map<String, List<PublicKeyRecord>>> second =
                    callers.submit(() -> shared.resolve(List.of("5")));
            // The fetch is held until the second caller is at the cache. The
            // outcome is the same if the wait runs out first: the second
            // caller then finds the answer in the cache.
            lookedUp.await(WAIT_SECONDS, TimeUnit.SECONDS);
            release.countDown();

            assertEquals(Map.of("5", List.of("1")), versions(first.get(WAIT_SECONDS, TimeUnit.SECONDS)));
            assertEquals(Map.of("5", List.of("1")), versions(second.get(WAIT_SECONDS, TimeUnit.SECONDS)));
            assertEquals(1, fetches.get());
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
    }
}
