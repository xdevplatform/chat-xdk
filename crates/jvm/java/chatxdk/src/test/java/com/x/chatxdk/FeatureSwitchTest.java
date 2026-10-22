package com.x.chatxdk;

import static org.junit.jupiter.api.Assertions.*;

import com.x.chatxdk.Types.*;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Feature switches (GET /2/chat/features). Nothing is called: each chat is pointed at a local
 * server through the package-private hook, and sends show the format: signature version "7" is
 * v0, "10" is v1.
 */
class FeatureSwitchTest {

    @BeforeAll
    static void keepFeatureFetchesOffline() {
        FeatureServer.keepOffline();
    }

    /** A keyed chat whose feature fetch goes to {@code endpoint}. */
    private static Chat newChat(String endpoint, byte[] keys, long timeoutMs, long recheckMs, long firstRetryMs) {
        Chat chat = new Chat();
        chat.configureFeatures(
                endpoint, Duration.ofMillis(timeoutMs), Duration.ofMillis(recheckMs), Duration.ofMillis(firstRetryMs));
        chat.importKeys(new ImportKeysParams(keys));
        chat.setIdentity(new SetIdentityParams("1001", "1"));
        return chat;
    }

    private static Chat newChat(String endpoint, byte[] keys) {
        return newChat(endpoint, keys, 2000, 3_600_000, 50);
    }

    /** Fresh private keys, each set with its own bucket. */
    private static byte[] newKeys() throws Exception {
        try (Chat chat = new Chat()) {
            chat.generateKeypairs();
            return chat.exportKeys();
        }
    }

    /** The signature version of a send: "7" for v0, "10" for v1. */
    private static String sendVersion(Chat chat) {
        EncryptMessageParams p = new EncryptMessageParams("conv-1", "hello");
        p.conversationKey = new byte[32];
        p.conversationKeyVersion = "1";
        try {
            return chat.encryptMessage(p).signatureInfo.signatureVersion;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void waitFor(String what, BooleanSupplier condition) throws InterruptedException {
        waitFor(what, 10_000, condition);
    }

    private static void waitFor(String what, long timeoutMs, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(20);
        }
        assertTrue(condition.getAsBoolean(), "timed out waiting for " + what);
    }

    @Test
    void featureSwitchesAreNotPublicApi() {
        for (Method method : Chat.class.getMethods()) {
            assertFalse(method.getName().toLowerCase().contains("feature"), method.getName());
        }
        assertEquals(1, Chat.class.getConstructors().length);
        for (Class<?> type : Types.class.getClasses()) {
            assertFalse(type.getSimpleName().contains("Feature"), type.getSimpleName());
        }
        assertTrue(Arrays.stream(ChatNative.class.getMethods())
                .noneMatch(method -> method.getName().contains("feature")));
        assertFalse(Modifier.isPublic(FeatureNative.class.getModifiers()));
        assertFalse(Modifier.isPublic(FeatureDriver.class.getModifiers()));
    }

    @Test
    void noRequestIsMadeUntilTheFirstSend() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint, newKeys())) {
            Thread.sleep(300);
            assertEquals(List.of(), server.buckets());

            assertEquals("7", sendVersion(chat), "the first send does not wait for the answer");
            waitFor("the request", () -> server.buckets().size() == 1);
            int bucket = Integer.parseInt(server.buckets().get(0));
            assertTrue(bucket >= 0 && bucket < 10000, String.valueOf(bucket));
        }
    }

    @Test
    void v1StartsOnceTheAnswerTurnsItOn() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint, newKeys())) {
            assertEquals("7", sendVersion(chat));
            waitFor("v1", () -> sendVersion(chat).equals("10"));
            assertEquals(1, server.buckets().size());
        }
    }

    @Test
    void aSendNeverWaitsForTheRequest() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 2000);
            try (Chat chat = newChat(server.endpoint, newKeys())) {
                long started = System.nanoTime();
                assertEquals("7", sendVersion(chat));
                assertTrue(System.nanoTime() - started < Duration.ofSeconds(1).toNanos());
            }
        }
    }

    @Test
    void chatsWithOneKeyShareOneRequest() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 300);
            byte[] keys = newKeys();
            List<Chat> chats = new ArrayList<>();
            try {
                for (int i = 0; i < 4; i++) {
                    chats.add(newChat(server.endpoint, keys));
                }
                for (Chat chat : chats) {
                    assertEquals("7", sendVersion(chat));
                }
                waitFor("v1 everywhere", () -> chats.stream().allMatch(chat -> sendVersion(chat).equals("10")));
                assertEquals(1, server.buckets().size(), server.buckets().toString());

                try (Chat later = newChat(server.endpoint, keys)) {
                    assertEquals("10", sendVersion(later), "a later chat takes the answer at hand");
                }
                assertEquals(1, server.buckets().size());
            } finally {
                chats.forEach(Chat::close);
            }
        }
    }

    @Test
    void chatsWithDifferentKeysAskSeparately() throws Exception {
        try (FeatureServer server = new FeatureServer();
                Chat first = newChat(server.endpoint, newKeys());
                Chat second = newChat(server.endpoint, newKeys())) {
            sendVersion(first);
            sendVersion(second);
            waitFor("two requests", () -> server.buckets().size() == 2);
            assertNotEquals(server.buckets().get(0), server.buckets().get(1));
        }
    }

    @Test
    void anyFailureLeavesSendsOnV0() throws Exception {
        Object[][] cases = {
            {404, "{\"features\":{\"v1_send\":true}}", 0L},
            {500, "{\"features\":{\"v1_send\":true}}", 0L},
            {200, "not json", 0L},
            {200, "{\"v1_send\":true}", 0L},
            {200, "{\"features\":{\"v1_send\":\"true\"}}", 0L},
            {200, "{\"features\":{\"v1_send\":true}}" + " ".repeat(64 * 1024), 0L},
            {200, "{\"features\":{\"v1_send\":true}}", 1000L},
        };
        for (Object[] c : cases) {
            int status = (int) c[0];
            String body = (String) c[1];
            long delayMs = (long) c[2];
            String label = status + " " + body.length() + " bytes " + delayMs + " ms";
            // A server of its own: chats share an answer per endpoint and bucket, and the case
            // before may have left one.
            try (FeatureServer server = new FeatureServer()) {
                server.set(status, body, delayMs);
                try (Chat chat = newChat(server.endpoint, newKeys(), 500, 3_600_000, 60_000)) {
                    assertEquals("7", sendVersion(chat), label);
                    waitFor("the request (" + label + ")", () -> server.buckets().size() == 1);
                    Thread.sleep(delayMs > 0 ? 1200 : 200);
                    assertEquals("7", sendVersion(chat), label);
                }
            }
        }
    }

    @Test
    void anUnreachableEndpointLeavesSendsOnV0() throws Exception {
        String endpoint;
        try (FeatureServer server = new FeatureServer()) {
            endpoint = server.endpoint;
        }
        try (Chat chat = newChat(endpoint, newKeys(), 500, 3_600_000, 50)) {
            assertEquals("7", sendVersion(chat));
            Thread.sleep(500);
            assertEquals("7", sendVersion(chat));
        }
    }

    @Test
    void aRequestStillOpenAtItsTimeoutFailsAndIsRetried() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 3000);
            try (Chat chat = newChat(server.endpoint, newKeys(), 300, 3_600_000, 200)) {
                assertEquals("7", sendVersion(chat));
                waitFor("a retry", 2500, () -> server.buckets().size() >= 2);
                assertEquals("7", sendVersion(chat));
            }
        }
    }

    @Test
    void theRecheckTurnsV1OffAndNeverBackOn() throws Exception {
        byte[] keys = newKeys();
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint, keys, 2000, 300, 50)) {
            sendVersion(chat);
            waitFor("v1", () -> sendVersion(chat).equals("10"));

            server.set(200, "{\"features\":{}}", 0);
            waitFor("the re-check to turn v1 off", () -> sendVersion(chat).equals("7"));

            server.set(200, "{\"features\":{\"v1_send\":true}}", 0);
            int seen = server.buckets().size();
            waitFor("two more re-checks", () -> server.buckets().size() >= seen + 2);
            assertEquals("7", sendVersion(chat), "a running chat never sees it turn on");
            try (Chat later = newChat(server.endpoint, keys, 2000, 300, 50)) {
                assertEquals("10", sendVersion(later), "a new chat takes the latest answer");
            }
        }
    }

    @Test
    void aFailedRecheckChangesNothing() throws Exception {
        try (FeatureServer server = new FeatureServer();
                Chat chat = newChat(server.endpoint, newKeys(), 2000, 300, 50)) {
            sendVersion(chat);
            waitFor("v1", () -> sendVersion(chat).equals("10"));
            server.set(503, "", 0);
            int seen = server.buckets().size();
            waitFor("two failed re-checks", () -> server.buckets().size() >= seen + 2);
            assertEquals("10", sendVersion(chat));
        }
    }

    @Test
    void closeStopsTheRequests() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            Chat chat = newChat(server.endpoint, newKeys(), 2000, 300, 50);
            sendVersion(chat);
            waitFor("v1", () -> sendVersion(chat).equals("10"));
            chat.close();
            int seen = server.buckets().size();
            Thread.sleep(1000);
            assertEquals(seen, server.buckets().size(), "no request after close()");
        }
    }

    /** A re-checking chat that nothing references once this returns. */
    private static void startUnreferencedChat(String endpoint) throws Exception {
        Chat chat = newChat(endpoint, newKeys(), 2000, 300, 50);
        sendVersion(chat);
        waitFor("v1", () -> sendVersion(chat).equals("10"));
    }

    @Test
    void theRequestsEndWithACollectedChat() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            startUnreferencedChat(server.endpoint);
            int running = server.buckets().size();
            waitFor("a re-check", () -> server.buckets().size() > running);
            for (int i = 0; i < 5; i++) {
                System.gc();
                Thread.sleep(50);
            }
            Thread.sleep(800);
            int seen = server.buckets().size();
            Thread.sleep(1200);
            assertEquals(seen, server.buckets().size(), "no request once the chat is collected");
        }
    }
}
