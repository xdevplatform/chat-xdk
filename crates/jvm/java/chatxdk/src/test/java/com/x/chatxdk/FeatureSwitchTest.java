package com.x.chatxdk;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.Headers;
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
 * Feature switches (GET /2/chat/features). Nothing is called: each chat reads from a local server
 * through the package-private constructor, and sends show the format: signature version "7" is
 * v0, "10" is v1.
 */
class FeatureSwitchTest {

    @BeforeAll
    static void keepFeatureReadsOffline() {
        FeatureServer.keepOffline();
    }

    /** A keyed chat that reads its feature switches from {@code endpoint}. */
    private static Chat newChat(String endpoint, long timeoutMs) throws Exception {
        Chat chat = new Chat(endpoint, Duration.ofMillis(timeoutMs));
        chat.generateKeypairs();
        chat.setIdentity(new SetIdentityParams("1001", "1"));
        return chat;
    }

    private static Chat newChat(String endpoint) throws Exception {
        return newChat(endpoint, 2000);
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
        long deadline = System.currentTimeMillis() + 10_000;
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
        assertFalse(Modifier.isPublic(FeatureFetch.class.getModifiers()));
    }

    @Test
    void aNewChatReadsTheSwitchesOnce() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint)) {
            waitFor("the request", () -> server.queries().size() == 1);
            assertEquals("", server.queries().get(0), "the request carries no query");
            waitFor("v1", () -> sendVersion(chat).equals("10"));
            chat.generateKeypairs();
            chat.setIdentity(new SetIdentityParams("1001", "1"));
            for (int i = 0; i < 5; i++) {
                sendVersion(chat);
            }
            Thread.sleep(300);
            assertEquals(1, server.queries().size(), server.queries().toString());
        }
    }

    @Test
    void thePublicConstructorReadsTheDefaultEndpoint() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            FeatureFetch.setDefaultEndpoint(server.endpoint);
            try (Chat chat = new Chat()) {
                waitFor("the request", () -> server.queries().size() == 1);
                chat.generateKeypairs();
                chat.setIdentity(new SetIdentityParams("1001", "1"));
                waitFor("v1", () -> sendVersion(chat).equals("10"));
            } finally {
                FeatureServer.keepOffline();
            }
        }
    }

    @Test
    void aSendNeverWaitsForTheRequest() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 2000);
            try (Chat chat = newChat(server.endpoint, 3000)) {
                long started = System.nanoTime();
                assertEquals("7", sendVersion(chat));
                assertTrue(System.nanoTime() - started < Duration.ofSeconds(1).toNanos());
            }
        }
    }

    @Test
    void chatsCreatedWhileARequestIsInFlightShareIt() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 800);
            List<Chat> chats = new ArrayList<>();
            try {
                for (int i = 0; i < 4; i++) {
                    chats.add(newChat(server.endpoint));
                }
                waitFor("v1 everywhere", () -> chats.stream().allMatch(chat -> sendVersion(chat).equals("10")));
                assertEquals(1, server.queries().size(), server.queries().toString());

                try (Chat later = newChat(server.endpoint)) {
                    waitFor("the later chat to ask for itself", () -> server.queries().size() == 2);
                    waitFor("v1 for the later chat", () -> sendVersion(later).equals("10"));
                }
            } finally {
                chats.forEach(Chat::close);
            }
        }
    }

    @Test
    void theAnswerHoldsForTheChatsLifetime() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint)) {
            waitFor("v1", () -> sendVersion(chat).equals("10"));
            server.set(200, "{\"features\":{}}", 0);
            try (Chat other = newChat(server.endpoint)) {
                waitFor("the second request", () -> server.queries().size() == 2);
                Thread.sleep(200);
                assertEquals("7", sendVersion(other), "the second chat reads its own answer");
                assertEquals("10", sendVersion(chat), "the first chat's answer holds");
            }
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
            try (FeatureServer server = new FeatureServer()) {
                server.set(status, body, delayMs);
                try (Chat chat = newChat(server.endpoint, 500)) {
                    waitFor("the request (" + label + ")", () -> server.queries().size() == 1);
                    Thread.sleep(delayMs + 200);
                    assertEquals("7", sendVersion(chat), label);
                    assertEquals(1, server.queries().size(), "a failure is not retried (" + label + ")");
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
        try (Chat chat = newChat(endpoint, 500)) {
            Thread.sleep(700);
            assertEquals("7", sendVersion(chat));
        }
    }

    @Test
    void aRequestStillOpenAtItsTimeoutFails() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 3000);
            try (Chat chat = newChat(server.endpoint, 300)) {
                Thread.sleep(1000);
                assertEquals("7", sendVersion(chat));
                assertEquals(1, server.queries().size());
            }
        }
    }

    /** A chat that nothing references once this returns. */
    private static void startUnreferencedChat(String endpoint) throws Exception {
        newChat(endpoint);
    }

    @Test
    void aRequestEndsSafelyForAClosedOrCollectedChat() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 800);
            newChat(server.endpoint).close();
            startUnreferencedChat(server.endpoint);
            System.gc();
            try (Chat kept = newChat(server.endpoint)) {
                waitFor("v1", () -> sendVersion(kept).equals("10"));
                assertEquals(1, server.queries().size());
            }
        }
    }

    @Test
    void theReadSendsNoCookiesOrCredentials() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.setCookie("session=from-the-first-answer; Path=/");
            try (Chat first = newChat(server.endpoint)) {
                waitFor("the first answer", () -> sendVersion(first).equals("10"));
            }
            try (Chat second = newChat(server.endpoint)) {
                waitFor("the second request", () -> server.queries().size() == 2);
                waitFor("the second answer", () -> sendVersion(second).equals("10"));
            }
            for (Headers headers : server.headers()) {
                assertNull(headers.getFirst("Cookie"), "the read sends no cookie");
                assertNull(headers.getFirst("Authorization"), "the read sends no credentials");
            }
        }
    }

    @Test
    void aRedirectIsNotFollowed() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.redirect();
            try (Chat chat = newChat(server.endpoint, 500)) {
                waitFor("the request", () -> server.queries().size() == 1);
                Thread.sleep(700);
                assertEquals("7", sendVersion(chat), "a redirect is a failed read");
                assertEquals(0, server.followedRedirects(), "the redirect is not followed");
            }
        }
    }
}
