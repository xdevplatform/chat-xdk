package com.x.chatxdk;

import com.sun.net.httpserver.HttpServer;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Feature switches (GET /2/chat/features). Nothing is called: every Chat fetches by itself, here
 * created through the package-private constructor that points it at a local server with shorter
 * timings, and the flags are read through the package-private accessors.
 */
class FeatureSwitchTest {

    /** A local GET /2/chat/features that records each request's bucket (null when none). */
    private static final class FeatureServer implements AutoCloseable {
        private final HttpServer server;
        private final List<String> buckets = new ArrayList<>();
        private int status = 200;
        private String body = "{\"features\":{\"v1_send\":true}}";
        private long delayMs;
        final String endpoint;

        FeatureServer() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String query = exchange.getRequestURI().getQuery();
                String bucket = null;
                if (query != null) {
                    for (String pair : query.split("&")) {
                        if (pair.startsWith("bucket=")) {
                            bucket = pair.substring("bucket=".length());
                        }
                    }
                }
                // The answer is fixed when the request is recorded, so a test that sees the
                // request can change the next answer.
                int replyStatus;
                String replyBody;
                long replyDelay;
                synchronized (this) {
                    buckets.add(bucket);
                    replyStatus = status;
                    replyBody = body;
                    replyDelay = delayMs;
                }
                try {
                    if (replyDelay > 0) {
                        Thread.sleep(replyDelay);
                    }
                    byte[] bytes = replyBody.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(replyStatus, bytes.length == 0 ? -1 : bytes.length);
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(bytes);
                    }
                } catch (Exception e) {
                    // The client gave up (timeout or close).
                } finally {
                    exchange.close();
                }
            });
            server.setExecutor(Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }));
            server.start();
            endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/2/chat/features";
        }

        synchronized void set(int status, String body, long delayMs) {
            this.status = status;
            this.body = body;
            this.delayMs = delayMs;
        }

        synchronized List<String> buckets() {
            return new ArrayList<>(buckets);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** A chat whose feature fetches go to {@code endpoint}. */
    private static Chat newChat(String endpoint, long refreshMs, long timeoutMs) {
        return new Chat(new FeatureSwitches.Options(
                endpoint, Duration.ofMillis(timeoutMs), Duration.ofMillis(refreshMs), Duration.ofMillis(20)));
    }

    private static Chat newChat(String endpoint) {
        return newChat(endpoint, 3_600_000, 500);
    }

    private static Chat withKeys(Chat chat) throws Exception {
        chat.generateKeypairs();
        chat.setIdentity("1001", "1");
        return chat;
    }

    private static SendPayload send(Chat chat) throws Exception {
        PublicKeyInput input = new PublicKeyInput();
        input.userId = "1001";
        input.publicKey = chat.getPublicKeys().identity;
        input.keyVersion = "1";
        ConversationKeyChangeParams keyChange = new ConversationKeyChangeParams(List.of(input));
        keyChange.conversationId = "conv-1";
        EncryptMessageParams p = new EncryptMessageParams("conv-1", "hello");
        p.conversationKey = chat.prepareConversationKeyChange(keyChange).conversationKey;
        p.conversationKeyVersion = "1";
        return chat.encryptMessage(p);
    }

    private static String sendVersion(Chat chat) throws Exception {
        return send(chat).signatureInfo.signatureVersion;
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

    /** Wait for a request carrying the chat's key bucket. */
    private static void keyedRequest(FeatureServer server, Chat chat) throws InterruptedException {
        String bucket = chat.featureBucket().toString();
        waitFor("a request with bucket " + bucket, () -> server.buckets().contains(bucket));
    }

    private static List<String> list(String... buckets) {
        return new ArrayList<>(Arrays.asList(buckets));
    }

    @Test
    void featureSwitchesAreNotPublicApi() {
        Set<String> removed = Set.of(
                "loadFeatureConfig", "isEnabled", "featureBucket", "applyFeatureConfig", "featureRefetchDue");
        for (Method method : Chat.class.getMethods()) {
            assertFalse(removed.contains(method.getName()), method.getName());
        }
        for (Field field : Chat.class.getFields()) {
            assertNotEquals("FEATURES_ENDPOINT", field.getName());
        }
        assertEquals(1, Chat.class.getConstructors().length);
        for (Class<?> type : Types.class.getClasses()) {
            assertNotEquals("LoadFeatureConfigParams", type.getSimpleName());
        }
        Set<String> natives = Arrays.stream(ChatNative.class.getMethods())
                .map(Method::getName)
                .collect(Collectors.toSet());
        assertTrue(natives.stream().noneMatch(name -> name.contains("feature") || name.contains("enabled")), natives.toString());
        assertFalse(Modifier.isPublic(FeatureNative.class.getModifiers()));
        assertFalse(Modifier.isPublic(FeatureSwitches.class.getModifiers()));
    }

    @Test
    void creatingAChatNeverWaitsForTheFetch() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 2000);
            long started = System.currentTimeMillis();
            try (Chat chat = newChat(server.endpoint, 3_600_000, 5000)) {
                long elapsed = System.currentTimeMillis() - started;
                assertTrue(elapsed < 1000, "took " + elapsed + " ms");
                withKeys(chat);
                assertEquals("7", sendVersion(chat));
            }
        }
    }

    @Test
    void everyFlagIsOffAndSendsAreV0UntilAResponseApplies() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(503, "", 0);
            try (Chat chat = withKeys(newChat(server.endpoint))) {
                keyedRequest(server, chat);
                assertFalse(chat.isEnabled("v1_send"));
                SendPayload payload = send(chat);
                assertEquals("7", payload.signatureInfo.signatureVersion);
                assertFalse(payload.xdkVersion.isEmpty());
            }
        }
    }

    @Test
    void aChatFetchesOnCreationAndAgainWithTheKeyBucket() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = newChat(server.endpoint)) {
            assertNull(chat.featureBucket());
            waitFor("the request on creation", () -> server.buckets().size() == 1);
            assertEquals(list((String) null), server.buckets());

            withKeys(chat);
            int bucket = chat.featureBucket();
            assertTrue(bucket >= 0 && bucket < 10000);
            keyedRequest(server, chat);
            waitFor("v1_send on", () -> chat.isEnabled("v1_send"));
            assertFalse(chat.featureRefetchDue());
            assertEquals(list(null, Integer.toString(bucket)), server.buckets());
            assertEquals("10", sendVersion(chat));
        }
    }

    @Test
    void keysLoadedBeforeTheFirstAnswerStillGetTheKeyBucket() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 200);
            try (Chat chat = withKeys(newChat(server.endpoint))) {
                waitFor("v1_send on", () -> chat.isEnabled("v1_send"));
                List<String> buckets = server.buckets();
                assertEquals(chat.featureBucket().toString(), buckets.get(buckets.size() - 1));
            }
        }
    }

    @Test
    void theKeyBucketAnswerReplacesTheIpAnswer() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            // An IP-bucketed "on" reads off once keys load, and the key's own answer decides.
            try (Chat first = newChat(server.endpoint)) {
                waitFor("the IP answer", () -> first.isEnabled("v1_send"));
                server.set(200, "{\"features\":{\"v1_send\":false}}", 0);
                withKeys(first);
                assertFalse(first.isEnabled("v1_send"));
                keyedRequest(server, first);
                waitFor("the key answer", () -> !first.featureRefetchDue());
                assertFalse(first.isEnabled("v1_send"));
            }

            // ...and the key's answer can turn a flag on that the IP answer left off.
            server.set(200, "{\"features\":{\"v1_send\":false,\"ip_answer\":true}}", 0);
            try (Chat second = newChat(server.endpoint)) {
                waitFor("the IP answer", () -> second.isEnabled("ip_answer"));
                server.set(200, "{\"features\":{\"v1_send\":true}}", 0);
                withKeys(second);
                waitFor("the key answer", () -> second.isEnabled("v1_send"));
                assertFalse(second.isEnabled("ip_answer"));
            }
        }
    }

    @Test
    void unknownKeysAreReadableAndMissingKeysAreOff() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"later_flag\":true,\"v1_send\":\"yes\"},\"extra\":1}", 0);
            try (Chat chat = withKeys(newChat(server.endpoint))) {
                waitFor("later_flag on", () -> chat.isEnabled("later_flag"));
                assertFalse(chat.isEnabled("v1_send"));
                assertFalse(chat.isEnabled("missing"));
            }
        }
    }

    @Test
    void anyFailureLeavesEveryFlagOff() throws Exception {
        Object[][] cases = {
            {404, "{\"features\":{\"v1_send\":true}}", 0L},
            {500, "{\"features\":{\"v1_send\":true}}", 0L},
            {200, "not json", 0L},
            {200, "{\"v1_send\":true}", 0L},
            {200, "{\"features\":{\"v1_send\":true}}", 1500L},
            {200, "{\"features\":{\"v1_send\":true}}" + " ".repeat(64 * 1024), 0L},
        };
        for (Object[] c : cases) {
            long delayMs = (Long) c[2];
            String body = (String) c[1];
            String what = c[0] + " " + body.substring(0, Math.min(40, body.length()))
                    + " (" + body.length() + " bytes) " + delayMs;
            try (FeatureServer server = new FeatureServer()) {
                server.set((Integer) c[0], (String) c[1], delayMs);
                try (Chat chat = withKeys(newChat(server.endpoint))) {
                    keyedRequest(server, chat);
                    Thread.sleep(delayMs > 0 ? 600 : 100);
                    assertFalse(chat.isEnabled("v1_send"), what);
                    assertEquals("7", sendVersion(chat), what);
                }
            }
        }
    }

    @Test
    void anUnreachableEndpointLeavesEveryFlagOff() throws Exception {
        String endpoint;
        try (FeatureServer server = new FeatureServer()) {
            endpoint = server.endpoint;
        }
        try (Chat chat = withKeys(newChat(endpoint))) {
            Thread.sleep(300);
            assertFalse(chat.isEnabled("v1_send"));
            assertTrue(chat.featureRefetchDue());
            assertEquals("7", sendVersion(chat));
        }
    }

    @Test
    void theRecheckTurnsFlagsOffButNeverOn() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(newChat(server.endpoint, 300, 500))) {
            waitFor("v1_send on", () -> chat.isEnabled("v1_send"));

            server.set(200, "{\"features\":{}}", 0);
            waitFor("the re-check to turn v1_send off", () -> !chat.isEnabled("v1_send"));
            assertEquals("7", sendVersion(chat));

            server.set(200, "{\"features\":{\"v1_send\":true}}", 0);
            int seen = server.buckets().size();
            waitFor("two more re-checks", () -> server.buckets().size() >= seen + 2);
            assertFalse(chat.isEnabled("v1_send"));
        }
    }

    @Test
    void aFailedRecheckChangesNothing() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(newChat(server.endpoint, 300, 500))) {
            waitFor("v1_send on", () -> chat.isEnabled("v1_send"));
            server.set(503, "", 0);
            int seen = server.buckets().size();
            waitFor("two failed re-checks", () -> server.buckets().size() >= seen + 2);
            assertTrue(chat.isEnabled("v1_send"));
        }
    }

    @Test
    void closeStopsTheFetches() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            Chat chat = withKeys(newChat(server.endpoint, 300, 10_000));
            waitFor("v1_send on", () -> chat.isEnabled("v1_send"));
            server.set(200, "{\"features\":{\"v1_send\":true}}", 5000);
            Thread.sleep(400);
            chat.close();
            int seen = server.buckets().size();
            Thread.sleep(1000);
            assertEquals(seen, server.buckets().size());
        }
    }

    /** A keyed, re-checking chat that nothing references once this returns. */
    private static void startUnreferencedChat(String endpoint) throws Exception {
        Chat chat = withKeys(newChat(endpoint, 300, 500));
        waitFor("v1_send on", () -> chat.isEnabled("v1_send"));
    }

    @Test
    void theFetchesEndWithAnUnreferencedChat() throws Exception {
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
            assertEquals(seen, server.buckets().size());
        }
    }

    private static long featureThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().equals("chat-xdk-features"))
                .count();
    }

    /** Keyed chats that nothing references once this returns, re-checking hourly. */
    private static void startUnreferencedKeyedChats(String endpoint, int count) throws Exception {
        for (int i = 0; i < count; i++) {
            Chat chat = withKeys(newChat(endpoint, 3_600_000, 500));
            waitFor("the key answer", () -> !chat.featureRefetchDue());
        }
    }

    @Test
    void aCollectedChatStopsItsThreadWithoutWaitingForTheRecheck() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            long baseline = featureThreads();
            startUnreferencedKeyedChats(server.endpoint, 3);
            assertEquals(baseline + 3, featureThreads());
            for (int i = 0; i < 20 && featureThreads() > baseline; i++) {
                System.gc();
                Thread.sleep(100);
            }
            waitFor("the threads to end", () -> featureThreads() == baseline);
        }
    }

    @Test
    void chatsAskingAtOnceShareARequest() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            server.set(200, "{\"features\":{\"v1_send\":true}}", 300);
            List<Chat> chats = new ArrayList<>();
            try {
                for (int i = 0; i < 4; i++) {
                    chats.add(newChat(server.endpoint));
                }
                waitFor("the IP answer", () -> chats.stream().allMatch(c -> c.isEnabled("v1_send")));
                assertEquals(list((String) null), server.buckets());

                chats.get(0).generateKeypairs();
                byte[] keys = chats.get(0).exportKeys();
                for (Chat chat : chats.subList(1, chats.size())) {
                    chat.importKeys(keys);
                }
                waitFor("the key answer", () -> chats.stream().noneMatch(Chat::featureRefetchDue));
                assertEquals(list(null, chats.get(0).featureBucket().toString()), server.buckets());
            } finally {
                chats.forEach(Chat::close);
            }
        }
    }

    @Test
    void aMalformedBodyIsRejectedAndChangesNothing() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            // The fetch never applies anything, so only the calls below change the flags.
            server.set(503, "", 0);
            try (Chat chat = withKeys(newChat(server.endpoint))) {
                keyedRequest(server, chat);
                Integer bucket = chat.featureBucket();
                chat.applyFeatureConfig("{\"features\":{\"v1_send\":true}}", bucket);
                assertThrows(ChatXdkException.class, () -> chat.applyFeatureConfig("[]", bucket, true));
                assertTrue(chat.isEnabled("v1_send"));
                chat.applyFeatureConfig("{\"features\":{}}", bucket, true);
                assertFalse(chat.isEnabled("v1_send"));
            }
        }
    }
}
