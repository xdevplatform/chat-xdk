package com.x.chatxdk;

import com.sun.net.httpserver.HttpServer;
import com.x.chatxdk.Types.*;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Feature switches (GET /2/chat/features): loadFeatureConfig against a local server, the
 * key-bucket refetch, the downgrade-only re-check, and the v0/v1 send switch.
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

        LoadFeatureConfigParams params(int refreshSeconds, int timeoutMs) {
            LoadFeatureConfigParams p = new LoadFeatureConfigParams();
            p.endpoint = endpoint;
            p.timeoutMs = timeoutMs;
            p.refreshSeconds = refreshSeconds;
            return p;
        }

        LoadFeatureConfigParams params(int refreshSeconds) {
            return params(refreshSeconds, 1000);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static Chat withKeys(Chat chat) throws Exception {
        chat.generateKeypairs();
        chat.setIdentity("1001", "1");
        return chat;
    }

    private static String sendVersion(Chat chat) throws Exception {
        PublicKeyInput input = new PublicKeyInput();
        input.userId = "1001";
        input.publicKey = chat.getPublicKeys().identity;
        input.keyVersion = "1";
        ConversationKeyChangeParams keyChange = new ConversationKeyChangeParams(List.of(input));
        keyChange.conversationId = "conv-1";
        EncryptMessageParams p = new EncryptMessageParams("conv-1", "hello");
        p.conversationKey = chat.prepareConversationKeyChange(keyChange).conversationKey;
        p.conversationKeyVersion = "1";
        SendPayload payload = chat.encryptMessage(p);
        assertFalse(payload.xdkVersion.isEmpty());
        return payload.signatureInfo.signatureVersion;
    }

    private static void waitFor(String what, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(50);
        }
        assertTrue(condition.getAsBoolean(), "timed out waiting for " + what);
    }

    @Test
    void everyFlagIsOffAndSendsAreV0BeforeAnyLoad() throws Exception {
        try (Chat chat = withKeys(new Chat())) {
            assertFalse(chat.isEnabled("v1_send"));
            assertEquals("7", sendVersion(chat));
        }
    }

    @Test
    void loadAfterKeysSendsTheKeyBucketAndSwitchesToV1() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(new Chat())) {
            Integer bucket = chat.featureBucket();
            assertNotNull(bucket);
            assertTrue(bucket >= 0 && bucket < 10000);
            assertTrue(chat.loadFeatureConfig(server.params(0)));
            assertEquals(List.of(bucket.toString()), server.buckets());
            assertTrue(chat.isEnabled("v1_send"));
            assertEquals("10", sendVersion(chat));
        }
    }

    @Test
    void unknownKeysAreReadableAndMissingKeysAreOff() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(new Chat())) {
            server.set(200, "{\"features\":{\"later_flag\":true,\"v1_send\":\"yes\"},\"extra\":1}", 0);
            assertTrue(chat.loadFeatureConfig(server.params(0)));
            assertTrue(chat.isEnabled("later_flag"));
            assertFalse(chat.isEnabled("v1_send"));
            assertFalse(chat.isEnabled("missing"));
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
        };
        for (Object[] c : cases) {
            try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(new Chat())) {
                server.set((Integer) c[0], (String) c[1], (Long) c[2]);
                String what = c[0] + " " + c[1];
                assertFalse(chat.loadFeatureConfig(server.params(0, 300)), what);
                assertFalse(chat.isEnabled("v1_send"), what);
                assertEquals("7", sendVersion(chat), what);
            }
        }
    }

    @Test
    void loadBeforeKeysRefetchesOnceWithTheKeyBucket() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = new Chat(); Chat other = new Chat()) {
            assertNull(chat.featureBucket());
            assertTrue(chat.loadFeatureConfig(server.params(0)));
            List<String> bucketless = new ArrayList<>();
            bucketless.add(null);
            assertEquals(bucketless, server.buckets());
            assertTrue(chat.isEnabled("v1_send"));

            server.set(200, "{\"features\":{\"v1_send\":false}}", 0);
            withKeys(chat);
            assertFalse(chat.isEnabled("v1_send"));
            String bucket = chat.featureBucket().toString();
            waitFor("the key-bucketed refetch",
                    () -> server.buckets().contains(bucket) && !chat.featureRefetchDue());
            assertFalse(chat.isEnabled("v1_send"));

            assertTrue(other.loadFeatureConfig(server.params(0)));
            server.set(200, "{\"features\":{\"v1_send\":true}}", 0);
            withKeys(other);
            waitFor("the refetch to turn v1_send on", () -> other.isEnabled("v1_send"));
        }
    }

    @Test
    void theRecheckTurnsFlagsOffButNeverOn() throws Exception {
        try (FeatureServer server = new FeatureServer(); Chat chat = withKeys(new Chat())) {
            assertTrue(chat.loadFeatureConfig(server.params(1)));
            server.set(200, "{\"features\":{}}", 0);
            waitFor("the re-check to turn v1_send off", () -> !chat.isEnabled("v1_send"));

            server.set(200, "{\"features\":{\"v1_send\":true}}", 0);
            int seen = server.buckets().size();
            waitFor("two more re-checks", () -> server.buckets().size() >= seen + 2);
            assertFalse(chat.isEnabled("v1_send"));

            server.set(503, "", 0);
            chat.applyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.featureBucket());
            int before = server.buckets().size();
            waitFor("two failed re-checks", () -> server.buckets().size() >= before + 2);
            assertTrue(chat.isEnabled("v1_send"));
        }
    }

    @Test
    void closeStopsTheRefresher() throws Exception {
        try (FeatureServer server = new FeatureServer()) {
            Chat chat = withKeys(new Chat());
            assertTrue(chat.loadFeatureConfig(server.params(1)));
            server.set(200, "{\"features\":{\"v1_send\":true}}", 5000);
            Thread.sleep(1200);
            chat.close();
            int seen = server.buckets().size();
            Thread.sleep(2500);
            assertEquals(seen, server.buckets().size());
            assertThrows(IllegalStateException.class, () -> chat.loadFeatureConfig(server.params(1)));
        }
    }

    @Test
    void applyFeatureConfigRejectsAMalformedBody() throws Exception {
        try (Chat chat = withKeys(new Chat())) {
            chat.applyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.featureBucket());
            assertThrows(ChatXdkException.class, () -> chat.applyFeatureConfig("[]", chat.featureBucket(), true));
            assertTrue(chat.isEnabled("v1_send"));
            chat.applyFeatureConfig("{\"features\":{}}", chat.featureBucket(), true);
            assertFalse(chat.isEnabled("v1_send"));
        }
    }
}
