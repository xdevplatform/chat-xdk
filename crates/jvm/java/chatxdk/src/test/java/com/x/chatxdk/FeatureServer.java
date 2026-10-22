package com.x.chatxdk;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.x.chatxdk.Types.EncryptMessageParams;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** A local GET /2/chat/features that records each request's bucket. */
final class FeatureServer implements AutoCloseable {

    /**
     * Nothing listens here: a chat no test points at a server of its own fetches from this
     * endpoint, fails, and stays on v0.
     */
    static final String OFFLINE = "http://127.0.0.1:9/2/chat/features";

    private static FeatureServer v1Server;

    /**
     * Each server gets an endpoint of its own: the core reuses an answer per endpoint and bucket
     * for 5 minutes, and a server can get the port of one that came before it.
     */
    private static final AtomicInteger IDS = new AtomicInteger();

    private final HttpServer server;
    private final List<String> buckets = new ArrayList<>();
    private int status = 200;
    private String body;
    private long delayMs;
    final String endpoint;

    FeatureServer() throws Exception {
        this("{\"features\":{\"v1_send\":true}}");
    }

    FeatureServer(String body) throws Exception {
        this.body = body;
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
            // The answer is fixed when the request is recorded, so a test that sees the request
            // can change the next answer.
            int replyStatus;
            String replyBody;
            long replyDelay;
            synchronized (this) {
                buckets.add(bucket);
                replyStatus = status;
                replyBody = this.body;
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
        endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/" + IDS.incrementAndGet()
                + "/2/chat/features";
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

    /** Point every chat that does not set its own endpoint at {@link #OFFLINE}. */
    static void keepOffline() {
        FeatureDriver.setDefaultEndpoint(OFFLINE);
    }

    /**
     * Turn v1_send on for {@code chat} as the X API would: point its feature fetch at a local
     * server that answers it, then send until a send is v1.
     */
    static synchronized void enableV1Send(Chat chat) throws Exception {
        if (v1Server == null) {
            v1Server = new FeatureServer();
        }
        chat.configureFeatures(v1Server.endpoint, Duration.ofSeconds(2), Duration.ofHours(1), Duration.ofMillis(50));
        EncryptMessageParams send = new EncryptMessageParams("feature-switches", "turn v1 on");
        send.senderId = "1";
        send.signingKeyVersion = "1";
        send.conversationKey = new byte[32];
        send.conversationKeyVersion = "1";
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!"10".equals(chat.encryptMessage(send).signatureInfo.signatureVersion)) {
            assertTrue(System.nanoTime() < deadline, "v1_send never turned on");
            Thread.sleep(10);
        }
    }
}
