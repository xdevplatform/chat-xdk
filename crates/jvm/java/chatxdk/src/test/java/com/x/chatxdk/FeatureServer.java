package com.x.chatxdk;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
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

/**
 * A local GET /2/chat/features that records each request's query string and headers. Its
 * {@link #REDIRECT_TARGET} path answers that v1_send is on, for the tests that check a redirect to it
 * is not followed. A request for another path, such as a retry of a server that had this port
 * before, gets a 404 and is not recorded.
 */
final class FeatureServer implements AutoCloseable {

    /**
     * Nothing listens here: a chat no test points at a server of its own reads its feature
     * switches from this endpoint, fails, and stays on v0.
     */
    static final String OFFLINE = "http://127.0.0.1:9/2/chat/features";

    static final String REDIRECT_TARGET = "/followed/2/chat/features";

    private static FeatureServer v1Server;

    /**
     * Each server gets an endpoint of its own: chats created while a GET for their endpoint is in
     * flight share it, and a server can get the port of one that came before it.
     */
    private static final AtomicInteger IDS = new AtomicInteger();

    private final HttpServer server;
    private final List<String> queries = new ArrayList<>();
    private final List<Headers> headers = new ArrayList<>();
    private int status = 200;
    private String body;
    private long delayMs;
    private String location;
    private String setCookie;
    private int followed;
    final String endpoint;

    FeatureServer() throws Exception {
        this("{\"features\":{\"v1_send\":true}}");
    }

    FeatureServer(String body) throws Exception {
        this.body = body;
        String path = "/" + IDS.incrementAndGet() + "/2/chat/features";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(REDIRECT_TARGET, exchange -> {
            synchronized (this) {
                followed++;
            }
            byte[] bytes = "{\"features\":{\"v1_send\":true}}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            } finally {
                exchange.close();
            }
        });
        server.createContext("/", exchange -> {
            if (!path.equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            String query = exchange.getRequestURI().getRawQuery();
            // The answer is fixed when the request is recorded, so a test that sees the request
            // can change the next answer.
            int replyStatus;
            String replyBody;
            long replyDelay;
            String replyLocation;
            String replyCookie;
            synchronized (this) {
                queries.add(query == null ? "" : query);
                Headers seen = new Headers();
                seen.putAll(exchange.getRequestHeaders());
                headers.add(seen);
                replyStatus = status;
                replyBody = this.body;
                replyDelay = delayMs;
                replyLocation = location;
                replyCookie = setCookie;
            }
            try {
                if (replyDelay > 0) {
                    Thread.sleep(replyDelay);
                }
                byte[] bytes = replyBody.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                if (replyLocation != null) {
                    exchange.getResponseHeaders().add("Location", replyLocation);
                }
                if (replyCookie != null) {
                    exchange.getResponseHeaders().add("Set-Cookie", replyCookie);
                }
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
        endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    synchronized void set(int status, String body, long delayMs) {
        this.status = status;
        this.body = body;
        this.delayMs = delayMs;
    }

    synchronized List<String> queries() {
        return new ArrayList<>(queries);
    }

    synchronized List<Headers> headers() {
        return new ArrayList<>(headers);
    }

    /** Answer each request with a redirect to {@link #REDIRECT_TARGET} on this server. */
    synchronized void redirect() {
        status = 302;
        location = "http://127.0.0.1:" + server.getAddress().getPort() + REDIRECT_TARGET;
    }

    synchronized void setCookie(String cookie) {
        setCookie = cookie;
    }

    /** How many requests reached {@link #REDIRECT_TARGET}. */
    synchronized int followedRedirects() {
        return followed;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    /** Point every chat that does not set its own endpoint at {@link #OFFLINE}. */
    static void keepOffline() {
        FeatureFetch.setDefaultEndpoint(OFFLINE);
    }

    /**
     * A chat whose feature switches turn v1_send on, as the X API would: it reads them from a
     * local server that answers so. {@link #waitForV1} waits for the answer.
     */
    static synchronized Chat v1Chat() throws Exception {
        if (v1Server == null) {
            v1Server = new FeatureServer();
        }
        return new Chat(null, v1Server.endpoint, Duration.ofSeconds(2));
    }

    /** Send from {@code chat}, which has keys, until a send is v1. */
    static void waitForV1(Chat chat) throws Exception {
        EncryptMessageParams send = new EncryptMessageParams("feature-switches", "wait for v1");
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
