package com.x.chatxdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.jna.Memory;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

/**
 * Reads a chat's feature switches ({@code GET /2/chat/features}) once, when the chat is created.
 * The native core decides what to fetch and what an answer means; this class performs the GET with
 * {@link HttpClient} and hands the status and body back. Nothing here is API.
 */
final class FeatureFetch {
    // The read is anonymous: the client has no cookie handler, so it stores and sends no cookies,
    // and it follows no redirect, so a 3xx answer reaches the core as a failed read rather than as
    // a request to another URL.
    private static final HttpClient HTTP =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private FeatureFetch() {}

    /**
     * Start {@code chat}'s one read of the feature switches: nothing to do when it takes the answer
     * of a GET already in flight.
     */
    static void start(Chat chat) {
        String json = chat.startFeatures();
        if (json.isEmpty()) {
            return;
        }
        JsonNode fetch;
        try {
            fetch = ChatJson.MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        perform(
                fetch.get("id").asLong(),
                fetch.get("url").asText(),
                fetch.get("timeout_ms").asLong(),
                fetch.get("max_bytes").asInt());
    }

    /**
     * For this repository's tests: the endpoint of every chat that does not set its own, or the X
     * API's when {@code endpoint} is null.
     */
    static void setDefaultEndpoint(String endpoint) {
        if (endpoint == null) {
            FfiStrings.consume(FeatureNative.INSTANCE.chat_xdk_internal_feature_set_default_endpoint(null));
            return;
        }
        try (Memory e = FfiStrings.utf8(endpoint)) {
            FfiStrings.consume(FeatureNative.INSTANCE.chat_xdk_internal_feature_set_default_endpoint(e));
        }
    }

    /**
     * Start the GET; when it ends, or at its timeout, its status and body go back to the core.
     * Status 0 when no complete response arrived.
     */
    private static void perform(long id, String url, long timeoutMs, int maxBytes) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Accept", "application/json")
                .GET()
                .build();
        CompletableFuture<HttpResponse<byte[]>> exchange =
                HTTP.sendAsync(request, info -> new CappedBody(maxBytes));
        CompletableFuture.delayedExecutor(timeoutMs, TimeUnit.MILLISECONDS).execute(() -> exchange.cancel(true));
        exchange.whenComplete((response, error) -> {
            if (error == null && response.body() != null) {
                complete(id, response.statusCode(), response.body());
            } else {
                complete(id, 0, new byte[0]);
            }
        });
    }

    private static void complete(long id, int status, byte[] body) {
        FeatureNative.INSTANCE.chat_xdk_internal_feature_complete(id, status, body, body.length);
    }

    /** Collects the body up to one byte past {@code maxBytes}, then stops reading. */
    private static final class CappedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int limit;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        CappedBody(int maxBytes) {
            this.limit = maxBytes + 1;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (result.isDone()) {
                    return;
                }
                byte[] chunk = new byte[Math.min(buffer.remaining(), limit - bytes.size())];
                buffer.get(chunk);
                bytes.write(chunk, 0, chunk.length);
                if (bytes.size() >= limit) {
                    subscription.cancel();
                    result.complete(bytes.toByteArray());
                    return;
                }
            }
        }

        @Override
        public void onError(Throwable error) {
            result.completeExceptionally(error);
        }

        @Override
        public void onComplete() {
            result.complete(bytes.toByteArray());
        }
    }
}
