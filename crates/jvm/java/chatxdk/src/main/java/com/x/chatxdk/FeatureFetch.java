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
 * Reads a chat's feature switches ({@code GET /2/chat/features}) when the chat is created, when
 * its identity is set, and again after each answer. The native core decides what to fetch, when to
 * fetch it again and what an answer means; this class performs each GET it hands out with
 * {@link HttpClient} and reports the status and body to it. Nothing here is API.
 */
final class FeatureFetch {
    // The read is anonymous: the client has no cookie handler, so it stores and sends no cookies,
    // and it follows no redirect, so a 3xx answer reaches the core as a failed read rather than as
    // a request to another URL.
    private static final HttpClient HTTP =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private FeatureFetch() {}

    /**
     * Start {@code chat}'s reads of the feature switches for its identity: perform the GET the
     * core hands out, if any, and then each GET the core hands back.
     */
    static void start(Chat chat) {
        schedule(chat.startFeatures());
    }

    /** Perform the GET {@code json} describes, if any, after its delay. */
    private static void schedule(String json) {
        if (json.isEmpty()) {
            return;
        }
        JsonNode fetch;
        try {
            fetch = ChatJson.MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        long id = fetch.get("id").asLong();
        String url = fetch.get("url").asText();
        long timeoutMs = fetch.get("timeout_ms").asLong();
        int maxBytes = fetch.get("max_bytes").asInt();
        long delayMs = fetch.path("delay_ms").asLong();
        if (delayMs <= 0) {
            perform(id, url, timeoutMs, maxBytes);
            return;
        }
        CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
                .execute(() -> perform(id, url, timeoutMs, maxBytes));
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
     * Start the GET; when it ends, or at its timeout, its status and body go back to the core, and
     * the refresh or retry the core returns, if any, is scheduled. Status 0 when no complete
     * response arrived.
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
        schedule(FfiStrings.consume(
                FeatureNative.INSTANCE.chat_xdk_internal_feature_complete(id, status, body, body.length)));
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
