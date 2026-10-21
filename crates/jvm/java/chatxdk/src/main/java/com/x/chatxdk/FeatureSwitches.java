package com.x.chatxdk;

import java.io.ByteArrayOutputStream;
import java.lang.ref.WeakReference;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

/**
 * Feature switches ({@code GET /2/chat/features}). Internal: every {@link Chat} fetches them
 * itself, without blocking or failing, and sends stay v0 unless a response turns {@code v1_send}
 * on. Nothing here is API. {@code CHAT_XDK_FEATURES_ENDPOINT}, which only this repository's tests
 * set, overrides the endpoint.
 */
final class FeatureSwitches {
    private static final String DEFAULT_ENDPOINT = "https://api.x.com/2/chat/features";
    private static final String ENDPOINT_ENV = "CHAT_XDK_FEATURES_ENDPOINT";
    private static final int MAX_BODY = 64 * 1024;
    private static final long MAX_REFETCH_BACKOFF_MS = 60_000;
    private static final HttpClient HTTP =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

    private FeatureSwitches() {}

    /** The endpoint and timings of a chat's feature fetches. */
    static final class Options {
        final String endpoint;
        final Duration timeout;
        final Duration refresh;
        final Duration keyPoll;

        Options(String endpoint, Duration timeout, Duration refresh, Duration keyPoll) {
            this.endpoint = endpoint;
            this.timeout = timeout;
            this.refresh = refresh;
            this.keyPoll = keyPoll;
        }

        static Options defaults() {
            String endpoint = System.getenv(ENDPOINT_ENV);
            return new Options(
                    endpoint == null || endpoint.isEmpty() ? DEFAULT_ENDPOINT : endpoint,
                    Duration.ofSeconds(2),
                    Duration.ofSeconds(300),
                    Duration.ofSeconds(1));
        }
    }

    /** A chat's fetch thread; {@link #stop} ends it. */
    static final class Runner {
        volatile boolean stopped;
        volatile Thread thread;
    }

    /**
     * Fetch the flags for {@code chat} now (retrying once), again with the key's bucket once keys
     * load (retrying with backoff), and re-check them every refresh interval with a fetch that can
     * only turn flags off, until {@link #stop}. The daemon thread holds the chat weakly, so an
     * unclosed chat is still cleaned up, and the fetches end with it.
     */
    static Runner start(Chat chat, Options options) {
        Runner runner = new Runner();
        WeakReference<Chat> ref = new WeakReference<>(chat);
        Thread thread = new Thread(() -> run(ref, runner, options), "chat-xdk-features");
        thread.setDaemon(true);
        runner.thread = thread;
        thread.start();
        return runner;
    }

    static void stop(Runner runner) {
        runner.stopped = true;
        Thread thread = runner.thread;
        if (thread != null) {
            thread.interrupt();
        }
    }

    // The loop reaches the chat only through these, so it never holds it while it waits.

    private static boolean alive(WeakReference<Chat> ref) {
        Chat chat = ref.get();
        return chat != null && !chat.isClosed();
    }

    private static boolean refetchDue(WeakReference<Chat> ref) {
        Chat chat = ref.get();
        return chat != null && chat.featureRefetchDueForRefresh();
    }

    private static boolean keyed(WeakReference<Chat> ref) {
        Chat chat = ref.get();
        return chat != null && chat.featuresKeyed();
    }

    private static int bucket(WeakReference<Chat> ref) {
        Chat chat = ref.get();
        return chat == null ? Chat.CLOSED : chat.featureBucketForRefresh();
    }

    private static boolean apply(WeakReference<Chat> ref, String body, int bucket, boolean downgradeOnly) {
        Chat chat = ref.get();
        return chat != null && chat.applyFeatureConfigForRefresh(body, bucket, downgradeOnly);
    }

    private static void run(WeakReference<Chat> ref, Runner runner, Options options) {
        try {
            loop(ref, runner, options);
        } catch (LinkageError e) {
            // A native library without the internal entry points: every flag stays off.
        }
    }

    private static void loop(WeakReference<Chat> ref, Runner runner, Options options) {
        try {
            if (!fetch(ref, options, false)) {
                fetch(ref, options, false);
            }
        } catch (RuntimeException e) {
            // Every flag stays off; the loop below retries.
        }
        long refreshMs = options.refresh.toMillis();
        long nextRecheck = now() + refreshMs;
        long retryAt = 0;
        long backoffMs = 1000;
        while (!runner.stopped) {
            boolean keyed = false;
            try {
                long now = now();
                if (refetchDue(ref)) {
                    if (now >= retryAt) {
                        if (fetch(ref, options, false)) {
                            backoffMs = 1000;
                            nextRecheck = now() + refreshMs;
                        } else {
                            retryAt = now() + backoffMs;
                            backoffMs = Math.min(backoffMs * 2, MAX_REFETCH_BACKOFF_MS);
                        }
                    }
                } else if (refreshMs > 0 && now >= nextRecheck) {
                    fetch(ref, options, true);
                    nextRecheck = now() + refreshMs;
                }
                keyed = keyed(ref);
            } catch (RuntimeException e) {
                // A failed step changes nothing; the next one retries.
            }
            if (runner.stopped || !alive(ref) || (keyed && refreshMs <= 0)) {
                return;
            }
            // Until a response for the key's bucket applies, watch for keys to load; afterwards,
            // wake only for the re-check.
            long waitMs = keyed ? Math.max(0, nextRecheck - now()) : options.keyPoll.toMillis();
            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /** Fetch the flags for the chat's bucket and apply them; true on success. */
    private static boolean fetch(WeakReference<Chat> ref, Options options, boolean downgradeOnly) {
        int bucket = bucket(ref);
        if (bucket == Chat.CLOSED) {
            return false;
        }
        String endpoint = options.endpoint;
        String url = bucket < 0 ? endpoint : endpoint + (endpoint.contains("?") ? "&" : "?") + "bucket=" + bucket;
        String body = get(url, options.timeout);
        return body != null && apply(ref, body, bucket, downgradeOnly);
    }

    /**
     * The body of a 200 response from {@code url} within {@code timeout} in all, or null on any
     * failure.
     */
    private static String get(String url, Duration timeout) {
        CompletableFuture<HttpResponse<byte[]>> future = null;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(timeout)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            future = HTTP.sendAsync(request, info -> new CappedBody());
            HttpResponse<byte[]> response = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            byte[] body = response.body();
            if (response.statusCode() != 200 || body == null) {
                return null;
            }
            return new String(body, StandardCharsets.UTF_8);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            if (future != null) {
                future.cancel(true);
            }
        }
    }

    private static long now() {
        return System.nanoTime() / 1_000_000;
    }

    /** Collects a body of at most {@link #MAX_BODY} bytes; a longer one is cut off as null. */
    private static final class CappedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

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
                if (bytes.size() + buffer.remaining() > MAX_BODY) {
                    subscription.cancel();
                    result.complete(null);
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.write(chunk, 0, chunk.length);
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
