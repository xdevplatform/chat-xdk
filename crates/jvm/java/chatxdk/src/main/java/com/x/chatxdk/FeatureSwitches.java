package com.x.chatxdk;

import java.lang.ref.WeakReference;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Fetches {@code GET /2/chat/features} for a {@link Chat} and runs its refresher thread. */
final class FeatureSwitches {
    private static final int MAX_BODY = 64 * 1024;
    private static final long MAX_REFETCH_BACKOFF_MS = 60_000;
    private static final HttpClient HTTP =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

    private FeatureSwitches() {}

    /** A running refresher; {@link #stop} ends it. */
    static final class Refresher {
        volatile boolean stopped;
        volatile Thread thread;
    }

    static boolean load(Chat chat, Types.LoadFeatureConfigParams params) {
        stop(chat);
        String endpoint =
                params.endpoint == null || params.endpoint.isEmpty() ? Chat.FEATURES_ENDPOINT : params.endpoint;
        Duration timeout = Duration.ofMillis(params.timeoutMs > 0 ? params.timeoutMs : 2000);
        long refreshMs = Math.max(0, params.refreshSeconds) * 1000L;

        boolean applied = fetch(chat, endpoint, timeout, false) || fetch(chat, endpoint, timeout, false);

        if (!chat.isClosed()) {
            Refresher refresher = new Refresher();
            WeakReference<Chat> ref = new WeakReference<>(chat);
            Thread thread = new Thread(
                    () -> refresh(ref, refresher, endpoint, timeout, refreshMs), "chat-xdk-features");
            thread.setDaemon(true);
            refresher.thread = thread;
            chat.featureRefresher = refresher;
            thread.start();
        }
        return applied;
    }

    static void stop(Chat chat) {
        Refresher refresher = chat.featureRefresher;
        chat.featureRefresher = null;
        if (refresher != null) {
            refresher.stopped = true;
            Thread thread = refresher.thread;
            if (thread != null) {
                thread.interrupt();
            }
        }
    }

    /** Fetch the flags for the current bucket and apply them; true on success. */
    private static boolean fetch(Chat chat, String endpoint, Duration timeout, boolean downgradeOnly) {
        int bucket = chat.featureBucketForRefresh();
        if (bucket == Chat.CLOSED) {
            return false;
        }
        String url = bucket < 0 ? endpoint : endpoint + (endpoint.contains("?") ? "&" : "?") + "bucket=" + bucket;
        String body = get(url, timeout);
        if (body == null || !chat.applyFeatureConfigForRefresh(body, bucket, downgradeOnly)) {
            return false;
        }
        if (!downgradeOnly) {
            chat.featureBucketless = bucket < 0;
        }
        return true;
    }

    /** The body of a 200 response from {@code url} within {@code timeout}, or null on any failure. */
    private static String get(String url, Duration timeout) {
        CompletableFuture<HttpResponse<byte[]>> future = null;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(timeout)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            future = HTTP.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray());
            HttpResponse<byte[]> response = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            byte[] body = response.body();
            if (response.statusCode() != 200 || body == null || body.length > MAX_BODY) {
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

    /**
     * Re-fetch once keys load after a bucketless response, and re-check every {@code refreshMs},
     * until stopped, closed, or the chat is garbage-collected.
     */
    private static void refresh(
            WeakReference<Chat> ref, Refresher refresher, String endpoint, Duration timeout, long refreshMs) {
        long nextRecheck = now() + refreshMs;
        long retryAt = 0;
        long backoffMs = 1000;
        while (!refresher.stopped) {
            boolean watchingKeys;
            Chat chat = ref.get();
            if (chat == null || chat.isClosed()) {
                return;
            }
            try {
                long now = now();
                if (chat.featureRefetchDueForRefresh()) {
                    if (now >= retryAt) {
                        if (fetch(chat, endpoint, timeout, false)) {
                            backoffMs = 1000;
                            nextRecheck = now() + refreshMs;
                        } else {
                            retryAt = now() + backoffMs;
                            backoffMs = Math.min(backoffMs * 2, MAX_REFETCH_BACKOFF_MS);
                        }
                    }
                } else if (refreshMs > 0 && now >= nextRecheck) {
                    fetch(chat, endpoint, timeout, true);
                    nextRecheck = now() + refreshMs;
                }
                watchingKeys = chat.featureBucketless;
            } catch (RuntimeException e) {
                watchingKeys = true;
            }
            chat = null;
            if (refresher.stopped || (!watchingKeys && refreshMs <= 0)) {
                return;
            }
            long waitMs = watchingKeys ? 1000 : Math.max(0, nextRecheck - now());
            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private static long now() {
        return System.nanoTime() / 1_000_000;
    }
}
