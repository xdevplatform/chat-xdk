package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.x.chatxdk.PublicKeyResolver;
import com.x.chatxdk.Types.PublicKeyRecord;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.LongSupplier;

/**
 * A public-key resolver for every chat in the process: one cache of
 * {@code GET /2/users/{id}/public_keys} answers, by user id, in front of a
 * {@link ChatCore.PublicKeyFetcher}.
 *
 * <p>A chat holds one user's private keys, so a process with several
 * signed-in users keeps one chat per user (see {@link UserChats}). Other
 * users' public keys are the same whichever chat asks. Give every chat this
 * one resolver with {@link ChatCore#resolvePublicKeysWith}, and the chats of
 * two signed-in users who meet the same user cost one request:
 *
 * <ul>
 *   <li>Calls that ask for a user whose lookup is under way wait for that
 *       lookup.</li>
 *   <li>A lookup that fails is logged and dropped, and the user is left out
 *       of the answer: the next call fetches again.</li>
 *   <li>An answer is served for the TTL, then fetched again, so a key a user
 *       registers later is picked up.</li>
 * </ul>
 *
 * <p>It may be called from several threads at once. The fetch of one user
 * does not hold up the lookup of another.
 */
public final class SharedPublicKeys implements PublicKeyResolver {

    /** How long a fetched answer is served before it is fetched again. */
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** One user's lookup: when its answer stops being served, and the answer once it arrives. */
    private static final class Lookup {
        final long expiresAtMs;

        /** Completed with the user's records, or with null when the fetch failed. */
        final CompletableFuture<List<PublicKeyRecord>> records = new CompletableFuture<>();

        Lookup(long expiresAtMs) {
            this.expiresAtMs = expiresAtMs;
        }
    }

    private final ChatCore.PublicKeyFetcher fetcher;
    private final long ttlMs;
    private final LongSupplier clockMs;

    /** The lookups made within one TTL, by user id. Read and written under its own lock. */
    private final Map<String, Lookup> lookups = new HashMap<>();

    /** A cache in front of {@code fetcher} that serves each answer for {@link #DEFAULT_TTL}. */
    public SharedPublicKeys(ChatCore.PublicKeyFetcher fetcher) {
        this(fetcher, DEFAULT_TTL, () -> System.nanoTime() / 1_000_000);
    }

    /**
     * A cache in front of {@code fetcher} that serves each answer for
     * {@code ttl}. {@code clockMs} is the clock, in milliseconds: only the
     * time between two of its readings is used.
     */
    public SharedPublicKeys(ChatCore.PublicKeyFetcher fetcher, Duration ttl, LongSupplier clockMs) {
        this.fetcher = fetcher;
        this.ttlMs = ttl.toMillis();
        this.clockMs = clockMs;
    }

    /**
     * The records of {@code userIds}, by user id, as the SDK's resolver
     * returns them. A user whose lookup failed is left out.
     */
    @Override
    public Map<String, List<PublicKeyRecord>> resolve(List<String> userIds) {
        Map<String, List<PublicKeyRecord>> records = new LinkedHashMap<>();
        for (String userId : userIds) {
            List<PublicKeyRecord> found = lookUp(userId);
            if (found != null) {
                records.put(userId, found);
            }
        }
        return records;
    }

    /** One user's records, or null when their fetch failed. */
    private List<PublicKeyRecord> lookUp(String userId) {
        Lookup lookup;
        boolean created = false;
        synchronized (lookups) {
            long now = clockMs.getAsLong();
            lookup = lookups.get(userId);
            if (lookup == null || lookup.expiresAtMs <= now) {
                // Lookups past their time are removed here, so the cache holds
                // no more than the users looked up within one TTL.
                lookups.values().removeIf(each -> each.expiresAtMs <= now);
                lookup = new Lookup(now + ttlMs);
                lookups.put(userId, lookup);
                created = true;
            }
        }
        // The thread that created the lookup runs its fetch, outside the lock;
        // every other thread waits for that fetch.
        if (created) {
            fetch(userId, lookup);
        }
        return lookup.records.join();
    }

    /**
     * Fetch one user's records and complete {@code lookup} with them. A fetch
     * that fails is logged, and its lookup is dropped from the cache and
     * completed with null.
     */
    private void fetch(String userId, Lookup lookup) {
        List<PublicKeyRecord> found = null;
        try {
            List<PublicKeyRecord> records = new ArrayList<>();
            for (JsonNode node : fetcher.fetch(userId)) {
                records.add(MAPPER.treeToValue(node, PublicKeyRecord.class));
            }
            found = Collections.unmodifiableList(records);
        } catch (Exception e) {
            System.err.println("public_keys_fetch_failed user=" + userId + " " + e.getMessage());
        } finally {
            // The lookup is completed whatever the fetch threw, so no thread
            // waits for it without end.
            if (found == null) {
                synchronized (lookups) {
                    lookups.remove(userId, lookup);
                }
            }
            lookup.records.complete(found);
        }
    }
}
