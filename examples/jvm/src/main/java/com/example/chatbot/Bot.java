package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.ChatXdkException;
import com.x.chatxdk.Types.DecryptEventsResult;
import com.x.chatxdk.Types.DecryptedEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The receive -&gt; decrypt -&gt; reply -&gt; encrypt -&gt; send loop. Conversation state
 * is kept in memory, one entry per conversation.
 *
 * <p>One bot serves one signed-in user, in any number of conversations. A
 * process with several signed-in users keeps one chat per user and gives each
 * the same public-key resolver (see {@link UserChats} and
 * {@link SharedPublicKeys}).
 */
public final class Bot {

    private final ChatCore core;
    private final XChatClient api;
    private final String botUserId;
    private final Map<String, ConversationState> state = new HashMap<>();

    public Bot(ChatCore core, XChatClient api, String botUserId) {
        this.core = core;
        this.api = api;
        this.botUserId = botUserId;
        // Session identity, once: every encrypt below signs as the bot without
        // passing a sender id per call.
        core.setIdentity(botUserId);
        // The SDK fetches the public keys it lacks through the API client: the
        // signing keys of whoever signed a page's events, the members who made
        // its key changes included.
        core.fetchPublicKeysWith(api::getPublicKeys);
    }

    /** Turn an incoming message into a reply (simple echo by default). */
    public static String generateReply(String text) {
        String t = text.trim();
        return (t.equals("ping") || t.equals("!ping")) ? "pong" : "You said: " + t;
    }

    private ConversationState stateFor(String conversationId) {
        return state.computeIfAbsent(conversationId, k -> new ConversationState());
    }

    /**
     * Batch-decrypt one GET events page: its key events, which carry the
     * conversation keys its messages decrypt under, and its data events, in
     * one batch. The SDK fetches the public keys the page lacks and caches the
     * keys of the key changes that verify. Logs what the page still could not
     * use.
     */
    private DecryptEventsResult decryptPage(String conversationId, JsonNode page) throws Exception {
        List<String> eventsB64 = new ArrayList<>(keyEvents(page));
        JsonNode data = page.path("data");
        if (data.isArray()) {
            for (JsonNode item : data) {
                String eventB64 = item.path("encoded_event").asText("");
                if (!eventB64.isEmpty()) eventsB64.add(eventB64);
            }
        }
        DecryptEventsResult result = core.decryptBatch(eventsB64);
        result.missingSigningKeys.forEach((index, key) -> System.err.printf(
                "signing_key_missing conv=%s event=%s user=%s version=%s%n",
                conversationId, index, key.userId, key.publicKeyVersion));
        result.unverifiedKeyChanges.forEach((index, change) -> System.err.printf(
                "key_change_unverified conv=%s event=%s reason=%s signer=%s key_dropped=%s%n",
                conversationId, index, change.reason, change.senderId, change.keyDropped));
        result.undecryptableKeyChanges.forEach((index, change) -> System.err.printf(
                "key_change_undecryptable conv=%s event=%s reason=%s%n", conversationId, index, change.reason));
        result.rejectedSigningKeys.forEach((index, key) -> System.err.printf(
                "signing_key_rejected index=%s user=%s version=%s%n", index, key.userId, key.publicKeyVersion));
        return result;
    }

    /** Pagination token from a GET events page, or null when absent. */
    private static String nextToken(JsonNode page) {
        JsonNode nt = page.path("meta").path("next_token");
        return nt.isTextual() ? nt.asText() : null;
    }

    /**
     * KeyChange events from a GET events page. They arrive in
     * meta.conversation_key_events, separate from data, and carry the
     * conversation keys — they must go into the same decryptEvents batch as
     * the data events.
     */
    private static List<String> keyEvents(JsonNode page) {
        List<String> out = new ArrayList<>();
        JsonNode arr = page.path("meta").path("conversation_key_events");
        if (arr.isArray()) {
            for (JsonNode e : arr) {
                if (e.isTextual()) out.add(e.asText());
            }
        }
        return out;
    }

    /**
     * Initial load: batch-decrypt the backlog (decryptEvents path), filling the
     * SDK's conversation-key cache from the key changes.
     */
    public void loadBacklog(String conversationId) throws Exception {
        ConversationState st = stateFor(conversationId);
        JsonNode page = api.getEvents(conversationId, 100, null);
        DecryptEventsResult result = decryptPage(conversationId, page);
        st.paginationToken = nextToken(page);
        System.out.printf("backlog_loaded conv=%s messages=%d keys=%d%n",
                conversationId, result.events.size(), result.conversationKeys.keys.size());
    }

    /**
     * Poll for a page of new events, batch-decrypt it (decryptEvents path),
     * and reply to each new incoming message it holds.
     */
    public void pollOnce(String conversationId) throws Exception {
        ConversationState st = stateFor(conversationId);
        JsonNode page = api.getEvents(conversationId, 50, st.paginationToken);
        DecryptEventsResult result = decryptPage(conversationId, page);
        result.errors.forEach((index, error) -> System.err.printf(
                "decrypt_failed conv=%s event=%s err=%s%n", conversationId, index, error));

        for (DecryptedEvent decrypted : result.events) {
            // A reply is threaded under the raw event of its message.
            if (decrypted.originalB64 != null) {
                maybeReply(conversationId, decrypted.event, decrypted.originalB64);
            }
        }
        // Advance the pagination token so the next poll fetches only new events.
        String next = nextToken(page);
        if (next != null && !next.isEmpty()) st.paginationToken = next;
    }

    private void maybeReply(String conversationId, JsonNode event, String eventB64) throws Exception {
        ConversationState st = stateFor(conversationId);
        String eventId = event.path("id").asText("");
        String senderId = event.path("sender_id").asText("");
        if (eventId.isEmpty() || !st.seenEventIds.add(eventId)) return;
        if (senderId.equals(botUserId)) return;

        String text = ChatCore.messageText(event);
        if (text == null || text.isEmpty()) return;

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        String replyConvId = event.path("conversation_id").asText(conversationId);
        String reply = generateReply(text);
        // Reply by raw event: the SDK derives the threaded-reply preview from
        // the incoming signed event and embeds it for recipient validation,
        // and the conversation key resolves from the key cache.
        ChatCore.SendBody body;
        try {
            body = core.encryptReply(replyConvId, reply, null, null, eventB64, null, null, null, null);
        } catch (ChatXdkException e) {
            if (e.getKind() != ChatXdkException.Kind.INVALID_STATE) throw e;
            System.err.println("no_conversation_key conv=" + conversationId);
            return;
        }
        api.sendMessage(replyConvId, body);
        System.out.printf("reply_sent conv=%s len=%d%n", replyConvId, reply.length());
    }

    /** Load the backlog then poll forever. */
    public void run(String conversationId, long pollIntervalMs) throws Exception {
        loadBacklog(conversationId);
        System.out.printf("bot_running conv=%s polling every %dms%n", conversationId, pollIntervalMs);
        while (true) {
            try {
                pollOnce(conversationId);
            } catch (Exception e) {
                System.err.println("poll_error conv=" + conversationId + " " + e.getMessage());
            }
            Thread.sleep(pollIntervalMs);
        }
    }

    /** In-memory state for one conversation. Its conversation keys live in the SDK's cache. */
    private static final class ConversationState {
        final Set<String> seenEventIds = new HashSet<>();
        String paginationToken;
    }
}
