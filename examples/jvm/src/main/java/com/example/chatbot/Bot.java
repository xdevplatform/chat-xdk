package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.ChatXdkException;
import com.x.chatxdk.Types.SigningKeyEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The receive -&gt; decrypt -&gt; reply -&gt; encrypt -&gt; send loop. Conversation state
 * is kept in memory, one entry per conversation.
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
    }

    /** Turn an incoming message into a reply (simple echo by default). */
    public static String generateReply(String text) {
        String t = text.trim();
        return (t.equals("ping") || t.equals("!ping")) ? "pong" : "You said: " + t;
    }

    private ConversationState stateFor(String conversationId) {
        return state.computeIfAbsent(conversationId, k -> new ConversationState());
    }

    private List<SigningKeyEntry> signingKeysFor(List<JsonNode> events) throws Exception {
        Set<String> senders = new LinkedHashSet<>();
        for (JsonNode e : events) {
            String sid = e.path("sender_id").asText("");
            if (!sid.isEmpty() && !sid.equals(botUserId)) senders.add(sid);
        }
        List<SigningKeyEntry> keys = new ArrayList<>();
        for (String senderId : senders) {
            try {
                for (JsonNode pk : api.getPublicKeys(senderId)) {
                    SigningKeyEntry entry = new SigningKeyEntry(
                            senderId,
                            pk.path("public_key_version").asText(""),
                            pk.path("signing_public_key").asText(""),
                            pk.path("public_key").asText(""),
                            pk.path("identity_public_key_signature").asText(""));
                    keys.add(entry);
                }
            } catch (Exception ex) {
                System.err.println("public_keys_fetch_failed sender=" + senderId);
            }
        }
        return keys;
    }

    private static List<JsonNode> dataArray(JsonNode page) {
        List<JsonNode> out = new ArrayList<>();
        JsonNode data = page.path("data");
        if (data.isArray()) data.forEach(out::add);
        return out;
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
        List<JsonNode> raw = dataArray(page);
        List<String> eventsB64 = new ArrayList<>(keyEvents(page));
        for (JsonNode e : raw) {
            String ev = e.path("encoded_event").asText("");
            if (!ev.isEmpty()) eventsB64.add(ev);
        }
        var result = core.decryptBatch(eventsB64, signingKeysFor(raw));
        st.paginationToken = nextToken(page);
        System.out.printf("backlog_loaded conv=%s messages=%d keys=%d%n",
                conversationId, result.events.size(), result.conversationKeys.keys.size());
    }

    /** Poll for new events; reply to each new message (decryptEvent path). */
    public void pollOnce(String conversationId) throws Exception {
        ConversationState st = stateFor(conversationId);
        JsonNode page = api.getEvents(conversationId, 50, st.paginationToken);
        List<JsonNode> raw = dataArray(page);
        List<SigningKeyEntry> signingKeys = signingKeysFor(raw);

        // Key changes for this page arrive in meta, not data; only the batch
        // path feeds the key cache, so route them through it before
        // decrypting the messages that need them.
        List<String> pageKeyEvents = keyEvents(page);
        if (!pageKeyEvents.isEmpty()) {
            core.decryptBatch(pageKeyEvents, signingKeys);
        }

        for (JsonNode item : raw) {
            String eventB64 = item.path("encoded_event").asText("");
            if (eventB64.isEmpty()) continue;
            // An empty key map: the conversation keys come from the cache.
            JsonNode event = core.decryptOne(eventB64, Map.of(), signingKeys);

            if ("KeyChange".equals(event.path("type").asText())) {
                // Only the batch path adopts keys into the cache; replay the
                // key change through it so the rotated key becomes the
                // sending key.
                core.decryptBatch(List.of(eventB64), signingKeys);
                continue;
            }
            maybeReply(conversationId, event, eventB64);
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
