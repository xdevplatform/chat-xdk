package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
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
                    SigningKeyEntry entry = new SigningKeyEntry();
                    entry.userId = senderId;
                    entry.publicKeyVersion = pk.path("public_key_version").asText("");
                    entry.publicKey = pk.path("signing_public_key").asText("");
                    entry.identityPublicKey = pk.path("public_key").asText("");
                    entry.identityPublicKeySignature = pk.path("identity_public_key_signature").asText("");
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

    /** Initial load: batch-decrypt the backlog (decryptEvents path). */
    public void loadBacklog(String conversationId) throws Exception {
        ConversationState st = stateFor(conversationId);
        JsonNode page = api.getEvents(conversationId, 100, null);
        List<JsonNode> raw = dataArray(page);
        List<String> eventsB64 = new ArrayList<>();
        for (JsonNode e : raw) {
            String ev = e.path("encoded_event").asText("");
            if (!ev.isEmpty()) eventsB64.add(ev);
        }
        var result = core.decryptBatch(eventsB64, signingKeysFor(raw));
        st.conversationKeys.putAll(result.conversationKeys.keys);
        st.latestKeyVersion = result.conversationKeys.latestVersion;
        st.paginationToken = nextToken(page);
        System.out.printf("backlog_loaded conv=%s messages=%d keys=%d%n",
                conversationId, result.messages.size(), result.conversationKeys.keys.size());
    }

    /** Poll for new events; reply to each new message (decryptEvent path). */
    public void pollOnce(String conversationId) throws Exception {
        ConversationState st = stateFor(conversationId);
        JsonNode page = api.getEvents(conversationId, 50, st.paginationToken);
        List<JsonNode> raw = dataArray(page);
        List<SigningKeyEntry> signingKeys = signingKeysFor(raw);

        for (JsonNode item : raw) {
            String eventB64 = item.path("encoded_event").asText("");
            if (eventB64.isEmpty()) continue;
            JsonNode event = core.decryptOne(eventB64, st.conversationKeys, signingKeys);

            if ("KeyChange".equals(event.path("type").asText())) {
                String keyVersion = event.path("key_version").asText();
                for (JsonNode pk : event.path("participant_keys")) {
                    String enc = pk.path("encrypted_key").asText("");
                    if (enc.isEmpty()) continue;
                    try {
                        st.conversationKeys.put(keyVersion, core.decryptConversationKey(enc));
                        st.latestKeyVersion = keyVersion;
                        break;
                    } catch (RuntimeException ignored) {
                        // not for us
                    }
                }
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

        String keyVersion = event.path("key_version").asText(st.latestKeyVersion);
        byte[] convKey = keyVersion == null ? null : st.conversationKeys.get(keyVersion);
        if (convKey == null || keyVersion == null) {
            System.err.println("no_conversation_key conv=" + conversationId);
            return;
        }

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        String replyConvId = event.path("conversation_id").asText(conversationId);
        String reply = generateReply(text);
        // Reply by raw event: the SDK derives the threaded-reply preview from
        // the incoming signed event and embeds it for recipient validation.
        ChatCore.SendBody body =
                core.encryptReply(replyConvId, reply, convKey, keyVersion, eventB64, null, null, null, null);
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

    private static final class ConversationState {
        final Map<String, byte[]> conversationKeys = new HashMap<>();
        String latestKeyVersion;
        final Set<String> seenEventIds = new HashSet<>();
        String paginationToken;
    }
}
