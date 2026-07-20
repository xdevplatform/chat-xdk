package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Minimal X Chat API client over HTTP with {@link java.net.http.HttpClient}.
 * Authentication is an OAuth2 user access token (scopes dm.read + dm.write).
 */
public final class XChatClient {

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String baseUrl;
    private final String accessToken;

    public XChatClient(String accessToken, String baseUrl) {
        this.accessToken = accessToken;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    private JsonNode get(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 300) {
            throw new RuntimeException("x api GET " + path + ": " + resp.statusCode() + " " + resp.body());
        }
        return mapper.readTree(resp.body());
    }

    private JsonNode post(String path, JsonNode body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 300) {
            throw new RuntimeException("x api POST " + path + ": " + resp.statusCode() + " " + resp.body());
        }
        String text = resp.body();
        return mapper.readTree(text == null || text.isEmpty() ? "{}" : text);
    }

    public String getMyUserId() throws Exception {
        return get("/2/users/me").path("data").path("id").asText();
    }

    /**
     * Fetch a user's registered public keys (for ECIES + verification, or to
     * check your own before registering).
     *
     * <p>Every field of the public_key resource ({@code public_key},
     * {@code signing_public_key}, {@code identity_public_key_signature},
     * {@code public_key_version}, {@code juicebox_config}) is always included;
     * the route takes no {@code public_key.fields} parameter.
     */
    public List<JsonNode> getPublicKeys(String userId) throws Exception {
        JsonNode data = get("/2/users/" + enc(userId) + "/public_keys").path("data");
        List<JsonNode> out = new ArrayList<>();
        if (data.isArray()) {
            data.forEach(out::add);
        } else if (!data.isMissingNode()) {
            out.add(data);
        }
        return out;
    }

    /**
     * Raised when the public-key write bucket is exhausted (HTTP 429).
     *
     * <p>The endpoint allows only a few writes per 24h; {@code resetEpoch} is
     * when the window frees up. Retrying before then just fails again.
     */
    public static final class RateLimited extends Exception {
        public final Long resetEpoch;

        public RateLimited(Long resetEpoch) {
            super("public-key registration rate limited (HTTP 429)");
            this.resetEpoch = resetEpoch;
        }
    }

    /**
     * Register a public key: POST /2/users/{id}/public_keys.
     *
     * <p>{@code body} is the registration object from {@code generateKeypairs}
     * in its snake_case wire form ({@code public_key} object, {@code version},
     * {@code generate_version}). Throws {@link RateLimited} on 429 so the caller
     * can stop instead of burning the strict daily budget.
     */
    public JsonNode addUserPublicKey(String userId, JsonNode body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/2/users/" + enc(userId) + "/public_keys"))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 429) {
            Long reset = resp.headers().firstValue("x-user-limit-24hour-reset").map(s -> {
                try {
                    return Long.parseLong(s);
                } catch (NumberFormatException e) {
                    return null;
                }
            }).orElse(null);
            throw new RateLimited(reset);
        }
        if (resp.statusCode() >= 300) {
            throw new RuntimeException("x api POST public_keys: " + resp.statusCode() + " " + resp.body());
        }
        String text = resp.body();
        return mapper.readTree(text == null || text.isEmpty() ? "{}" : text);
    }

    /** Juicebox config JSON plus the latest key version, for the optional PIN backup. */
    public record JuiceboxConfigResult(String configJson, String version) {}

    /**
     * Build the Juicebox config JSON + latest key version for {@code setup}.
     * Every public_key field ({@code juicebox_config} included) is always
     * returned; the route takes no {@code public_key.fields} parameter.
     */
    public JuiceboxConfigResult getJuiceboxConfig(String userId) throws Exception {
        JsonNode data = get("/2/users/" + enc(userId) + "/public_keys").path("data");
        List<JsonNode> items = new ArrayList<>();
        if (data.isArray()) {
            data.forEach(items::add);
        } else if (!data.isMissingNode()) {
            items.add(data);
        }
        if (items.isEmpty()) {
            throw new RuntimeException("no public keys returned");
        }
        JsonNode latest = items.get(0);
        for (JsonNode it : items) {
            if (it.path("public_key_version").asLong(0) >= latest.path("public_key_version").asLong(0)) {
                latest = it;
            }
        }
        JsonNode cfg = latest.path("juicebox_config");
        if (cfg.isMissingNode() || cfg.isNull()) {
            throw new RuntimeException("no juicebox_config on the account");
        }
        // Passed to the SDK as-is: it reads `key_store_token_map_json` verbatim.
        return new JuiceboxConfigResult(cfg.toString(), latest.path("public_key_version").asText("1"));
    }

    /** GET the raw (encrypted) events for a conversation. */
    public JsonNode getEvents(String conversationId, int maxResults, String paginationToken) throws Exception {
        String path = "/2/chat/conversations/" + enc(conversationId.replace(":", "-")) + "/events?max_results=" + maxResults;
        if (paginationToken != null && !paginationToken.isEmpty()) {
            path += "&pagination_token=" + enc(paginationToken);
        }
        return get(path);
    }

    // -- Conversation / key management ---------------------------------------

    /**
     * POST a prepared conversation-key change (initialize or rotate).
     *
     * <p>{@code body} is the request shape built by {@link ChatCore#prepToRequest}.
     * For a 1:1, {@code conversationId} may be the recipient's user ID; the
     * server derives (and returns) the canonical conversation ID.
     */
    public JsonNode addConversationKeys(String conversationId, JsonNode body) throws Exception {
        return post("/2/chat/conversations/" + enc(conversationId.replace(":", "-")) + "/keys", body);
    }

    /** Mint a new group conversation id ({@code g…}). */
    public String initializeGroup() throws Exception {
        JsonNode out = post("/2/chat/conversations/group/initialize", mapper.createObjectNode());
        return out.path("data").path("conversation_id").asText("");
    }

    /**
     * POST /2/chat/conversations/group — create a group conversation.
     *
     * <p>{@code body} carries {@code conversation_id}, {@code group_members},
     * {@code group_admins}, and the two-signature key change from
     * {@link ChatCore#prepareGroupCreate}.
     */
    public JsonNode createConversation(JsonNode body) throws Exception {
        return post("/2/chat/conversations/group", body);
    }

    /**
     * POST /2/chat/conversations/{id}/members — add members to a group.
     *
     * <p>{@code body} carries {@code user_ids} plus the rotated key change from
     * {@link ChatCore#prepareGroupMembersChange}.
     */
    public JsonNode addGroupMembers(String conversationId, JsonNode body) throws Exception {
        return post("/2/chat/conversations/" + enc(conversationId) + "/members", body);
    }

    // -- Media (encrypted blobs) -----------------------------------------------

    private static final int UPLOAD_CHUNK = 3 * 1024 * 1024;

    /**
     * Upload an encrypted media blob; returns its {@code media_hash_key}.
     *
     * <p>Three-step flow: initialize (returns an upload session and the hash
     * key), append (3 MB segments), finalize. The media endpoints take the
     * colon form of the conversation id in the body.
     */
    public String uploadMedia(String conversationId, byte[] ciphertext) throws Exception {
        String conv = conversationId.replace("-", ":");
        var initBody = mapper.createObjectNode();
        initBody.put("conversation_id", conv);
        initBody.put("total_bytes", ciphertext.length);
        JsonNode init = post("/2/chat/media/upload/initialize", initBody);
        JsonNode data = init.path("data");
        String sessionId = data.path("session_id").asText(data.path("sessionId").asText(""));
        String mediaHashKey = data.path("media_hash_key").asText(data.path("mediaHashKey").asText(""));
        if (sessionId.isEmpty() || mediaHashKey.isEmpty()) {
            throw new RuntimeException("media upload initialize failed: " + init);
        }

        int segment = 0;
        for (int offset = 0; offset < ciphertext.length; offset += UPLOAD_CHUNK) {
            int end = Math.min(offset + UPLOAD_CHUNK, ciphertext.length);
            byte[] chunk = Arrays.copyOfRange(ciphertext, offset, end);
            var appendBody = mapper.createObjectNode();
            appendBody.put("conversation_id", conv);
            appendBody.put("media_hash_key", mediaHashKey);
            appendBody.put("segment_index", String.valueOf(segment));
            appendBody.put("media", Base64.getEncoder().encodeToString(chunk));
            post("/2/chat/media/upload/" + enc(sessionId) + "/append", appendBody);
            segment++;
        }

        var finalizeBody = mapper.createObjectNode();
        finalizeBody.put("conversation_id", conv);
        finalizeBody.put("media_hash_key", mediaHashKey);
        finalizeBody.put("num_parts", String.valueOf(segment));
        post("/2/chat/media/upload/" + enc(sessionId) + "/finalize", finalizeBody);
        return mediaHashKey;
    }

    /**
     * Download an encrypted media blob as raw bytes.
     *
     * <p>The response body is binary ciphertext — it must be read as bytes;
     * any text decoding would corrupt it. The download path takes the hyphen
     * form of the conversation id.
     */
    public byte[] downloadMedia(String conversationId, String mediaHashKey) throws Exception {
        String conv = conversationId.replace(":", "-");
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create(baseUrl + "/2/chat/media/" + enc(conv) + "/" + enc(mediaHashKey)))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() >= 300) {
            throw new RuntimeException("x api media download: " + resp.statusCode());
        }
        return resp.body();
    }

    // -- Sending --------------------------------------------------------------

    /** POST an encrypted message produced by {@link ChatCore#encryptReply}. */
    public void sendMessage(String conversationId, ChatCore.SendBody body) throws Exception {
        var payload = mapper.createObjectNode();
        payload.put("message_id", body.messageId());
        payload.put("encoded_message_create_event", body.encodedMessageCreateEvent());
        payload.put("encoded_message_event_signature", body.encodedMessageEventSignature());
        post("/2/chat/conversations/" + enc(conversationId.replace(":", "-")) + "/messages", payload);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
