package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Types.AttachmentDescriptor;
import com.x.chatxdk.Types.DecryptEventsResult;
import com.x.chatxdk.Types.EntityDescriptor;
import com.x.chatxdk.Types.PreparedConversationChange;
import com.x.chatxdk.Types.PublicKeyInput;
import com.x.chatxdk.Types.SigningKeyEntry;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Live end-to-end test against the X Chat API. Skipped unless CHATXDK_E2E=1 and
 * the credential env vars are set, so the normal offline {@code mvn test} is
 * unaffected.
 *
 * <pre>
 * CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... CHAT_SIGNING_KEY_VERSION=... \
 * CHAT_CONVERSATION_ID=... mvn -Dtest=E2ELiveTest test
 * </pre>
 *
 * Flow (each numbered step asserts against the live API):
 * <ol>
 *   <li>batch-decrypt inbound history (pagination when a second page exists)</li>
 *   <li>rotate the conversation key (prepare -&gt; POST /keys -&gt; decrypt own CKCE)</li>
 *   <li>send a threaded reply with an entity + TTL under the rotated key,
 *       fetch it back, decrypt it via the single-event path, and verify it</li>
 *   <li>react to the sent message (add + remove), decrypting the add back</li>
 * </ol>
 *
 * Optional extras:
 * <ul>
 *   <li>CHATXDK_E2E_MEDIA=1 also stream-encrypts a media blob, uploads it,
 *       sends a message referencing it, then downloads and decrypts it back</li>
 *   <li>CHATXDK_E2E_GROUPS=1 also creates a group (two-signature create),
 *       sends a group message, and adds the 1:1 partner as a member</li>
 * </ul>
 */
class E2ELiveTest {

    private static final String THUMBS_UP = "\uD83D\uDC4D";

    private static String env(String k) {
        String v = System.getenv(k);
        return v == null ? System.getProperty(k) : v;
    }

    private static SigningKeyEntry signingFrom(JsonNode pk, String userId) {
        SigningKeyEntry e = new SigningKeyEntry();
        e.userId = userId;
        e.publicKeyVersion = pk.path("public_key_version").asText("");
        e.publicKey = pk.path("signing_public_key").asText("");
        e.identityPublicKey = pk.path("public_key").asText("");
        e.identityPublicKeySignature = pk.path("identity_public_key_signature").asText("");
        return e;
    }

    /** Public-keys response -&gt; the flat entries the prepare methods take. */
    private static List<PublicKeyInput> keyEntries(List<JsonNode> pks, String userId) {
        List<PublicKeyInput> out = new ArrayList<>();
        for (JsonNode pk : pks) {
            PublicKeyInput input = new PublicKeyInput();
            input.userId = userId;
            input.publicKey = pk.path("public_key").asText("");
            input.keyVersion = pk.path("public_key_version").asText("");
            out.add(input);
        }
        return out;
    }

    private static List<JsonNode> dataArray(JsonNode page) {
        List<JsonNode> out = new ArrayList<>();
        if (page.path("data").isArray()) {
            page.get("data").forEach(out::add);
        }
        return out;
    }

    /**
     * KeyChange events from a GET events page. They arrive in
     * meta.conversation_key_events, separate from data, and carry the
     * conversation keys — they must go into the same decryptBatch call as the
     * data events.
     */
    private static List<String> keyEvents(JsonNode page) {
        List<String> out = new ArrayList<>();
        JsonNode arr = page.path("meta").path("conversation_key_events");
        if (arr.isArray()) {
            for (JsonNode e : arr) {
                if (e.isTextual()) {
                    out.add(e.asText());
                }
            }
        }
        return out;
    }

    /** A decrypted event plus its raw base64 envelope (the reply/reaction
     * target for the by-event API). */
    private record Decrypted(ObjectNode event, String rawB64) {}

    /**
     * Poll the conversation until the event for {@code messageId} lands, and
     * return it decrypted via the single-event path ({@code decryptOne}).
     *
     * <p>The target envelope is matched by its raw event id before decrypting,
     * so a decrypt failure on our own event (e.g. a broken sign-&gt;verify loop)
     * surfaces in the timeout message instead of being silently swallowed.
     */
    private static Decrypted awaitDecrypted(
            XChatClient api,
            ChatCore core,
            String conversationId,
            Map<String, byte[]> convKeys,
            List<SigningKeyEntry> signing,
            String messageId)
            throws Exception {
        Exception lastErr = null;
        for (int i = 0; i < 10; i++) {
            JsonNode page = api.getEvents(conversationId, 25, null);
            for (JsonNode e : dataArray(page)) {
                String b64 = e.path("encoded_event").asText("");
                if (b64.isEmpty()) {
                    continue;
                }
                boolean isTarget = messageId.equals(e.path("id").asText(""));
                JsonNode one;
                try {
                    one = core.decryptOne(b64, convKeys, signing);
                } catch (Exception ex) {
                    if (isTarget) {
                        lastErr = ex;
                    }
                    continue;
                }
                if (isTarget || messageId.equals(one.path("id").asText(""))) {
                    return new Decrypted((ObjectNode) one, b64);
                }
            }
            Thread.sleep(1000);
        }
        throw new AssertionError("event for sent message " + messageId + " never appeared"
                + (lastErr == null ? "" : " (last decrypt error: " + lastErr + ")"));
    }

    @Test
    void e2eLive() throws Exception {
        assumeTrue("1".equals(env("CHATXDK_E2E")), "set CHATXDK_E2E=1 to run the live e2e test");
        String token = env("X_ACCESS_TOKEN");
        String blob = env("CHAT_PRIVATE_KEYS_B64");
        String ver = env("CHAT_SIGNING_KEY_VERSION");
        String conv = env("CHAT_CONVERSATION_ID");
        assertTrue(token != null && blob != null && ver != null && conv != null, "missing env vars");

        XChatClient api = new XChatClient(token, "https://api.x.com");
        try (ChatCore core = new ChatCore()) {
            core.loadKeys(blob, ver);
            String myId = api.getMyUserId();
            core.setIdentity(myId); // session identity, once

            // -- 1. Inbound history: batch decrypt (+ pagination when available)
            JsonNode page = api.getEvents(conv, 10, null);
            List<JsonNode> raw = new ArrayList<>(dataArray(page));
            List<String> keyEventsB64 = new ArrayList<>(keyEvents(page));
            String nextToken = page.path("meta").path("next_token").asText("");
            if (!nextToken.isEmpty()) {
                JsonNode page2 = api.getEvents(conv, 10, nextToken);
                List<JsonNode> raw2 = dataArray(page2);
                Set<String> ids1 = new LinkedHashSet<>();
                raw.forEach(e -> ids1.add(e.path("id").asText()));
                boolean overlap = raw2.stream().anyMatch(e -> ids1.contains(e.path("id").asText()));
                assertTrue(!raw2.isEmpty() && !overlap, "pagination made no progress");
                raw.addAll(raw2);
                keyEventsB64.addAll(keyEvents(page2));
                System.out.println("pagination: fetched second page with " + raw2.size() + " events");
            }

            Set<String> ids = new LinkedHashSet<>();
            ids.add(myId);
            for (JsonNode e : raw) {
                String s = e.path("sender_id").asText("");
                if (!s.isEmpty()) {
                    ids.add(s);
                }
            }
            List<SigningKeyEntry> signing = new ArrayList<>();
            Map<String, List<JsonNode>> pksByUser = new LinkedHashMap<>();
            for (String id : ids) {
                try {
                    List<JsonNode> pks = api.getPublicKeys(id);
                    pksByUser.put(id, pks);
                    for (JsonNode pk : pks) {
                        signing.add(signingFrom(pk, id));
                    }
                } catch (Exception ignored) {
                    // keys unavailable for this user; their events stay unverified
                }
            }

            List<String> eventsB64 = new ArrayList<>(keyEventsB64);
            for (JsonNode e : raw) {
                String ev = e.path("encoded_event").asText("");
                if (!ev.isEmpty()) {
                    eventsB64.add(ev);
                }
            }
            DecryptEventsResult batch = core.decryptBatch(eventsB64, signing);
            long decrypted = batch.messages.stream()
                    .filter(m -> ChatCore.messageText(m.event) != null)
                    .count();
            Map<String, byte[]> convKeys = new HashMap<>(batch.conversationKeys.keys);
            System.out.println("live inbound messages decrypted: " + decrypted
                    + "; conversation keys: " + convKeys.size());
            assertTrue(decrypted > 0, "expected to decrypt at least one live message");

            // Canonical conversation_id, partner id, and the raw inbound event
            // to thread the reply on, from the decrypted batch.
            String canonicalConv = conv;
            String lastInboundEventB64 = null;
            for (var m : batch.messages) {
                JsonNode ev = m.event;
                if (ev == null) {
                    continue;
                }
                if (!ev.path("conversation_id").asText("").isEmpty()) {
                    canonicalConv = ev.get("conversation_id").asText();
                }
                if ("Message".equals(ev.path("type").asText())
                        && !myId.equals(ev.path("sender_id").asText(""))
                        && m.originalB64 != null) {
                    lastInboundEventB64 = m.originalB64;
                }
            }
            String partnerId = ids.stream().filter(id -> !id.equals(myId)).findFirst().orElse(null);
            assertTrue(partnerId != null, "expected a conversation partner among the senders");

            // -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE ---
            List<PublicKeyInput> bothKeys = new ArrayList<>();
            bothKeys.addAll(keyEntries(pksByUser.getOrDefault(myId, List.of()), myId));
            bothKeys.addAll(keyEntries(pksByUser.getOrDefault(partnerId, List.of()), partnerId));
            PreparedConversationChange prep =
                    core.prepareConversationKeyChange(bothKeys, null);
            String signingPub = core.publicKeys().signing;
            JsonNode resp = api.addConversationKeys(conv, ChatCore.prepToRequest(prep, signingPub));
            JsonNode data = resp.path("data");
            assertTrue(
                    !data.path("sequence_id").asText("").isEmpty()
                            || !data.path("conversation_key_change_sequence_id").asText("").isEmpty(),
                    "key rotation not acknowledged: " + resp);
            String serverConv = data.path("conversation_id").asText("");
            System.out.println("rotated conversation key to version " + prep.conversationKeyVersion
                    + (serverConv.isEmpty() ? "" : "; server conversation_id: " + serverConv));

            // The rotated key becomes the sending key; re-fetch (polling briefly,
            // in case the CKCE has not propagated yet) so our own CKCE decrypts
            // and the cache includes the new version.
            String kv = prep.conversationKeyVersion;
            for (int i = 0; i < 5; i++) {
                JsonNode refetchPage = api.getEvents(conv, 10, null);
                List<String> refetch = new ArrayList<>(keyEvents(refetchPage));
                for (JsonNode e : dataArray(refetchPage)) {
                    String ev = e.path("encoded_event").asText("");
                    if (!ev.isEmpty()) {
                        refetch.add(ev);
                    }
                }
                batch = core.decryptBatch(refetch, signing);
                convKeys = new HashMap<>(batch.conversationKeys.keys);
                if (convKeys.containsKey(kv)) {
                    break;
                }
                Thread.sleep(1500);
            }
            assertTrue(convKeys.containsKey(kv),
                    "own rotated CKCE (version " + kv + ") did not decrypt+verify");
            byte[] key = convKeys.get(kv);

            // -- 3. Send under the rotated key; fetch back; single-event decrypt
            // The reply threads on the raw inbound event; its key version
            // predates the rotation, so its KeyChange events ride along for
            // the preview.
            List<String> ckces = new ArrayList<>();
            for (var m : batch.messages) {
                if (m.event != null
                        && "KeyChange".equals(m.event.path("type").asText())
                        && m.originalB64 != null) {
                    ckces.add(m.originalB64);
                }
            }
            String marker = "chat-xdk e2e [jvm] " + (System.currentTimeMillis() / 1000);
            EntityDescriptor mention = new EntityDescriptor();
            mention.start = 0;
            mention.end = 5;
            mention.entityType = "mention";
            ChatCore.SendBody body = core.encryptReply(
                    canonicalConv,
                    "@user " + marker,
                    key,
                    kv,
                    lastInboundEventB64,
                    List.of(mention),
                    null,
                    24L * 60 * 60 * 1000,
                    ckces);
            api.sendMessage(canonicalConv, body);
            System.out.println("sent live encrypted message: \"" + marker + "\"");

            Decrypted sent = awaitDecrypted(api, core, conv, convKeys, signing, body.messageId());
            ObjectNode one = sent.event();
            assertEquals("@user " + marker, ChatCore.messageText(one), "round-trip text mismatch: " + one);
            assertTrue(one.path("verified").asBoolean(false),
                    "own sent message failed signature verification");
            System.out.println("sent message decrypted + verified via the single-event path");

            // -- 4. Reactions: add (round-trip) then remove -------------------
            // React by raw event: the target sequence id is derived from it.
            ChatCore.SendBody add =
                    core.encryptReaction(true, sent.rawB64(), THUMBS_UP, key, kv);
            api.sendMessage(canonicalConv, add);
            ObjectNode reaction =
                    awaitDecrypted(api, core, conv, convKeys, signing, add.messageId()).event();
            JsonNode content = reaction.path("content");
            assertTrue(
                    "Reaction".equals(content.path("content_type").asText())
                            && THUMBS_UP.equals(content.path("emoji").asText()),
                    "expected a Reaction event, got " + content);
            assertTrue(reaction.path("verified").asBoolean(false),
                    "reaction failed signature verification");
            System.out.println("reaction add decrypted + verified");

            ChatCore.SendBody remove =
                    core.encryptReaction(false, sent.rawB64(), THUMBS_UP, key, kv);
            api.sendMessage(canonicalConv, remove);
            System.out.println("reaction remove sent");

            // -- 5. Optional: media — stream-encrypt, upload, send, download,
            // decrypt ----------------------------------------------------------
            if ("1".equals(env("CHATXDK_E2E_MEDIA"))) {
                mediaFlow(api, core, conv, canonicalConv, key, kv, convKeys, signing);
            }

            // -- 6. Optional: group create + message + member add -------------
            if ("1".equals(env("CHATXDK_E2E_GROUPS"))) {
                groupsFlow(api, core, myId, partnerId, bothKeys, signing);
            }

            System.out.println("E2E JVM: PASS");
        }
    }

    private static void mediaFlow(
            XChatClient api,
            ChatCore core,
            String conv,
            String canonicalConv,
            byte[] key,
            String kv,
            Map<String, byte[]> convKeys,
            List<SigningKeyEntry> signing)
            throws Exception {
        // A deterministic multi-chunk payload, so the incremental encryptor
        // emits several frames and any corruption is byte-attributable.
        byte[] plaintext = new byte[300_000];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) ((i * 31 + 7) % 256);
        }
        byte[] ciphertext = core.encryptMedia(plaintext, key);
        String mediaHashKey = api.uploadMedia(canonicalConv, ciphertext);
        System.out.println("encrypted media uploaded: " + mediaHashKey
                + " (" + ciphertext.length + " bytes)");

        AttachmentDescriptor descriptor =
                AttachmentDescriptor.media(mediaHashKey, 0, 0, plaintext.length, "e2e.bin", 5, null);
        ChatCore.SendBody mediaMsg = core.encryptReply(
                canonicalConv,
                "chat-xdk e2e media [jvm] " + (System.currentTimeMillis() / 1000),
                key,
                kv,
                null,
                null,
                List.of(descriptor),
                24L * 60 * 60 * 1000,
                null);
        api.sendMessage(canonicalConv, mediaMsg);
        ObjectNode one = awaitDecrypted(api, core, conv, convKeys, signing, mediaMsg.messageId()).event();
        assertTrue(one.path("verified").asBoolean(false),
                "media message failed signature verification");
        String gotKey = null;
        for (JsonNode a : one.path("content").path("attachments")) {
            if (a.hasNonNull("media")) {
                gotKey = a.path("media").path("media_hash_key").asText("");
                break;
            }
        }
        assertEquals(mediaHashKey, gotKey,
                "attachment did not round-trip: " + one.path("content").path("attachments"));

        byte[] downloaded = api.downloadMedia(canonicalConv, mediaHashKey);
        assertArrayEquals(plaintext, core.decryptMedia(downloaded, key),
                "downloaded media did not decrypt to the original bytes");
        System.out.println("media downloaded + stream-decrypted to the original bytes");
    }

    private static void groupsFlow(
            XChatClient api,
            ChatCore core,
            String myId,
            String partnerId,
            List<PublicKeyInput> bothKeys,
            List<SigningKeyEntry> signing)
            throws Exception {
        List<PublicKeyInput> myKeys =
                bothKeys.stream().filter(k -> myId.equals(k.userId)).toList();
        String signingPub = core.publicKeys().signing;

        String groupId = api.initializeGroup();
        assertTrue(groupId.startsWith("g"), "unexpected group id: " + groupId);

        // Create with the caller as sole member/admin so the member add below
        // exercises prepareGroupMembersChange with the partner.
        PreparedConversationChange prep =
                core.prepareGroupCreate(myKeys, groupId, List.of(myId), List.of(myId));
        List<String> members = List.of(myId);
        try {
            api.createConversation(groupCreateBody(groupId, members, myId, prep, signingPub));
        } catch (Exception ex) {
            // Some deployments reject single-member groups; fall back to creating
            // with both participants (skipping the member-add below).
            prep = core.prepareGroupCreate(
                    bothKeys, groupId, List.of(myId, partnerId), List.of(myId));
            members = List.of(myId, partnerId);
            api.createConversation(groupCreateBody(groupId, members, myId, prep, signingPub));
        }
        String kv = prep.conversationKeyVersion;
        byte[] key = prep.conversationKey;
        System.out.println("group created: " + groupId + " with " + members.size() + " member(s)");

        String marker = "chat-xdk e2e group [jvm] " + (System.currentTimeMillis() / 1000);
        ChatCore.SendBody msg = core.encryptReply(groupId, marker, key, kv);
        api.sendMessage(groupId, msg);
        Map<String, byte[]> convKeys = Map.of(kv, key);
        ObjectNode one = awaitDecrypted(api, core, groupId, convKeys, signing, msg.messageId()).event();
        assertTrue(
                marker.equals(ChatCore.messageText(one)) && one.path("verified").asBoolean(false),
                "group message round-trip failed: " + one);
        System.out.println("group message decrypted + verified");

        if (!members.contains(partnerId)) {
            PreparedConversationChange mPrep = core.prepareGroupMembersChange(
                    bothKeys, groupId, List.of(partnerId), members, List.of(myId));
            ObjectNode body = ChatCore.prepToRequest(mPrep, signingPub);
            body.putArray("user_ids").add(partnerId);
            api.addGroupMembers(groupId, body);
            System.out.println("group member add: " + partnerId
                    + " added (key rotated to " + mPrep.conversationKeyVersion + ")");
        }
    }

    private static ObjectNode groupCreateBody(
            String groupId,
            List<String> members,
            String adminId,
            PreparedConversationChange prep,
            String signingPub) {
        ObjectNode body = ChatCore.prepToRequest(prep, signingPub);
        body.put("conversation_id", groupId);
        var groupMembers = body.putArray("group_members");
        members.forEach(groupMembers::add);
        body.putArray("group_admins").add(adminId);
        body.put("group_name", "chat-xdk e2e");
        return body;
    }
}
