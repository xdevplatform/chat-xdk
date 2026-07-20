using System.Text.Json;
using ChatXdk;
using ChatBot;
using Xunit;

namespace ChatBot.Tests;

/// <summary>
/// Live end-to-end test against the X Chat API, using the example's real
/// <see cref="ChatCore"/> (ChatXdk binding) and <see cref="XChatClient"/>.
/// Skipped unless CHATXDK_E2E=1 and the credential env vars are set, so the
/// normal offline <c>dotnet test</c> is unaffected.
///
/// <code>
/// CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... CHAT_SIGNING_KEY_VERSION=... \
/// CHAT_CONVERSATION_ID=... dotnet test
/// </code>
///
/// Flow (each numbered step asserts against the live API):
///   1. batch-decrypt inbound history (pagination when a second page exists)
///   2. rotate the conversation key (prepare -> POST /keys -> decrypt own CKCE)
///   3. send a threaded reply with an entity + TTL under the rotated key,
///      fetch it back, decrypt it via the single-event path, and verify it
///   4. react to the sent message (add + remove), decrypting the add back
///
/// Optional extras: CHATXDK_E2E_MEDIA=1 also stream-encrypts a media blob,
/// uploads it, sends a message referencing it, then downloads and
/// stream-decrypts it back to the original bytes; CHATXDK_E2E_GROUPS=1 also
/// creates a group (two-signature create), sends a group message, and adds
/// the 1:1 partner as a member.
/// </summary>
public class E2ELiveTests
{
    private static string? Env(string k) => Environment.GetEnvironmentVariable(k);

    /// <summary>String value of a JSON property that may arrive as a string or number.</summary>
    private static string? Str(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v)
            ? v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Number => v.GetRawText(),
                _ => null,
            }
            : null;

    private static List<JsonElement> Data(JsonElement page) =>
        page.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array
            ? d.EnumerateArray().ToList()
            : new List<JsonElement>();

    private static List<string> EventsB64(IEnumerable<JsonElement> raw) =>
        raw.Select(e => Str(e, "encoded_event")).Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).ToList();

    private static SigningKeyEntry SigningFrom(JsonElement pk, string userId) => new()
    {
        UserId = userId,
        PublicKeyVersion = Str(pk, "public_key_version") ?? "",
        PublicKey = Str(pk, "signing_public_key") ?? "",
        IdentityPublicKey = Str(pk, "public_key") ?? "",
        IdentityPublicKeySignature = Str(pk, "identity_public_key_signature") ?? "",
    };

    /// <summary>Public-keys response -> the flat entries the prepare methods take.</summary>
    private static List<PublicKeyInput> KeyEntries(IEnumerable<JsonElement> pks, string userId) =>
        pks.Select(pk => new PublicKeyInput
        {
            UserId = userId,
            PublicKey = Str(pk, "public_key") ?? "",
            KeyVersion = Str(pk, "public_key_version") ?? "",
        }).ToList();

    /// <summary>
    /// Poll the conversation until the event for <paramref name="messageId"/> lands,
    /// and return it decrypted via the single-event path (<see cref="ChatCore.DecryptOne"/>),
    /// plus the raw base64 envelope (the reply/reaction target for the by-event API).
    ///
    /// The target envelope is matched by its raw event id before decrypting, so a
    /// decrypt failure on our own event (e.g. a broken sign->verify loop) surfaces
    /// in the timeout message instead of being silently swallowed.
    /// </summary>
    private static async Task<(JsonElement Event, string RawB64)> AwaitDecryptedAsync(
        XChatClient api,
        ChatCore core,
        string conversationId,
        Dictionary<string, byte[]> convKeys,
        List<SigningKeyEntry> signing,
        string messageId,
        int tries = 10)
    {
        Exception? lastErr = null;
        for (var i = 0; i < tries; i++)
        {
            var page = await api.GetEventsAsync(conversationId, 25);
            foreach (var e in Data(page))
            {
                var b64 = Str(e, "encoded_event");
                if (string.IsNullOrEmpty(b64)) continue;
                var isTarget = (Str(e, "id") ?? "") == messageId;
                JsonElement one;
                try
                {
                    one = core.DecryptOne(b64, convKeys, signing);
                }
                catch (Exception ex)
                {
                    if (isTarget) lastErr = ex;
                    continue;
                }
                if (!isTarget && (Str(one, "id") ?? "") != messageId) continue;
                return (one, b64!);
            }
            await Task.Delay(1000);
        }
        throw new Exception($"event for sent message \"{messageId}\" never appeared"
            + (lastErr is null ? "" : $" (last decrypt error: {lastErr.Message})"));
    }

    [Fact]
    public async Task E2ELive()
    {
        if (Env("CHATXDK_E2E") != "1") return; // skip in normal offline runs

        var token = Env("X_ACCESS_TOKEN")!;
        var blob = Env("CHAT_PRIVATE_KEYS_B64")!;
        var ver = Env("CHAT_SIGNING_KEY_VERSION")!;
        var conv = Env("CHAT_CONVERSATION_ID")!;
        Assert.False(string.IsNullOrEmpty(token) || string.IsNullOrEmpty(blob)
            || string.IsNullOrEmpty(ver) || string.IsNullOrEmpty(conv));

        var api = new XChatClient(token, "https://api.x.com");
        using var core = new ChatCore();
        core.LoadKeys(blob, ver);
        var myId = await api.GetMyUserIdAsync();
        core.SetIdentity(myId); // session identity, once

        // -- 1. Inbound history: batch decrypt (+ pagination when available) ----
        var page = await api.GetEventsAsync(conv, 10);
        var raw = Data(page);
        var nextToken = page.TryGetProperty("meta", out var meta) ? Str(meta, "next_token") : null;
        if (!string.IsNullOrEmpty(nextToken))
        {
            var page2 = await api.GetEventsAsync(conv, 10, nextToken);
            var raw2 = Data(page2);
            var ids1 = raw.Select(e => Str(e, "id") ?? "").ToHashSet();
            Assert.True(raw2.Count > 0 && !raw2.Any(e => ids1.Contains(Str(e, "id") ?? "")),
                "pagination made no progress");
            raw.AddRange(raw2);
            Console.WriteLine($"pagination: fetched second page with {raw2.Count} events");
        }

        var ids = new HashSet<string> { myId };
        foreach (var e in raw)
            if (Str(e, "sender_id") is { Length: > 0 } sid)
                ids.Add(sid);

        var signing = new List<SigningKeyEntry>();
        var pksByUser = new Dictionary<string, List<JsonElement>>();
        foreach (var id in ids)
        {
            try
            {
                var pks = await api.GetPublicKeysAsync(id);
                pksByUser[id] = pks;
                signing.AddRange(pks.Select(pk => SigningFrom(pk, id)));
            }
            catch
            {
                // users without registered keys contribute nothing to verify against
            }
        }

        var batch = core.DecryptBatch(EventsB64(raw), signing);
        var decrypted = batch.Messages.Count(m => !string.IsNullOrEmpty(EventHelpers.MessageText(m.Event)));
        var convKeys = new Dictionary<string, byte[]>(batch.ConversationKeys.Keys);
        Console.WriteLine($"live inbound messages decrypted: {decrypted}; conversation keys: {convKeys.Count}");
        Assert.True(decrypted > 0, "expected to decrypt at least one live message");

        // Canonical conversation_id, partner id, and the raw inbound event to
        // thread the reply on, from the decrypted batch.
        var canonicalConv = conv;
        string? lastInboundEventB64 = null;
        foreach (var m in batch.Messages)
        {
            var ev = m.Event;
            if (Str(ev, "conversation_id") is { Length: > 0 } cid) canonicalConv = cid;
            if (Str(ev, "type") == "Message" && Str(ev, "sender_id") != myId)
                lastInboundEventB64 = m.OriginalB64 ?? lastInboundEventB64;
        }
        var partnerId = ids.FirstOrDefault(id => id != myId);
        Assert.True(partnerId is not null, "expected a conversation partner among the senders");

        // -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE ---------
        var bothKeys = KeyEntries(pksByUser.GetValueOrDefault(myId) ?? new(), myId)
            .Concat(KeyEntries(pksByUser.GetValueOrDefault(partnerId!) ?? new(), partnerId!))
            .ToList();
        var prep = core.PrepareConversationKeyChange(bothKeys);
        var signingPub = core.PublicKeys().Signing;
        var resp = await api.AddConversationKeysAsync(conv, EventHelpers.PrepToRequest(prep, signingPub));
        var data = resp.ValueKind == JsonValueKind.Object && resp.TryGetProperty("data", out var dEl) ? dEl : default;
        Assert.True(
            !string.IsNullOrEmpty(Str(data, "sequence_id"))
            || !string.IsNullOrEmpty(Str(data, "conversation_key_change_sequence_id")),
            $"key rotation not acknowledged: {resp}");
        var serverConv = Str(data, "conversation_id");
        Console.WriteLine($"rotated conversation key to version {prep.ConversationKeyVersion}"
            + (string.IsNullOrEmpty(serverConv) ? "" : $"; server conversation_id: {serverConv}"));

        // The rotated key becomes the sending key; re-fetch (polling briefly, in
        // case the CKCE has not propagated yet) so our own CKCE decrypts and the
        // cache includes the new version.
        var kv = prep.ConversationKeyVersion;
        for (var i = 0; i < 5; i++)
        {
            page = await api.GetEventsAsync(conv, 10);
            batch = core.DecryptBatch(EventsB64(Data(page)), signing);
            convKeys = new Dictionary<string, byte[]>(batch.ConversationKeys.Keys);
            if (convKeys.ContainsKey(kv)) break;
            await Task.Delay(1500);
        }
        Assert.True(convKeys.ContainsKey(kv), $"own rotated CKCE (version {kv}) did not decrypt+verify");
        var key = convKeys[kv];

        // -- 3. Send under the rotated key; fetch back; single-event decrypt ----
        // The reply threads on the raw inbound event; its key version predates
        // the rotation, so its KeyChange events ride along for the preview.
        var ckces = batch.Messages
            .Where(m => Str(m.Event, "type") == "KeyChange" && m.OriginalB64 is { Length: > 0 })
            .Select(m => m.OriginalB64!)
            .ToList();
        var marker = $"chat-xdk e2e [dotnet] {DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        var body = core.EncryptReply(
            canonicalConv,
            $"@user {marker}",
            key,
            kv,
            replyToEvent: lastInboundEventB64,
            entities: new[] { new EntityDescriptor { Start = 0, End = 5, EntityType = "mention" } },
            ttlMsec: 24L * 60 * 60 * 1000,
            replyToCkces: ckces);
        await api.SendMessageAsync(canonicalConv, body);
        Console.WriteLine($"sent live encrypted message: \"{marker}\"");

        var (one, sentRawB64) = await AwaitDecryptedAsync(api, core, conv, convKeys, signing, body.MessageId);
        Assert.True(EventHelpers.MessageText(one) == $"@user {marker}", $"round-trip text mismatch: {one}");
        Assert.True(one.TryGetProperty("verified", out var v3) && v3.GetBoolean(),
            "own sent message failed signature verification");
        Console.WriteLine("sent message decrypted + verified via the single-event path");

        // -- 4. Reactions: add (round-trip) then remove --------------------------
        // React by raw event: the target sequence id is derived from it.
        var add = core.EncryptReaction(
            add: true,
            targetEventB64: sentRawB64,
            emoji: "\U0001F44D",
            conversationKey: key,
            conversationKeyVersion: kv);
        await api.SendMessageAsync(canonicalConv, add);
        var (reaction, _) = await AwaitDecryptedAsync(api, core, conv, convKeys, signing, add.MessageId);
        var content = reaction.TryGetProperty("content", out var cEl) ? cEl : default;
        Assert.True(Str(content, "content_type") == "Reaction" && Str(content, "emoji") == "\U0001F44D",
            $"expected a Reaction event, got {content}");
        Assert.True(reaction.TryGetProperty("verified", out var v4) && v4.GetBoolean(),
            "reaction failed signature verification");
        Console.WriteLine("reaction add decrypted + verified");

        var remove = core.EncryptReaction(
            add: false,
            targetEventB64: sentRawB64,
            emoji: "\U0001F44D",
            conversationKey: key,
            conversationKeyVersion: kv);
        await api.SendMessageAsync(canonicalConv, remove);
        Console.WriteLine("reaction remove sent");

        // -- 5. Optional: media — stream-encrypt, upload, send, download, decrypt
        if (Env("CHATXDK_E2E_MEDIA") == "1")
        {
            // A deterministic multi-chunk payload, so the incremental encryptor
            // emits several frames and any corruption is byte-attributable.
            var plaintext = new byte[300_000];
            for (var i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)((i * 31 + 7) % 256);
            var ciphertext = core.EncryptMedia(plaintext, key);
            var mediaHashKey = await api.UploadMediaAsync(canonicalConv, ciphertext);
            Console.WriteLine($"encrypted media uploaded: {mediaHashKey} ({ciphertext.Length} bytes)");

            var mediaMsg = core.EncryptReply(
                canonicalConv,
                $"chat-xdk e2e media [dotnet] {DateTimeOffset.UtcNow.ToUnixTimeSeconds()}",
                key,
                kv,
                attachments: new[]
                {
                    AttachmentDescriptor.Media(mediaHashKey, 0, 0, plaintext.Length, "e2e.bin", 5),
                },
                ttlMsec: 24L * 60 * 60 * 1000);
            await api.SendMessageAsync(canonicalConv, mediaMsg);
            var (mediaOne, _) = await AwaitDecryptedAsync(api, core, conv, convKeys, signing, mediaMsg.MessageId);
            Assert.True(mediaOne.TryGetProperty("verified", out var v5) && v5.GetBoolean(),
                "media message failed signature verification");
            var atts = mediaOne.TryGetProperty("content", out var mContent)
                && mContent.TryGetProperty("attachments", out var aEl)
                && aEl.ValueKind == JsonValueKind.Array
                ? aEl.EnumerateArray().ToList()
                : new List<JsonElement>();
            var gotKey = atts
                .Where(a => a.ValueKind == JsonValueKind.Object
                    && a.TryGetProperty("media", out var m) && m.ValueKind == JsonValueKind.Object)
                .Select(a => Str(a.GetProperty("media"), "media_hash_key"))
                .FirstOrDefault();
            Assert.True(gotKey == mediaHashKey,
                $"attachment did not round-trip: {JsonSerializer.Serialize(atts)}");

            var downloaded = await api.DownloadMediaAsync(canonicalConv, mediaHashKey);
            Assert.True(core.DecryptMedia(downloaded, key).AsSpan().SequenceEqual(plaintext),
                "downloaded media did not decrypt to the original bytes");
            Console.WriteLine("media downloaded + stream-decrypted to the original bytes");
        }

        // -- 6. Optional: group create + message + member add --------------------
        if (Env("CHATXDK_E2E_GROUPS") == "1")
            await GroupsFlowAsync(api, core, myId, partnerId!, bothKeys, signing);

        Console.WriteLine("E2E DOTNET: PASS");
    }

    private static async Task GroupsFlowAsync(
        XChatClient api,
        ChatCore core,
        string myId,
        string partnerId,
        List<PublicKeyInput> bothKeys,
        List<SigningKeyEntry> signing)
    {
        var myKeys = bothKeys.Where(k => k.UserId == myId).ToList();
        var signingPub = core.PublicKeys().Signing;

        var groupId = await api.InitializeGroupAsync();
        Assert.True(groupId.StartsWith("g"), $"unexpected group id: \"{groupId}\"");

        // Create with the caller as sole member/admin so the member add below
        // exercises PrepareGroupMembersChange with the partner.
        var prep = core.PrepareGroupCreate(myKeys, groupId, new[] { myId }, new[] { myId });
        var members = new List<string> { myId };
        var body = EventHelpers.PrepToRequest(prep, signingPub);
        body["conversation_id"] = groupId;
        body["group_members"] = members;
        body["group_admins"] = new[] { myId };
        body["group_name"] = "chat-xdk e2e";
        try
        {
            await api.CreateConversationAsync(body);
        }
        catch
        {
            // Some deployments reject single-member groups; fall back to creating
            // with both participants (skipping the member-add below).
            prep = core.PrepareGroupCreate(bothKeys, groupId, new[] { myId, partnerId }, new[] { myId });
            members = new List<string> { myId, partnerId };
            body = EventHelpers.PrepToRequest(prep, signingPub);
            body["conversation_id"] = groupId;
            body["group_members"] = members;
            body["group_admins"] = new[] { myId };
            body["group_name"] = "chat-xdk e2e";
            await api.CreateConversationAsync(body);
        }
        var kv = prep.ConversationKeyVersion;
        var key = prep.ConversationKey!;
        Console.WriteLine($"group created: {groupId} with {members.Count} member(s)");

        var marker = $"chat-xdk e2e group [dotnet] {DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        var msg = core.EncryptReply(groupId, marker, key, kv);
        await api.SendMessageAsync(groupId, msg);
        var convKeys = new Dictionary<string, byte[]> { [kv] = key };
        var (one, _) = await AwaitDecryptedAsync(api, core, groupId, convKeys, signing, msg.MessageId);
        Assert.True(
            EventHelpers.MessageText(one) == marker
            && one.TryGetProperty("verified", out var v) && v.GetBoolean(),
            $"group message round-trip failed: {one}");
        Console.WriteLine("group message decrypted + verified");

        if (!members.Contains(partnerId))
        {
            var mPrep = core.PrepareGroupMembersChange(
                bothKeys, groupId, new[] { partnerId }, members, new[] { myId });
            var mBody = EventHelpers.PrepToRequest(mPrep, signingPub);
            mBody["user_ids"] = new[] { partnerId };
            await api.AddGroupMembersAsync(groupId, mBody);
            Console.WriteLine($"group member add: {partnerId} added (key rotated to {mPrep.ConversationKeyVersion})");
        }
    }
}
