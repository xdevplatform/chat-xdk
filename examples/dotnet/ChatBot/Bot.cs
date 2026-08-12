using System.Text.Json;
using ChatXdk;

namespace ChatBot;

/// <summary>
/// The receive -> decrypt -> reply -> encrypt -> send loop. Conversation state
/// is kept in memory, one entry per conversation.
/// </summary>
public sealed class Bot
{
    private readonly ChatCore _core;
    private readonly XChatClient _api;
    private readonly string _botUserId;
    private readonly Dictionary<string, ConversationState> _state = new();

    public Bot(ChatCore core, XChatClient api, string botUserId)
    {
        _core = core;
        _api = api;
        _botUserId = botUserId;
        // Session identity, once: every encrypt below signs as the bot without
        // passing a sender id per call.
        _core.SetIdentity(botUserId);
    }

    /// <summary>Turn an incoming message into a reply (simple echo by default).</summary>
    public static string GenerateReply(string text) =>
        text.Trim() is "ping" or "!ping" ? "pong" : $"You said: {text.Trim()}";

    private ConversationState State(string conversationId)
    {
        if (!_state.TryGetValue(conversationId, out var st))
        {
            st = new ConversationState();
            _state[conversationId] = st;
        }
        return st;
    }

    /// <summary>Pagination token from a GET events page, or null when absent.</summary>
    private static string? NextToken(JsonElement page) =>
        page.TryGetProperty("meta", out var meta)
        && meta.ValueKind == JsonValueKind.Object
        && meta.TryGetProperty("next_token", out var nt)
        && nt.ValueKind == JsonValueKind.String
            ? nt.GetString()
            : null;

    /// <summary>
    /// KeyChange events from a GET events page. They arrive in
    /// meta.conversation_key_events, separate from data, and carry the
    /// conversation keys — they must go into the same DecryptEvents batch as
    /// the data events.
    /// </summary>
    private static List<string> KeyEvents(JsonElement page) =>
        page.TryGetProperty("meta", out var meta)
        && meta.ValueKind == JsonValueKind.Object
        && meta.TryGetProperty("conversation_key_events", out var arr)
        && arr.ValueKind == JsonValueKind.Array
            ? arr.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .ToList()
            : new List<string>();

    private async Task<List<SigningKeyEntry>> SigningKeysForAsync(IEnumerable<JsonElement> events)
    {
        var senders = events
            .Select(e => e.TryGetProperty("sender_id", out var s) ? s.GetString() : null)
            .Where(id => !string.IsNullOrEmpty(id) && id != _botUserId)
            .Distinct()
            .ToList();

        var keys = new List<SigningKeyEntry>();
        foreach (var senderId in senders)
        {
            try
            {
                foreach (var pk in await _api.GetPublicKeysAsync(senderId!))
                {
                    keys.Add(new SigningKeyEntry
                    {
                        UserId = senderId!,
                        PublicKeyVersion = pk.TryGetProperty("public_key_version", out var v) ? v.GetString() ?? "" : "",
                        PublicKey = pk.TryGetProperty("signing_public_key", out var sp) ? sp.GetString() ?? "" : "",
                        IdentityPublicKey = pk.TryGetProperty("public_key", out var p) ? p.GetString() ?? "" : "",
                        IdentityPublicKeySignature = pk.TryGetProperty("identity_public_key_signature", out var sig) ? sig.GetString() ?? "" : "",
                    });
                }
            }
            catch
            {
                Console.Error.WriteLine($"public_keys_fetch_failed sender={senderId}");
            }
        }
        return keys;
    }

    /// <summary>Initial load: batch-decrypt the backlog (DecryptEvents path).</summary>
    public async Task LoadBacklogAsync(string conversationId)
    {
        var st = State(conversationId);
        var page = await _api.GetEventsAsync(conversationId, 100);
        var raw = page.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array
            ? d.EnumerateArray().ToList()
            : new List<JsonElement>();
        var eventsB64 = KeyEvents(page);
        eventsB64.AddRange(raw
            .Select(e => e.TryGetProperty("encoded_event", out var ev) ? ev.GetString() : null)
            .Where(s => !string.IsNullOrEmpty(s))
            .Select(s => s!));

        var result = _core.DecryptBatch(eventsB64, await SigningKeysForAsync(raw));
        foreach (var (version, key) in result.ConversationKeys.Keys)
            st.ConversationKeys[version] = key;
        st.LatestKeyVersion = result.ConversationKeys.LatestVersion;
        st.PaginationToken = NextToken(page);
        Console.WriteLine($"backlog_loaded conv={conversationId} messages={result.Messages.Count} keys={result.ConversationKeys.Keys.Count}");
    }

    /// <summary>Poll for new events; reply to each new message (DecryptEvent path).</summary>
    public async Task PollOnceAsync(string conversationId)
    {
        var st = State(conversationId);
        var page = await _api.GetEventsAsync(conversationId, 50, st.PaginationToken);
        var raw = page.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array
            ? d.EnumerateArray().ToList()
            : new List<JsonElement>();
        var signingKeys = await SigningKeysForAsync(raw);

        // Key changes for this page arrive in meta, not data; adopt their
        // keys before decrypting the messages that need them.
        var pageKeyEvents = KeyEvents(page);
        if (pageKeyEvents.Count > 0)
        {
            var rotated = _core.DecryptBatch(pageKeyEvents, signingKeys);
            foreach (var (version, key) in rotated.ConversationKeys.Keys)
                st.ConversationKeys[version] = key;
            if (rotated.ConversationKeys.LatestVersion is { } lv)
                st.LatestKeyVersion = lv;
        }

        foreach (var item in raw)
        {
            if (!item.TryGetProperty("encoded_event", out var ev) || ev.GetString() is not { } eventB64)
                continue;
            var decrypted = _core.DecryptOne(eventB64, st.ConversationKeys, signingKeys);

            if (decrypted.TryGetProperty("type", out var t) && t.GetString() == "KeyChange")
            {
                var keyVersion = decrypted.GetProperty("key_version").GetString()!;
                foreach (var pk in decrypted.GetProperty("participant_keys").EnumerateArray())
                {
                    var enc = pk.GetProperty("encrypted_key").GetString();
                    if (string.IsNullOrEmpty(enc)) continue;
                    try
                    {
                        st.ConversationKeys[keyVersion] = _core.DecryptConversationKey(enc);
                        st.LatestKeyVersion = keyVersion;
                        break;
                    }
                    catch { /* not for us */ }
                }
                continue;
            }
            await MaybeReplyAsync(conversationId, decrypted, eventB64);
        }
        // Advance the pagination token so the next poll fetches only new events.
        if (NextToken(page) is { Length: > 0 } next)
            st.PaginationToken = next;
    }

    private async Task MaybeReplyAsync(string conversationId, JsonElement evt, string eventB64)
    {
        var st = State(conversationId);
        var eventId = evt.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
        var senderId = evt.TryGetProperty("sender_id", out var s) ? s.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(eventId) || !st.SeenEventIds.Add(eventId)) return;
        if (senderId == _botUserId) return;

        var text = EventHelpers.MessageText(evt);
        if (string.IsNullOrEmpty(text)) return;

        var keyVersion = evt.TryGetProperty("key_version", out var kv) ? kv.GetString() : st.LatestKeyVersion;
        if (keyVersion is null || !st.ConversationKeys.TryGetValue(keyVersion, out var convKey))
        {
            Console.Error.WriteLine($"no_conversation_key conv={conversationId}");
            return;
        }

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        var replyConvId = evt.TryGetProperty("conversation_id", out var cid)
            ? cid.GetString() ?? conversationId
            : conversationId;
        var reply = GenerateReply(text);
        // Reply by raw event: the SDK derives the threaded-reply preview from
        // the incoming signed event and embeds it for recipient validation.
        var body = _core.EncryptReply(replyConvId, reply, convKey, keyVersion, replyToEvent: eventB64);
        await _api.SendMessageAsync(replyConvId, body);
        Console.WriteLine($"reply_sent conv={replyConvId} len={reply.Length}");
    }

    /// <summary>Load the backlog then poll forever.</summary>
    public async Task RunAsync(string conversationId, TimeSpan pollInterval)
    {
        await LoadBacklogAsync(conversationId);
        Console.WriteLine($"bot_running conv={conversationId} polling every {pollInterval}");
        while (true)
        {
            try { await PollOnceAsync(conversationId); }
            catch (Exception e) { Console.Error.WriteLine($"poll_error conv={conversationId} {e.Message}"); }
            await Task.Delay(pollInterval);
        }
    }

    private sealed class ConversationState
    {
        public Dictionary<string, byte[]> ConversationKeys { get; } = new();
        public string? LatestKeyVersion { get; set; }
        public HashSet<string> SeenEventIds { get; } = new();
        public string? PaginationToken { get; set; }
    }
}
