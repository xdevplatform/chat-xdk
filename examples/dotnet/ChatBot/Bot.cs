using System.Text.Json;
using ChatXdk;

namespace ChatBot;

/// <summary>
/// The receive -> decrypt -> reply -> encrypt -> send loop. Conversation state
/// is kept in memory, one entry per conversation.
///
/// One bot serves one signed-in user, in any number of conversations. A
/// process with several signed-in users keeps one chat per user and gives
/// each the same public-keys resolver: <see cref="UserChats"/> and
/// <see cref="SharedPublicKeys"/> in MultiUser.cs do that.
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
        // The SDK fetches the public keys it lacks through the API client:
        // the signing keys of whoever signed a page's events, the members
        // who made its key changes included.
        _core.FetchPublicKeysWith(_api.GetPublicKeysAsync);
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

    /// <summary>
    /// Batch-decrypt one GET events <paramref name="page"/>: its key events,
    /// which carry the conversation keys its messages decrypt under, and its
    /// data events, in one batch. The SDK fetches the public keys the page
    /// lacks and caches the keys of the key changes that verify. Logs what
    /// the page still could not use.
    /// </summary>
    private async Task<DecryptEventsResult> DecryptPageAsync(string conversationId, JsonElement page)
    {
        var eventsB64 = KeyEvents(page);
        if (page.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in data.EnumerateArray())
            {
                if (item.TryGetProperty("encoded_event", out var ev)
                    && ev.ValueKind == JsonValueKind.String
                    && ev.GetString() is { Length: > 0 } eventB64)
                    eventsB64.Add(eventB64);
            }
        }

        var result = await _core.DecryptBatchAsync(eventsB64);
        foreach (var (index, key) in result.MissingSigningKeys)
            Console.Error.WriteLine(
                $"signing_key_missing conv={conversationId} event={index} user={key.UserId} "
                + $"version={key.PublicKeyVersion}");
        foreach (var (index, change) in result.UnverifiedKeyChanges)
            Console.Error.WriteLine(
                $"key_change_unverified conv={conversationId} event={index} reason={change.Reason} "
                + $"signer={change.SenderId} key_dropped={change.KeyDropped}");
        foreach (var (index, change) in result.UndecryptableKeyChanges)
            Console.Error.WriteLine(
                $"key_change_undecryptable conv={conversationId} event={index} reason={change.Reason}");
        foreach (var (index, key) in result.RejectedSigningKeys)
            Console.Error.WriteLine(
                $"signing_key_rejected index={index} user={key.UserId} version={key.PublicKeyVersion}");
        return result;
    }

    /// <summary>
    /// Initial load: batch-decrypt the backlog (DecryptEventsAsync path),
    /// filling the SDK's conversation-key cache from the key changes.
    /// </summary>
    public async Task LoadBacklogAsync(string conversationId)
    {
        var st = State(conversationId);
        var page = await _api.GetEventsAsync(conversationId, 100);
        var result = await DecryptPageAsync(conversationId, page);
        st.PaginationToken = NextToken(page);
        Console.WriteLine($"backlog_loaded conv={conversationId} messages={result.Events.Count} keys={result.ConversationKeys.Keys.Count}");
    }

    /// <summary>
    /// Poll for a page of new events, batch-decrypt it (DecryptEventsAsync
    /// path), and reply to each new incoming message it holds.
    /// </summary>
    public async Task PollOnceAsync(string conversationId)
    {
        var st = State(conversationId);
        var page = await _api.GetEventsAsync(conversationId, 50, st.PaginationToken);
        var result = await DecryptPageAsync(conversationId, page);
        foreach (var (index, error) in result.Errors)
            Console.Error.WriteLine($"decrypt_failed conv={conversationId} event={index} err={error}");

        foreach (var decrypted in result.Events)
        {
            // A reply is threaded under the raw event of its message.
            if (decrypted.OriginalB64 is { Length: > 0 } eventB64)
                await MaybeReplyAsync(conversationId, decrypted.Event, eventB64);
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

        // The message signature covers the conversation_id, so sign with the
        // canonical id carried inside the event (the X API uses a different
        // separator in its URL paths than the form embedded in events).
        var replyConvId = evt.TryGetProperty("conversation_id", out var cid)
            ? cid.GetString() ?? conversationId
            : conversationId;
        var reply = GenerateReply(text);
        // Reply by raw event: the SDK derives the threaded-reply preview from
        // the incoming signed event and embeds it for recipient validation,
        // and the conversation key resolves from the key cache.
        SendBody body;
        try
        {
            body = _core.EncryptReply(replyConvId, reply, replyToEvent: eventB64);
        }
        catch (ChatXdkException e) when (e.Kind == ChatXdkErrorKind.InvalidState)
        {
            Console.Error.WriteLine($"no_conversation_key conv={conversationId}");
            return;
        }
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

    /// <summary>In-memory state for one conversation. Its conversation keys live in the SDK's cache.</summary>
    private sealed class ConversationState
    {
        public HashSet<string> SeenEventIds { get; } = new();
        public string? PaginationToken { get; set; }
    }
}
