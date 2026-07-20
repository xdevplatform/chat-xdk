using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace ChatBot;

/// <summary>
/// Minimal X Chat API client over HTTP with <see cref="HttpClient"/>.
/// Authentication is an OAuth2 user access token (scopes dm.read + dm.write).
/// </summary>
public sealed class XChatClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public XChatClient(string accessToken, string baseUrl = "https://api.x.com")
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }

    public async Task<string> GetMyUserIdAsync()
    {
        var doc = await _http.GetFromJsonAsync<JsonElement>($"{_baseUrl}/2/users/me");
        return doc.GetProperty("data").GetProperty("id").GetString()!;
    }

    /// <summary>Fetch a user's registered public keys (for ECIES + verify, or to
    /// check your own before registering). Every field of the public_key
    /// resource (<c>public_key</c>, <c>signing_public_key</c>,
    /// <c>identity_public_key_signature</c>, <c>public_key_version</c>,
    /// <c>juicebox_config</c>) is always included; the route takes no
    /// <c>public_key.fields</c> parameter.</summary>
    public async Task<List<JsonElement>> GetPublicKeysAsync(string userId)
    {
        var doc = await _http.GetFromJsonAsync<JsonElement>(
            $"{_baseUrl}/2/users/{Uri.EscapeDataString(userId)}/public_keys");
        var data = doc.GetProperty("data");
        return data.ValueKind == JsonValueKind.Array
            ? data.EnumerateArray().ToList()
            : new List<JsonElement> { data };
    }

    /// <summary>
    /// Register a public key: POST /2/users/{id}/public_keys.
    ///
    /// <paramref name="body"/> is the registration object from
    /// <c>GenerateKeypairs</c> in its snake_case wire form (<c>public_key</c>
    /// object, <c>version</c>, <c>generate_version</c>). Throws
    /// <see cref="RateLimitedException"/> on 429 so the caller can stop instead
    /// of burning the strict daily budget.
    /// </summary>
    public async Task<JsonElement> AddUserPublicKeyAsync(string userId, object body)
    {
        var resp = await _http.PostAsJsonAsync(
            $"{_baseUrl}/2/users/{Uri.EscapeDataString(userId)}/public_keys", body);
        if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        {
            long? reset = null;
            if (resp.Headers.TryGetValues("x-user-limit-24hour-reset", out var vals)
                && long.TryParse(vals.FirstOrDefault(), out var r))
                reset = r;
            throw new RateLimitedException(reset);
        }
        resp.EnsureSuccessStatusCode();
        var text = await resp.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(text)) return default;
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }

    /// <summary>
    /// Build the Juicebox config JSON + latest key version for the optional PIN
    /// backup. Every public_key field (<c>juicebox_config</c> included) is always
    /// returned; the route takes no <c>public_key.fields</c> parameter.
    /// </summary>
    public async Task<(string ConfigJson, string Version)> GetJuiceboxConfigAsync(string userId)
    {
        var doc = await _http.GetFromJsonAsync<JsonElement>(
            $"{_baseUrl}/2/users/{Uri.EscapeDataString(userId)}/public_keys");
        var data = doc.GetProperty("data");
        var items = data.ValueKind == JsonValueKind.Array
            ? data.EnumerateArray().ToList()
            : new List<JsonElement> { data };
        if (items.Count == 0)
            throw new InvalidOperationException("no public keys returned");
        var latest = items[0];
        foreach (var it in items)
            if (VersionInt(it) >= VersionInt(latest)) latest = it;
        if (!latest.TryGetProperty("juicebox_config", out var cfg) || cfg.ValueKind == JsonValueKind.Null)
            throw new InvalidOperationException("no juicebox_config on the account");
        // Passed to the SDK as-is: it reads `key_store_token_map_json` verbatim.
        return (cfg.GetRawText(), VersionStr(latest));
    }

    private static long VersionInt(JsonElement el) =>
        el.TryGetProperty("public_key_version", out var v)
            ? v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out var n) ? n
              : v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0
            : 0;

    private static string VersionStr(JsonElement el) =>
        el.TryGetProperty("public_key_version", out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "1" : v.ToString()
            : "1";

    /// <summary>GET the raw (encrypted) events for a conversation.</summary>
    public async Task<JsonElement> GetEventsAsync(string conversationId, int maxResults = 50, string? paginationToken = null)
    {
        var url = $"{_baseUrl}/2/chat/conversations/{Uri.EscapeDataString(conversationId.Replace(':', '-'))}/events?max_results={maxResults}";
        if (!string.IsNullOrEmpty(paginationToken))
            url += $"&pagination_token={Uri.EscapeDataString(paginationToken)}";
        return await _http.GetFromJsonAsync<JsonElement>(url);
    }

    // -- Conversation / key management ---------------------------------------

    /// <summary>
    /// POST a prepared conversation-key change (initialize or rotate).
    /// <paramref name="body"/> is the request shape built by
    /// <see cref="EventHelpers.PrepToRequest"/>. For a 1:1, <paramref name="conversationId"/>
    /// may be the recipient's user ID; the server derives (and returns) the
    /// canonical conversation ID.
    /// </summary>
    public Task<JsonElement> AddConversationKeysAsync(string conversationId, object body)
        => PostAsync($"/2/chat/conversations/{Uri.EscapeDataString(conversationId.Replace(':', '-'))}/keys", body);

    /// <summary>Mint a new group conversation id (<c>g…</c>).</summary>
    public async Task<string> InitializeGroupAsync()
    {
        var doc = await PostAsync("/2/chat/conversations/group/initialize", new Dictionary<string, object?>());
        return doc.TryGetProperty("data", out var data)
            && data.TryGetProperty("conversation_id", out var id)
            ? id.GetString() ?? ""
            : "";
    }

    /// <summary>
    /// POST /2/chat/conversations/group — create a group conversation.
    /// <paramref name="body"/> carries <c>conversation_id</c>, <c>group_members</c>,
    /// <c>group_admins</c>, and the two-signature key change from
    /// <see cref="ChatCore.PrepareGroupCreate"/>.
    /// </summary>
    public Task<JsonElement> CreateConversationAsync(object body)
        => PostAsync("/2/chat/conversations/group", body);

    /// <summary>
    /// POST /2/chat/conversations/{id}/members — add members to a group.
    /// <paramref name="body"/> carries <c>user_ids</c> plus the rotated key change
    /// from <see cref="ChatCore.PrepareGroupMembersChange"/>.
    /// </summary>
    public Task<JsonElement> AddGroupMembersAsync(string conversationId, object body)
        => PostAsync($"/2/chat/conversations/{Uri.EscapeDataString(conversationId)}/members", body);

    // -- Media (encrypted blobs) ---------------------------------------------

    private const int UploadChunk = 3 * 1024 * 1024;

    /// <summary>
    /// Upload an encrypted media blob; returns its <c>media_hash_key</c>.
    ///
    /// Three-step flow: initialize (returns an upload session and the hash
    /// key), append (3 MB segments), finalize. The media endpoints take the
    /// colon form of the conversation id in the body.
    /// </summary>
    public async Task<string> UploadMediaAsync(string conversationId, byte[] ciphertext)
    {
        var conv = conversationId.Replace('-', ':');
        var init = await PostAsync("/2/chat/media/upload/initialize", new Dictionary<string, object?>
        {
            ["conversation_id"] = conv,
            ["total_bytes"] = ciphertext.Length,
        });
        var data = init.ValueKind == JsonValueKind.Object && init.TryGetProperty("data", out var d)
            ? d
            : default;
        var sessionId = Prop(data, "session_id") ?? Prop(data, "sessionId");
        var mediaHashKey = Prop(data, "media_hash_key") ?? Prop(data, "mediaHashKey");
        if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(mediaHashKey))
            throw new InvalidOperationException($"media upload initialize failed: {init}");

        var segment = 0;
        for (var offset = 0; offset < ciphertext.Length; offset += UploadChunk)
        {
            var len = Math.Min(UploadChunk, ciphertext.Length - offset);
            await PostAsync($"/2/chat/media/upload/{Uri.EscapeDataString(sessionId)}/append",
                new Dictionary<string, object?>
                {
                    ["conversation_id"] = conv,
                    ["media_hash_key"] = mediaHashKey,
                    ["segment_index"] = segment.ToString(),
                    ["media"] = Convert.ToBase64String(ciphertext, offset, len),
                });
            segment++;
        }

        await PostAsync($"/2/chat/media/upload/{Uri.EscapeDataString(sessionId)}/finalize",
            new Dictionary<string, object?>
            {
                ["conversation_id"] = conv,
                ["media_hash_key"] = mediaHashKey,
                ["num_parts"] = segment.ToString(),
            });
        return mediaHashKey;
    }

    /// <summary>
    /// Download an encrypted media blob as raw bytes.
    ///
    /// The response body is binary ciphertext — it must be read as bytes;
    /// any text decoding would corrupt it. The download path takes the
    /// hyphen form of the conversation id.
    /// </summary>
    public Task<byte[]> DownloadMediaAsync(string conversationId, string mediaHashKey)
    {
        var conv = conversationId.Replace(':', '-');
        return _http.GetByteArrayAsync(
            $"{_baseUrl}/2/chat/media/{Uri.EscapeDataString(conv)}/{Uri.EscapeDataString(mediaHashKey)}");
    }

    // -- Sending ------------------------------------------------------------

    /// <summary>POST an encrypted message produced by <see cref="ChatCore.EncryptReply"/>.</summary>
    public async Task SendMessageAsync(string conversationId, SendBody body)
    {
        var payload = new Dictionary<string, string>
        {
            ["message_id"] = body.MessageId,
            ["encoded_message_create_event"] = body.EncodedMessageCreateEvent,
            ["encoded_message_event_signature"] = body.EncodedMessageEventSignature,
        };
        var resp = await _http.PostAsJsonAsync(
            $"{_baseUrl}/2/chat/conversations/{Uri.EscapeDataString(conversationId.Replace(':', '-'))}/messages", payload);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>String value of a JSON property on an object element, or null.</summary>
    private static string? Prop(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    /// <summary>POST a snake_case JSON body and return the parsed response document.</summary>
    private async Task<JsonElement> PostAsync(string path, object body)
    {
        var resp = await _http.PostAsJsonAsync(_baseUrl + path, body);
        resp.EnsureSuccessStatusCode();
        var text = await resp.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(text)) return default;
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }
}

/// <summary>
/// Raised when the public-key write bucket is exhausted (HTTP 429).
///
/// The endpoint allows only a few writes per 24h; <see cref="ResetEpoch"/> is
/// when the window frees up. Retrying before then just fails again.
/// </summary>
public sealed class RateLimitedException : Exception
{
    public long? ResetEpoch { get; }

    public RateLimitedException(long? resetEpoch)
        : base("public-key registration rate limited (HTTP 429)")
        => ResetEpoch = resetEpoch;
}
