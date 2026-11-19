using System.Text.Json;
using ChatXdk;

namespace ChatBot;

/// <summary>
/// One cache of <c>GET /2/users/{id}/public_keys</c> answers for the whole
/// process, by user id.
///
/// Other users' public keys are the same whichever chat asks, so a process
/// with several signed-in users gives every chat the same hook:
/// <see cref="ResolveAsync"/> has the shape of the SDK's
/// <c>ResolvePublicKeys</c> hook. The chats of two signed-in users who meet
/// the same user then cost one request:
///
/// <list type="bullet">
///   <item>Calls that ask for a user whose lookup is under way wait for that
///   lookup.</item>
///   <item>A lookup that fails is logged and dropped, and the user is left
///   out of the answer: the next call fetches again.</item>
///   <item>An answer is served for the TTL, then fetched again, so a key a
///   user registers later is picked up.</item>
/// </list>
///
/// Its methods may be called from several threads at once.
/// </summary>
public sealed class SharedPublicKeys
{
    /// <summary>How long a fetched answer is served before it is fetched again.</summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

    private readonly Func<string, Task<List<JsonElement>>> _fetchPublicKeys;
    private readonly TimeSpan _ttl;
    private readonly Func<DateTimeOffset> _now;

    // Guards _lookups. It is held to read and change the map, never while a
    // fetch runs, so lookups of different users do not wait for each other.
    private readonly object _gate = new();
    private readonly Dictionary<string, Lookup> _lookups = new();

    /// <summary>
    /// <paramref name="fetchPublicKeys"/> returns one user's records: the
    /// <c>data</c> array of <c>GET /2/users/{id}/public_keys</c>, as
    /// <see cref="ChatCore.FetchPublicKeysWith"/> takes it.
    /// <paramref name="ttl"/> is how long an answer is served,
    /// <see cref="DefaultTtl"/> when null. <paramref name="now"/> is the
    /// clock, the system clock when null.
    /// </summary>
    public SharedPublicKeys(
        Func<string, Task<List<JsonElement>>> fetchPublicKeys,
        TimeSpan? ttl = null,
        Func<DateTimeOffset>? now = null)
    {
        _fetchPublicKeys = fetchPublicKeys;
        _ttl = ttl ?? DefaultTtl;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// The records of <paramref name="userIds"/>, by user id: the SDK's
    /// <c>ResolvePublicKeys</c> hook. A user whose lookup failed is left out.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>> ResolveAsync(
        IReadOnlyList<string> userIds)
    {
        // Every lookup starts before the first one is awaited, so the users
        // are fetched side by side.
        var lookups = userIds.Select(userId => LookUpAsync(userId)).ToList();
        var records = new Dictionary<string, IReadOnlyList<PublicKeyRecord>>();
        for (var index = 0; index < userIds.Count; index++)
        {
            var found = await lookups[index].ConfigureAwait(false);
            if (found is not null)
                records[userIds[index]] = found;
        }
        return records;
    }

    /// <summary>
    /// The lookup of <paramref name="userId"/>: the one the cache holds while
    /// its time is not up, or one that starts here. It completes with the
    /// user's records, or with null when the fetch failed.
    /// </summary>
    private Task<IReadOnlyList<PublicKeyRecord>?> LookUpAsync(string userId)
    {
        var at = _now();
        Lookup lookup;
        lock (_gate)
        {
            if (_lookups.TryGetValue(userId, out var cached) && cached.Expires > at)
                return cached.Records.Task;
            // Answers past their time go here, so the cache holds no more
            // than the users looked up within one TTL.
            var expired = _lookups.Where(entry => entry.Value.Expires <= at).Select(entry => entry.Key).ToList();
            foreach (var id in expired)
                _lookups.Remove(id);
            lookup = new Lookup(at + _ttl);
            _lookups[userId] = lookup;
        }
        // The lock is released: the fetch runs outside it.
        _ = FetchAsync(userId, lookup);
        return lookup.Records.Task;
    }

    /// <summary>
    /// Fetch the records of <paramref name="userId"/> and complete
    /// <paramref name="lookup"/> with them. A fetch that fails is logged,
    /// takes the lookup out of the cache when the cache still holds it, and
    /// completes it with null. This method never throws.
    /// </summary>
    private async Task FetchAsync(string userId, Lookup lookup)
    {
        try
        {
            var found = await _fetchPublicKeys(userId).ConfigureAwait(false);
            lookup.Records.SetResult(found
                .Select(item => item.Deserialize<PublicKeyRecord>())
                .OfType<PublicKeyRecord>()
                .ToList());
        }
        catch (Exception e)
        {
            lock (_gate)
            {
                if (_lookups.TryGetValue(userId, out var current) && ReferenceEquals(current, lookup))
                    _lookups.Remove(userId);
            }
            Console.Error.WriteLine($"public_keys_fetch_failed user={userId} err={e.Message}");
            lookup.Records.SetResult(null);
        }
    }

    /// <summary>One user's lookup, under way or answered.</summary>
    private sealed class Lookup
    {
        public Lookup(DateTimeOffset expires) => Expires = expires;

        /// <summary>When the answer stops being served.</summary>
        public DateTimeOffset Expires { get; }

        /// <summary>
        /// Completes with the user's records, or with null when the fetch
        /// failed. The callers waiting for it continue on the thread pool,
        /// not inside the call that completes it.
        /// </summary>
        public TaskCompletionSource<IReadOnlyList<PublicKeyRecord>?> Records { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}

/// <summary>
/// One <see cref="ChatCore"/> per signed-in user, all fetching public keys
/// through one hook.
///
/// A chat holds one user's private keys and signs as that user. A process
/// that serves several signed-in users keeps one chat per user, for all of
/// that user's conversations, and never one per conversation: the chat keeps
/// its conversation keys by conversation and the public keys it has met by
/// user id.
///
/// Its methods may be called from several threads at once.
/// </summary>
public sealed class UserChats
{
    private readonly Func<IReadOnlyList<string>, Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>>> _resolvePublicKeys;
    private readonly object _gate = new();
    private readonly Dictionary<string, ChatCore> _chats = new();

    /// <summary>
    /// <paramref name="resolvePublicKeys"/> is the hook every chat shares:
    /// <see cref="SharedPublicKeys.ResolveAsync"/>.
    /// </summary>
    public UserChats(
        Func<IReadOnlyList<string>, Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>>> resolvePublicKeys)
    {
        _resolvePublicKeys = resolvePublicKeys;
    }

    /// <summary>
    /// The chat of the signed-in user <paramref name="userId"/>, created on
    /// first use from the user's private-key blob and the
    /// <c>public_key_version</c> it was registered under. Calls for one user
    /// get the same chat, and that chat serves every conversation of the
    /// user. A chat that could not be created is not kept: the next call
    /// tries again.
    /// </summary>
    public ChatCore ChatFor(string userId, string privateKeysB64, string signingKeyVersion)
    {
        // A chat is created under the lock, so two calls for one user at the
        // same time make one chat. Creating it waits for no network request.
        lock (_gate)
        {
            if (!_chats.TryGetValue(userId, out var chat))
            {
                chat = Open(userId, privateKeysB64, signingKeyVersion);
                _chats[userId] = chat;
            }
            return chat;
        }
    }

    private ChatCore Open(string userId, string privateKeysB64, string signingKeyVersion)
    {
        var core = new ChatCore();
        try
        {
            core.LoadKeys(privateKeysB64, signingKeyVersion);
            core.SetIdentity(userId);
            core.ResolvePublicKeysWith(_resolvePublicKeys);
        }
        catch
        {
            core.Dispose();
            throw;
        }
        return core;
    }

    /// <summary>
    /// Sign <paramref name="userId"/> out: forget the user's chat and dispose
    /// it. No other thread may be using that chat.
    /// </summary>
    public void Close(string userId)
    {
        ChatCore? chat;
        lock (_gate)
        {
            if (!_chats.Remove(userId, out chat))
                return;
        }
        chat.Dispose();
    }
}
