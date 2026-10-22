using System.Globalization;
using System.Text;

namespace ChatXdk
{
    /// <summary>
    /// Feature switches (<c>GET /2/chat/features</c>). Internal: every <see cref="Chat"/>
    /// fetches them itself, without blocking or failing, and sends stay v0 unless a response
    /// turns <c>v1_send</c> on. Nothing here is API. <c>CHAT_XDK_FEATURES_ENDPOINT</c>, which
    /// only this repository's tests set, overrides the endpoint. Kept out of
    /// <see cref="Chat"/>, whose unsafe context rules out <c>await</c>.
    /// </summary>
    internal static class FeatureSwitches
    {
        private const string DefaultEndpoint = "https://api.x.com/2/chat/features";
        private const string EndpointEnv = "CHAT_XDK_FEATURES_ENDPOINT";
        private const int MaxBody = 64 * 1024;

        private static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };

        // Feature requests in flight, by URL.
        private static readonly Dictionary<string, Task<string?>> Requests = new();

        /// <summary>The endpoint and timings of a chat's feature fetches.</summary>
        internal sealed record Options(string Endpoint, TimeSpan Timeout, TimeSpan Refresh, TimeSpan KeyPoll)
        {
            internal static Options Default()
            {
                var endpoint = Environment.GetEnvironmentVariable(EndpointEnv);
                return new Options(
                    string.IsNullOrEmpty(endpoint) ? DefaultEndpoint : endpoint,
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromSeconds(300),
                    TimeSpan.FromSeconds(1));
            }
        }

        /// <summary>
        /// Fetch the flags for <paramref name="chat"/> now (retrying once), again with the
        /// key's bucket once keys load (retrying with a backoff that grows to the refresh
        /// interval), and re-check them every refresh interval with a fetch that can only turn
        /// flags off, until the returned source is cancelled. The task holds the chat weakly, so an undisposed chat is still finalized,
        /// and the fetches end with it.
        /// </summary>
        internal static CancellationTokenSource Start(Chat chat, Options options)
        {
            var stop = new CancellationTokenSource();
            var chatRef = new WeakReference<Chat>(chat);
            var token = stop.Token;
            _ = Task.Run(() => RunAsync(chatRef, options, token));
            return stop;
        }

        // The async methods below reach the chat only through these, so no Chat local lives
        // in their state machines (Debug builds keep every local there) across an await.

        private static bool Alive(WeakReference<Chat> chatRef) =>
            chatRef.TryGetTarget(out var chat) && !chat.Disposed;

        private static bool RefetchDue(WeakReference<Chat> chatRef) =>
            chatRef.TryGetTarget(out var chat) && chat.FeatureRefetchDueForTask();

        private static bool Keyed(WeakReference<Chat> chatRef) =>
            chatRef.TryGetTarget(out var chat) && chat.FeaturesKeyed();

        private static bool TryBucket(WeakReference<Chat> chatRef, out int bucket)
        {
            bucket = -1;
            return chatRef.TryGetTarget(out var chat) && chat.TryFeatureBucket(out bucket);
        }

        private static bool TryApply(WeakReference<Chat> chatRef, string body, int bucket, bool downgradeOnly) =>
            chatRef.TryGetTarget(out var chat) && chat.TryApplyFeatureConfig(body, bucket, downgradeOnly);

        private static async Task RunAsync(WeakReference<Chat> chatRef, Options options, CancellationToken stop)
        {
            try
            {
                if (!await FetchAsync(chatRef, options, false, stop).ConfigureAwait(false))
                    await FetchAsync(chatRef, options, false, stop).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Every flag stays off; the loop below retries.
            }

            var refreshMs = (long)options.Refresh.TotalMilliseconds;
            var maxBackoffMs = Math.Max(refreshMs, 1000);
            var nextRecheck = Environment.TickCount64 + refreshMs;
            long retryAt = 0;
            long backoffMs = 1000;
            while (!stop.IsCancellationRequested)
            {
                var keyed = false;
                try
                {
                    var now = Environment.TickCount64;
                    if (RefetchDue(chatRef))
                    {
                        if (now >= retryAt)
                        {
                            if (await FetchAsync(chatRef, options, false, stop).ConfigureAwait(false))
                            {
                                backoffMs = 1000;
                                nextRecheck = Environment.TickCount64 + refreshMs;
                            }
                            else
                            {
                                retryAt = Environment.TickCount64 + backoffMs;
                                backoffMs = Math.Min(backoffMs * 2, maxBackoffMs);
                            }
                        }
                    }
                    else if (refreshMs > 0 && now >= nextRecheck)
                    {
                        await FetchAsync(chatRef, options, true, stop).ConfigureAwait(false);
                        nextRecheck = Environment.TickCount64 + refreshMs;
                    }
                    keyed = Keyed(chatRef);
                }
                catch (Exception)
                {
                    // A failed step changes nothing; the next one retries.
                }

                if (!Alive(chatRef) || (keyed && refreshMs <= 0)) return;
                // Until a response for the key's bucket applies, watch for keys to load;
                // afterwards, wake only for the re-check.
                var waitMs = keyed
                    ? Math.Max(0, nextRecheck - Environment.TickCount64)
                    : (long)options.KeyPoll.TotalMilliseconds;
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(waitMs), stop).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        /// <summary>Fetch the flags for the chat's bucket and apply them; true on success.</summary>
        private static async Task<bool> FetchAsync(
            WeakReference<Chat> chatRef, Options options, bool downgradeOnly, CancellationToken stop)
        {
            if (!TryBucket(chatRef, out var bucket)) return false;
            var url = bucket < 0
                ? options.Endpoint
                : options.Endpoint + (options.Endpoint.Contains('?') ? "&" : "?") + "bucket="
                    + bucket.ToString(CultureInfo.InvariantCulture);
            var body = await SharedGetAsync(url, options.Timeout, stop).ConfigureAwait(false);
            return body != null && TryApply(chatRef, body, bucket, downgradeOnly);
        }

        /// <summary>
        /// The body for <paramref name="url"/>, from the request another chat has in flight for
        /// it or else from a new one, so chats that ask at once share a request. The request ends
        /// with the chat that started it; the chats waiting on it then see a failure and retry.
        /// </summary>
        private static Task<string?> SharedGetAsync(string url, TimeSpan timeout, CancellationToken stop)
        {
            lock (Requests)
            {
                if (Requests.TryGetValue(url, out var inFlight)) return inFlight.WaitAsync(stop);
                var request = Task.Run(() => GetAsync(url, timeout, stop));
                Requests[url] = request;
                // Runs only once this lock is released, so the entry is in place to remove.
                request.ContinueWith(
                    _ =>
                    {
                        lock (Requests) Requests.Remove(url);
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.None,
                    TaskScheduler.Default);
                return request;
            }
        }

        /// <summary>The body of a 200 response from <paramref name="url"/>, or null on any failure.</summary>
        private static async Task<string?> GetAsync(string url, TimeSpan timeout, CancellationToken cancellationToken)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Accept.ParseAdd("application/json");
                using var response = await Http
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                    .ConfigureAwait(false);
                if ((int)response.StatusCode != 200) return null;
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                var buffer = new byte[MaxBody + 1];
                var total = 0;
                int read;
                while (total < buffer.Length
                    && (read = await stream.ReadAsync(buffer.AsMemory(total), deadline.Token).ConfigureAwait(false)) > 0)
                {
                    total += read;
                }
                return total > MaxBody ? null : Encoding.UTF8.GetString(buffer, 0, total);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
