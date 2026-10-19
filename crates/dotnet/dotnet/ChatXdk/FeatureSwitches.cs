using System.Globalization;
using System.Text;

namespace ChatXdk
{
    /// <summary>
    /// Fetches <c>GET /2/chat/features</c> for a <see cref="Chat"/> and runs its refresher.
    /// Kept out of <see cref="Chat"/>, whose unsafe context rules out <c>await</c>.
    /// </summary>
    internal static class FeatureSwitches
    {
        private const int MaxBody = 64 * 1024;
        private const long MaxRefetchBackoffMs = 60_000;

        private static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };

        internal static async Task<bool> LoadAsync(
            Chat chat, LoadFeatureConfigParams parameters, CancellationToken cancellationToken)
        {
            Stop(chat);
            var endpoint = string.IsNullOrEmpty(parameters.Endpoint) ? Chat.FeaturesEndpoint : parameters.Endpoint;
            var timeout = TimeSpan.FromMilliseconds(parameters.TimeoutMs > 0 ? parameters.TimeoutMs : 2000);
            var refreshMs = Math.Max(0, parameters.RefreshSeconds) * 1000L;

            var applied = await FetchAsync(chat, endpoint, timeout, false, cancellationToken).ConfigureAwait(false)
                || await FetchAsync(chat, endpoint, timeout, false, cancellationToken).ConfigureAwait(false);

            if (!chat.Disposed)
            {
                var refresh = new CancellationTokenSource();
                chat.FeatureRefresh = refresh;
                _ = Task.Run(() => RefreshAsync(chat, endpoint, timeout, refreshMs, refresh.Token));
            }
            return applied;
        }

        internal static void Stop(Chat chat)
        {
            Interlocked.Exchange(ref chat.FeatureRefresh, null)?.Cancel();
        }

        /// <summary>Fetch the flags for the current bucket and apply them; true on success.</summary>
        private static async Task<bool> FetchAsync(
            Chat chat, string endpoint, TimeSpan timeout, bool downgradeOnly, CancellationToken cancellationToken)
        {
            if (!chat.TryFeatureBucket(out var bucket)) return false;
            var url = bucket < 0
                ? endpoint
                : endpoint + (endpoint.Contains('?') ? "&" : "?") + "bucket="
                    + bucket.ToString(CultureInfo.InvariantCulture);
            var body = await GetAsync(url, timeout, cancellationToken).ConfigureAwait(false);
            if (body == null || !chat.TryApplyFeatureConfig(body, bucket, downgradeOnly)) return false;
            if (!downgradeOnly) chat.FeatureBucketless = bucket < 0;
            return true;
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

        /// <summary>
        /// Re-fetch once keys load after a bucketless response, and re-check every
        /// <paramref name="refreshMs"/>, until cancelled or the chat is disposed.
        /// </summary>
        private static async Task RefreshAsync(
            Chat chat, string endpoint, TimeSpan timeout, long refreshMs, CancellationToken cancellationToken)
        {
            var nextRecheck = Environment.TickCount64 + refreshMs;
            long retryAt = 0;
            long backoffMs = 1000;
            while (!cancellationToken.IsCancellationRequested && !chat.Disposed)
            {
                var watchingKeys = true;
                try
                {
                    var now = Environment.TickCount64;
                    if (chat.FeatureRefetchDueForRefresh())
                    {
                        if (now >= retryAt)
                        {
                            if (await FetchAsync(chat, endpoint, timeout, false, cancellationToken).ConfigureAwait(false))
                            {
                                backoffMs = 1000;
                                nextRecheck = Environment.TickCount64 + refreshMs;
                            }
                            else
                            {
                                retryAt = Environment.TickCount64 + backoffMs;
                                backoffMs = Math.Min(backoffMs * 2, MaxRefetchBackoffMs);
                            }
                        }
                    }
                    else if (refreshMs > 0 && now >= nextRecheck)
                    {
                        await FetchAsync(chat, endpoint, timeout, true, cancellationToken).ConfigureAwait(false);
                        nextRecheck = Environment.TickCount64 + refreshMs;
                    }
                    watchingKeys = chat.FeatureBucketless;
                }
                catch (Exception)
                {
                    // A failed tick changes nothing; the next one retries.
                }

                if (!watchingKeys && refreshMs <= 0) return;
                var waitMs = watchingKeys ? 1000 : Math.Max(0, nextRecheck - Environment.TickCount64);
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(waitMs), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }
}
