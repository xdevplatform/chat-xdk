using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChatXdk
{
    /// <summary>
    /// Reads a chat's feature switches (<c>GET /2/chat/features</c>) when the chat is created,
    /// when its identity is set, and again after each answer. The native core decides what to
    /// fetch, when to fetch it again and what an answer means; this class performs each GET it
    /// hands out with <see cref="HttpClient"/> on the thread pool and reports the status and
    /// body to it. Nothing here is API.
    /// </summary>
    internal static class FeatureFetch
    {
        // The read is anonymous: it stores and sends no cookies, and it follows no redirect, so a
        // 3xx answer reaches the core as a failed read rather than as a request to another URL.
        private static readonly HttpClient Http =
            new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
            {
                Timeout = Timeout.InfiniteTimeSpan,
            };

        /// <summary>
        /// Start <paramref name="chat"/>'s reads of the feature switches for its identity:
        /// perform the GET the core hands out, if any, and then each GET the core hands back.
        /// </summary>
        internal static void Start(Chat chat)
        {
            var json = chat.StartFeatures();
            if (json.Length == 0) return;
            var fetch = JsonSerializer.Deserialize<Fetch>(json)!;
            _ = Task.Run(() => PerformAsync(fetch));
        }

        /// <summary>
        /// For this repository's tests: the endpoint of every chat that does not set its own,
        /// or the X API's when <paramref name="endpoint"/> is null.
        /// </summary>
        internal static unsafe void SetDefaultEndpoint(string? endpoint)
        {
            if (endpoint == null)
            {
                Chat.ConsumeResult(NativeMethods.chat_xdk_internal_feature_set_default_endpoint(null));
                return;
            }
            var endpointBytes = Chat.Utf8Z(endpoint);
            fixed (byte* endpointPtr = endpointBytes)
                Chat.ConsumeResult(NativeMethods.chat_xdk_internal_feature_set_default_endpoint(endpointPtr));
        }

        /// <summary>
        /// Perform <paramref name="fetch"/> after its delay, then the refresh or retry each
        /// result returns, until none does.
        /// </summary>
        private static async Task PerformAsync(Fetch? fetch)
        {
            while (fetch != null)
            {
                if (fetch.DelayMs > 0)
                    await Task.Delay(TimeSpan.FromMilliseconds(fetch.DelayMs)).ConfigureAwait(false);
                var (status, body) = await GetAsync(fetch).ConfigureAwait(false);
                fetch = Complete(fetch.Id, status, body);
            }
        }

        /// <summary>
        /// The status and body of the GET, all within its timeout: the body is read to its
        /// end or to one byte past the limit. Status 0 when no complete response arrived.
        /// </summary>
        private static async Task<(int Status, byte[] Body)> GetAsync(Fetch fetch)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(fetch.TimeoutMs));
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, fetch.Url);
                request.Headers.Accept.ParseAdd("application/json");
                using var response = await Http
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                    .ConfigureAwait(false);
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                var buffer = new byte[fetch.MaxBytes + 1];
                var total = 0;
                int read;
                while (total < buffer.Length
                    && (read = await stream.ReadAsync(buffer.AsMemory(total), deadline.Token).ConfigureAwait(false)) > 0)
                {
                    total += read;
                }
                return ((int)response.StatusCode, buffer[..total]);
            }
            catch (Exception)
            {
                return (0, Array.Empty<byte>());
            }
        }

        /// <summary>
        /// Report the result of the GET <paramref name="id"/>; returns the next GET to perform, a
        /// refresh or a retry, if any.
        /// </summary>
        private static unsafe Fetch? Complete(ulong id, int status, byte[] body)
        {
            string json;
            fixed (byte* bodyPtr = body)
                json = Chat.ConsumeResult(
                    NativeMethods.chat_xdk_internal_feature_complete(id, status, bodyPtr, (nuint)body.Length));
            return json.Length == 0 ? null : JsonSerializer.Deserialize<Fetch>(json);
        }

        private sealed record Fetch(
            [property: JsonPropertyName("id")] ulong Id,
            [property: JsonPropertyName("url")] string Url,
            [property: JsonPropertyName("timeout_ms")] long TimeoutMs,
            [property: JsonPropertyName("max_bytes")] int MaxBytes,
            [property: JsonPropertyName("delay_ms")] long DelayMs);
    }
}
