using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChatXdk
{
    /// <summary>
    /// Reads a chat's feature switches (<c>GET /2/chat/features</c>) once, when the chat is
    /// created. The native core decides what to fetch and what an answer means; this class
    /// performs the GET with <see cref="HttpClient"/> on the thread pool and hands the status
    /// and body back. Nothing here is API.
    /// </summary>
    internal static class FeatureFetch
    {
        private static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };

        /// <summary>
        /// Start <paramref name="chat"/>'s one read of the feature switches: nothing to do when
        /// it takes the answer of a GET already in flight.
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

        private static async Task PerformAsync(Fetch fetch)
        {
            var (status, body) = await GetAsync(fetch).ConfigureAwait(false);
            Complete(fetch.Id, status, body);
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

        private static unsafe void Complete(ulong id, int status, byte[] body)
        {
            fixed (byte* bodyPtr = body)
                NativeMethods.chat_xdk_internal_feature_complete(id, status, bodyPtr, (nuint)body.Length);
        }

        private sealed record Fetch(
            [property: JsonPropertyName("id")] ulong Id,
            [property: JsonPropertyName("url")] string Url,
            [property: JsonPropertyName("timeout_ms")] long TimeoutMs,
            [property: JsonPropertyName("max_bytes")] int MaxBytes);
    }
}
