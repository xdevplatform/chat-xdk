// Feature switches (GET /2/chat/features): LoadFeatureConfigAsync against a local server,
// the key-bucket refetch, the downgrade-only re-check, and the v0/v1 send switch.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace ChatXdk.Tests
{
    public class FeatureSwitchTests
    {
        /// <summary>A local GET /2/chat/features that records each request's bucket.</summary>
        private sealed class FeatureServer : IDisposable
        {
            private readonly HttpListener _listener = new();
            private readonly object _sync = new();
            private readonly List<string?> _buckets = new();
            private int _status = 200;
            private string _body = "{\"features\":{\"v1_send\":true}}";
            private int _delayMs;

            public string Endpoint { get; }

            public FeatureServer()
            {
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                var port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();
                _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                _listener.Start();
                Endpoint = $"http://127.0.0.1:{port}/2/chat/features";
                _ = Task.Run(ServeAsync);
            }

            public void Set(int status, string body, int delayMs = 0)
            {
                lock (_sync)
                {
                    _status = status;
                    _body = body;
                    _delayMs = delayMs;
                }
            }

            public List<string?> Buckets
            {
                get
                {
                    lock (_sync) return new List<string?>(_buckets);
                }
            }

            private async Task ServeAsync()
            {
                while (_listener.IsListening)
                {
                    HttpListenerContext context;
                    try
                    {
                        context = await _listener.GetContextAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    _ = Task.Run(() => HandleAsync(context));
                }
            }

            private async Task HandleAsync(HttpListenerContext context)
            {
                int status;
                string body;
                int delayMs;
                lock (_sync)
                {
                    _buckets.Add(context.Request.QueryString["bucket"]);
                    status = _status;
                    body = _body;
                    delayMs = _delayMs;
                }
                try
                {
                    if (delayMs > 0) await Task.Delay(delayMs);
                    var bytes = Encoding.UTF8.GetBytes(body);
                    context.Response.StatusCode = status;
                    context.Response.ContentType = "application/json";
                    context.Response.ContentLength64 = bytes.Length;
                    await context.Response.OutputStream.WriteAsync(bytes);
                    context.Response.Close();
                }
                catch (Exception)
                {
                    // The client gave up (timeout or Dispose).
                }
            }

            public LoadFeatureConfigParams Params(int refreshSeconds, int timeoutMs = 1000) =>
                new() { Endpoint = Endpoint, TimeoutMs = timeoutMs, RefreshSeconds = refreshSeconds };

            public void Dispose()
            {
                _listener.Stop();
                _listener.Close();
            }
        }

        private static Chat WithKeys(Chat chat)
        {
            chat.GenerateKeypairs();
            chat.SetIdentity("1001", "1");
            return chat;
        }

        private static string SendVersion(Chat chat)
        {
            var prep = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "1001", PublicKey = chat.GetPublicKeys().Identity, KeyVersion = "1" } })
            {
                ConversationId = "conv-1",
            });
            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "hello")
            {
                ConversationKey = prep.ConversationKey!,
                ConversationKeyVersion = "1",
            });
            return payload.SignatureInfo.SignatureVersion;
        }

        private static async Task WaitFor(string what, Func<bool> condition)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                if (condition()) return;
                await Task.Delay(50);
            }
            Assert.True(condition(), "timed out waiting for " + what);
        }

        [Fact]
        public void EveryFlagIsOff_AndSendsAreV0_BeforeAnyLoad()
        {
            using var chat = WithKeys(new Chat());
            Assert.False(chat.IsEnabled("v1_send"));
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task LoadAfterKeys_SendsTheKeyBucket_AndSwitchesToV1()
        {
            using var server = new FeatureServer();
            using var chat = WithKeys(new Chat());
            var bucket = chat.FeatureBucket();
            Assert.NotNull(bucket);
            Assert.InRange(bucket!.Value, 0, 9999);

            Assert.True(await chat.LoadFeatureConfigAsync(server.Params(0)));
            Assert.Equal(new List<string?> { bucket.Value.ToString() }, server.Buckets);
            Assert.True(chat.IsEnabled("v1_send"));
            Assert.Equal("10", SendVersion(chat));
        }

        [Fact]
        public async Task UnknownKeys_AreReadable_AndMissingKeysAreOff()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"later_flag\":true,\"v1_send\":\"yes\"},\"extra\":1}");
            using var chat = WithKeys(new Chat());
            Assert.True(await chat.LoadFeatureConfigAsync(server.Params(0)));
            Assert.True(chat.IsEnabled("later_flag"));
            Assert.False(chat.IsEnabled("v1_send"));
            Assert.False(chat.IsEnabled("missing"));
        }

        [Theory]
        [InlineData(404, "{\"features\":{\"v1_send\":true}}", 0)]
        [InlineData(500, "{\"features\":{\"v1_send\":true}}", 0)]
        [InlineData(200, "not json", 0)]
        [InlineData(200, "{\"v1_send\":true}", 0)]
        [InlineData(200, "{\"features\":{\"v1_send\":true}}", 1500)]
        public async Task AnyFailure_LeavesEveryFlagOff(int status, string body, int delayMs)
        {
            using var server = new FeatureServer();
            server.Set(status, body, delayMs);
            using var chat = WithKeys(new Chat());
            Assert.False(await chat.LoadFeatureConfigAsync(server.Params(0, timeoutMs: 300)));
            Assert.False(chat.IsEnabled("v1_send"));
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task LoadBeforeKeys_RefetchesOnceWithTheKeyBucket()
        {
            using var server = new FeatureServer();
            using var chat = new Chat();
            Assert.Null(chat.FeatureBucket());
            Assert.True(await chat.LoadFeatureConfigAsync(server.Params(0)));
            Assert.Equal(new List<string?> { null }, server.Buckets);
            Assert.True(chat.IsEnabled("v1_send"));

            server.Set(200, "{\"features\":{\"v1_send\":false}}");
            WithKeys(chat);
            Assert.False(chat.IsEnabled("v1_send"));
            var bucket = chat.FeatureBucket()!.Value.ToString();
            await WaitFor("the key-bucketed refetch",
                () => server.Buckets.Contains(bucket) && !chat.FeatureRefetchDue());
            Assert.False(chat.IsEnabled("v1_send"));

            using var other = new Chat();
            Assert.True(await other.LoadFeatureConfigAsync(server.Params(0)));
            server.Set(200, "{\"features\":{\"v1_send\":true}}");
            WithKeys(other);
            await WaitFor("the refetch to turn v1_send on", () => other.IsEnabled("v1_send"));
        }

        [Fact]
        public async Task TheRecheck_TurnsFlagsOff_ButNeverOn()
        {
            using var server = new FeatureServer();
            using var chat = WithKeys(new Chat());
            Assert.True(await chat.LoadFeatureConfigAsync(server.Params(1)));
            server.Set(200, "{\"features\":{}}");
            await WaitFor("the re-check to turn v1_send off", () => !chat.IsEnabled("v1_send"));

            server.Set(200, "{\"features\":{\"v1_send\":true}}");
            var seen = server.Buckets.Count;
            await WaitFor("two more re-checks", () => server.Buckets.Count >= seen + 2);
            Assert.False(chat.IsEnabled("v1_send"));

            server.Set(503, "");
            chat.ApplyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.FeatureBucket());
            var before = server.Buckets.Count;
            await WaitFor("two failed re-checks", () => server.Buckets.Count >= before + 2);
            Assert.True(chat.IsEnabled("v1_send"));
        }

        [Fact]
        public async Task Dispose_StopsTheRefresher()
        {
            using var server = new FeatureServer();
            var chat = WithKeys(new Chat());
            Assert.True(await chat.LoadFeatureConfigAsync(server.Params(1)));
            server.Set(200, "{\"features\":{\"v1_send\":true}}", 5000);
            await Task.Delay(1200);
            chat.Dispose();
            var seen = server.Buckets.Count;
            await Task.Delay(2500);
            Assert.Equal(seen, server.Buckets.Count);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => chat.LoadFeatureConfigAsync(server.Params(1)));
        }

        [Fact]
        public void ApplyFeatureConfig_RejectsAMalformedBody()
        {
            using var chat = WithKeys(new Chat());
            chat.ApplyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.FeatureBucket());
            Assert.Throws<ChatXdkException>(() => chat.ApplyFeatureConfig("[]", chat.FeatureBucket(), true));
            Assert.True(chat.IsEnabled("v1_send"));
            chat.ApplyFeatureConfig("{\"features\":{}}", chat.FeatureBucket(), true);
            Assert.False(chat.IsEnabled("v1_send"));
        }
    }
}
