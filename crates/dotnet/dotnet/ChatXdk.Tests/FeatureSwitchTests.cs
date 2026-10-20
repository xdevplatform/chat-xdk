// Feature switches (GET /2/chat/features). Nothing is called: every Chat fetches by itself,
// here created through the internal constructor that points it at a local server with
// shorter timings, and the flags are read through the internal accessors.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace ChatXdk.Tests
{
    internal static class FeatureTestEnvironment
    {
        // Keeps the automatic feature fetch of every chat made with new Chat() off the
        // network. Tests that need a server pass it to the internal constructor rather than
        // change the environment, because test classes run in parallel.
#pragma warning disable CA2255 // This is the test assembly's own setup, not a library's.
        [ModuleInitializer]
        internal static void KeepFeatureFetchesOffTheNetwork()
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CHAT_XDK_FEATURES_ENDPOINT")))
                Environment.SetEnvironmentVariable("CHAT_XDK_FEATURES_ENDPOINT", "http://127.0.0.1:9/2/chat/features");
        }
#pragma warning restore CA2255
    }

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
                // The answer is fixed when the request is recorded, so a test that sees the
                // request can change the next answer.
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

            public void Dispose()
            {
                _listener.Stop();
                _listener.Close();
            }
        }

        /// <summary>A chat whose feature fetches go to <paramref name="endpoint"/>.</summary>
        private static Chat NewChat(string endpoint, int refreshMs = 3_600_000, int timeoutMs = 500) =>
            new(new FeatureSwitches.Options(
                endpoint,
                TimeSpan.FromMilliseconds(timeoutMs),
                TimeSpan.FromMilliseconds(refreshMs),
                TimeSpan.FromMilliseconds(20)));

        private static Chat WithKeys(Chat chat)
        {
            chat.GenerateKeypairs();
            chat.SetIdentity("1001", "1");
            return chat;
        }

        private static SendPayload Send(Chat chat)
        {
            var prep = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "1001", PublicKey = chat.GetPublicKeys().Identity, KeyVersion = "1" } })
            {
                ConversationId = "conv-1",
            });
            return chat.EncryptMessage(new EncryptMessageParams("conv-1", "hello")
            {
                ConversationKey = prep.ConversationKey!,
                ConversationKeyVersion = "1",
            });
        }

        private static string SendVersion(Chat chat) => Send(chat).SignatureInfo.SignatureVersion;

        private static string Bucket(Chat chat) =>
            chat.FeatureBucket()!.Value.ToString(CultureInfo.InvariantCulture);

        private static async Task WaitFor(string what, Func<bool> condition)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                if (condition()) return;
                await Task.Delay(20);
            }
            Assert.True(condition(), "timed out waiting for " + what);
        }

        /// <summary>Wait for a request carrying the chat's key bucket.</summary>
        private static Task KeyedRequest(FeatureServer server, Chat chat)
        {
            var bucket = Bucket(chat);
            return WaitFor("a request with bucket " + bucket, () => server.Buckets.Contains(bucket));
        }

        [Fact]
        public void FeatureSwitches_AreNotPublicApi()
        {
            foreach (var name in new[]
            {
                "LoadFeatureConfigAsync", "IsEnabled", "FeatureBucket", "ApplyFeatureConfig",
                "FeatureRefetchDue", "FeaturesEndpoint",
            })
            {
                Assert.Empty(typeof(Chat).GetMember(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static));
            }
            Assert.DoesNotContain(typeof(Chat).Assembly.GetExportedTypes(), type => type.Name.Contains("Feature"));
            Assert.Single(typeof(Chat).GetConstructors());
        }

        [Fact]
        public void CreatingAChat_NeverWaitsForTheFetch()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", 2000);
            var started = Stopwatch.StartNew();
            using var chat = NewChat(server.Endpoint, timeoutMs: 5000);
            Assert.True(started.ElapsedMilliseconds < 1000, $"took {started.ElapsedMilliseconds} ms");
            WithKeys(chat);
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task EveryFlagIsOff_AndSendsAreV0_UntilAResponseApplies()
        {
            using var server = new FeatureServer();
            server.Set(503, "");
            using var chat = WithKeys(NewChat(server.Endpoint));
            await KeyedRequest(server, chat);
            Assert.False(chat.IsEnabled("v1_send"));
            var payload = Send(chat);
            Assert.Equal("7", payload.SignatureInfo.SignatureVersion);
            Assert.NotEmpty(payload.XdkVersion);
        }

        [Fact]
        public async Task AChat_FetchesOnCreation_AndAgainWithTheKeyBucket()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint);
            Assert.Null(chat.FeatureBucket());
            await WaitFor("the request on creation", () => server.Buckets.Count == 1);
            Assert.Equal(new List<string?> { null }, server.Buckets);

            WithKeys(chat);
            Assert.InRange(chat.FeatureBucket()!.Value, 0, 9999);
            await KeyedRequest(server, chat);
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));
            Assert.False(chat.FeatureRefetchDue());
            Assert.Equal(new List<string?> { null, Bucket(chat) }, server.Buckets);
            Assert.Equal("10", SendVersion(chat));
        }

        [Fact]
        public async Task KeysLoadedBeforeTheFirstAnswer_StillGetTheKeyBucket()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", 200);
            using var chat = WithKeys(NewChat(server.Endpoint));
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));
            Assert.Equal(Bucket(chat), server.Buckets.Last());
        }

        [Fact]
        public async Task TheKeyBucketAnswer_ReplacesTheIpAnswer()
        {
            using var server = new FeatureServer();

            // An IP-bucketed "on" reads off once keys load, and the key's own answer decides.
            using var first = NewChat(server.Endpoint);
            await WaitFor("the IP answer", () => first.IsEnabled("v1_send"));
            server.Set(200, "{\"features\":{\"v1_send\":false}}");
            WithKeys(first);
            Assert.False(first.IsEnabled("v1_send"));
            await KeyedRequest(server, first);
            await WaitFor("the key answer", () => !first.FeatureRefetchDue());
            Assert.False(first.IsEnabled("v1_send"));

            // ...and the key's answer can turn a flag on that the IP answer left off.
            server.Set(200, "{\"features\":{\"v1_send\":false,\"ip_answer\":true}}");
            using var second = NewChat(server.Endpoint);
            await WaitFor("the IP answer", () => second.IsEnabled("ip_answer"));
            server.Set(200, "{\"features\":{\"v1_send\":true}}");
            WithKeys(second);
            await WaitFor("the key answer", () => second.IsEnabled("v1_send"));
            Assert.False(second.IsEnabled("ip_answer"));
        }

        [Fact]
        public async Task UnknownKeys_AreReadable_AndMissingKeysAreOff()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"later_flag\":true,\"v1_send\":\"yes\"},\"extra\":1}");
            using var chat = WithKeys(NewChat(server.Endpoint));
            await WaitFor("later_flag on", () => chat.IsEnabled("later_flag"));
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
            using var chat = WithKeys(NewChat(server.Endpoint));
            await KeyedRequest(server, chat);
            await Task.Delay(delayMs > 0 ? 600 : 100);
            Assert.False(chat.IsEnabled("v1_send"));
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task AnUnreachableEndpoint_LeavesEveryFlagOff()
        {
            string endpoint;
            using (var server = new FeatureServer())
                endpoint = server.Endpoint;
            using var chat = WithKeys(NewChat(endpoint));
            await Task.Delay(300);
            Assert.False(chat.IsEnabled("v1_send"));
            Assert.True(chat.FeatureRefetchDue());
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task TheRecheck_TurnsFlagsOff_ButNeverOn()
        {
            using var server = new FeatureServer();
            using var chat = WithKeys(NewChat(server.Endpoint, refreshMs: 300));
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));

            server.Set(200, "{\"features\":{}}");
            await WaitFor("the re-check to turn v1_send off", () => !chat.IsEnabled("v1_send"));
            Assert.Equal("7", SendVersion(chat));

            server.Set(200, "{\"features\":{\"v1_send\":true}}");
            var seen = server.Buckets.Count;
            await WaitFor("two more re-checks", () => server.Buckets.Count >= seen + 2);
            Assert.False(chat.IsEnabled("v1_send"));
        }

        [Fact]
        public async Task AFailedRecheck_ChangesNothing()
        {
            using var server = new FeatureServer();
            using var chat = WithKeys(NewChat(server.Endpoint, refreshMs: 300));
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));
            server.Set(503, "");
            var seen = server.Buckets.Count;
            await WaitFor("two failed re-checks", () => server.Buckets.Count >= seen + 2);
            Assert.True(chat.IsEnabled("v1_send"));
        }

        [Fact]
        public async Task Dispose_StopsTheFetches()
        {
            using var server = new FeatureServer();
            var chat = WithKeys(NewChat(server.Endpoint, refreshMs: 300, timeoutMs: 10_000));
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));
            server.Set(200, "{\"features\":{\"v1_send\":true}}", 5000);
            await Task.Delay(400);
            chat.Dispose();
            var seen = server.Buckets.Count;
            await Task.Delay(1000);
            Assert.Equal(seen, server.Buckets.Count);
        }

        /// <summary>A keyed, re-checking chat that nothing references once this completes.</summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task StartUnreferencedChat(string endpoint)
        {
            var chat = WithKeys(NewChat(endpoint, refreshMs: 300));
            await WaitFor("v1_send on", () => chat.IsEnabled("v1_send"));
        }

        [Fact]
        public async Task TheFetches_EndWithAnUnreferencedChat()
        {
            using var server = new FeatureServer();
            await StartUnreferencedChat(server.Endpoint);
            var running = server.Buckets.Count;
            await WaitFor("a re-check", () => server.Buckets.Count > running);
            for (var i = 0; i < 5; i++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                await Task.Delay(50);
            }
            await Task.Delay(800);
            var seen = server.Buckets.Count;
            await Task.Delay(1200);
            Assert.Equal(seen, server.Buckets.Count);
        }

        [Fact]
        public async Task AMalformedBody_IsRejected_AndChangesNothing()
        {
            using var server = new FeatureServer();
            // The fetch never applies anything, so only the calls below change the flags.
            server.Set(503, "");
            using var chat = WithKeys(NewChat(server.Endpoint));
            await KeyedRequest(server, chat);
            var bucket = chat.FeatureBucket();
            chat.ApplyFeatureConfig("{\"features\":{\"v1_send\":true}}", bucket);
            Assert.Throws<ChatXdkException>(() => chat.ApplyFeatureConfig("[]", bucket, true));
            Assert.True(chat.IsEnabled("v1_send"));
            chat.ApplyFeatureConfig("{\"features\":{}}", bucket, true);
            Assert.False(chat.IsEnabled("v1_send"));
        }
    }
}
