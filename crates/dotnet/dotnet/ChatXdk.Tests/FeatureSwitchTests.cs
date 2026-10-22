// Feature switches (GET /2/chat/features). Nothing is called: each chat is pointed at a
// local server through the internal hook, and sends show the format: signature version "7"
// is v0, "10" is v1.

using System;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Xunit;

namespace ChatXdk.Tests
{
    public class FeatureSwitchTests
    {
        private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

        /// <summary>A keyed chat whose feature fetch goes to <paramref name="endpoint"/>.</summary>
        private static Chat NewChat(
            string endpoint, byte[] keys, int timeoutMs = 2000, int recheckMs = 3_600_000, int firstRetryMs = 50)
        {
            var chat = new Chat();
            chat.ConfigureFeatures(
                endpoint,
                TimeSpan.FromMilliseconds(timeoutMs),
                TimeSpan.FromMilliseconds(recheckMs),
                TimeSpan.FromMilliseconds(firstRetryMs));
            chat.ImportKeys(new ImportKeysParams(keys));
            chat.SetIdentity(new SetIdentityParams("1001", "1"));
            return chat;
        }

        /// <summary>Fresh private keys, each set with its own bucket.</summary>
        private static byte[] NewKeys()
        {
            using var chat = new Chat();
            chat.GenerateKeypairs();
            return chat.ExportKeys()!;
        }

        /// <summary>The signature version of a send: "7" for v0, "10" for v1.</summary>
        private static string SendVersion(Chat chat) =>
            chat.EncryptMessage(new EncryptMessageParams("conv-1", "hello")
            {
                ConversationKey = new byte[32],
                ConversationKeyVersion = "1",
            }).SignatureInfo.SignatureVersion;

        private static async Task WaitFor(string what, Func<bool> condition, int timeoutMs = 10_000)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                if (condition()) return;
                await Task.Delay(20);
            }
            Assert.True(condition(), "timed out waiting for " + what);
        }

        [Fact]
        public void FeatureSwitches_AreNotPublicApi()
        {
            var assembly = typeof(Chat).Assembly;
            Assert.DoesNotContain(assembly.GetExportedTypes(), type => type.Name.Contains("Feature"));
            foreach (var type in assembly.GetExportedTypes())
            {
                var members = type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static);
                Assert.DoesNotContain(members, member => member.Name.Contains("Feature"));
            }
            Assert.Single(typeof(Chat).GetConstructors());
        }

        [Fact]
        public async Task NoRequestIsMadeUntilTheFirstSend()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint, NewKeys());
            await Task.Delay(300);
            Assert.Empty(server.Buckets);

            Assert.Equal("7", SendVersion(chat));
            await WaitFor("the request", () => server.Buckets.Count == 1);
            var bucket = int.Parse(server.Buckets[0]!, CultureInfo.InvariantCulture);
            Assert.InRange(bucket, 0, 9999);
        }

        [Fact]
        public async Task V1StartsOnceTheAnswerTurnsItOn()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint, NewKeys());
            Assert.Equal("7", SendVersion(chat));
            await WaitFor("v1", () => SendVersion(chat) == "10");
            Assert.Single(server.Buckets);
        }

        [Fact]
        public void ASendNeverWaitsForTheRequest()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 2000);
            using var chat = NewChat(server.Endpoint, NewKeys());
            var started = DateTime.UtcNow;
            Assert.Equal("7", SendVersion(chat));
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(1));
        }

        [Fact]
        public async Task ChatsWithOneKeyShareOneRequest()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 300);
            var keys = NewKeys();
            var chats = Enumerable.Range(0, 4).Select(_ => NewChat(server.Endpoint, keys)).ToList();
            try
            {
                foreach (var chat in chats) Assert.Equal("7", SendVersion(chat));
                await WaitFor("v1 everywhere", () => chats.All(chat => SendVersion(chat) == "10"));
                Assert.Single(server.Buckets);

                using var later = NewChat(server.Endpoint, keys);
                Assert.Equal("10", SendVersion(later));
                Assert.Single(server.Buckets);
            }
            finally
            {
                foreach (var chat in chats) chat.Dispose();
            }
        }

        [Fact]
        public async Task ChatsWithDifferentKeysAskSeparately()
        {
            using var server = new FeatureServer();
            using var first = NewChat(server.Endpoint, NewKeys());
            using var second = NewChat(server.Endpoint, NewKeys());
            SendVersion(first);
            SendVersion(second);
            await WaitFor("two requests", () => server.Buckets.Count == 2);
            Assert.NotEqual(server.Buckets[0], server.Buckets[1]);
        }

        [Fact]
        public async Task AnyFailureLeavesSendsOnV0()
        {
            var cases = new (int Status, string Body, int DelayMs)[]
            {
                (404, "{\"features\":{\"v1_send\":true}}", 0),
                (500, "{\"features\":{\"v1_send\":true}}", 0),
                (200, "not json", 0),
                (200, "{\"v1_send\":true}", 0),
                (200, "{\"features\":{\"v1_send\":\"true\"}}", 0),
                (200, "{\"features\":{\"v1_send\":true}}" + new string(' ', 64 * 1024), 0),
                (200, "{\"features\":{\"v1_send\":true}}", 1000),
            };
            foreach (var (status, body, delayMs) in cases)
            {
                // A server of its own: chats share an answer per endpoint and bucket, and the
                // case before may have left one.
                using var server = new FeatureServer();
                server.Set(status, body, delayMs);
                using var chat = NewChat(server.Endpoint, NewKeys(), timeoutMs: 500, firstRetryMs: 60_000);
                Assert.Equal("7", SendVersion(chat));
                await WaitFor("the request", () => server.Buckets.Count == 1);
                await Task.Delay(delayMs > 0 ? 1200 : 200);
                Assert.Equal("7", SendVersion(chat));
            }
        }

        [Fact]
        public async Task AnUnreachableEndpointLeavesSendsOnV0()
        {
            string endpoint;
            using (var server = new FeatureServer()) endpoint = server.Endpoint;
            using var chat = NewChat(endpoint, NewKeys(), timeoutMs: 500);
            Assert.Equal("7", SendVersion(chat));
            await Task.Delay(500);
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task ARequestStillOpenAtItsTimeoutFailsAndIsRetried()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 3000);
            using var chat = NewChat(server.Endpoint, NewKeys(), timeoutMs: 300, firstRetryMs: 200);
            Assert.Equal("7", SendVersion(chat));
            await WaitFor("a retry", () => server.Buckets.Count >= 2, timeoutMs: 2500);
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task TheRecheckTurnsV1OffAndNeverBackOn()
        {
            using var server = new FeatureServer();
            var keys = NewKeys();
            using var chat = NewChat(server.Endpoint, keys, recheckMs: 300);
            SendVersion(chat);
            await WaitFor("v1", () => SendVersion(chat) == "10");

            server.Set(200, "{\"features\":{}}");
            await WaitFor("the re-check to turn v1 off", () => SendVersion(chat) == "7");

            server.Set(200, "{\"features\":{\"v1_send\":true}}");
            var seen = server.Buckets.Count;
            await WaitFor("two more re-checks", () => server.Buckets.Count >= seen + 2);
            Assert.Equal("7", SendVersion(chat));
            using var later = NewChat(server.Endpoint, keys, recheckMs: 300);
            Assert.Equal("10", SendVersion(later));
        }

        [Fact]
        public async Task AFailedRecheckChangesNothing()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint, NewKeys(), recheckMs: 300);
            SendVersion(chat);
            await WaitFor("v1", () => SendVersion(chat) == "10");
            server.Set(503, "");
            var seen = server.Buckets.Count;
            await WaitFor("two failed re-checks", () => server.Buckets.Count >= seen + 2);
            Assert.Equal("10", SendVersion(chat));
        }

        [Fact]
        public async Task DisposeStopsTheRequests()
        {
            using var server = new FeatureServer();
            var chat = NewChat(server.Endpoint, NewKeys(), recheckMs: 300);
            SendVersion(chat);
            await WaitFor("v1", () => SendVersion(chat) == "10");
            chat.Dispose();
            var seen = server.Buckets.Count;
            await Task.Delay(1000);
            Assert.Equal(seen, server.Buckets.Count);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task StartUnreferencedChat(string endpoint)
        {
            var chat = NewChat(endpoint, NewKeys(), recheckMs: 300);
            SendVersion(chat);
            await WaitFor("v1", () => SendVersion(chat) == "10");
        }

        [Fact]
        public async Task TheRequestsEndWithAFinalizedChat()
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
    }
}
