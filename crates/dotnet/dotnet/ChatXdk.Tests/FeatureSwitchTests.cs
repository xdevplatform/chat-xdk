// Feature switches (GET /2/chat/features). Nothing is called: each chat reads from a local
// server through the internal constructor, and sends show the format: signature version "7"
// is v0, "10" is v1.

using System;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Xunit;

namespace ChatXdk.Tests
{
    public class FeatureSwitchTests
    {
        /// <summary>A keyed chat that reads its feature switches from <paramref name="endpoint"/>.</summary>
        private static Chat NewChat(string endpoint, int timeoutMs = 2000)
        {
            var chat = new Chat(endpoint, TimeSpan.FromMilliseconds(timeoutMs));
            chat.GenerateKeypairs();
            chat.SetIdentity(new SetIdentityParams("1001", "1"));
            return chat;
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
        public async Task ANewChatReadsTheSwitchesOnce()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint);
            await WaitFor("the request", () => server.Queries.Count == 1);
            Assert.Equal("", server.Queries[0]);
            await WaitFor("v1", () => SendVersion(chat) == "10");
            chat.GenerateKeypairs();
            chat.SetIdentity(new SetIdentityParams("1001", "1"));
            for (var i = 0; i < 5; i++) SendVersion(chat);
            await Task.Delay(300);
            Assert.Single(server.Queries);
        }

        [Fact]
        public void ASendNeverWaitsForTheRequest()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 2000);
            using var chat = NewChat(server.Endpoint, timeoutMs: 3000);
            var started = DateTime.UtcNow;
            Assert.Equal("7", SendVersion(chat));
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(1));
        }

        [Fact]
        public async Task ChatsCreatedWhileARequestIsInFlightShareIt()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 800);
            var chats = Enumerable.Range(0, 4).Select(_ => NewChat(server.Endpoint)).ToList();
            try
            {
                await WaitFor("v1 everywhere", () => chats.All(chat => SendVersion(chat) == "10"));
                Assert.Single(server.Queries);

                using var later = NewChat(server.Endpoint);
                await WaitFor("the later chat to ask for itself", () => server.Queries.Count == 2);
                await WaitFor("v1 for the later chat", () => SendVersion(later) == "10");
            }
            finally
            {
                foreach (var chat in chats) chat.Dispose();
            }
        }

        [Fact]
        public async Task TheAnswerHoldsForTheChatsLifetime()
        {
            using var server = new FeatureServer();
            using var chat = NewChat(server.Endpoint);
            await WaitFor("v1", () => SendVersion(chat) == "10");
            server.Set(200, "{\"features\":{}}");
            using var other = NewChat(server.Endpoint);
            await WaitFor("the second request", () => server.Queries.Count == 2);
            await Task.Delay(200);
            Assert.Equal("7", SendVersion(other));
            Assert.Equal("10", SendVersion(chat));
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
                using var server = new FeatureServer();
                server.Set(status, body, delayMs);
                using var chat = NewChat(server.Endpoint, timeoutMs: 500);
                await WaitFor("the request", () => server.Queries.Count == 1);
                await Task.Delay(delayMs + 200);
                Assert.Equal("7", SendVersion(chat));
                Assert.Single(server.Queries);
            }
        }

        [Fact]
        public async Task AnUnreachableEndpointLeavesSendsOnV0()
        {
            string endpoint;
            using (var server = new FeatureServer()) endpoint = server.Endpoint;
            using var chat = NewChat(endpoint, timeoutMs: 500);
            await Task.Delay(700);
            Assert.Equal("7", SendVersion(chat));
        }

        [Fact]
        public async Task ARequestStillOpenAtItsTimeoutFails()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 3000);
            using var chat = NewChat(server.Endpoint, timeoutMs: 300);
            await Task.Delay(1000);
            Assert.Equal("7", SendVersion(chat));
            Assert.Single(server.Queries);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void StartUnreferencedChat(string endpoint) => NewChat(endpoint);

        [Fact]
        public async Task ARequestEndsSafelyForADisposedOrFinalizedChat()
        {
            using var server = new FeatureServer();
            server.Set(200, "{\"features\":{\"v1_send\":true}}", delayMs: 800);
            NewChat(server.Endpoint).Dispose();
            StartUnreferencedChat(server.Endpoint);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            using var kept = NewChat(server.Endpoint);
            await WaitFor("v1", () => SendVersion(kept) == "10");
            Assert.Single(server.Queries);
        }
    }
}
