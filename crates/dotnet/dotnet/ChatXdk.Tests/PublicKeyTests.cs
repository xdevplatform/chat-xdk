// Other users' public keys: the signing keys a batch reports missing, the
// records AddPublicKeys stores, the keys the prepare calls read from the store
// when they are passed none, and the ResolvePublicKeys hook the Async calls
// fetch the missing keys through.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using static ChatXdk.Tests.KeyChangeSignerTests;

namespace ChatXdk.Tests
{
    public class PublicKeyTests
    {
        /// <summary>The admin and the member of the group.</summary>
        private static readonly string[] Both = { "5001", "5002" };

        /// <summary>The admin, the member and the user who joins the group.</summary>
        private static readonly string[] WithJoiner = { "5001", "5002", "5004" };

        /// <summary>A party whose chat has its user as session identity.</summary>
        private static Party Session(string userId)
        {
            var party = new Party(userId);
            party.Chat.SetIdentity(new SetIdentityParams(userId, KeyVersion));
            return party;
        }

        /// <summary>The record the X API returns for <paramref name="party"/>'s keys.</summary>
        private static PublicKeyRecord Record(Party party) => new()
        {
            PublicKeyVersion = party.SigningKey.PublicKeyVersion,
            PublicKey = party.SigningKey.IdentityPublicKey,
            SigningPublicKey = party.SigningKey.PublicKey,
            IdentityPublicKeySignature = party.SigningKey.IdentityPublicKeySignature,
        };

        /// <summary>The records of <paramref name="parties"/>, by user id.</summary>
        private static Dictionary<string, IReadOnlyList<PublicKeyRecord>> Records(params Party[] parties) =>
            parties.ToDictionary(
                party => party.UserId,
                party => (IReadOnlyList<PublicKeyRecord>)new[] { Record(party) });

        /// <summary>
        /// The body <c>GET /2/users/{id}/public_keys</c> answers with for
        /// <paramref name="party"/>'s keys: the record among the fields the SDK does not read,
        /// with <paramref name="version"/> as its key version, a string or a number.
        /// </summary>
        private static string ApiResponse(Party party, object version) =>
            JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["data"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["public_key_version"] = version,
                        ["public_key"] = party.SigningKey.IdentityPublicKey,
                        ["signing_public_key"] = party.SigningKey.PublicKey,
                        ["identity_public_key_signature"] = party.SigningKey.IdentityPublicKeySignature,
                        ["public_key_fingerprint"] = null,
                        ["juicebox_config"] = new Dictionary<string, object?>
                        {
                            ["max_guess_count"] = 20,
                            ["token_map"] = Array.Empty<string>(),
                        },
                    },
                },
            });

        /// <summary>The records of an API response <paramref name="body"/>: its <c>data</c>
        /// array, deserialized as it is.</summary>
        private static IReadOnlyList<PublicKeyRecord> ApiRecords(string body)
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.GetProperty("data").Deserialize<List<PublicKeyRecord>>()!;
        }

        /// <summary>The text of each message among a result's events.</summary>
        private static string[] Texts(DecryptEventsResult result) =>
            result.Events
                .Select(decrypted => decrypted.Event)
                .Where(decrypted => decrypted.GetProperty("type").GetString() == "Message")
                .Select(message => message.GetProperty("content").GetProperty("text").GetString()!)
                .ToArray();

        /// <summary>The users a prepared change encrypted its key to, sorted.</summary>
        private static string[] Recipients(PreparedConversationChange prepared) =>
            prepared.ConversationParticipantKeys
                .Select(key => key.UserId)
                .OrderBy(userId => userId, StringComparer.Ordinal)
                .ToArray();

        /// <summary>Asserts that <paramref name="result"/> lists as missing the signing key, at
        /// the parties' key version, of the sender of each event of
        /// <paramref name="expected"/>, and no other.</summary>
        private static void AssertMissing(DecryptEventsResult result, params (string Index, string UserId)[] expected)
        {
            Assert.Equal(
                expected.Select(missing => missing.Index),
                result.MissingSigningKeys.Keys.OrderBy(index => index, StringComparer.Ordinal));
            foreach (var (index, userId) in expected)
            {
                Assert.Equal(userId, result.MissingSigningKeys[index].UserId);
                Assert.Equal(KeyVersion, result.MissingSigningKeys[index].PublicKeyVersion);
            }
        }

        /// <summary>An admin who rotates a group's key, a member who sends a message under it,
        /// and the bot, with its session identity, that receives both events.</summary>
        private sealed class Page : IDisposable
        {
            public Page()
            {
                Change = NewKeyChange(Admin, new[] { Admin, Member, Bot }, Group);
                Events = new[] { Change.EventB64, SentMessage(Member, Group, Change, "hello group") };
            }

            public Party Admin { get; } = new("5001");
            public Party Member { get; } = new("5002");
            public Party Bot { get; } = Session("5003");
            public KeyChange Change { get; }
            public string[] Events { get; }

            /// <summary>The bot's DecryptEvents of the page, passing no signing keys.</summary>
            public DecryptEventsResult Decrypt() =>
                Bot.Chat.DecryptEvents(new DecryptEventsParams(Events));

            /// <summary>The bot's DecryptEventsAsync of the page, passing no signing keys.</summary>
            public Task<DecryptEventsResult> DecryptAsync() =>
                Bot.Chat.DecryptEventsAsync(new DecryptEventsParams(Events));

            public void Dispose()
            {
                Admin.Dispose();
                Member.Dispose();
                Bot.Dispose();
            }
        }

        /// <summary>A hook that answers from the records of the parties it knows, and the user
        /// ids each call to it was given.</summary>
        private sealed class KeyDirectory
        {
            private readonly Dictionary<string, IReadOnlyList<PublicKeyRecord>> _records;

            public KeyDirectory(params Party[] known) => _records = Records(known);

            public List<IReadOnlyList<string>> Calls { get; } = new();

            public async Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>> ResolveAsync(
                IReadOnlyList<string> userIds)
            {
                Calls.Add(userIds.ToArray());
                // Answer as a lookup over the network does: after the call has returned.
                await Task.Yield();
                return userIds
                    .Where(userId => _records.ContainsKey(userId))
                    .ToDictionary(userId => userId, userId => _records[userId]);
            }
        }

        /// <summary>One of the prepare calls that make a conversation key, as the admin makes
        /// it with no public keys passed, and the users it encrypts the key to.</summary>
        private sealed record PrepareCall(
            Func<Chat, PreparedConversationChange> Prepare,
            Func<Chat, Task<PreparedConversationChange>> PrepareAsync,
            string[] Members);

        private static GroupCreateParams Create() =>
            new GroupCreateParams(Group, Both, new[] { "5001" });

        private static GroupMembersChangeParams AddJoiner() =>
            new GroupMembersChangeParams(Group, new[] { "5004" }, Both, new[] { "5001" }, Array.Empty<string>());

        private static GroupMembersRemoveParams RemoveJoiner() =>
            new GroupMembersRemoveParams(Group, new[] { "5004" }) { RemainingMemberIds = Both };

        private static ConversationKeyChangeParams Rotate() =>
            new ConversationKeyChangeParams { ConversationId = Group, MemberIds = Both };

        /// <summary>A key change of the admin's one-to-one with the member, which names the
        /// conversation by the member's id.</summary>
        private static ConversationKeyChangeParams RotateOneToOne() =>
            new ConversationKeyChangeParams { ConversationId = "5002" };

        /// <summary>The four prepare calls, and the one-to-one form of the key change.</summary>
        private static PrepareCall[] PrepareCalls() => new[]
        {
            new PrepareCall(
                chat => chat.PrepareGroupCreate(Create()),
                chat => chat.PrepareGroupCreateAsync(Create()),
                Both),
            new PrepareCall(
                chat => chat.PrepareGroupMembersChange(AddJoiner()),
                chat => chat.PrepareGroupMembersChangeAsync(AddJoiner()),
                WithJoiner),
            new PrepareCall(
                chat => chat.PrepareGroupMembersRemove(RemoveJoiner()),
                chat => chat.PrepareGroupMembersRemoveAsync(RemoveJoiner()),
                Both),
            new PrepareCall(
                chat => chat.PrepareConversationKeyChange(Rotate()),
                chat => chat.PrepareConversationKeyChangeAsync(Rotate()),
                Both),
            new PrepareCall(
                chat => chat.PrepareConversationKeyChange(RotateOneToOne()),
                chat => chat.PrepareConversationKeyChangeAsync(RotateOneToOne()),
                Both),
        };

        [Fact]
        public void DecryptEvents_WithoutItsSendersSigningKeys_ListsThemAsMissing()
        {
            using var page = new Page();
            var bot = page.Bot.Chat;

            var result = page.Decrypt();

            Assert.Empty(result.Events);
            AssertMissing(result, ("0", "5001"), ("1", "5002"));
            // The users to fetch keys for, once each, in batch order.
            Assert.Equal(Both, bot.MissingPublicKeys(result));
            // Neither key arrived, and neither is asked for again at once.
            Assert.Empty(bot.MissingPublicKeys(result));

            // With the member's keys passed, only the admin's is missing.
            var withMember = bot.DecryptEvents(
                new DecryptEventsParams(page.Events) { SigningKeys = new[] { page.Member.SigningKey } });
            AssertMissing(withMember, ("0", "5001"));
        }

        [Fact]
        public void AddPublicKeys_StoresTheRecordsTheApiReturns()
        {
            using var page = new Page();
            var bot = page.Bot.Chat;

            // A record without its signing key is left out.
            bot.AddPublicKeys(new Dictionary<string, IReadOnlyList<PublicKeyRecord>>
            {
                [page.Admin.UserId] = new[]
                {
                    new PublicKeyRecord
                    {
                        PublicKeyVersion = KeyVersion,
                        PublicKey = page.Admin.SigningKey.IdentityPublicKey,
                        IdentityPublicKeySignature = page.Admin.SigningKey.IdentityPublicKeySignature,
                    },
                },
            });
            Assert.Empty(page.Decrypt().Events);

            // The API's own records, with the fields the SDK does not read: the key version
            // is a number in one and a string in the other.
            bot.AddPublicKeys(new Dictionary<string, IReadOnlyList<PublicKeyRecord>>
            {
                [page.Admin.UserId] = ApiRecords(ApiResponse(page.Admin, int.Parse(KeyVersion))),
                [page.Member.UserId] = ApiRecords(ApiResponse(page.Member, KeyVersion)),
            });
            var result = page.Decrypt();

            Assert.Empty(result.Errors);
            Assert.Empty(result.MissingSigningKeys);
            Assert.Equal(new[] { "hello group" }, Texts(result));
        }

        [Fact]
        public void PublicKeyRecord_ReadsItsKeyVersionAsAStringOrANumber()
        {
            const string template =
                "{\"public_key_version\":VERSION,\"public_key\":\"identity\",\"signing_public_key\":\"signing\","
                + "\"identity_public_key_signature\":\"binding\",\"public_key_fingerprint\":null,"
                + "\"juicebox_config\":{\"max_guess_count\":20,\"token_map\":[]}}";
            // The record whose key version is written as version.
            PublicKeyRecord Read(string version) =>
                JsonSerializer.Deserialize<PublicKeyRecord>(template.Replace("VERSION", version))!;

            foreach (var version in new[] { "\"7\"", "7", "7.0" })
            {
                var record = Read(version);
                Assert.Equal("7", record.PublicKeyVersion);
                Assert.Equal("identity", record.PublicKey);
                Assert.Equal("signing", record.SigningPublicKey);
                Assert.Equal("binding", record.IdentityPublicKeySignature);
            }

            // No key version, and a number that is not a whole number, read as none.
            Assert.Equal(string.Empty, Read("null").PublicKeyVersion);
            Assert.Equal(string.Empty, Read("7.5").PublicKeyVersion);
            Assert.Throws<JsonException>(() => Read("true"));

            // A record is written under the API's names, its key version as a string.
            using var written = JsonDocument.Parse(JsonSerializer.Serialize(Read("7")));
            var version7 = written.RootElement.GetProperty("public_key_version");
            Assert.Equal(JsonValueKind.String, version7.ValueKind);
            Assert.Equal("7", version7.GetString());
            Assert.Equal("identity", written.RootElement.GetProperty("public_key").GetString());
            Assert.Equal("signing", written.RootElement.GetProperty("signing_public_key").GetString());
            Assert.Equal("binding", written.RootElement.GetProperty("identity_public_key_signature").GetString());
        }

        [Fact]
        public void ResolvePublicKeys_SettingAHook_TurnsTheKeyCacheOn()
        {
            using var admin = Session("5001");
            Assert.Null(admin.Chat.ResolvePublicKeys);

            admin.Chat.ResolvePublicKeys = new KeyDirectory().ResolveAsync;
            Assert.NotNull(admin.Chat.ResolvePublicKeys);

            // The key the admin's key change makes is cached: a send that passes no key
            // uses it.
            var change = NewKeyChange(admin, new[] { admin }, Group);
            Assert.Equal(
                change.Version,
                admin.Chat.EncryptMessage(new EncryptMessageParams(Group, "hello")).ConversationKeyVersion);

            // Removing the hook leaves the cache on.
            admin.Chat.ResolvePublicKeys = null;
            Assert.Null(admin.Chat.ResolvePublicKeys);
            Assert.Equal(
                change.Version,
                admin.Chat.EncryptMessage(new EncryptMessageParams(Group, "hello")).ConversationKeyVersion);
        }

        [Fact]
        public async Task DecryptEventsAsync_FetchesTheMissingKeysThroughTheHook_AndDecryptsOnceMore()
        {
            using var page = new Page();
            var bot = page.Bot.Chat;
            var directory = new KeyDirectory(page.Admin, page.Member);
            bot.ResolvePublicKeys = directory.ResolveAsync;

            // The synchronous call reports what is missing and never calls the hook.
            AssertMissing(page.Decrypt(), ("0", "5001"), ("1", "5002"));
            Assert.Empty(directory.Calls);

            // Signing keys that are passed are what the call verifies with.
            var passed = await bot.DecryptEventsAsync(
                new DecryptEventsParams(page.Events) { SigningKeys = new[] { page.Member.SigningKey } });
            AssertMissing(passed, ("0", "5001"));
            Assert.Empty(directory.Calls);

            var result = await page.DecryptAsync();

            Assert.Empty(result.Errors);
            Assert.Empty(result.MissingSigningKeys);
            Assert.Equal(new[] { "hello group" }, Texts(result));
            Assert.Equal(Both, Assert.Single(directory.Calls));

            // Setting the hook turned the key cache on: a send that passes no key finds the
            // key of the key change that verified.
            var payload = bot.EncryptMessage(new EncryptMessageParams(Group, "hi"));
            Assert.Equal(page.Change.Version, payload.ConversationKeyVersion);

            // The keys are stored: the next batch needs no lookup, in either call.
            Assert.Equal(new[] { "hello group" }, Texts(await page.DecryptAsync()));
            Assert.Equal(new[] { "hello group" }, Texts(page.Decrypt()));
            Assert.Single(directory.Calls);
        }

        [Fact]
        public async Task DecryptEventsAsync_KeysTheHookDidNotBring_StayMissingAndAreNotAskedForAgain()
        {
            using var page = new Page();
            // The hook knows the admin alone.
            var directory = new KeyDirectory(page.Admin);
            page.Bot.Chat.ResolvePublicKeys = directory.ResolveAsync;

            var result = await page.DecryptAsync();

            AssertMissing(result, ("1", "5002"));
            Assert.Equal(Both, Assert.Single(directory.Calls));

            // The member's lookup brought nothing: the next call does not ask again.
            AssertMissing(await page.DecryptAsync(), ("1", "5002"));
            Assert.Single(directory.Calls);
        }

        [Fact]
        public async Task DecryptEventsAsync_HookThatReturnsNull_AddsNothing()
        {
            using var page = new Page();
            var calls = 0;
            page.Bot.Chat.ResolvePublicKeys = _ =>
            {
                calls++;
                return Task.FromResult<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>>(null!);
            };

            var result = await page.DecryptAsync();

            Assert.Empty(result.Events);
            AssertMissing(result, ("0", "5001"), ("1", "5002"));
            Assert.Equal(1, calls);
        }

        [Fact]
        public async Task AsyncCalls_HookThatThrows_ThrowToTheCaller()
        {
            // Thrown before the hook returns its task.
            using var page = new Page();
            page.Bot.Chat.ResolvePublicKeys = _ => throw new InvalidOperationException("lookup failed");
            var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => page.DecryptAsync());
            Assert.Equal("lookup failed", thrown.Message);

            // Thrown by the task the hook returns.
            using var later = new Page();
            later.Bot.Chat.ResolvePublicKeys = async _ =>
            {
                await Task.Yield();
                throw new InvalidOperationException("lookup failed later");
            };
            thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => later.DecryptAsync());
            Assert.Equal("lookup failed later", thrown.Message);

            // A prepare call throws it too.
            using var admin = Session("5001");
            admin.Chat.ResolvePublicKeys = _ => throw new InvalidOperationException("lookup failed");
            thrown = await Assert.ThrowsAsync<InvalidOperationException>(
                () => admin.Chat.PrepareGroupCreateAsync(Create()));
            Assert.Equal("lookup failed", thrown.Message);
        }

        [Fact]
        public void PrepareCalls_WithNoPublicKeys_EncryptToTheStoredKeysOfTheirMembers()
        {
            using var admin = Session("5001");
            using var member = new Party("5002");
            using var joiner = new Party("5004");
            admin.Chat.AddPublicKeys(Records(admin, member, joiner));

            foreach (var call in PrepareCalls())
                Assert.Equal(call.Members, Recipients(call.Prepare(admin.Chat)));

            // The member decrypts the key a create holds for it.
            var created = admin.Chat.PrepareGroupCreate(Create());
            var forMember = Assert.Single(created.ConversationParticipantKeys, key => key.UserId == member.UserId);
            Assert.Equal(
                created.ConversationKey,
                member.Chat.DecryptConversationKey(forMember.EncryptedConversationKey));

            // A one-to-one names its two users by its id: here the member's id alone.
            Assert.Equal("5001:5002", admin.Chat.PrepareConversationKeyChange(RotateOneToOne()).ConversationId);

            // The constructors that take public keys read the stored ones when they are
            // given none.
            var none = Array.Empty<PublicKeyInput>();
            Assert.Equal(Both, Recipients(admin.Chat.PrepareGroupCreate(
                new GroupCreateParams(null, Group, Both, new[] { "5001" }))));
            Assert.Equal(Both, Recipients(admin.Chat.PrepareGroupMembersRemove(
                new GroupMembersRemoveParams(none, Group, new[] { "5004" }) { RemainingMemberIds = Both })));
            Assert.Equal(Both, Recipients(admin.Chat.PrepareConversationKeyChange(
                new ConversationKeyChangeParams(none) { ConversationId = Group, MemberIds = Both })));
        }

        [Fact]
        public void PrepareCalls_WithNoStoredKeysForAMember_FailNamingThatMember()
        {
            using var admin = Session("5001");
            admin.Chat.AddPublicKeys(Records(admin));

            foreach (var call in PrepareCalls())
            {
                var e = Assert.Throws<ChatXdkException>(() => call.Prepare(admin.Chat));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, e.Kind);
                var missing = string.Join(", ", call.Members.Where(userId => userId != admin.UserId));
                Assert.Contains($"public_keys is empty and no public keys are stored for user(s) {missing}:", e.Message);
            }

            // Without members to read keys for, a removal reports its empty public keys.
            var unnamed = Assert.Throws<ChatXdkException>(() => admin.Chat.PrepareGroupMembersRemove(
                new GroupMembersRemoveParams(Group, new[] { "5004" })));
            Assert.Contains("public_keys is empty: pass the public keys of the remaining members", unnamed.Message);
        }

        [Fact]
        public async Task PrepareCallsAsync_FetchTheKeysTheyLackThroughTheHook()
        {
            using var member = new Party("5002");
            using var joiner = new Party("5004");

            foreach (var call in PrepareCalls())
            {
                // An admin with no stored keys.
                using var admin = Session("5001");
                var directory = new KeyDirectory(admin, member, joiner);
                admin.Chat.ResolvePublicKeys = directory.ResolveAsync;

                // The synchronous call fails without calling the hook.
                var e = Assert.Throws<ChatXdkException>(() => call.Prepare(admin.Chat));
                Assert.Contains(
                    $"no public keys are stored for user(s) {string.Join(", ", call.Members)}:", e.Message);
                Assert.Empty(directory.Calls);

                var prepared = await call.PrepareAsync(admin.Chat);

                Assert.Equal(call.Members, Recipients(prepared));
                Assert.Equal(call.Members, Assert.Single(directory.Calls));

                // The keys are stored: the next call needs no lookup, in either form.
                Assert.Equal(call.Members, Recipients(await call.PrepareAsync(admin.Chat)));
                Assert.Equal(call.Members, Recipients(call.Prepare(admin.Chat)));
                Assert.Single(directory.Calls);
            }
        }

        [Fact]
        public async Task PrepareCallsAsync_WithPublicKeysPassed_NeverCallTheHook()
        {
            using var admin = Session("5001");
            using var member = new Party("5002");
            using var joiner = new Party("5004");
            var directory = new KeyDirectory(admin, member, joiner);
            admin.Chat.ResolvePublicKeys = directory.ResolveAsync;
            var bothKeys = new[] { admin.PublicKey, member.PublicKey };
            var withJoinerKeys = new[] { admin.PublicKey, member.PublicKey, joiner.PublicKey };

            // The admin has no stored keys: the keys that are passed are the ones encrypted to.
            var created = await admin.Chat.PrepareGroupCreateAsync(
                new GroupCreateParams(bothKeys, Group, Both, new[] { "5001" }));
            Assert.Equal(Both, Recipients(created));
            var added = await admin.Chat.PrepareGroupMembersChangeAsync(new GroupMembersChangeParams(
                withJoinerKeys, Group, new[] { "5004" }, Both, new[] { "5001" }, Array.Empty<string>()));
            Assert.Equal(WithJoiner, Recipients(added));
            var removed = await admin.Chat.PrepareGroupMembersRemoveAsync(
                new GroupMembersRemoveParams(bothKeys, Group, new[] { "5004" }));
            Assert.Equal(Both, Recipients(removed));
            var rotated = await admin.Chat.PrepareConversationKeyChangeAsync(
                new ConversationKeyChangeParams(bothKeys) { ConversationId = Group });
            Assert.Equal(Both, Recipients(rotated));

            Assert.Empty(directory.Calls);
        }

        [Fact]
        public async Task PrepareCallsAsync_MembersTheHookDidNotBring_FailTheCallAndAreNotAskedForAgain()
        {
            using var admin = Session("5001");
            // The hook knows the admin alone.
            var directory = new KeyDirectory(admin);
            admin.Chat.ResolvePublicKeys = directory.ResolveAsync;

            for (var attempt = 0; attempt < 2; attempt++)
            {
                var e = await Assert.ThrowsAsync<ChatXdkException>(
                    () => admin.Chat.PrepareGroupCreateAsync(Create()));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, e.Kind);
                Assert.Contains("no public keys are stored for user(s) 5002:", e.Message);
                Assert.Equal(Both, Assert.Single(directory.Calls));
            }
        }
    }
}
