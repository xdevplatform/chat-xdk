using System.Text.Json;
using ChatXdk;
using ChatBot;
using Xunit;
using static ChatBot.Tests.ChatCoreTests;

namespace ChatBot.Tests;

/// <summary>
/// Offline tests for the .NET example's multi-user helpers: one chat per
/// signed-in user, all fetching public keys through one hook over one cache.
///
/// Like <see cref="ChatCoreTests"/>, these drive the real ChatXdk binding.
/// </summary>
public class MultiUserTests
{
    /// <summary>The chat <paramref name="chats"/> keeps for
    /// <paramref name="user"/>, signed in with the user's keys.</summary>
    private static ChatCore SignIn(UserChats chats, Party user) =>
        chats.ChatFor(user.UserId, user.PrivateKeysB64, "1");

    /// <summary>
    /// The page each of <paramref name="readers"/> receives after
    /// <paramref name="admin"/> changes the key of the group
    /// <paramref name="conversationId"/>, which they and
    /// <paramref name="member"/> are in, and <paramref name="member"/> sends
    /// <paramref name="text"/> under it: the key change, then the message.
    /// </summary>
    private static async Task<string[]> GroupPageAsync(
        Party admin, Party member, Party[] readers, string conversationId, string text)
    {
        var publicKeys = new[] { admin, member }.Concat(readers).Select(party => party.PublicKey).ToList();
        var prepared = await admin.Core.PrepareConversationKeyChangeAsync(publicKeys, conversationId);
        var keyChange = DeliveredAction(
            prepared.ActionSignatures[0], admin.UserId, conversationId, "2100000000000000000");
        var body = member.Core.EncryptReply(
            conversationId, text, prepared.ConversationKey, prepared.ConversationKeyVersion);
        return new[] { keyChange, Delivered(body.EventB64, "2100000000000000001") };
    }

    /// <summary>A record as the X API returns it, with its key version alone.</summary>
    private static JsonElement KeyRecord(string version) =>
        JsonSerializer.SerializeToElement(new Dictionary<string, string> { ["public_key_version"] = version });

    /// <summary>The key version of the one record <paramref name="answer"/>
    /// holds for <paramref name="userId"/>.</summary>
    private static string VersionOf(
        IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>> answer, string userId) =>
        Assert.Single(answer[userId]).PublicKeyVersion;

    [Fact]
    public async Task The_Chats_Of_Two_Signed_In_Users_Fetch_The_Keys_Of_A_User_They_Both_Meet_Once()
    {
        using var admin = new Party("5001");
        using var member = new Party("5002");
        using var alice = new Party("5003");
        using var bob = new Party("5004");
        var asked = new List<string>();
        var shared = new SharedPublicKeys(PublicKeysOf(asked, admin, member));
        var chats = new UserChats(shared.ResolveAsync);
        var events = await GroupPageAsync(admin, member, new[] { alice, bob }, "g900", "hello group");

        foreach (var signedIn in new[] { alice, bob })
        {
            var chat = SignIn(chats, signedIn);
            var page = await chat.DecryptBatchAsync(events);
            Assert.Empty(page.Errors);
            Assert.Empty(page.MissingSigningKeys);
            Assert.Equal(
                new[] { null, "hello group" },
                page.Events.Select(decrypted => EventHelpers.MessageText(decrypted.Event)));
            chats.Close(signedIn.UserId);
        }
        // Each chat needed the keys of the admin and the member: the second
        // chat took them from the cache the first one filled.
        Assert.Equal(new[] { "5001", "5002" }, asked);
    }

    [Fact]
    public async Task A_Signed_In_User_Has_One_Chat_Which_Serves_Every_Conversation_Of_The_User()
    {
        using var admin = new Party("5001");
        using var member = new Party("5002");
        using var alice = new Party("5003");
        using var bob = new Party("5004");
        var shared = new SharedPublicKeys(PublicKeysOf(new List<string>(), admin, member));
        var chats = new UserChats(shared.ResolveAsync);

        // Sign-ins of one user get one chat, also from two threads at once.
        var signIns = await Task.WhenAll(
            Task.Run(() => SignIn(chats, alice)), Task.Run(() => SignIn(chats, alice)));
        var chat = signIns[0];
        Assert.Same(chat, signIns[1]);
        Assert.Same(chat, SignIn(chats, alice));
        Assert.NotSame(chat, SignIn(chats, bob));

        foreach (var conversationId in new[] { "g900", "g901" })
        {
            var events = await GroupPageAsync(
                admin, member, new[] { alice }, conversationId, $"hello {conversationId}");
            var page = await chat.DecryptBatchAsync(events);
            Assert.Empty(page.Errors);
            // The reply takes the conversation's key from the chat's key cache.
            var body = chat.EncryptReply(conversationId, "hi");
            Assert.False(string.IsNullOrEmpty(body.EncodedMessageCreateEvent));
        }
        // The chat holds no key for a conversation it has not read.
        var noKey = Assert.Throws<ChatXdkException>(() => chat.EncryptReply("g902", "hi"));
        Assert.Equal(ChatXdkErrorKind.InvalidState, noKey.Kind);

        // After a sign-out, the next sign-in makes another chat.
        chats.Close(alice.UserId);
        Assert.NotSame(chat, SignIn(chats, alice));
        chats.Close(alice.UserId);
        chats.Close(bob.UserId);
    }

    [Fact]
    public async Task SharedPublicKeys_Retries_A_Failed_Lookup_And_Fetches_Again_After_The_Ttl()
    {
        var time = DateTimeOffset.UnixEpoch;
        var failing = true;
        var asked = new List<string>();
        // Each answer carries the number of the fetch that brought it.
        var shared = new SharedPublicKeys(
            userId =>
            {
                asked.Add(userId);
                return userId == "7" && failing
                    ? Task.FromException<List<JsonElement>>(new InvalidOperationException("HTTP 503"))
                    : Task.FromResult(new List<JsonElement> { KeyRecord($"{asked.Count}") });
            },
            ttl: TimeSpan.FromMilliseconds(100),
            now: () => time);

        // A lookup that fails leaves that user out, and the other user's
        // records still arrive.
        var first = await shared.ResolveAsync(new[] { "7", "5" });
        Assert.Equal(new[] { "5" }, first.Keys);
        Assert.Equal("2", VersionOf(first, "5"));

        // The failed lookup was not kept: the next call fetches again.
        failing = false;
        Assert.Equal("3", VersionOf(await shared.ResolveAsync(new[] { "7" }), "7"));
        Assert.Equal(new[] { "7", "5", "7" }, asked);

        // An answer is served until its time is up, then fetched again.
        time = time.AddMilliseconds(99);
        Assert.Equal("2", VersionOf(await shared.ResolveAsync(new[] { "5" }), "5"));
        Assert.Equal(3, asked.Count);
        time = time.AddMilliseconds(1);
        Assert.Equal("4", VersionOf(await shared.ResolveAsync(new[] { "5" }), "5"));
    }

    [Fact]
    public async Task SharedPublicKeys_Shares_A_Lookup_Under_Way()
    {
        // The fetch ends when the test completes this source, so the test
        // decides how long the lookup is under way.
        var release = new TaskCompletionSource<List<JsonElement>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var fetches = 0;
        var shared = new SharedPublicKeys(_ =>
        {
            Interlocked.Increment(ref fetches);
            return release.Task;
        });

        // The second caller asks while the first caller's lookup is under
        // way: neither has an answer before the fetch ends.
        var first = shared.ResolveAsync(new[] { "5" });
        var second = shared.ResolveAsync(new[] { "5" });
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);
        release.SetResult(new List<JsonElement> { KeyRecord("1") });

        // Both callers get the answer of the one fetch.
        foreach (var answer in await Task.WhenAll(first, second))
            Assert.Equal("1", VersionOf(answer, "5"));
        Assert.Equal(1, fetches);
    }
}
