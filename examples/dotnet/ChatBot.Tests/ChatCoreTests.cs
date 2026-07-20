using System.Text.Json;
using ChatXdk;
using ChatBot;
using Xunit;

namespace ChatBot.Tests;

/// <summary>
/// Offline tests for the .NET example's crypto core.
///
/// These drive the REAL ChatXdk binding through the same <see cref="ChatCore"/>
/// the bot uses — no mocking. They prove an actual encrypt -> decrypt round-trip
/// and that the binding reproduces the committed key vectors.
/// </summary>
public class ChatCoreTests
{
    private sealed record Vectors(
        string PrivateKeysConcatB64,
        string ConversationKeyB64,
        string IdentityPublicB64,
        string SigningPublicB64,
        string EventMessageB64,
        string EventConversationId,
        string EventConversationKeyVersion);

    private static Vectors LoadVectors()
    {
        // Walk up from the test binary until we find the repo's fixtures.
        var dir = AppContext.BaseDirectory;
        string? path = null;
        for (var d = new DirectoryInfo(dir); d is not null; d = d.Parent)
        {
            var candidate = Path.Combine(d.FullName, "tests", "fixtures", "sdk_vectors.json");
            if (File.Exists(candidate)) { path = candidate; break; }
        }
        Assert.NotNull(path);
        using var doc = JsonDocument.Parse(File.ReadAllText(path!));
        var r = doc.RootElement;
        return new Vectors(
            r.GetProperty("private_keys_concat_b64").GetString()!,
            r.GetProperty("conversation_key_b64").GetString()!,
            r.GetProperty("identity_public_b64").GetString()!,
            r.GetProperty("signing_public_b64").GetString()!,
            r.GetProperty("event_message_b64").GetString()!,
            r.GetProperty("event_conversation_id").GetString()!,
            r.GetProperty("event_conversation_key_version").GetString()!);
    }

    private static ChatCore LoadedCore(Vectors v)
    {
        var core = new ChatCore();
        core.LoadKeys(v.PrivateKeysConcatB64, "1");
        return core;
    }

    [Fact]
    public void LoadKeys_Matches_Fixture_Public_Keys()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        var keys = core.PublicKeys();
        Assert.Equal(v.IdentityPublicB64, keys.Identity);
        Assert.Equal(v.SigningPublicB64, keys.Signing);
    }

    [Fact]
    public void Generic_Encrypt_Decrypt_Roundtrip()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        var key = Convert.FromBase64String(v.ConversationKeyB64);
        const string plaintext = "hello from the dotnet example";
        var ciphertext = core.Encrypt(plaintext, key);
        Assert.NotEqual(plaintext, ciphertext);
        Assert.Equal(plaintext, core.Decrypt(ciphertext, key));
    }

    [Fact]
    public void Conversation_Key_Prepare_And_Decrypt_Roundtrip()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("me");
        var prepared = core.PrepareConversationKeyChange(new[]
        {
            new PublicKeyInput { UserId = "me", PublicKey = v.IdentityPublicB64, KeyVersion = "1" },
        }, "conv-1");
        Assert.Single(prepared.ParticipantKeys);
        var decrypted = core.DecryptConversationKey(prepared.ParticipantKeys[0].EncryptedKey);
        Assert.Equal(prepared.ConversationKey, decrypted);
    }

    [Fact]
    public void EncryptReply_Produces_Sendable_Payload()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("12345");
        var key = Convert.FromBase64String(v.ConversationKeyB64);
        var body = core.EncryptReply("6789:12345", "pong", key, "1710000000000");
        Assert.False(string.IsNullOrEmpty(body.EncodedMessageCreateEvent));
        Assert.False(string.IsNullOrEmpty(body.EncodedMessageEventSignature));
        Assert.False(string.IsNullOrEmpty(body.MessageId));
    }

    [Fact]
    public void DecryptBatch_Empty_Is_Safe()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        var result = core.DecryptBatch(Array.Empty<string>());
        Assert.Empty(result.Messages);
    }

    [Fact]
    public void DecryptOne_Rejects_Garbage()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        Assert.ThrowsAny<Exception>(() =>
            core.DecryptOne("not-valid-base64!!!", new Dictionary<string, byte[]>()));
    }

    [Fact]
    public void PrepToRequest_Maps_The_Rest_Shape()
    {
        // The mapper output is exactly what the X API's write endpoints take;
        // a drifted field name here breaks every flow in the live e2e.
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("1000");
        var prep = core.PrepareConversationKeyChange(new[]
        {
            new PublicKeyInput { UserId = "1000", PublicKey = v.IdentityPublicB64, KeyVersion = "1" },
        }, "1000:2000");
        var signingPub = core.PublicKeys().Signing;

        // Assert on the serialized form — the exact JSON the HTTP layer posts.
        using var doc = JsonDocument.Parse(
            JsonSerializer.Serialize(EventHelpers.PrepToRequest(prep, signingPub)));
        var body = doc.RootElement;

        Assert.Equal(prep.ConversationKeyVersion, body.GetProperty("conversation_key_version").GetString());
        var pk = Assert.Single(body.GetProperty("conversation_participant_keys").EnumerateArray());
        Assert.Equal(
            new[] { "encrypted_conversation_key", "public_key_version", "user_id" },
            pk.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        var sig = Assert.Single(body.GetProperty("action_signatures").EnumerateArray());
        Assert.Equal(prep.ActionSignatures[0].MessageId, sig.GetProperty("message_id").GetString());
        Assert.False(string.IsNullOrEmpty(sig.GetProperty("encoded_message_event_detail").GetString()));
        var inner = sig.GetProperty("message_event_signature");
        Assert.Equal(signingPub, inner.GetProperty("signing_public_key").GetString());
        Assert.False(string.IsNullOrEmpty(inner.GetProperty("signature").GetString()));
        Assert.False(string.IsNullOrEmpty(inner.GetProperty("public_key_version").GetString()));
        // CKCE signature payloads are withheld (they embed the plaintext key).
        Assert.False(sig.TryGetProperty("signature_payload", out _));
    }

    [Fact]
    public void PrepareGroupCreate_Yields_Two_Signatures()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("1000");
        var prep = core.PrepareGroupCreate(new[]
        {
            new PublicKeyInput { UserId = "1000", PublicKey = v.IdentityPublicB64, KeyVersion = "1" },
        }, "g123", new[] { "1000" }, new[] { "1000" });
        Assert.Equal(2, prep.ActionSignatures.Count);
        Assert.NotNull(prep.ConversationKey);
        Assert.Equal(32, prep.ConversationKey!.Length);
    }

    [Fact]
    public void EncryptReaction_Produces_Sendable_Payload()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("1000");
        var convKey = Convert.FromBase64String(v.ConversationKeyB64);
        // React to the fixture raw event: the conversation id and target
        // sequence id are derived from it by the SDK.
        var body = core.EncryptReaction(
            add: true,
            targetEventB64: v.EventMessageB64,
            emoji: "\U0001F44D",
            conversationKey: convKey,
            conversationKeyVersion: v.EventConversationKeyVersion);
        Assert.False(string.IsNullOrEmpty(body.MessageId));
        Assert.False(string.IsNullOrEmpty(body.EncodedMessageCreateEvent));
        Assert.False(string.IsNullOrEmpty(body.EncodedMessageEventSignature));
    }

    [Fact]
    public void Media_Stream_Encrypt_Decrypt_Roundtrip()
    {
        // The chunked stream path the media flow uses: multi-chunk payload in,
        // identical bytes out, and truncation is detected.
        var v = LoadVectors();
        using var core = LoadedCore(v);
        var convKey = Convert.FromBase64String(v.ConversationKeyB64);
        var plaintext = new byte[300_000];
        for (var i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)((i * 31 + 7) % 256);

        var ciphertext = core.EncryptMedia(plaintext, convKey);
        Assert.False(ciphertext.AsSpan(0, plaintext.Length).SequenceEqual(plaintext));
        Assert.Equal(plaintext, core.DecryptMedia(ciphertext, convKey));

        Assert.ThrowsAny<Exception>(() => core.DecryptMedia(ciphertext[..^4], convKey));
    }

    [Fact]
    public void Threaded_Reply_With_Entities_And_Ttl_Encrypts()
    {
        var v = LoadVectors();
        using var core = LoadedCore(v);
        core.SetIdentity("1000");
        var convKey = Convert.FromBase64String(v.ConversationKeyB64);
        // Reply by raw event: the preview is derived from the fixture event,
        // which was encrypted under the same fixture key + version.
        var body = core.EncryptReply(
            v.EventConversationId,
            "@user hello",
            convKey,
            v.EventConversationKeyVersion,
            replyToEvent: v.EventMessageB64,
            entities: new[] { new EntityDescriptor { Start = 0, End = 5, EntityType = "mention" } },
            ttlMsec: 60_000);
        Assert.False(string.IsNullOrEmpty(body.EncodedMessageCreateEvent));
    }
}
