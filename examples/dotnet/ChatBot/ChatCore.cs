using System.Text.Json;
using ChatXdk;

namespace ChatBot;

/// <summary>
/// Crypto core for the .NET chat-xdk example bot.
///
/// A thin, network-free wrapper around the <see cref="ChatXdk.Chat"/>
/// binding. Everything that touches the SDK lives here so it can be unit-tested
/// directly (see ChatBot.Tests). The four core feature touchpoints are all here:
///
/// <list type="bullet">
///   <item>key management     -> LoadKeys / SetIdentity / GenerateAndRegister</item>
///   <item>conversation keys  -> PrepareConversationKeyChange / DecryptConversationKey</item>
///   <item>message encryption -> EncryptReply</item>
///   <item>event decryption   -> DecryptBatch (DecryptEvents) and DecryptOne (DecryptEvent)</item>
/// </list>
/// </summary>
public sealed class ChatCore : IDisposable
{
    private readonly Chat _chat = new();
    public string SigningKeyVersion { get; private set; } = "1";

    // -- Key management -----------------------------------------------------

    /// <summary>Import an existing base64 private-key blob (identity[+signing])
    /// together with the key version it was registered under.</summary>
    public void LoadKeys(string privateKeysB64, string signingKeyVersion = "1")
    {
        _chat.ImportKeys(Convert.FromBase64String(privateKeysB64), signingKeyVersion);
        SigningKeyVersion = signingKeyVersion;
    }

    /// <summary>
    /// Set the session identity once; every encrypt/prepare call below then
    /// signs as this user without passing a sender id per call.
    /// </summary>
    public void SetIdentity(string userId) => _chat.SetIdentity(userId, SigningKeyVersion);

    /// <summary>Generate a fresh identity. Returns the registration payload to
    /// POST to the X API plus the exported private blob (base64) to persist.</summary>
    public (PublicKeyRegistrationPayload Registration, string PrivateKeysB64) GenerateAndRegister()
    {
        var payload = _chat.GenerateKeypairs();
        var exported = _chat.ExportKeys() ?? Array.Empty<byte>();
        return (payload, Convert.ToBase64String(exported));
    }

    public PublicKeys PublicKeys() => _chat.GetPublicKeys();

    // -- Conversation keys --------------------------------------------------

    public PreparedConversationChange PrepareConversationKeyChange(
        IReadOnlyList<PublicKeyInput> publicKeys, string? conversationId = null)
        => _chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(publicKeys)
        {
            ConversationId = conversationId,
        });

    /// <summary>ECIES-decrypt one conversation key -> raw 32-byte key.</summary>
    public byte[] DecryptConversationKey(string encryptedKeyB64)
        => _chat.DecryptConversationKey(encryptedKeyB64);

    // -- Decryption: the two paths -----------------------------------------

    /// <summary>Batch path — used on initial conversation load.</summary>
    public DecryptEventsResult DecryptBatch(IEnumerable<string> eventsB64, IEnumerable<SigningKeyEntry>? signingKeys = null)
        => _chat.DecryptEvents(eventsB64, signingKeys);

    /// <summary>Single-event path — used for each new event after the initial load.</summary>
    public JsonElement DecryptOne(string eventB64, Dictionary<string, byte[]> conversationKeys, IEnumerable<SigningKeyEntry>? signingKeys = null)
        => _chat.DecryptEvent(eventB64, conversationKeys, signingKeys);

    // -- Message encryption -------------------------------------------------

    /// <summary>
    /// Encrypt + sign a message; returns fields ready for the X API send.
    /// The sender comes from <see cref="SetIdentity"/>. Without
    /// <paramref name="replyToEvent"/> this sends a fresh message via
    /// <c>EncryptMessage</c>; with it, the SDK's <c>EncryptReply</c> builds a
    /// *threaded* reply whose preview is derived from that raw signed event.
    /// <paramref name="entities"/> are (start, end, type) byte ranges;
    /// <paramref name="attachments"/> are attachment descriptors (e.g. a media
    /// reference); <paramref name="ttlMsec"/> makes the message disappear
    /// after the given lifetime.
    /// </summary>
    public SendBody EncryptReply(
        string conversationId,
        string text,
        byte[] conversationKey,
        string conversationKeyVersion,
        string? replyToEvent = null,
        IReadOnlyList<EntityDescriptor>? entities = null,
        IReadOnlyList<AttachmentDescriptor>? attachments = null,
        long? ttlMsec = null,
        IReadOnlyList<string>? replyToCkces = null)
    {
        var payload = replyToEvent is null
            ? _chat.EncryptMessage(new EncryptMessageParams(conversationId, text)
            {
                ConversationKey = conversationKey,
                ConversationKeyVersion = conversationKeyVersion,
                Entities = entities,
                Attachments = attachments,
                TtlMsec = ttlMsec,
            })
            : _chat.EncryptReply(new EncryptReplyParams(conversationId, text, replyToEvent)
            {
                ConversationKey = conversationKey,
                ConversationKeyVersion = conversationKeyVersion,
                // Key-change events for the original's key version, when it
                // differs from this reply's version.
                ReplyToCkces = replyToCkces,
                Entities = entities,
                Attachments = attachments,
                TtlMsec = ttlMsec,
            });
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(payload.MessageId, payload.EncryptedContent, payload.EncodedEventSignature);
    }

    /// <summary>Encrypt + sign a reaction add/remove targeting a raw event
    /// (the conversation id and target sequence id are derived from it).</summary>
    public SendBody EncryptReaction(
        bool add,
        string targetEventB64,
        string emoji,
        byte[] conversationKey,
        string conversationKeyVersion)
    {
        var parameters = new EncryptReactionParams(targetEventB64, emoji)
        {
            ConversationKey = conversationKey,
            ConversationKeyVersion = conversationKeyVersion,
        };
        var payload = add ? _chat.EncryptAddReaction(parameters) : _chat.EncryptRemoveReaction(parameters);
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(payload.MessageId, payload.EncryptedContent, payload.EncodedEventSignature);
    }

    // -- Group management -----------------------------------------------------

    /// <summary>Prepare a group creation: fresh key + the two required signatures.</summary>
    public PreparedConversationChange PrepareGroupCreate(
        IReadOnlyList<PublicKeyInput> publicKeys,
        string conversationId,
        IReadOnlyList<string> memberIds,
        IReadOnlyList<string> adminIds)
        => _chat.PrepareGroupCreate(new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds));

    /// <summary>Prepare a member add: rotated key + the two required signatures.</summary>
    public PreparedConversationChange PrepareGroupMembersChange(
        IReadOnlyList<PublicKeyInput> publicKeys,
        string conversationId,
        IReadOnlyList<string> newMemberIds,
        IReadOnlyList<string> currentMemberIds,
        IReadOnlyList<string> currentAdminIds)
        => _chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
            publicKeys,
            conversationId,
            newMemberIds,
            currentMemberIds,
            currentAdminIds,
            Array.Empty<string>()));

    // -- Media streaming -----------------------------------------------------

    private const int MediaChunk = 1024 * 1024;

    /// <summary>
    /// Encrypt a media blob with the incremental stream API.
    ///
    /// Feeding fixed-size chunks through <c>Push</c> keeps memory bounded no
    /// matter how large the file is; <c>Finish</c> emits the final frame that
    /// seals the stream (decryption fails without it).
    /// </summary>
    public byte[] EncryptMedia(byte[] plaintext, byte[] conversationKey)
    {
        using var enc = _chat.StreamEncryptor(conversationKey);
        using var output = new MemoryStream();
        for (var offset = 0; offset < plaintext.Length; offset += MediaChunk)
        {
            var len = Math.Min(MediaChunk, plaintext.Length - offset);
            output.Write(enc.Push(plaintext.AsSpan(offset, len).ToArray()));
        }
        output.Write(enc.Finish());
        return output.ToArray();
    }

    /// <summary>
    /// Decrypt a media blob with the incremental stream API.
    ///
    /// <c>Finish</c> throws if the stream was truncated, so plaintext from
    /// <c>Push</c> must not be treated as complete until it succeeds.
    /// </summary>
    public byte[] DecryptMedia(byte[] ciphertext, byte[] conversationKey)
    {
        using var dec = _chat.StreamDecryptor(conversationKey);
        using var output = new MemoryStream();
        for (var offset = 0; offset < ciphertext.Length; offset += MediaChunk)
        {
            var len = Math.Min(MediaChunk, ciphertext.Length - offset);
            output.Write(dec.Push(ciphertext.AsSpan(offset, len).ToArray()));
        }
        output.Write(dec.Finish());
        return output.ToArray();
    }

    // -- Generic helpers (handy for metadata + tests) -----------------------

    public string Encrypt(string plaintext, byte[] conversationKey) => _chat.Encrypt(plaintext, conversationKey);

    public string Decrypt(string ciphertextB64, byte[] conversationKey) => _chat.Decrypt(ciphertextB64, conversationKey);

    public void Dispose() => _chat.Dispose();
}

/// <summary>Fields the X API expects for an encrypted message send.</summary>
public sealed record SendBody(string MessageId, string EncodedMessageCreateEvent, string EncodedMessageEventSignature);

/// <summary>Pull the plain text out of a decrypted Message event, or null.</summary>
public static class EventHelpers
{
    public static string? MessageText(JsonElement evt)
    {
        if (!evt.TryGetProperty("type", out var type) || type.GetString() != "Message")
            return null;
        if (evt.TryGetProperty("content", out var content) &&
            content.TryGetProperty("text", out var text))
            return text.GetString();
        return null;
    }

    /// <summary>
    /// Map a prepared conversation change into the X API request shape
    /// (snake_case field names, ready to serialize as the JSON body).
    ///
    /// Works for 1:1 key changes (one signature) and group create / member add
    /// (two signatures). <paramref name="signingPublicKey"/> is the sender's own
    /// signing key, which the API expects alongside each signature.
    /// </summary>
    public static Dictionary<string, object?> PrepToRequest(PreparedConversationChange prep, string signingPublicKey)
    {
        var actionSignatures = new List<Dictionary<string, object?>>();
        foreach (var sig in prep.ActionSignatures)
        {
            var entry = new Dictionary<string, object?>
            {
                ["message_id"] = sig.MessageId,
                ["encoded_message_event_detail"] = sig.EncodedMessageEventDetail,
                ["message_event_signature"] = new Dictionary<string, object?>
                {
                    ["signature"] = sig.Signature,
                    ["signature_version"] = sig.SignatureVersion,
                    ["public_key_version"] = sig.PublicKeyVersion,
                    ["signing_public_key"] = signingPublicKey,
                },
            };
            // Conversation-key-change payloads are withheld by the SDK (they
            // embed the plaintext key); only include the field when present.
            if (!string.IsNullOrEmpty(sig.SignaturePayload))
                entry["signature_payload"] = sig.SignaturePayload;
            actionSignatures.Add(entry);
        }
        return new Dictionary<string, object?>
        {
            ["conversation_key_version"] = prep.ConversationKeyVersion,
            ["conversation_participant_keys"] = prep.ParticipantKeys
                .Select(pk => new Dictionary<string, object?>
                {
                    ["user_id"] = pk.UserId,
                    ["encrypted_conversation_key"] = pk.EncryptedKey,
                    ["public_key_version"] = pk.PublicKeyVersion,
                })
                .ToList(),
            ["action_signatures"] = actionSignatures,
        };
    }
}
