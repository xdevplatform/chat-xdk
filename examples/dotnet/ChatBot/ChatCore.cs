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
///   <item>conversation keys  -> PrepareConversationKeyChangeAsync / DecryptConversationKey</item>
///   <item>message encryption -> EncryptReply, then EncryptMedia for its files</item>
///   <item>event decryption   -> DecryptBatchAsync (DecryptEventsAsync) and DecryptOne
///   (DecryptEvent)</item>
/// </list>
///
/// Other users' public keys reach the SDK through one hook,
/// <see cref="FetchPublicKeysWith"/>: the SDK calls it for the keys a decrypt
/// or a key change lacks, and stores what it returns.
/// </summary>
public sealed class ChatCore : IDisposable
{
    private readonly Chat _chat = new();
    public string SigningKeyVersion { get; private set; } = "";

    /// <summary>
    /// A chat whose conversation-key cache is on: <see cref="DecryptBatchAsync"/>
    /// fills it from verified key changes, and the encrypt calls take the
    /// newest key from it.
    /// </summary>
    public ChatCore()
    {
        _chat.SetCacheKeys(true);
    }

    // -- Key management -----------------------------------------------------

    /// <summary>Import an existing base64 private-key blob (identity[+signing])
    /// together with the public_key_version the X API returned when it was
    /// registered.</summary>
    public void LoadKeys(string privateKeysB64, string signingKeyVersion)
    {
        _chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(privateKeysB64)) { SigningKeyVersion = signingKeyVersion });
        SigningKeyVersion = signingKeyVersion;
    }

    /// <summary>
    /// Set the session identity once; every encrypt/prepare call below then
    /// signs as this user without passing a sender id per call.
    /// </summary>
    public void SetIdentity(string userId)
    {
        if (string.IsNullOrEmpty(SigningKeyVersion))
            throw new InvalidOperationException(
                "signing key version unknown: pass LoadKeys the public_key_version the X API "
                + "returned when the keys were registered");
        _chat.SetIdentity(new SetIdentityParams(userId, SigningKeyVersion));
    }

    /// <summary>Generate a fresh identity. Returns the registration payload to
    /// POST to the X API plus the exported private blob (base64) to persist.</summary>
    public (PublicKeyRegistrationPayload Registration, string PrivateKeysB64) GenerateAndRegister()
    {
        var payload = _chat.GenerateKeypairs();
        var exported = _chat.ExportKeys();
        return (payload, Convert.ToBase64String(exported));
    }

    public PublicKeys PublicKeys() => _chat.GetPublicKeys();

    // -- Other users' public keys -------------------------------------------

    /// <summary>
    /// Have the SDK fetch the public keys it lacks with
    /// <paramref name="fetchPublicKeys"/>, which returns one user's records:
    /// the <c>data</c> array of <c>GET /2/users/{id}/public_keys</c>.
    ///
    /// This sets the SDK's <c>ResolvePublicKeys</c> hook.
    /// <see cref="DecryptBatchAsync"/> then fetches the signing keys a page's
    /// events name and the SDK does not hold, those of the members who made
    /// its key changes as well as those of the senders of its messages, and
    /// decrypts the page once more. The prepare calls that make a
    /// conversation key fetch their members' identity keys when they are
    /// passed no public keys. The SDK stores what arrives, and waits a minute
    /// before it asks again for a key a lookup did not bring.
    ///
    /// A user whose fetch fails is logged and left out, so the keys of the
    /// other users still arrive.
    /// </summary>
    public void FetchPublicKeysWith(Func<string, Task<List<JsonElement>>> fetchPublicKeys)
    {
        _chat.ResolvePublicKeys = async userIds =>
        {
            var records = new Dictionary<string, IReadOnlyList<PublicKeyRecord>>();
            foreach (var userId in userIds)
            {
                try
                {
                    var found = await fetchPublicKeys(userId);
                    records[userId] = found
                        .Select(item => item.Deserialize<PublicKeyRecord>())
                        .OfType<PublicKeyRecord>()
                        .ToList();
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"public_keys_fetch_failed user={userId} err={e.Message}");
                }
            }
            return records;
        };
    }

    /// <summary>
    /// Set the SDK's <c>ResolvePublicKeys</c> hook to
    /// <paramref name="resolvePublicKeys"/> as it is: a function that takes
    /// user ids and returns each user's records, by user id. A process with
    /// several signed-in users gives every chat the same function, so they
    /// share its lookups (see MultiUser.cs).
    /// </summary>
    public void ResolvePublicKeysWith(
        Func<IReadOnlyList<string>, Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>>> resolvePublicKeys)
    {
        _chat.ResolvePublicKeys = resolvePublicKeys;
    }

    // -- Conversation keys --------------------------------------------------

    /// <summary>
    /// Prepare a conversation-key change: a fresh key encrypted to every
    /// participant, and the signature the X API takes with it.
    ///
    /// <paramref name="publicKeys"/> are the participants' identity keys.
    /// Pass null for a one-to-one that <paramref name="conversationId"/>
    /// names, by its id or by the other user's id alone: the SDK reads both
    /// users' keys from the public keys it holds, fetching the ones it lacks
    /// through <see cref="FetchPublicKeysWith"/>.
    /// </summary>
    public Task<PreparedConversationChange> PrepareConversationKeyChangeAsync(
        IReadOnlyList<PublicKeyInput>? publicKeys, string? conversationId = null)
        => _chat.PrepareConversationKeyChangeAsync(new ConversationKeyChangeParams(publicKeys)
        {
            ConversationId = conversationId,
        });

    /// <summary>ECIES-decrypt one conversation key -> raw 32-byte key.</summary>
    public byte[] DecryptConversationKey(string encryptedKeyB64)
        => _chat.DecryptConversationKey(encryptedKeyB64);

    // -- Decryption: the two paths -----------------------------------------

    /// <summary>
    /// Batch path — every page of events goes through it, the key changes
    /// and the data events together: it extracts the conversation keys from
    /// the KeyChange events, caches those of the key changes that verify,
    /// then decrypts every event.
    ///
    /// Signatures verify with the public keys the SDK holds. The ones the
    /// page lacks are fetched through <see cref="FetchPublicKeysWith"/>; the
    /// result's <c>MissingSigningKeys</c> lists those that did not arrive.
    /// </summary>
    public Task<DecryptEventsResult> DecryptBatchAsync(IEnumerable<string> eventsB64)
        => _chat.DecryptEventsAsync(new DecryptEventsParams(eventsB64.ToList()));

    /// <summary>
    /// Single-event path — decrypt one event. An empty
    /// <paramref name="conversationKeys"/> takes the keys from the SDK's
    /// cache, and the signature verifies with the public keys the SDK holds.
    /// This path fetches none: an event whose sender's keys the SDK may lack
    /// goes through <see cref="DecryptBatchAsync"/>.
    /// </summary>
    public JsonElement DecryptOne(string eventB64, Dictionary<string, byte[]> conversationKeys)
        => _chat.DecryptEvent(new DecryptEventParams(eventB64, conversationKeys));

    // -- Message encryption -------------------------------------------------

    /// <summary>
    /// Encrypt + sign a message; returns fields ready for the X API send.
    /// The sender comes from <see cref="SetIdentity"/>. Without
    /// <paramref name="replyToEvent"/> this sends a fresh message via
    /// <c>EncryptMessage</c>; with it, the SDK's <c>EncryptReply</c> builds a
    /// *threaded* reply whose preview is derived from that raw signed event.
    /// <paramref name="entities"/> are (start, end, type) byte ranges;
    /// <paramref name="attachments"/> are attachment descriptors, each file
    /// naming the media hash key its upload started with (encrypt the files
    /// afterwards with <see cref="EncryptMedia"/> and the returned body's
    /// <c>EventB64</c>); <paramref name="quickReply"/> offers selectable
    /// options or answers them; <paramref name="ttlMsec"/> makes the message
    /// disappear after the given lifetime. <paramref name="replyToAttachmentId"/>
    /// replies to one attachment of <paramref name="replyToEvent"/>, such as one
    /// photo of an album: its <c>attachment_id</c>, which the preview quotes
    /// alone. The conversation key comes from the SDK's cache unless
    /// <paramref name="conversationKey"/> and
    /// <paramref name="conversationKeyVersion"/> are passed.
    /// </summary>
    public SendBody EncryptReply(
        string conversationId,
        string text,
        byte[]? conversationKey = null,
        string? conversationKeyVersion = null,
        string? replyToEvent = null,
        IReadOnlyList<EntityDescriptor>? entities = null,
        IReadOnlyList<AttachmentDescriptor>? attachments = null,
        long? ttlMsec = null,
        IReadOnlyList<string>? replyToCkces = null,
        QuickReply? quickReply = null,
        string? replyToAttachmentId = null)
    {
        var payload = replyToEvent is null && replyToAttachmentId is null
            ? _chat.EncryptMessage(new EncryptMessageParams(conversationId, text)
            {
                ConversationKey = conversationKey,
                ConversationKeyVersion = conversationKeyVersion,
                Entities = entities,
                Attachments = attachments,
                QuickReply = quickReply,
                TtlMsec = ttlMsec,
            })
            : _chat.EncryptReply(new EncryptReplyParams(conversationId, text, replyToEvent)
            {
                ConversationKey = conversationKey,
                ConversationKeyVersion = conversationKeyVersion,
                // Key-change events for the original's key version, when it
                // differs from this reply's version.
                ReplyToCkces = replyToCkces,
                ReplyToAttachmentId = replyToAttachmentId,
                Entities = entities,
                Attachments = attachments,
                QuickReply = quickReply,
                TtlMsec = ttlMsec,
            });
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(
            payload.MessageId,
            payload.EncodedMessageCreateEvent,
            payload.EncodedMessageEventSignature,
            payload.XdkVersion,
            payload.EventB64);
    }

    /// <summary>Encrypt + sign a reaction add/remove targeting a raw event
    /// (the conversation id and target sequence id are derived from it).
    /// <paramref name="targetAttachmentId"/> reacts to one attachment of the
    /// event, such as one photo of an album: its <c>attachment_id</c>, which
    /// the SDK checks against the decrypted event. Remove the reaction with
    /// the same <paramref name="targetAttachmentId"/>.</summary>
    public SendBody EncryptReaction(
        bool add,
        string targetEventB64,
        string emoji,
        byte[] conversationKey,
        string conversationKeyVersion,
        string? targetAttachmentId = null)
    {
        var parameters = new EncryptReactionParams(targetEventB64, emoji)
        {
            ConversationKey = conversationKey,
            ConversationKeyVersion = conversationKeyVersion,
            TargetAttachmentId = targetAttachmentId,
        };
        var payload = add ? _chat.EncryptAddReaction(parameters) : _chat.EncryptRemoveReaction(parameters);
        // The SDK generates the message id and returns it in the payload.
        return new SendBody(
            payload.MessageId,
            payload.EncodedMessageCreateEvent,
            payload.EncodedMessageEventSignature,
            payload.XdkVersion,
            payload.EventB64);
    }

    // -- Group management -----------------------------------------------------

    /// <summary>
    /// Prepare a group creation: fresh key + the two required signatures. A plaintext
    /// <paramref name="title"/> is encrypted under the new key; send the result's
    /// <c>EncryptedTitle</c> as the request's <c>group_name</c>.
    ///
    /// Pass null for <paramref name="publicKeys"/> to have the SDK read the
    /// identity keys of <paramref name="memberIds"/> and
    /// <paramref name="adminIds"/> from the public keys it holds, fetching the
    /// ones it lacks through <see cref="FetchPublicKeysWith"/>.
    /// </summary>
    public Task<PreparedConversationChange> PrepareGroupCreateAsync(
        IReadOnlyList<PublicKeyInput>? publicKeys,
        string conversationId,
        IReadOnlyList<string> memberIds,
        IReadOnlyList<string> adminIds,
        string? title = null)
        => _chat.PrepareGroupCreateAsync(new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds)
        {
            Title = title,
        });

    /// <summary>
    /// Prepare a member add: rotated key + the two required signatures.
    ///
    /// Pass null for <paramref name="publicKeys"/> to have the SDK read the
    /// identity keys of <paramref name="currentMemberIds"/> and
    /// <paramref name="newMemberIds"/> from the public keys it holds,
    /// fetching the ones it lacks through <see cref="FetchPublicKeysWith"/>.
    /// </summary>
    public Task<PreparedConversationChange> PrepareGroupMembersChangeAsync(
        IReadOnlyList<PublicKeyInput>? publicKeys,
        string conversationId,
        IReadOnlyList<string> newMemberIds,
        IReadOnlyList<string> currentMemberIds,
        IReadOnlyList<string> currentAdminIds)
        => _chat.PrepareGroupMembersChangeAsync(new GroupMembersChangeParams(
            publicKeys,
            conversationId,
            newMemberIds,
            currentMemberIds,
            currentAdminIds,
            Array.Empty<string>()));

    /// <summary>
    /// Prepare a member removal that rotates the key for who stays.
    ///
    /// <paramref name="publicKeys"/> are the identity keys of the members who
    /// remain. Pass null, and name those members in
    /// <paramref name="remainingMemberIds"/>, to have the SDK read their keys
    /// from the public keys it holds, fetching the ones it lacks through
    /// <see cref="FetchPublicKeysWith"/>; with <paramref name="publicKeys"/>
    /// passed, <paramref name="remainingMemberIds"/> is not read.
    /// </summary>
    public Task<PreparedConversationChange> PrepareGroupMembersRemoveAsync(
        IReadOnlyList<PublicKeyInput>? publicKeys,
        string conversationId,
        IReadOnlyList<string> userIds,
        IReadOnlyList<string>? remainingMemberIds = null)
        => _chat.PrepareGroupMembersRemoveAsync(new GroupMembersRemoveParams(publicKeys, conversationId, userIds)
        {
            RemainingMemberIds = remainingMemberIds,
        });

    // -- Media files ----------------------------------------------------------

    private const int MediaChunk = 1024 * 1024;

    /// <summary>
    /// Encrypt a media file of an outgoing message with the incremental file API.
    ///
    /// <paramref name="eventB64"/> is the <c>EventB64</c> of the body
    /// <see cref="EncryptReply"/> returned for the message,
    /// <paramref name="conversationKey"/> and <paramref name="conversationKeyVersion"/>
    /// the key the message was encrypted under, and <paramref name="mediaHashKey"/>
    /// the hash key the file's upload started with, as listed in the message's
    /// attachments; the SDK encrypts the file under that attachment's key.
    /// Feeding fixed-size chunks through <c>Push</c> keeps memory bounded no
    /// matter how large the file is; <c>Finish</c> emits the final frame that
    /// seals the file (decryption fails without it).
    /// </summary>
    public byte[] EncryptMedia(
        byte[] plaintext, string eventB64, byte[] conversationKey, string conversationKeyVersion, string mediaHashKey)
    {
        using var enc = _chat.FileEncryptor(new FileEncryptorParams(eventB64, mediaHashKey)
        {
            ConversationKey = conversationKey,
            ConversationKeyVersion = conversationKeyVersion,
        });
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
    /// Decrypt a downloaded media file with the incremental file API.
    ///
    /// <paramref name="eventB64"/> is the raw event of the message that carries the
    /// media and <paramref name="conversationKeys"/> its conversation's key map, as
    /// passed to <see cref="DecryptOne"/>; the SDK finds <paramref name="mediaHashKey"/>
    /// in the event and derives that file's key. <c>Finish</c> throws if the file
    /// was truncated, so plaintext from <c>Push</c> must not be treated as complete
    /// until it succeeds.
    /// </summary>
    public byte[] DecryptMedia(
        byte[] ciphertext, string eventB64, Dictionary<string, byte[]> conversationKeys, string mediaHashKey)
    {
        using var dec = _chat.FileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
        using var output = new MemoryStream();
        for (var offset = 0; offset < ciphertext.Length; offset += MediaChunk)
        {
            var len = Math.Min(MediaChunk, ciphertext.Length - offset);
            output.Write(dec.Push(ciphertext.AsSpan(offset, len).ToArray()));
        }
        output.Write(dec.Finish());
        return output.ToArray();
    }

    // -- Group metadata -------------------------------------------------------

    /// <summary>
    /// Prepare a group title change: the SDK encrypts the plaintext title under the
    /// conversation key and signs it. Send <c>EncryptedValue</c> as the group's name and
    /// <c>ActionSignatures</c> on the request.
    /// </summary>
    public PreparedGroupMetadataChange PrepareGroupTitleChange(
        string conversationId, string title, byte[] conversationKey, string conversationKeyVersion)
        => _chat.PrepareGroupTitleChange(new GroupTitleChangeParams(conversationId, title)
        {
            ConversationKey = conversationKey,
            ConversationKeyVersion = conversationKeyVersion,
        });

    /// <summary>Decrypt a group title or description the X API returns.</summary>
    public string Decrypt(string ciphertextB64, byte[] conversationKey) => _chat.Decrypt(ciphertextB64, conversationKey);

    public void Dispose() => _chat.Dispose();
}

/// <summary>
/// Fields the X API expects for an encrypted message send, plus the message's
/// <c>EventB64</c>, which stays local: the message as recipients receive it, to
/// encrypt the message's files from with <see cref="ChatCore.EncryptMedia"/>.
/// </summary>
public sealed record SendBody(
    string MessageId,
    string EncodedMessageCreateEvent,
    string EncodedMessageEventSignature,
    string XdkVersion,
    string EventB64);

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
    /// (two signatures). The participant keys and action signatures already
    /// have the request's shape.
    /// </summary>
    public static Dictionary<string, object?> PrepToRequest(PreparedConversationChange prep) =>
        new()
        {
            ["conversation_key_version"] = prep.ConversationKeyVersion,
            ["conversation_participant_keys"] = prep.ConversationParticipantKeys,
            ["action_signatures"] = prep.ActionSignatures,
        };

    /// <summary>
    /// Map a rotating member removal into the members/remove request.
    /// Both signatures go in <c>action_signatures</c>. The new key version and
    /// the participant keys for the members who stay go in <c>group_key_rotation_data</c>.
    /// </summary>
    public static Dictionary<string, object?> RemovalToRequest(
        IReadOnlyList<string> userIds, PreparedConversationChange prep) =>
        new()
        {
            ["user_ids"] = userIds,
            ["action_signatures"] = prep.ActionSignatures,
            ["group_key_rotation_data"] = new Dictionary<string, object?>
            {
                ["conversation_key_version"] = prep.ConversationKeyVersion,
                ["conversation_participant_keys"] = prep.ConversationParticipantKeys,
            },
        };
}
