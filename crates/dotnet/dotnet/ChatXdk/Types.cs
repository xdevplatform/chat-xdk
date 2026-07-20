using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChatXdk
{
    // Registration / public keys

    /// <summary>The user's identity and signing public keys.</summary>
    public sealed class PublicKeys
    {
        [JsonPropertyName("identity")]
        public string Identity { get; init; } = "";

        [JsonPropertyName("signing")]
        public string Signing { get; init; } = "";

        [JsonPropertyName("version")]
        public string Version { get; init; } = "";
    }

    /// <summary>
    /// Registration fields expected by the X API
    /// (<c>POST /2/chat/keys</c>).
    /// </summary>
    public sealed class PublicKeyRegistration
    {
        [JsonPropertyName("identity_public_key_signature")]
        public string IdentityPublicKeySignature { get; init; } = "";

        [JsonPropertyName("public_key")]
        public string PublicKey { get; init; } = "";

        [JsonPropertyName("public_key_fingerprint")]
        public string? PublicKeyFingerprint { get; init; }

        [JsonPropertyName("registration_method")]
        public string RegistrationMethod { get; init; } = "";

        [JsonPropertyName("signing_public_key")]
        public string SigningPublicKey { get; init; } = "";

        [JsonPropertyName("signing_public_key_signature")]
        public string? SigningPublicKeySignature { get; init; }
    }

    /// <summary>
    /// Returned by <see cref="Chat.GenerateKeypairs"/>.
    /// POST the <see cref="PublicKey"/> object to the X API to register keys.
    /// </summary>
    public sealed class PublicKeyRegistrationPayload
    {
        [JsonPropertyName("public_key")]
        public PublicKeyRegistration PublicKey { get; init; } = new();

        [JsonPropertyName("version")]
        public string? Version { get; init; }

        [JsonPropertyName("generate_version")]
        public bool GenerateVersion { get; init; }
    }

    // Send payload

    /// <summary>Signature metadata for a sent message.</summary>
    public sealed class SignatureInfo
    {
        [JsonPropertyName("public_key_version")]
        public string PublicKeyVersion { get; init; } = "";

        [JsonPropertyName("signature_version")]
        public string SignatureVersion { get; init; } = "";
    }

    /// <summary>
    /// Encrypted message payload ready to POST to the X API.
    /// Returned by all <c>Encrypt*</c> methods.
    /// </summary>
    public sealed class SendPayload
    {
        /// <summary>
        /// SDK-generated message id (UUID) embedded in the signed event. Send it as
        /// the message's <c>message_id</c>, keep it to dedup and to anchor replies,
        /// and reuse the same encrypted payload on retries so an id is never minted twice.
        /// </summary>
        [JsonPropertyName("message_id")]
        public string MessageId { get; init; } = "";

        /// <summary>Base64-encoded ciphertext of the encrypted message event.</summary>
        [JsonPropertyName("encrypted_content")]
        public string EncryptedContent { get; init; } = "";

        /// <summary>Base64-encoded raw r||s signature over the encrypted content.</summary>
        [JsonPropertyName("signature")]
        public string Signature { get; init; } = "";

        /// <summary>
        /// Base64-encoded Thrift <c>MessageEventSignature</c>.
        /// Pass as <c>encoded_message_event_signature</c> in the X API request.
        /// </summary>
        [JsonPropertyName("encoded_event_signature")]
        public string EncodedEventSignature { get; init; } = "";

        /// <summary>Signing key and signature version metadata for this payload.</summary>
        [JsonPropertyName("signature_info")]
        public SignatureInfo SignatureInfo { get; init; } = new();

        /// <summary>Version of the conversation key used to encrypt the content.</summary>
        [JsonPropertyName("conversation_key_version")]
        public string ConversationKeyVersion { get; init; } = "";

        /// <summary>Whether the X API should send a push notification.</summary>
        [JsonPropertyName("should_notify")]
        public bool ShouldNotify { get; init; }
    }

    // Action signatures (group operations)

    /// <summary>
    /// Signed action payload authenticating a conversation key change or member add.
    /// </summary>
    public sealed class ActionSignature
    {
        [JsonPropertyName("message_id")]
        public string MessageId { get; init; } = "";

        [JsonPropertyName("encoded_message_event_detail")]
        public string EncodedMessageEventDetail { get; init; } = "";

        [JsonPropertyName("signature")]
        public string Signature { get; init; } = "";

        [JsonPropertyName("signature_version")]
        public string SignatureVersion { get; init; } = "";

        [JsonPropertyName("public_key_version")]
        public string PublicKeyVersion { get; init; } = "";

        /// <summary>
        /// The comma-separated payload string that was signed. Empty for
        /// conversation-key changes, whose payload embeds the plaintext
        /// conversation key and is withheld.
        /// </summary>
        [JsonPropertyName("signature_payload")]
        public string SignaturePayload { get; init; } = "";
    }

    // Key / recipient types

    /// <summary>A signing key entry for <see cref="Chat.DecryptEvent"/> and <see cref="Chat.DecryptEvents"/>.</summary>
    public sealed class SigningKeyEntry
    {
        /// <summary>ID of the user this signing key belongs to.</summary>
        [JsonPropertyName("user_id")]
        public required string UserId { get; init; }

        /// <summary>Version of the user's signing public key as returned by the X API.</summary>
        [JsonPropertyName("public_key_version")]
        public required string PublicKeyVersion { get; init; }

        /// <summary>Base64-encoded signing public key (SEC1 or SPKI).</summary>
        [JsonPropertyName("public_key")]
        public required string PublicKey { get; init; }

        /// <summary>Base64-encoded identity public key (SEC1 or SPKI) for this user.</summary>
        [JsonPropertyName("identity_public_key")]
        public required string IdentityPublicKey { get; init; }

        /// <summary>
        /// Base64-encoded raw r||s signature proving the signing key is bound to the
        /// identity key. Returned by the X API on the public keys response.
        /// </summary>
        [JsonPropertyName("identity_public_key_signature")]
        public required string IdentityPublicKeySignature { get; init; }
    }

    /// <summary>Public key entry for the prepare methods (<see cref="Chat.PrepareConversationKeyChange"/>).</summary>
    public sealed class PublicKeyInput
    {
        [JsonPropertyName("user_id")]
        public required string UserId { get; init; }

        [JsonPropertyName("public_key")]
        public required string PublicKey { get; init; }

        [JsonPropertyName("key_version")]
        public required string KeyVersion { get; init; }
    }

    /// <summary>
    /// Returned by <see cref="Chat.PrepareConversationKeyChange"/>,
    /// <see cref="Chat.PrepareGroupCreate"/>, and
    /// <see cref="Chat.PrepareGroupMembersChange"/>. Carries everything needed to POST the change.
    /// </summary>
    public sealed class PreparedConversationChange
    {
        /// <summary>Conversation id the change applies to (derived for a one-to-one, or the id you passed).</summary>
        [JsonPropertyName("conversation_id")]
        public string ConversationId { get; init; } = "";

        /// <summary>
        /// Raw 32-byte conversation key when one was generated, otherwise <see langword="null"/>.
        /// (JSON carries it base64-encoded; <see cref="byte"/> arrays map to that natively.)
        /// </summary>
        [JsonPropertyName("conversation_key")]
        public byte[]? ConversationKey { get; init; }

        /// <summary>Version assigned to the conversation key.</summary>
        [JsonPropertyName("conversation_key_version")]
        public string ConversationKeyVersion { get; init; } = "";

        /// <summary>The conversation key encrypted once per participant.</summary>
        [JsonPropertyName("participant_keys")]
        public List<EncryptedKeyForRecipient> ParticipantKeys { get; init; } = new();

        /// <summary>Action signatures authenticating the change, ready to POST.</summary>
        [JsonPropertyName("action_signatures")]
        public List<ActionSignature> ActionSignatures { get; init; } = new();
    }

    /// <summary>
    /// Conversation keys from <see cref="Chat.ExtractConversationKeys"/> or nested inside
    /// <see cref="DecryptEventsResult"/>.
    /// </summary>
    public sealed class ConversationKeyBundle
    {
        /// <summary>Version string → raw 32-byte conversation key.</summary>
        public Dictionary<string, byte[]> Keys { get; init; } = new();

        /// <summary>Highest key version (for encrypting new messages), or <see langword="null"/>.</summary>
        public string? LatestVersion { get; init; }
    }

    /// <summary>Width and height from <see cref="ChatXdkUtilities.DetectImageDimensions"/>.</summary>
    public sealed class ImageDimensions
    {
        [JsonPropertyName("width")]
        public uint Width { get; init; }

        [JsonPropertyName("height")]
        public uint Height { get; init; }
    }

    /// <summary>One decrypted event from <see cref="Chat.DecryptEvents"/>.</summary>
    public sealed class DecryptedMessage
    {
        /// <summary>The decrypted event JSON (<c>type</c>, …).</summary>
        public JsonElement Event { get; init; }

        /// <summary>Original webhook base64 payload when present.</summary>
        public string? OriginalB64 { get; init; }
    }

    /// <summary>Result of <see cref="Chat.DecryptEvents"/>.</summary>
    public sealed class DecryptEventsResult
    {
        /// <summary>The successfully decrypted events, in input order.</summary>
        public IReadOnlyList<DecryptedMessage> Messages { get; init; } = Array.Empty<DecryptedMessage>();

        /// <summary>Extracted keys and <see cref="ConversationKeyBundle.LatestVersion"/>.</summary>
        public ConversationKeyBundle ConversationKeys { get; init; } = new();

        /// <summary>String indices into the input batch for events that failed to decrypt.</summary>
        public Dictionary<string, string> Errors { get; init; } = new();
    }

    /// <summary>An encrypted conversation key for one recipient.</summary>
    public sealed class EncryptedKeyForRecipient
    {
        [JsonPropertyName("user_id")]
        public string UserId { get; init; } = "";

        [JsonPropertyName("encrypted_key")]
        public string EncryptedKey { get; init; } = "";

        [JsonPropertyName("public_key_version")]
        public string PublicKeyVersion { get; init; } = "";
    }

    // Encryption parameter types

    /// <summary>
    /// Rich-text entity (URL, mention, hashtag, etc.) descriptor.
    /// <see cref="Start"/> and <see cref="End"/> are byte offsets into the message text.
    /// </summary>
    public sealed class EntityDescriptor
    {
        /// <summary>Byte offset into the message text where the entity begins.</summary>
        public int Start { get; init; }
        /// <summary>Byte offset into the message text where the entity ends (exclusive).</summary>
        public int End { get; init; }
        /// <summary>One of: "url", "mention", "hashtag", "cashtag", "email", "address", "phone_number".</summary>
        public string EntityType { get; init; } = "";
    }

    /// <summary>
    /// Attachment descriptor. Use the factory methods to create well-formed instances.
    /// </summary>
    public sealed class AttachmentDescriptor
    {
        /// <summary>Attachment kind: one of "media", "url", or "post".</summary>
        [JsonPropertyName("attachment_type")]
        public string AttachmentType { get; init; } = "";

        // Media fields — always present for "media" attachments, null for other types.
        // Do NOT use WhenWritingDefault on numeric fields: a value of 0 is valid and
        // must be transmitted so the Rust side doesn't silently default-to-zero.
        /// <summary>Hash key identifying the uploaded media blob.</summary>
        [JsonPropertyName("media_hash_key")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? MediaHashKey { get; init; }

        /// <summary>Media width in pixels.</summary>
        [JsonPropertyName("width")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Width { get; init; }

        /// <summary>Media height in pixels.</summary>
        [JsonPropertyName("height")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Height { get; init; }

        /// <summary>Size of the media file in bytes.</summary>
        [JsonPropertyName("filesize_bytes")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? FilesizeBytes { get; init; }

        /// <summary>Original filename of the media.</summary>
        [JsonPropertyName("filename")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Filename { get; init; }

        /// <summary>1=image, 2=gif, 3=video, 4=audio, 5=file, 6=svg.</summary>
        [JsonPropertyName("media_type")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? MediaType { get; init; }

        /// <summary>Duration of audio/video media in milliseconds.</summary>
        [JsonPropertyName("duration_millis")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? DurationMillis { get; init; }

        // URL fields
        /// <summary>Target URL for a "url" card attachment.</summary>
        [JsonPropertyName("url")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; init; }

        /// <summary>Display title shown for the URL card.</summary>
        [JsonPropertyName("display_title")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DisplayTitle { get; init; }

        /// <summary>Encrypted banner (preview) image for the URL card.</summary>
        [JsonPropertyName("banner_image")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public UrlAttachmentImageDescriptor? BannerImage { get; init; }

        /// <summary>Encrypted favicon image for the URL card.</summary>
        [JsonPropertyName("favicon_image")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public UrlAttachmentImageDescriptor? FaviconImage { get; init; }

        // Post fields
        /// <summary>Numeric rest ID of the referenced post/tweet.</summary>
        [JsonPropertyName("rest_id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? RestId { get; init; }

        /// <summary>Canonical URL of the referenced post/tweet.</summary>
        [JsonPropertyName("post_url")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PostUrl { get; init; }

        // Factory methods

        /// <summary>Create a media attachment.</summary>
        public static AttachmentDescriptor Media(
            string mediaHashKey,
            long width,
            long height,
            long filesizeBytes,
            string filename,
            int? mediaType = null,
            long? durationMillis = null) => new()
        {
            AttachmentType = "media",
            MediaHashKey = mediaHashKey,
            // Store as nullable so the JSON serializer always emits the field
            // (even when the value is 0) rather than omitting it.
            Width = width,
            Height = height,
            FilesizeBytes = filesizeBytes,
            Filename = filename,
            MediaType = mediaType,
            DurationMillis = durationMillis,
        };

        /// <summary>
        /// Create a URL card attachment. Supplying <paramref name="displayTitle"/> and
        /// <paramref name="bannerImage"/> makes receiving clients render a full clickable
        /// preview card: encrypt the image with <see cref="Chat.EncryptStream"/>, upload it
        /// to the conversation's media store, and reference the returned media hash key.
        /// </summary>
        public static AttachmentDescriptor UrlCard(
            string url,
            string? displayTitle = null,
            UrlAttachmentImageDescriptor? bannerImage = null,
            UrlAttachmentImageDescriptor? faviconImage = null) => new()
        {
            AttachmentType = "url",
            Url = url,
            DisplayTitle = displayTitle,
            BannerImage = bannerImage,
            FaviconImage = faviconImage,
        };

        /// <summary>Create a post/tweet attachment.</summary>
        public static AttachmentDescriptor Post(string? restId = null, string? postUrl = null) => new()
        {
            AttachmentType = "post",
            RestId = restId,
            PostUrl = postUrl,
        };
    }

    /// <summary>
    /// An encrypted preview image (banner or favicon) referenced by a URL card
    /// attachment via its media hash key.
    /// <para>
    /// <see cref="FilesizeBytes"/> and <see cref="Filename"/> are required
    /// alongside <see cref="MediaHashKey"/>: receiving clients' shared ingest
    /// silently discards the whole preview image when either is missing on
    /// the wire.
    /// </para>
    /// </summary>
    public sealed class UrlAttachmentImageDescriptor
    {
        /// <summary>Media hash key returned by the media upload for the encrypted image.</summary>
        [JsonPropertyName("media_hash_key")]
        public string MediaHashKey { get; init; } = "";

        /// <summary>Size of the encrypted image in bytes. Required.</summary>
        [JsonPropertyName("filesize_bytes")]
        public long FilesizeBytes { get; init; }

        /// <summary>Original filename of the image. Required.</summary>
        [JsonPropertyName("filename")]
        public string Filename { get; init; } = "";

        /// <summary>Image width in pixels.</summary>
        [JsonPropertyName("width")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Width { get; init; }

        /// <summary>Image height in pixels.</summary>
        [JsonPropertyName("height")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Height { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.EncryptMessage"/>.
    /// The constructor takes the required fields; identity and key overrides
    /// (<see cref="SenderId"/>/<see cref="SigningKeyVersion"/> and
    /// <see cref="ConversationKey"/>/<see cref="ConversationKeyVersion"/>) are
    /// optional and resolve from the session identity
    /// (<see cref="Chat.SetIdentity"/>) and the opt-in key cache
    /// (<see cref="Chat.SetCacheKeys"/>) when null.
    /// </summary>
    public sealed class EncryptMessageParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="conversationId">ID of the conversation the message belongs to.</param>
        /// <param name="text">Plaintext message body to encrypt.</param>
        public EncryptMessageParams(string conversationId, string text)
        {
            ConversationId = conversationId;
            Text = text;
        }

        /// <summary>ID of the conversation the message belongs to.</summary>
        public string ConversationId { get; }
        /// <summary>Plaintext message body to encrypt.</summary>
        public string Text { get; }
        /// <summary>User ID of the sender; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>
        /// Raw 32-byte conversation key; resolves from the key cache when null
        /// (set together with <see cref="ConversationKeyVersion"/>).
        /// </summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>Version of the conversation key; resolves from the key cache when null.</summary>
        public string? ConversationKeyVersion { get; init; }
        /// <summary>Optional rich-text entities (URLs, mentions, hashtags) in the text.</summary>
        public IReadOnlyList<EntityDescriptor>? Entities { get; init; }
        /// <summary>Optional media, URL, or post attachments.</summary>
        public IReadOnlyList<AttachmentDescriptor>? Attachments { get; init; }
        /// <summary>Whether to send a push notification. Defaults to true.</summary>
        public bool? ShouldNotify { get; init; }
        /// <summary>Time-to-live for disappearing messages in milliseconds.</summary>
        public long? TtlMsec { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.EncryptReply"/>.
    /// The preferred form passes the raw signed event being replied to
    /// (<see cref="ReplyToEvent"/>) and lets the SDK derive the reply preview
    /// from it; the <c>ReplyTo*</c> field overrides remain for callers that no
    /// longer hold the raw event. Identity and key overrides resolve like
    /// <see cref="EncryptMessageParams"/>.
    /// </summary>
    public sealed class EncryptReplyParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="conversationId">ID of the conversation the reply belongs to.</param>
        /// <param name="text">Plaintext reply body to encrypt.</param>
        /// <param name="replyToEvent">
        /// Base64 raw signed event being replied to. Pass null or "" only when
        /// supplying the <c>ReplyTo*</c> fields directly instead.
        /// </param>
        public EncryptReplyParams(string conversationId, string text, string? replyToEvent)
        {
            ConversationId = conversationId;
            Text = text;
            ReplyToEvent = string.IsNullOrEmpty(replyToEvent) ? null : replyToEvent;
        }

        /// <summary>ID of the conversation the reply belongs to.</summary>
        public string ConversationId { get; }
        /// <summary>Plaintext reply body to encrypt.</summary>
        public string Text { get; }
        /// <summary>
        /// Base64 raw signed event being replied to. The reply preview
        /// (sequence id, sender, text, entities, attachments) is derived from
        /// it and the raw event is embedded so recipients can validate the preview.
        /// </summary>
        public string? ReplyToEvent { get; }
        /// <summary>Base64 raw signed edit event, when the original was edited.</summary>
        public string? ReplyToEditEvent { get; init; }
        /// <summary>
        /// Base64 raw key-change events needed to decrypt the original when it
        /// was encrypted under a different key version than this reply.
        /// </summary>
        public IReadOnlyList<string>? ReplyToCkces { get; init; }
        /// <summary>User ID of the sender; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>
        /// Raw 32-byte conversation key; resolves from the key cache when null
        /// (set together with <see cref="ConversationKeyVersion"/>).
        /// </summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>Version of the conversation key; resolves from the key cache when null.</summary>
        public string? ConversationKeyVersion { get; init; }
        /// <summary>Sequence ID of the message being replied to; derived from <see cref="ReplyToEvent"/> when null.</summary>
        public string? ReplyToSequenceId { get; init; }
        /// <summary>Sender ID of the message being replied to (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public long? ReplyToSenderId { get; init; }
        /// <summary>Text of the message being replied to (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public string? ReplyToText { get; init; }
        /// <summary>Optional rich-text entities in the reply text.</summary>
        public IReadOnlyList<EntityDescriptor>? Entities { get; init; }
        /// <summary>Optional attachments on the reply.</summary>
        public IReadOnlyList<AttachmentDescriptor>? Attachments { get; init; }
        /// <summary>Rich-text entities of the quoted message (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public IReadOnlyList<EntityDescriptor>? ReplyToEntities { get; init; }
        /// <summary>Attachments of the quoted message (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public IReadOnlyList<AttachmentDescriptor>? ReplyToAttachments { get; init; }
        /// <summary>Whether to send a push notification. Defaults to true.</summary>
        public bool? ShouldNotify { get; init; }
        /// <summary>Time-to-live for disappearing messages in milliseconds.</summary>
        public long? TtlMsec { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.EncryptAddReaction"/> and <see cref="Chat.EncryptRemoveReaction"/>.
    /// The preferred form passes the raw event being reacted to
    /// (<see cref="TargetEvent"/>) and lets the SDK derive the conversation id
    /// and target sequence id from it; the explicit field overrides remain for
    /// callers that no longer hold the raw event. The same instance can be
    /// passed to both methods to add and later remove the same reaction.
    /// </summary>
    public sealed class EncryptReactionParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="targetEvent">
        /// Base64 raw event being reacted to. Pass null or "" only when supplying
        /// <see cref="ConversationId"/> and <see cref="TargetMessageSequenceId"/> directly instead.
        /// </param>
        /// <param name="emoji">The reaction emoji.</param>
        public EncryptReactionParams(string? targetEvent, string emoji)
        {
            TargetEvent = string.IsNullOrEmpty(targetEvent) ? null : targetEvent;
            Emoji = emoji;
        }

        /// <summary>Base64 raw event being reacted to; the conversation id and target sequence id are derived from it.</summary>
        public string? TargetEvent { get; }
        /// <summary>The reaction emoji.</summary>
        public string Emoji { get; }
        /// <summary>ID of the conversation the reaction belongs to; derived from <see cref="TargetEvent"/> when null.</summary>
        public string? ConversationId { get; init; }
        /// <summary>Sequence ID of the message being reacted to; derived from <see cref="TargetEvent"/> when null.</summary>
        public string? TargetMessageSequenceId { get; init; }
        /// <summary>User ID of the sender; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>
        /// Raw 32-byte conversation key; resolves from the key cache when null
        /// (set together with <see cref="ConversationKeyVersion"/>).
        /// </summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>Version of the conversation key; resolves from the key cache when null.</summary>
        public string? ConversationKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareConversationKeyChange"/>.</summary>
    public sealed class ConversationKeyChangeParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="publicKeys">Public keys for every participant the new key is encrypted for.</param>
        public ConversationKeyChangeParams(IReadOnlyList<PublicKeyInput> publicKeys)
        {
            PublicKeys = publicKeys;
        }

        /// <summary>Public keys for every participant the new key is encrypted for.</summary>
        public IReadOnlyList<PublicKeyInput> PublicKeys { get; }
        /// <summary>User ID of the sender signing the change; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>Conversation the change applies to; null derives the one-to-one id.</summary>
        public string? ConversationId { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupMembersChange"/>.</summary>
    public sealed class GroupMembersChangeParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="publicKeys">Public keys for the updated roster.</param>
        /// <param name="conversationId">ID of the group conversation being modified.</param>
        /// <param name="newMemberIds">IDs of the members being added.</param>
        /// <param name="currentMemberIds">Current member IDs before the add.</param>
        /// <param name="currentAdminIds">Current admin IDs.</param>
        /// <param name="currentPendingMemberIds">Current pending (invited) member IDs.</param>
        public GroupMembersChangeParams(
            IReadOnlyList<PublicKeyInput> publicKeys,
            string conversationId,
            IReadOnlyList<string> newMemberIds,
            IReadOnlyList<string> currentMemberIds,
            IReadOnlyList<string> currentAdminIds,
            IReadOnlyList<string> currentPendingMemberIds)
        {
            PublicKeys = publicKeys;
            ConversationId = conversationId;
            NewMemberIds = newMemberIds;
            CurrentMemberIds = currentMemberIds;
            CurrentAdminIds = currentAdminIds;
            CurrentPendingMemberIds = currentPendingMemberIds;
        }

        /// <summary>Public keys for the updated roster.</summary>
        public IReadOnlyList<PublicKeyInput> PublicKeys { get; }
        /// <summary>ID of the group conversation being modified.</summary>
        public string ConversationId { get; }
        /// <summary>IDs of the members being added.</summary>
        public IReadOnlyList<string> NewMemberIds { get; }
        /// <summary>Current member IDs before the add.</summary>
        public IReadOnlyList<string> CurrentMemberIds { get; }
        /// <summary>Current admin IDs.</summary>
        public IReadOnlyList<string> CurrentAdminIds { get; }
        /// <summary>Current pending (invited) member IDs.</summary>
        public IReadOnlyList<string> CurrentPendingMemberIds { get; }
        /// <summary>User ID of the sender signing the change; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>Current group title, if set.</summary>
        public string? CurrentTitle { get; init; }
        /// <summary>Current group avatar URL, if set.</summary>
        public string? CurrentAvatarUrl { get; init; }
        /// <summary>Current disappearing-message TTL in milliseconds, if set.</summary>
        public long? CurrentTtlMsec { get; init; }
        /// <summary>Current screen-capture-blocking state, if set.</summary>
        public bool? CurrentScreenCaptureBlockingEnabled { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupCreate"/>.</summary>
    public sealed class GroupCreateParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="publicKeys">Public keys for the new roster.</param>
        /// <param name="conversationId">ID of the group conversation being created.</param>
        /// <param name="memberIds">IDs of the initial members.</param>
        /// <param name="adminIds">IDs of the initial admins.</param>
        public GroupCreateParams(
            IReadOnlyList<PublicKeyInput> publicKeys,
            string conversationId,
            IReadOnlyList<string> memberIds,
            IReadOnlyList<string> adminIds)
        {
            PublicKeys = publicKeys;
            ConversationId = conversationId;
            MemberIds = memberIds;
            AdminIds = adminIds;
        }

        /// <summary>Public keys for the new roster.</summary>
        public IReadOnlyList<PublicKeyInput> PublicKeys { get; }
        /// <summary>ID of the group conversation being created.</summary>
        public string ConversationId { get; }
        /// <summary>IDs of the initial members.</summary>
        public IReadOnlyList<string> MemberIds { get; }
        /// <summary>IDs of the initial admins.</summary>
        public IReadOnlyList<string> AdminIds { get; }
        /// <summary>User ID of the sender signing the create; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
        /// <summary>Group title, if set.</summary>
        public string? Title { get; init; }
        /// <summary>Group avatar URL, if set.</summary>
        public string? AvatarUrl { get; init; }
        /// <summary>Disappearing-message TTL in milliseconds, if set.</summary>
        public long? TtlMsec { get; init; }
    }
}
