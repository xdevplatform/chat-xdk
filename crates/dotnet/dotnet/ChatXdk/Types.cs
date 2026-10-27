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
        /// Message id (UUID) the SDK generated and embedded in the signed event. Send it
        /// as the message's <c>message_id</c>, keep it to dedup and to anchor replies, and
        /// reuse the same encrypted payload on retries so an id is never minted twice.
        /// </summary>
        [JsonPropertyName("message_id")]
        public string MessageId { get; init; } = "";

        /// <summary>
        /// The outgoing message as a base64 event: what recipients receive, without the
        /// fields the server assigns. Pass it to <see cref="Chat.EncryptFile"/> or
        /// <see cref="Chat.FileEncryptor"/> to encrypt the message's files, or to
        /// <see cref="Chat.DecryptEvent"/> to read the message back.
        /// </summary>
        [JsonPropertyName("event_b64")]
        public string EventB64 { get; init; } = "";

        /// <summary>
        /// Base64-encoded Thrift <c>MessageCreateEvent</c> carrying the encrypted contents:
        /// the send request's <c>encoded_message_create_event</c>.
        /// </summary>
        [JsonPropertyName("encoded_message_create_event")]
        public string EncodedMessageCreateEvent { get; init; } = "";

        /// <summary>Base64-encoded raw r||s signature over the encrypted content.</summary>
        [JsonPropertyName("signature")]
        public string Signature { get; init; } = "";

        /// <summary>
        /// Base64-encoded Thrift <c>MessageEventSignature</c>: the send request's
        /// <c>encoded_message_event_signature</c>.
        /// </summary>
        [JsonPropertyName("encoded_message_event_signature")]
        public string EncodedMessageEventSignature { get; init; } = "";

        /// <summary>Signing key and signature version metadata for this payload.</summary>
        [JsonPropertyName("signature_info")]
        public SignatureInfo SignatureInfo { get; init; } = new();

        /// <summary>Version of the conversation key used to encrypt the content.</summary>
        [JsonPropertyName("conversation_key_version")]
        public string ConversationKeyVersion { get; init; } = "";

        /// <summary>Whether the X API should send a push notification.</summary>
        [JsonPropertyName("should_notify")]
        public bool ShouldNotify { get; init; }

        /// <summary>
        /// Version of the Chat XDK that built this payload.
        /// </summary>
        [JsonPropertyName("xdk_version")]
        public string XdkVersion { get; init; } = "";
    }

    // Action signatures (group operations)

    /// <summary>
    /// Signed action authenticating a conversation key change, group change,
    /// message delete, or read receipt, shaped as an entry of a request's
    /// <c>action_signatures</c>: the signature is nested under
    /// <c>message_event_signature</c>.
    /// </summary>
    public sealed class ActionSignature
    {
        [JsonPropertyName("message_id")]
        public string MessageId { get; init; } = "";

        [JsonPropertyName("encoded_message_event_detail")]
        public string EncodedMessageEventDetail { get; init; } = "";

        /// <summary>The signature over the action, with its versions and the signer's signing public key.</summary>
        [JsonPropertyName("message_event_signature")]
        public MessageEventSignature MessageEventSignature { get; init; } = new();
    }

    /// <summary>The signature of an <see cref="ActionSignature"/>.</summary>
    public sealed class MessageEventSignature
    {
        /// <summary>Base64 ECDSA signature of the payload.</summary>
        [JsonPropertyName("signature")]
        public string Signature { get; init; } = "";

        /// <summary>Signature protocol version.</summary>
        [JsonPropertyName("signature_version")]
        public string SignatureVersion { get; init; } = "";

        /// <summary>Version of the signing public key.</summary>
        [JsonPropertyName("public_key_version")]
        public string PublicKeyVersion { get; init; } = "";

        /// <summary>The signer's base64 signing public key, as <see cref="Chat.GetPublicKeys"/> returns it.</summary>
        [JsonPropertyName("signing_public_key")]
        public string SigningPublicKey { get; init; } = "";
    }

    /// <summary>
    /// A signed message delete or read receipt: the <c>action_signatures</c> a request
    /// carries for it, one entry.
    /// </summary>
    public sealed class PreparedAction
    {
        /// <summary>The signed action, as the request's <c>action_signatures</c> entries.</summary>
        [JsonPropertyName("action_signatures")]
        public List<ActionSignature> ActionSignatures { get; init; } = new();
    }

    /// <summary>
    /// A signed group title or description change: the value encrypted under the
    /// conversation key and the <c>action_signatures</c> a request carries. Returned by
    /// <see cref="Chat.PrepareGroupTitleChange"/> and
    /// <see cref="Chat.PrepareGroupDescriptionChange"/>.
    /// </summary>
    public sealed class PreparedGroupMetadataChange
    {
        /// <summary>The value encrypted under the conversation key, base64: what the request sends.</summary>
        [JsonPropertyName("encrypted_value")]
        public string EncryptedValue { get; init; } = "";

        /// <summary>Version of the conversation key the value is encrypted under.</summary>
        [JsonPropertyName("conversation_key_version")]
        public string ConversationKeyVersion { get; init; } = "";

        /// <summary>The signed change, as the request's <c>action_signatures</c> entries.</summary>
        [JsonPropertyName("action_signatures")]
        public List<ActionSignature> ActionSignatures { get; init; } = new();
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

        /// <summary>The base64 identity public key (SEC1 or SPKI): the X API's <c>public_key</c>.</summary>
        [JsonPropertyName("identity_public_key")]
        public required string IdentityPublicKey { get; init; }

        /// <summary>The key's version, as the X API returns it.</summary>
        [JsonPropertyName("public_key_version")]
        public required string PublicKeyVersion { get; init; }
    }

    /// <summary>
    /// Returned by <see cref="Chat.PrepareConversationKeyChange"/>,
    /// <see cref="Chat.PrepareGroupCreate"/>, <see cref="Chat.PrepareGroupMembersChange"/>, and
    /// <see cref="Chat.PrepareGroupMembersRemove"/>. Carries everything needed to POST the change.
    /// </summary>
    public sealed class PreparedConversationChange
    {
        /// <summary>Conversation id the change applies to (derived for a one-to-one, or the id you passed).</summary>
        [JsonPropertyName("conversation_id")]
        public string ConversationId { get; init; } = "";

        /// <summary>
        /// Raw 32-byte conversation key the call generated.
        /// (JSON carries it base64-encoded; <see cref="byte"/> arrays map to that natively.)
        /// </summary>
        [JsonPropertyName("conversation_key")]
        public byte[] ConversationKey { get; init; } = Array.Empty<byte>();

        /// <summary>Version assigned to the conversation key.</summary>
        [JsonPropertyName("conversation_key_version")]
        public string ConversationKeyVersion { get; init; } = "";

        /// <summary>The conversation key encrypted once per participant.</summary>
        [JsonPropertyName("conversation_participant_keys")]
        public List<ConversationParticipantKey> ConversationParticipantKeys { get; init; } = new();

        /// <summary>Action signatures authenticating the change, ready to POST.</summary>
        [JsonPropertyName("action_signatures")]
        public List<ActionSignature> ActionSignatures { get; init; } = new();

        /// <summary>
        /// Set by <see cref="Chat.PrepareGroupCreate"/> and
        /// <see cref="Chat.PrepareGroupMembersChange"/> when the params carry a title: the
        /// title encrypted under the new conversation key, base64, the <c>group_name</c> a
        /// create request sends and the <c>encrypted_title</c> an add-members request sends;
        /// otherwise null.
        /// </summary>
        [JsonPropertyName("encrypted_title")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? EncryptedTitle { get; init; }

        /// <summary>
        /// Set by <see cref="Chat.PrepareGroupMembersChange"/> when the params carry a
        /// description: the description encrypted under the new conversation key, base64, as
        /// the signed member add carries it; otherwise null.
        /// </summary>
        [JsonPropertyName("encrypted_description")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? EncryptedDescription { get; init; }
    }

    /// <summary>
    /// Conversation keys from <see cref="Chat.ExtractConversationKeys"/> or nested inside
    /// <see cref="DecryptEventsResult"/>.
    /// </summary>
    public sealed class ConversationKeyBundle
    {
        /// <summary>Version string → raw 32-byte conversation key.</summary>
        public Dictionary<string, byte[]> Keys { get; init; } = new();

        /// <summary>
        /// The version to encrypt with: from <see cref="Chat.DecryptEvents"/>, the newest version
        /// whose key change verified (<see langword="null"/> until one verifies); from
        /// <see cref="Chat.ExtractConversationKeys"/>, the batch's highest version.
        /// </summary>
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

    /// <summary>One event <see cref="Chat.DecryptEvents"/> decrypted, of any event type.</summary>
    public sealed class DecryptedEvent
    {
        /// <summary>The decrypted event JSON (<c>type</c>, …).</summary>
        public JsonElement Event { get; init; }

        /// <summary>Original webhook base64 payload when present.</summary>
        public string? OriginalB64 { get; init; }
    }

    /// <summary>Result of <see cref="Chat.DecryptEvents"/>.</summary>
    public sealed class DecryptEventsResult
    {
        /// <summary>The events that decrypted, in batch order, of every event type.</summary>
        public IReadOnlyList<DecryptedEvent> Events { get; init; } = Array.Empty<DecryptedEvent>();

        /// <summary>Extracted keys and <see cref="ConversationKeyBundle.LatestVersion"/>.</summary>
        public ConversationKeyBundle ConversationKeys { get; init; } = new();

        /// <summary>String indices into the input batch for events that failed to decrypt.</summary>
        public Dictionary<string, string> Errors { get; init; } = new();
    }

    /// <summary>
    /// A group title or description as a received group change carries it: the <c>title</c>
    /// of a <c>Created</c> change, the <c>new_title</c> of a <c>TitleChanged</c> one and the
    /// <c>new_description</c> of a <c>DescriptionChanged</c> one. A value converts from the
    /// decrypted event JSON with <c>element.Deserialize&lt;GroupText&gt;()</c>. <see cref="Kind"/>
    /// <c>"Text"</c> carries <see cref="Text"/>: the value decrypted, or the plaintext an event
    /// that names no key version carries. <see cref="Kind"/> <c>"Unavailable"</c> carries
    /// <see cref="Raw"/>: a value the SDK could not decrypt, as the event carries it. 0.5.x
    /// apps sent titles as plaintext while naming a key version, so show <see cref="Raw"/>
    /// when a title isn't decryptable.
    /// </summary>
    public sealed class GroupText
    {
        /// <summary><c>"Text"</c> or <c>"Unavailable"</c>.</summary>
        [JsonPropertyName("kind")]
        public string Kind { get; init; } = "";

        /// <summary>The decrypted or plaintext value, for <c>"Text"</c>.</summary>
        [JsonPropertyName("text")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Text { get; init; }

        /// <summary>The value as the event carries it, for <c>"Unavailable"</c>.</summary>
        [JsonPropertyName("raw")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Raw { get; init; }
    }

    /// <summary>
    /// One participant's copy of a conversation key, encrypted to their identity key: an entry
    /// of the X API's <c>conversation_participant_keys</c>. A prepared change carries these for
    /// its request, and a received key change carries them in its decrypted JSON.
    /// </summary>
    public sealed class ConversationParticipantKey
    {
        [JsonPropertyName("user_id")]
        public string UserId { get; init; } = "";

        [JsonPropertyName("encrypted_conversation_key")]
        public string EncryptedConversationKey { get; init; } = "";

        [JsonPropertyName("public_key_version")]
        public string PublicKeyVersion { get; init; } = "";
    }

    // Encryption parameter types

    /// <summary>
    /// Rich-text entity (URL, mention, hashtag, etc.) descriptor.
    /// <see cref="Start"/> and <see cref="End"/> count bytes of the text's UTF-8 encoding, not
    /// <see cref="string"/> indices (<c>Encoding.UTF8.GetByteCount(text[..i])</c> converts index
    /// <c>i</c>), so <c>0 &lt;= Start &lt;= End &lt;=</c> the text's UTF-8 length; other offsets fail
    /// the call with a <see cref="ChatXdkException"/> of kind
    /// <see cref="ChatXdkErrorKind.InvalidInput"/>.
    /// </summary>
    public sealed class EntityDescriptor
    {
        /// <summary>
        /// Describe an entity of <paramref name="entityType"/> spanning bytes
        /// <paramref name="start"/> to <paramref name="end"/> of the message text.
        /// </summary>
        public EntityDescriptor(int start, int end, string entityType)
        {
            ArgumentNullException.ThrowIfNull(entityType);
            Start = start;
            End = end;
            EntityType = entityType;
        }

        /// <summary>UTF-8 byte offset into the text where the entity begins.</summary>
        public int Start { get; }
        /// <summary>UTF-8 byte offset into the text where the entity ends (exclusive).</summary>
        public int End { get; }
        /// <summary>
        /// One of: "url", "mention", "hashtag", "cashtag", "email", "address", "phone_number".
        /// Any other value, an empty one included, fails the call with a
        /// <see cref="ChatXdkException"/> of kind <see cref="ChatXdkErrorKind.InvalidInput"/>.
        /// </summary>
        public string EntityType { get; }
    }

    /// <summary>
    /// Attachment descriptor, created by <see cref="Media"/>, <see cref="UrlCard"/> or
    /// <see cref="Post"/>.
    /// </summary>
    public sealed class AttachmentDescriptor
    {
        private AttachmentDescriptor(string attachmentType) => AttachmentType = attachmentType;

        /// <summary>Attachment kind: one of "media", "url", or "post".</summary>
        [JsonPropertyName("attachment_type")]
        public string AttachmentType { get; }

        // Media fields: set on "media" attachments, null on the others. Nullable so that a
        // media attachment's width, height and size are sent even when 0.
        /// <summary>Hash key identifying the uploaded media blob.</summary>
        [JsonPropertyName("media_hash_key")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? MediaHashKey { get; private init; }

        /// <summary>Media width in pixels.</summary>
        [JsonPropertyName("width")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Width { get; private init; }

        /// <summary>Media height in pixels.</summary>
        [JsonPropertyName("height")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Height { get; private init; }

        /// <summary>Size of the encrypted media file in bytes: <c>EncryptedFileSize</c> of its size.</summary>
        [JsonPropertyName("filesize_bytes")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? FilesizeBytes { get; private init; }

        /// <summary>Original filename of the media.</summary>
        [JsonPropertyName("filename")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Filename { get; private init; }

        /// <summary>1=image, 2=gif, 3=video, 4=audio, 5=file, 6=svg.</summary>
        [JsonPropertyName("media_type")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? MediaType { get; private init; }

        /// <summary>Duration of audio/video media in milliseconds.</summary>
        [JsonPropertyName("duration_millis")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? DurationMillis { get; private init; }

        // URL fields
        /// <summary>Target URL for a "url" card attachment.</summary>
        [JsonPropertyName("url")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; private init; }

        /// <summary>Display title shown for the URL card.</summary>
        [JsonPropertyName("display_title")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DisplayTitle { get; private init; }

        /// <summary>Encrypted banner (preview) image for the URL card.</summary>
        [JsonPropertyName("banner_image")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public UrlAttachmentImageDescriptor? BannerImage { get; private init; }

        /// <summary>Encrypted favicon image for the URL card.</summary>
        [JsonPropertyName("favicon_image")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public UrlAttachmentImageDescriptor? FaviconImage { get; private init; }

        // Post fields
        /// <summary>Numeric rest ID of the referenced post/tweet.</summary>
        [JsonPropertyName("rest_id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? RestId { get; private init; }

        /// <summary>Canonical URL of the referenced post/tweet.</summary>
        [JsonPropertyName("post_url")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PostUrl { get; private init; }

        // Factory methods

        /// <summary>
        /// Create a media attachment. An empty <paramref name="filename"/>, a
        /// <paramref name="filesizeBytes"/> of 0 or less, or a negative <paramref name="width"/>
        /// or <paramref name="height"/> fails the send with a <see cref="ChatXdkException"/> of
        /// kind <see cref="ChatXdkErrorKind.InvalidInput"/>.
        /// </summary>
        public static AttachmentDescriptor Media(
            string mediaHashKey,
            long width,
            long height,
            long filesizeBytes,
            string filename,
            int? mediaType = null,
            long? durationMillis = null)
        {
            ArgumentNullException.ThrowIfNull(mediaHashKey);
            ArgumentNullException.ThrowIfNull(filename);
            return new("media")
            {
                MediaHashKey = mediaHashKey,
                Width = width,
                Height = height,
                FilesizeBytes = filesizeBytes,
                Filename = filename,
                MediaType = mediaType,
                DurationMillis = durationMillis,
            };
        }

        /// <summary>
        /// Create a URL card attachment. Supplying <paramref name="displayTitle"/> and
        /// <paramref name="bannerImage"/> makes receiving clients render a full clickable
        /// preview card: start the image's upload to the conversation's media store,
        /// reference the media hash key it returns, then encrypt the image with
        /// <see cref="Chat.EncryptFile"/> and the message's <see cref="SendPayload.EventB64"/>
        /// and finish the upload. An empty <paramref name="url"/> fails the send with a
        /// <see cref="ChatXdkException"/> of kind <see cref="ChatXdkErrorKind.InvalidInput"/>.
        /// </summary>
        public static AttachmentDescriptor UrlCard(
            string url,
            string? displayTitle = null,
            UrlAttachmentImageDescriptor? bannerImage = null,
            UrlAttachmentImageDescriptor? faviconImage = null)
        {
            ArgumentNullException.ThrowIfNull(url);
            return new("url")
            {
                Url = url,
                DisplayTitle = displayTitle,
                BannerImage = bannerImage,
                FaviconImage = faviconImage,
            };
        }

        /// <summary>
        /// Create a post/tweet attachment from its <paramref name="restId"/>, its
        /// <paramref name="postUrl"/>, or both; one with neither fails the send with a
        /// <see cref="ChatXdkException"/> of kind <see cref="ChatXdkErrorKind.InvalidInput"/>.
        /// </summary>
        public static AttachmentDescriptor Post(string? restId = null, string? postUrl = null) => new("post")
        {
            RestId = restId,
            PostUrl = postUrl,
        };
    }

    /// <summary>
    /// An encrypted preview image (banner or favicon) referenced by a URL card
    /// attachment via its media hash key.
    /// <para>
    /// Receiving clients' shared ingest discards the whole preview image when its
    /// <see cref="FilesizeBytes"/> or <see cref="Filename"/> is missing on the wire, so a
    /// send fails with a <see cref="ChatXdkException"/> of kind
    /// <see cref="ChatXdkErrorKind.InvalidInput"/> when either is empty or not above 0.
    /// </para>
    /// </summary>
    public sealed class UrlAttachmentImageDescriptor
    {
        /// <summary>
        /// Describe the image whose upload started with <paramref name="mediaHashKey"/>:
        /// <paramref name="filesizeBytes"/> is the encrypted image's size,
        /// <c>EncryptedFileSize</c> of the image's size, and <paramref name="filename"/> its
        /// original name.
        /// </summary>
        public UrlAttachmentImageDescriptor(string mediaHashKey, long filesizeBytes, string filename)
        {
            ArgumentNullException.ThrowIfNull(mediaHashKey);
            ArgumentNullException.ThrowIfNull(filename);
            MediaHashKey = mediaHashKey;
            FilesizeBytes = filesizeBytes;
            Filename = filename;
        }

        /// <summary>Media hash key the image's upload started with.</summary>
        [JsonPropertyName("media_hash_key")]
        public string MediaHashKey { get; }

        /// <summary>Size of the encrypted image in bytes: <c>EncryptedFileSize</c> of the image's size.</summary>
        [JsonPropertyName("filesize_bytes")]
        public long FilesizeBytes { get; }

        /// <summary>Original filename of the image.</summary>
        [JsonPropertyName("filename")]
        public string Filename { get; }

        /// <summary>Image width in pixels; a negative one fails the send.</summary>
        [JsonPropertyName("width")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Width { get; init; }

        /// <summary>Image height in pixels; a negative one fails the send.</summary>
        [JsonPropertyName("height")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? Height { get; init; }
    }

    /// <summary>
    /// A quick reply carried by a text message: set exactly one of
    /// <see cref="Request"/> (offering selectable options) or
    /// <see cref="Response"/> (selecting one). The JSON shape matches the
    /// <c>quick_reply</c> of decrypted text content, so a received value
    /// deserializes with <c>JsonSerializer.Deserialize&lt;QuickReply&gt;</c>
    /// and can be sent back unchanged.
    /// </summary>
    public sealed class QuickReply
    {
        [JsonPropertyName("request")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public QuickReplyRequest? Request { get; init; }

        [JsonPropertyName("response")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public QuickReplyResponse? Response { get; init; }
    }

    /// <summary>A quick-reply request offering a set of selectable options.</summary>
    public sealed class QuickReplyRequest
    {
        [JsonPropertyName("options")]
        public QuickReplyOptionsRequest Options { get; init; } = new();
    }

    /// <summary>A quick-reply response selecting a previously offered option.</summary>
    public sealed class QuickReplyResponse
    {
        [JsonPropertyName("options")]
        public QuickReplyOptionsResponse Options { get; init; } = new();
    }

    /// <summary>The options offered by a quick-reply request.</summary>
    public sealed class QuickReplyOptionsRequest
    {
        [JsonPropertyName("id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Id { get; init; }

        [JsonPropertyName("options")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyList<QuickReplyOption>? Options { get; init; }
    }

    /// <summary>The option selected in a quick-reply response.</summary>
    public sealed class QuickReplyOptionsResponse
    {
        [JsonPropertyName("request_id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? RequestId { get; init; }

        [JsonPropertyName("metadata")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Metadata { get; init; }

        [JsonPropertyName("selected_option_id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? SelectedOptionId { get; init; }
    }

    /// <summary>A single selectable quick-reply option.</summary>
    public sealed class QuickReplyOption
    {
        [JsonPropertyName("id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Id { get; init; }

        [JsonPropertyName("label")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Label { get; init; }

        [JsonPropertyName("metadata")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Metadata { get; init; }

        [JsonPropertyName("description")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Description { get; init; }
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
        /// <summary>
        /// Optional attachments: posts, links, and files (media, and link-card images). Each
        /// file names the media hash key its upload started with; encrypt the files afterwards
        /// with <see cref="Chat.EncryptFile"/> or <see cref="Chat.FileEncryptor"/>. Upload each
        /// file for one message only: reusing another message's uploads can give this message
        /// that message's id.
        /// </summary>
        public IReadOnlyList<AttachmentDescriptor>? Attachments { get; init; }
        /// <summary>Optional quick reply: a request offering options, or a response selecting one.</summary>
        public QuickReply? QuickReply { get; init; }
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
        /// <summary>User ID of the message's sender, as digits (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public string? ReplyToSenderId { get; init; }
        /// <summary>Text of the message being replied to (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public string? ReplyToText { get; init; }
        /// <summary>Optional rich-text entities in the reply text.</summary>
        public IReadOnlyList<EntityDescriptor>? Entities { get; init; }
        /// <summary>Optional attachments on the reply, as in <see cref="EncryptMessageParams.Attachments"/>.</summary>
        public IReadOnlyList<AttachmentDescriptor>? Attachments { get; init; }
        /// <summary>Rich-text entities of the quoted message (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public IReadOnlyList<EntityDescriptor>? ReplyToEntities { get; init; }
        /// <summary>Attachments of the quoted message (for the preview); derived from <see cref="ReplyToEvent"/> when null.</summary>
        public IReadOnlyList<AttachmentDescriptor>? ReplyToAttachments { get; init; }
        /// <summary>Optional quick reply: a request offering options, or a response selecting one.</summary>
        public QuickReply? QuickReply { get; init; }
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

    /// <summary>
    /// Parameters for <see cref="Chat.EncryptEdit"/>.
    /// The preferred form passes the raw event of the message being edited
    /// (<see cref="TargetEvent"/>) and lets the SDK derive the conversation id
    /// and target sequence id from it; the explicit field overrides remain for
    /// callers that no longer hold the raw event.
    /// </summary>
    public sealed class EncryptEditParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="targetEvent">
        /// Base64 raw event being edited. Pass null or "" only when supplying
        /// <see cref="ConversationId"/> and <see cref="TargetMessageSequenceId"/> directly instead.
        /// </param>
        /// <param name="updatedText">The replacement message text.</param>
        public EncryptEditParams(string? targetEvent, string updatedText)
        {
            TargetEvent = string.IsNullOrEmpty(targetEvent) ? null : targetEvent;
            UpdatedText = updatedText;
        }

        /// <summary>Base64 raw event being edited; the conversation id and target sequence id are derived from it.</summary>
        public string? TargetEvent { get; }
        /// <summary>The replacement message text.</summary>
        public string UpdatedText { get; }
        /// <summary>Rich-text entities for the replacement text; null clears any entities the original carried.</summary>
        public IReadOnlyList<EntityDescriptor>? Entities { get; init; }
        /// <summary>ID of the conversation the edit belongs to; derived from <see cref="TargetEvent"/> when null.</summary>
        public string? ConversationId { get; init; }
        /// <summary>Sequence ID of the message being edited; derived from <see cref="TargetEvent"/> when null.</summary>
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

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupMembersChange"/>. <see cref="CurrentTitle"/>
    /// and <see cref="CurrentDescription"/> are plaintext: the call encrypts each under the new
    /// conversation key it generates. <see cref="CurrentAvatarUrl"/> is the avatar's media URL,
    /// signed as is.
    /// </summary>
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
        /// <summary>Current group title, as plaintext, if set; the call encrypts it.</summary>
        public string? CurrentTitle { get; init; }
        /// <summary>Current group avatar media URL, if set.</summary>
        public string? CurrentAvatarUrl { get; init; }
        /// <summary>Current group description, as plaintext, if set; the call encrypts it.</summary>
        public string? CurrentDescription { get; init; }
        /// <summary>Current disappearing-message TTL in milliseconds, if set.</summary>
        public long? CurrentTtlMsec { get; init; }
        /// <summary>Current screen-capture-blocking state, if set.</summary>
        public bool? CurrentScreenCaptureBlockingEnabled { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupCreate"/>. A create sets no avatar; set it
    /// afterwards with <see cref="Chat.PrepareGroupAvatarChange"/>.
    /// </summary>
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
        /// <summary>Group title, as plaintext, if set; the create encrypts it.</summary>
        public string? Title { get; init; }
        /// <summary>Disappearing-message TTL in milliseconds, if set.</summary>
        public long? TtlMsec { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.SetIdentity"/>.</summary>
    public sealed class SetIdentityParams
    {
        /// <summary>Create params with both fields.</summary>
        /// <param name="userId">Your user ID: the sender of everything this chat signs.</param>
        /// <param name="signingKeyVersion">
        /// The <c>public_key_version</c> the X API returned when your keys were registered.
        /// </param>
        public SetIdentityParams(string userId, string signingKeyVersion)
        {
            UserId = userId;
            SigningKeyVersion = signingKeyVersion;
        }

        /// <summary>Your user ID: the sender of everything this chat signs.</summary>
        public string UserId { get; }
        /// <summary>The <c>public_key_version</c> the X API returned when your keys were registered.</summary>
        public string SigningKeyVersion { get; }
    }

    /// <summary>Parameters for <see cref="Chat.ImportKeys"/>.</summary>
    public sealed class ImportKeysParams
    {
        /// <summary>Create params with the key blob; <see cref="SigningKeyVersion"/> defaults to null.</summary>
        /// <param name="keys">The key blob <see cref="Chat.ExportKeys"/> returned.</param>
        public ImportKeysParams(byte[] keys)
        {
            Keys = keys;
        }

        /// <summary>The key blob <see cref="Chat.ExportKeys"/> returned: 32 or 64 bytes.</summary>
        public byte[] Keys { get; }
        /// <summary>
        /// The <c>public_key_version</c> the X API returned when the keys were registered; null
        /// leaves the signing-key version unset.
        /// </summary>
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.DecryptEvent"/>.</summary>
    public sealed class DecryptEventParams
    {
        /// <summary>Create params with the required fields; <see cref="SigningKeys"/> defaults to null.</summary>
        /// <param name="eventB64">The base64 event, as delivered.</param>
        /// <param name="conversationKeys">
        /// Version → raw 32-byte conversation key, from <see cref="Chat.DecryptEvents"/> or
        /// <see cref="Chat.ExtractConversationKeys"/>. Leave it null for events without message
        /// contents, or to take the keys from the opt-in key cache (<see cref="Chat.SetCacheKeys"/>).
        /// </param>
        public DecryptEventParams(string eventB64, IReadOnlyDictionary<string, byte[]>? conversationKeys = null)
        {
            EventB64 = eventB64;
            ConversationKeys = conversationKeys;
        }

        /// <summary>The base64 event, as delivered.</summary>
        public string EventB64 { get; }
        /// <summary>Version → raw 32-byte conversation key; null when none were passed.</summary>
        public IReadOnlyDictionary<string, byte[]>? ConversationKeys { get; }
        /// <summary>
        /// Signing keys to verify the event with; null or empty uses the keys stored via
        /// <see cref="Chat.SetSigningKeys"/>. The SDK picks the sender's key for the version the
        /// event carries.
        /// </summary>
        public IReadOnlyList<SigningKeyEntry>? SigningKeys { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.DecryptEvents"/>.</summary>
    public sealed class DecryptEventsParams
    {
        /// <summary>Create params with the required fields; <see cref="SigningKeys"/> defaults to null.</summary>
        /// <param name="events">
        /// The base64 events, as delivered. Their key changes supply the conversation keys the
        /// messages among them are decrypted with.
        /// </param>
        public DecryptEventsParams(IReadOnlyList<string> events)
        {
            Events = events;
        }

        /// <summary>The base64 events, as delivered.</summary>
        public IReadOnlyList<string> Events { get; }
        /// <summary>
        /// Signing keys of all participants; null or empty uses the keys stored via
        /// <see cref="Chat.SetSigningKeys"/>.
        /// </summary>
        public IReadOnlyList<SigningKeyEntry>? SigningKeys { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.EncryptFile"/>.</summary>
    public sealed class EncryptFileParams
    {
        /// <summary>
        /// Create params with the required fields; the conversation key pair defaults to the key
        /// cache.
        /// </summary>
        /// <param name="file">The file to encrypt.</param>
        /// <param name="eventB64">
        /// The <see cref="SendPayload.EventB64"/> of the payload that <see cref="Chat.EncryptMessage"/>
        /// or <see cref="Chat.EncryptReply"/> returned for the message carrying the file.
        /// </param>
        /// <param name="mediaHashKey">
        /// The media hash key the file's upload started with, as listed in the message's attachments.
        /// </param>
        public EncryptFileParams(byte[] file, string eventB64, string mediaHashKey)
        {
            File = file;
            EventB64 = eventB64;
            MediaHashKey = mediaHashKey;
        }

        /// <summary>The file to encrypt.</summary>
        public byte[] File { get; }
        /// <summary>The <see cref="SendPayload.EventB64"/> of the message carrying the file.</summary>
        public string EventB64 { get; }
        /// <summary>The media hash key the file's upload started with.</summary>
        public string MediaHashKey { get; }
        /// <summary>
        /// The raw 32-byte conversation key the message was encrypted under; with
        /// <see cref="ConversationKeyVersion"/> null too, it resolves from the key cache, as for
        /// <see cref="EncryptMessageParams"/>.
        /// </summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>The version of <see cref="ConversationKey"/>: the message's key version.</summary>
        public string? ConversationKeyVersion { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.FileEncryptor"/>: those of <see cref="EncryptFileParams"/>
    /// apart from the file, which is fed to the encryptor.
    /// </summary>
    public sealed class FileEncryptorParams
    {
        /// <summary>
        /// Create params with the required fields; the conversation key pair defaults to the key
        /// cache.
        /// </summary>
        /// <param name="eventB64">The <see cref="SendPayload.EventB64"/> of the message carrying the file.</param>
        /// <param name="mediaHashKey">
        /// The media hash key the file's upload started with, as listed in the message's attachments.
        /// </param>
        public FileEncryptorParams(string eventB64, string mediaHashKey)
        {
            EventB64 = eventB64;
            MediaHashKey = mediaHashKey;
        }

        /// <summary>The <see cref="SendPayload.EventB64"/> of the message carrying the file.</summary>
        public string EventB64 { get; }
        /// <summary>The media hash key the file's upload started with.</summary>
        public string MediaHashKey { get; }
        /// <summary>The raw 32-byte conversation key the message was encrypted under; null resolves it from the key cache.</summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>The version of <see cref="ConversationKey"/>: the message's key version.</summary>
        public string? ConversationKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.DecryptFile"/>.</summary>
    public sealed class DecryptFileParams
    {
        /// <summary>Create params with the required fields.</summary>
        /// <param name="encrypted">The encrypted file, as downloaded.</param>
        /// <param name="eventB64">
        /// The base64 event of the message that carries the file, as passed to <see cref="Chat.DecryptEvent"/>.
        /// </param>
        /// <param name="conversationKeys">
        /// The conversation's key map, as passed to <see cref="Chat.DecryptEvent"/>; it must hold the key
        /// for the message's version.
        /// </param>
        /// <param name="mediaHashKey">
        /// The file's media hash key from the decrypted message: a media attachment, a link card's
        /// banner or favicon, or media quoted in its reply preview.
        /// </param>
        public DecryptFileParams(
            byte[] encrypted,
            string eventB64,
            IReadOnlyDictionary<string, byte[]> conversationKeys,
            string mediaHashKey)
        {
            Encrypted = encrypted;
            EventB64 = eventB64;
            ConversationKeys = conversationKeys;
            MediaHashKey = mediaHashKey;
        }

        /// <summary>The encrypted file, as downloaded.</summary>
        public byte[] Encrypted { get; }
        /// <summary>The base64 event of the message that carries the file.</summary>
        public string EventB64 { get; }
        /// <summary>Version → raw 32-byte conversation key.</summary>
        public IReadOnlyDictionary<string, byte[]> ConversationKeys { get; }
        /// <summary>The file's media hash key from the decrypted message.</summary>
        public string MediaHashKey { get; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.FileDecryptor"/>: those of <see cref="DecryptFileParams"/>
    /// apart from the encrypted file, which is fed to the decryptor.
    /// </summary>
    public sealed class FileDecryptorParams
    {
        /// <summary>Create params with the required fields.</summary>
        /// <param name="eventB64">
        /// The base64 event of the message that carries the file, as passed to <see cref="Chat.DecryptEvent"/>.
        /// </param>
        /// <param name="conversationKeys">
        /// The conversation's key map, as passed to <see cref="Chat.DecryptEvent"/>; it must hold the key
        /// for the message's version.
        /// </param>
        /// <param name="mediaHashKey">
        /// The file's media hash key from the decrypted message: a media attachment, a link card's
        /// banner or favicon, or media quoted in its reply preview.
        /// </param>
        public FileDecryptorParams(
            string eventB64,
            IReadOnlyDictionary<string, byte[]> conversationKeys,
            string mediaHashKey)
        {
            EventB64 = eventB64;
            ConversationKeys = conversationKeys;
            MediaHashKey = mediaHashKey;
        }

        /// <summary>The base64 event of the message that carries the file.</summary>
        public string EventB64 { get; }
        /// <summary>Version → raw 32-byte conversation key.</summary>
        public IReadOnlyDictionary<string, byte[]> ConversationKeys { get; }
        /// <summary>The file's media hash key from the decrypted message.</summary>
        public string MediaHashKey { get; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareMessageDelete"/>.
    /// A delete is a signed plaintext event, not an encrypted message, so no
    /// conversation key is involved: the result is an action signature the
    /// caller submits alongside the delete request.
    /// </summary>
    public sealed class MessageDeleteParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="conversationId">ID of the conversation the messages belong to.</param>
        /// <param name="sequenceIds">Sequence IDs of the messages to delete.</param>
        /// <param name="deleteForAll">
        /// Delete for every participant (true, own messages only) or only from
        /// the caller's view (false).
        /// </param>
        public MessageDeleteParams(
            string conversationId,
            IReadOnlyList<string> sequenceIds,
            bool deleteForAll)
        {
            ConversationId = conversationId;
            SequenceIds = sequenceIds;
            DeleteForAll = deleteForAll;
        }

        /// <summary>ID of the conversation the messages belong to.</summary>
        public string ConversationId { get; }
        /// <summary>Sequence IDs of the messages to delete.</summary>
        public IReadOnlyList<string> SequenceIds { get; }
        /// <summary>Delete for every participant (true, own messages only) or only from the caller's view (false).</summary>
        public bool DeleteForAll { get; }
        /// <summary>User ID of the sender signing the delete; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareMarkConversationRead"/>.
    /// A read receipt is a signed plaintext event, not an encrypted message, so
    /// no conversation key is involved: the result is an action signature the
    /// caller submits alongside the mark-read request.
    /// </summary>
    public sealed class MarkConversationReadParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="conversationId">ID of the conversation being marked read.</param>
        /// <param name="seenUntilSequenceId">Sequence ID of the newest event read.</param>
        public MarkConversationReadParams(string conversationId, string seenUntilSequenceId)
        {
            ConversationId = conversationId;
            SeenUntilSequenceId = seenUntilSequenceId;
        }

        /// <summary>ID of the conversation being marked read.</summary>
        public string ConversationId { get; }
        /// <summary>Sequence ID of the newest event read.</summary>
        public string SeenUntilSequenceId { get; }
        /// <summary>When the conversation was read, in milliseconds since the Unix epoch; the current time when null.</summary>
        public long? SeenAtMsec { get; init; }
        /// <summary>User ID of the sender signing the read receipt; resolves from the session identity when null.</summary>
        public string? SenderId { get; init; }
        /// <summary>Version of the sender's signing key; resolves from the session identity when null.</summary>
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>
    /// A screen-capture setting signed by <see cref="Chat.PrepareScreenCapture"/>.
    /// Blocking names are the events X clients sign. Detection names are the
    /// events this SDK's verifier reconstructs.
    /// </summary>
    public enum ScreenCaptureChange
    {
        BlockingEnabled,
        BlockingDisabled,
        DetectionEnabled,
        DetectionDisabled,
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupMembersRemove"/>. The call rotates the
    /// conversation key for the members who stay.
    /// </summary>
    public sealed class GroupMembersRemoveParams
    {
        /// <summary>Create params with the required fields; all optional fields default to null.</summary>
        /// <param name="publicKeys">Identity public keys of the members who stay.</param>
        /// <param name="conversationId">ID of the group conversation.</param>
        /// <param name="userIds">User IDs being removed.</param>
        public GroupMembersRemoveParams(
            IReadOnlyList<PublicKeyInput> publicKeys,
            string conversationId,
            IReadOnlyList<string> userIds)
        {
            PublicKeys = publicKeys;
            ConversationId = conversationId;
            UserIds = userIds;
        }

        /// <summary>Identity public keys of the members who stay; the new key is encrypted for them.</summary>
        public IReadOnlyList<PublicKeyInput> PublicKeys { get; }
        public string ConversationId { get; }
        public IReadOnlyList<string> UserIds { get; }
        /// <summary>The group's title, re-encrypted under the new conversation key; null leaves it out.</summary>
        public string? Title { get; init; }
        /// <summary>The group's description, re-encrypted under the new conversation key; null leaves it out.</summary>
        public string? Description { get; init; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupLeave"/>. Leave does not rotate the key.</summary>
    public sealed class GroupLeaveParams
    {
        public GroupLeaveParams(string conversationId) => ConversationId = conversationId;
        public string ConversationId { get; }
        public string? PromoteAdminId { get; init; }
        public string? ConversationKeyVersion { get; init; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupTitleChange"/>. <see cref="NewTitle"/> is plaintext: the
    /// call encrypts it under the conversation key, <see cref="ConversationKey"/> /
    /// <see cref="ConversationKeyVersion"/> or, both null, the key cache.
    /// </summary>
    public sealed class GroupTitleChangeParams
    {
        public GroupTitleChangeParams(string conversationId, string newTitle)
        {
            ConversationId = conversationId;
            NewTitle = newTitle;
        }

        public string ConversationId { get; }
        /// <summary>The group's new title, as plaintext.</summary>
        public string NewTitle { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
        /// <summary>Raw 32-byte conversation key; resolves from the key cache when null.</summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>Version of the conversation key; resolves from the key cache when null.</summary>
        public string? ConversationKeyVersion { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupAvatarChange"/>. A group's avatar URL is not
    /// encrypted: <see cref="NewAvatarUrl"/> is the media URL of the avatar image, which the app
    /// encrypts under the conversation key and uploads first.
    /// </summary>
    public sealed class GroupAvatarChangeParams
    {
        public GroupAvatarChangeParams(string conversationId, string newAvatarUrl, string conversationKeyVersion)
        {
            ConversationId = conversationId;
            NewAvatarUrl = newAvatarUrl;
            ConversationKeyVersion = conversationKeyVersion;
        }

        public string ConversationId { get; }
        /// <summary>The media URL of the group's new avatar image, signed and sent as is.</summary>
        public string NewAvatarUrl { get; }
        /// <summary>Version of the conversation key the avatar image is encrypted under.</summary>
        public string ConversationKeyVersion { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>
    /// Parameters for <see cref="Chat.PrepareGroupDescriptionChange"/>. <see cref="NewDescription"/> is plaintext: the
    /// call encrypts it under the conversation key, <see cref="ConversationKey"/> /
    /// <see cref="ConversationKeyVersion"/> or, both null, the key cache.
    /// </summary>
    public sealed class GroupDescriptionChangeParams
    {
        public GroupDescriptionChangeParams(string conversationId, string newDescription)
        {
            ConversationId = conversationId;
            NewDescription = newDescription;
        }

        public string ConversationId { get; }
        /// <summary>The group's new description, as plaintext.</summary>
        public string NewDescription { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
        /// <summary>Raw 32-byte conversation key; resolves from the key cache when null.</summary>
        public byte[]? ConversationKey { get; init; }
        /// <summary>Version of the conversation key; resolves from the key cache when null.</summary>
        public string? ConversationKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupAdminsAdd"/>.</summary>
    public sealed class GroupAdminsAddParams
    {
        public GroupAdminsAddParams(string conversationId, IReadOnlyList<string> userIds)
        {
            ConversationId = conversationId;
            UserIds = userIds;
        }

        public string ConversationId { get; }
        public IReadOnlyList<string> UserIds { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupAdminsRemove"/>.</summary>
    public sealed class GroupAdminsRemoveParams
    {
        public GroupAdminsRemoveParams(string conversationId, IReadOnlyList<string> userIds)
        {
            ConversationId = conversationId;
            UserIds = userIds;
        }

        public string ConversationId { get; }
        public IReadOnlyList<string> UserIds { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupInviteEnable"/>.</summary>
    public sealed class GroupInviteEnableParams
    {
        public GroupInviteEnableParams(string conversationId, string inviteUrl)
        {
            ConversationId = conversationId;
            InviteUrl = inviteUrl;
        }

        public string ConversationId { get; }
        public string InviteUrl { get; }
        public long? ExpiresAtMsec { get; init; }
        public string? AffiliateId { get; init; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupInviteDisable"/>.</summary>
    public sealed class GroupInviteDisableParams
    {
        public GroupInviteDisableParams(string conversationId) => ConversationId = conversationId;
        public string ConversationId { get; }
        public string? DisabledBy { get; init; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupJoinRequest"/>.</summary>
    public sealed class GroupJoinRequestParams
    {
        public GroupJoinRequestParams(string conversationId) => ConversationId = conversationId;
        public string ConversationId { get; }
        public string? RequestingUserId { get; init; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareGroupJoinReject"/>.</summary>
    public sealed class GroupJoinRejectParams
    {
        public GroupJoinRejectParams(string conversationId, IReadOnlyList<string> userIds)
        {
            ConversationId = conversationId;
            UserIds = userIds;
        }

        public string ConversationId { get; }
        public IReadOnlyList<string> UserIds { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareMessageTtlChange"/>.</summary>
    public sealed class MessageTtlChangeParams
    {
        public MessageTtlChangeParams(string conversationId, long ttlMsec)
        {
            ConversationId = conversationId;
            TtlMsec = ttlMsec;
        }

        public string ConversationId { get; }
        public long TtlMsec { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareMessageTtlRemove"/>.</summary>
    public sealed class MessageTtlRemoveParams
    {
        public MessageTtlRemoveParams(string conversationId) => ConversationId = conversationId;
        public string ConversationId { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }

    /// <summary>Parameters for <see cref="Chat.PrepareScreenCapture"/>.</summary>
    public sealed class ScreenCaptureParams
    {
        public ScreenCaptureParams(string conversationId, ScreenCaptureChange change)
        {
            ConversationId = conversationId;
            Change = change;
        }

        public string ConversationId { get; }
        public ScreenCaptureChange Change { get; }
        public string? SenderId { get; init; }
        public string? SigningKeyVersion { get; init; }
    }
}
