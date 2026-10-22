package com.x.chatxdk;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Data types for the Chat SDK public API. */
public final class Types {

    private Types() {}

    /** The user's identity and signing public keys. */
    public static final class PublicKeys {
        /** Base64-encoded identity public key. */
        @JsonProperty("identity")
        public String identity = "";

        /** Base64-encoded signing public key. */
        @JsonProperty("signing")
        public String signing = "";

        /** Version assigned to this set of public keys. */
        @JsonProperty("version")
        public String version = "";
    }

    /**
     * Registration fields expected by the X API
     * ({@code POST /2/chat/keys}).
     */
    public static final class PublicKeyRegistration {
        /** Base64-encoded raw r||s signature over the identity public key. */
        @JsonProperty("identity_public_key_signature")
        public String identityPublicKeySignature = "";

        /** Base64-encoded identity public key (SEC1 or SPKI). */
        @JsonProperty("public_key")
        public String publicKey = "";

        /** Optional fingerprint of the identity public key. */
        @JsonProperty("public_key_fingerprint")
        public String publicKeyFingerprint;

        /** Identifier for how the keys were registered. */
        @JsonProperty("registration_method")
        public String registrationMethod = "";

        /** Base64-encoded signing public key (SEC1 or SPKI). */
        @JsonProperty("signing_public_key")
        public String signingPublicKey = "";

        /** Optional Base64-encoded signature over the signing public key. */
        @JsonProperty("signing_public_key_signature")
        public String signingPublicKeySignature;
    }

    /**
     * Returned by {@link Chat#generateKeypairs}.
     * POST the {@link #publicKey} object to the X API to register keys.
     */
    public static final class PublicKeyRegistrationPayload {
        /** The registration fields to upload to the X API. */
        @JsonProperty("public_key")
        public PublicKeyRegistration publicKey = new PublicKeyRegistration();
    }

    /** Signature metadata for a sent message. */
    public static final class SignatureInfo {
        /** Version of the signing public key used to sign the payload. */
        @JsonProperty("public_key_version")
        public String publicKeyVersion = "";

        /** Signature scheme version. */
        @JsonProperty("signature_version")
        public String signatureVersion = "";
    }

    /**
     * Encrypted message payload ready to POST to the X API.
     * Returned by all {@code encrypt*} methods.
     */
    public static final class SendPayload {
        /**
         * Message id (UUID) the SDK generated and embedded in the signed event. Send it as
         * the message's {@code message_id}, keep it to dedup and to anchor replies, and reuse
         * the same encrypted payload on retries so an id is never minted twice.
         */
        @JsonProperty("message_id")
        public String messageId = "";

        /**
         * The outgoing message as a base64 event: what recipients receive, without the fields
         * the server assigns. Pass it to {@link Chat#encryptFile} or {@link Chat#fileEncryptor}
         * to encrypt the message's files, or to {@link Chat#decryptEvent} to read the message back.
         */
        @JsonProperty("event_b64")
        public String eventB64 = "";

        /**
         * Base64-encoded Thrift {@code MessageCreateEvent} carrying the encrypted contents: the
         * send request's {@code encoded_message_create_event}. A payload stored by 0.5.x carries
         * it as {@code encrypted_content}, which also reads.
         */
        @JsonProperty("encoded_message_create_event")
        @JsonAlias("encrypted_content")
        public String encodedMessageCreateEvent = "";

        /** Base64-encoded raw r||s signature over the encrypted content. */
        @JsonProperty("signature")
        public String signature = "";

        /**
         * Base64-encoded Thrift {@code MessageEventSignature}: the send request's
         * {@code encoded_message_event_signature}. A payload stored by 0.5.x carries it as
         * {@code encoded_event_signature}, which also reads.
         */
        @JsonProperty("encoded_message_event_signature")
        @JsonAlias("encoded_event_signature")
        public String encodedMessageEventSignature = "";

        /** Signing key and signature version metadata for this payload. */
        @JsonProperty("signature_info")
        public SignatureInfo signatureInfo = new SignatureInfo();

        /** Version of the conversation key used to encrypt the content. */
        @JsonProperty("conversation_key_version")
        public String conversationKeyVersion = "";

        /** Whether the X API should send a push notification. */
        @JsonProperty("should_notify")
        public boolean shouldNotify;

        /**
         * Version of the Chat XDK that built this payload.
         */
        @JsonProperty("xdk_version")
        public String xdkVersion = "";
    }

    /**
     * Signed action authenticating a conversation key change, group change,
     * message delete, or read receipt, shaped as an entry of a request's
     * {@code action_signatures}: the signature is nested under
     * {@code message_event_signature}.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class ActionSignature {
        /** ID of the message carrying the action. */
        @JsonProperty("message_id")
        public String messageId = "";

        /** Base64-encoded Thrift message-event detail that was signed. */
        @JsonProperty("encoded_message_event_detail")
        public String encodedMessageEventDetail = "";

        /** The signature over the action, with its versions and the signer's signing public key. */
        @JsonProperty("message_event_signature")
        public MessageEventSignature messageEventSignature = new MessageEventSignature();

        /**
         * The comma-separated payload string that was signed; {@code null} for
         * conversation-key changes, whose payload embeds the plaintext
         * conversation key and is withheld.
         */
        @JsonProperty("signature_payload")
        public String signaturePayload;
    }

    /** The signature of an {@link ActionSignature}. */
    public static final class MessageEventSignature {
        /** Base64-encoded raw r||s signature over the action payload. */
        @JsonProperty("signature")
        public String signature = "";

        /** Signature scheme version. */
        @JsonProperty("signature_version")
        public String signatureVersion = "";

        /** Version of the signing public key used. */
        @JsonProperty("public_key_version")
        public String publicKeyVersion = "";

        /** The signer's base64 signing public key, as {@link Chat#getPublicKeys} returns it. */
        @JsonProperty("signing_public_key")
        public String signingPublicKey = "";
    }

    /**
     * A signed message delete or read receipt: the {@code action_signatures} a
     * request carries for it, one entry.
     */
    public static final class PreparedAction {
        /** The signed action, as the request's {@code action_signatures} entries. */
        @JsonProperty("action_signatures")
        public List<ActionSignature> actionSignatures = Collections.emptyList();
    }

    /** A signing key entry for {@link Chat#decryptEvent} and {@link Chat#decryptEvents}. */
    public static final class SigningKeyEntry {
        /** ID of the user this signing key belongs to. */
        @JsonProperty("user_id")
        public String userId;

        /** Version of the user's signing public key as returned by the X API. */
        @JsonProperty("public_key_version")
        public String publicKeyVersion;

        /** Base64-encoded signing public key (SEC1 or SPKI). */
        @JsonProperty("public_key")
        public String publicKey;

        /** Base64-encoded identity public key (SEC1 or SPKI) for this user. */
        @JsonProperty("identity_public_key")
        public String identityPublicKey;

        /**
         * Base64-encoded raw r||s signature proving the signing key is bound to the
         * identity key. Returned by the X API on the public keys response.
         */
        @JsonProperty("identity_public_key_signature")
        public String identityPublicKeySignature;
    }

    /** Public key entry for the prepare methods ({@link Chat#prepareConversationKeyChange}). */
    public static final class PublicKeyInput {
        /** ID of the user this public key belongs to. */
        @JsonProperty("user_id")
        public String userId;

        /** Base64-encoded identity public key (SEC1 or SPKI). */
        @JsonProperty("public_key")
        public String publicKey;

        /** Version of the user's public key as returned by the X API. */
        @JsonProperty("key_version")
        public String keyVersion;
    }

    /**
     * Returned by {@link Chat#prepareConversationKeyChange},
     * {@link Chat#prepareGroupCreate}, and {@link Chat#prepareGroupMembersChange}.
     * Carries everything needed to POST the change.
     */
    public static final class PreparedConversationChange {
        /** Conversation id the change applies to (derived for a one-to-one, or the id you passed). */
        @JsonProperty("conversation_id")
        public String conversationId = "";

        /**
         * Raw 32-byte conversation key when one was generated, otherwise {@code null}.
         * Unlike a String, the array can be zeroed once no longer needed.
         */
        @JsonProperty("conversation_key")
        public byte[] conversationKey;

        /** Version assigned to the conversation key. */
        @JsonProperty("conversation_key_version")
        public String conversationKeyVersion = "";

        /** The conversation key encrypted once per participant. */
        @JsonProperty("participant_keys")
        public List<EncryptedKeyForRecipient> participantKeys = Collections.emptyList();

        /** Action signatures authenticating the change, ready to POST. */
        @JsonProperty("action_signatures")
        public List<ActionSignature> actionSignatures = Collections.emptyList();
    }

    /**
     * Conversation keys from {@link Chat#extractConversationKeys} or nested inside
     * {@link DecryptEventsResult}.
     */
    public static final class ConversationKeyBundle {
        /** Version string &#8594; raw 32-byte conversation key. */
        public Map<String, byte[]> keys = Collections.emptyMap();

        /** Highest key version (for encrypting new messages), or {@code null}. */
        public String latestVersion;
    }

    /** Width and height from {@link ChatXdkUtilities#detectImageDimensions}. */
    public static final class ImageDimensions {
        /** Image width in pixels. */
        @JsonProperty("width")
        public long width;

        /** Image height in pixels. */
        @JsonProperty("height")
        public long height;

        public ImageDimensions() {}
    }

    /** One decrypted event from {@link Chat#decryptEvents}. */
    public static final class DecryptedMessage {
        /** The decrypted event JSON ({@code type}, &#8230;). */
        public JsonNode event;

        /** Original webhook base64 payload when present. */
        public String originalB64;
    }

    /** Result of {@link Chat#decryptEvents}. */
    public static final class DecryptEventsResult {
        /** The successfully decrypted events. */
        public List<DecryptedMessage> messages = Collections.emptyList();

        /** Extracted keys and {@link ConversationKeyBundle#latestVersion}. */
        public ConversationKeyBundle conversationKeys = new ConversationKeyBundle();

        /** String indices into the input batch for events that failed to decrypt. */
        public Map<String, String> errors = Collections.emptyMap();
    }

    /** An encrypted conversation key for one recipient. */
    public static final class EncryptedKeyForRecipient {
        /** ID of the recipient user. */
        @JsonProperty("user_id")
        public String userId = "";

        /** Base64-encoded conversation key encrypted to the recipient (ECIES). */
        @JsonProperty("encrypted_key")
        public String encryptedKey = "";

        /** Version of the recipient's public key used to encrypt the conversation key. */
        @JsonProperty("public_key_version")
        public String publicKeyVersion = "";
    }

    /**
     * Rich-text entity (URL, mention, hashtag, etc.) descriptor.
     * {@link #start} and {@link #end} are byte offsets into the message text.
     */
    public static final class EntityDescriptor {
        /** Byte offset of the start of the entity in the message text. */
        public int start;

        /** Byte offset of the end of the entity in the message text. */
        public int end;

        /** One of: "url", "mention", "hashtag", "cashtag", "email", "address", "phone_number". */
        public String entityType = "";
    }

    /**
     * Attachment descriptor. Use the factory methods to create well-formed instances.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class AttachmentDescriptor {
        /** Attachment kind: one of "media", "url", or "post". */
        @JsonProperty("attachment_type")
        public String attachmentType = "";

        /** Media hash key identifying the uploaded media. */
        @JsonProperty("media_hash_key")
        public String mediaHashKey;

        /** Media width in pixels. */
        @JsonProperty("width")
        public Long width;

        /** Media height in pixels. */
        @JsonProperty("height")
        public Long height;

        /** Media file size in bytes. */
        @JsonProperty("filesize_bytes")
        public Long filesizeBytes;

        /** Media file name. */
        @JsonProperty("filename")
        public String filename;

        /** 1=image, 2=gif, 3=video, 4=audio, 5=file, 6=svg. */
        @JsonProperty("media_type")
        public Integer mediaType;

        /** Media duration in milliseconds (for audio/video). */
        @JsonProperty("duration_millis")
        public Long durationMillis;

        /** URL for a URL-card attachment. */
        @JsonProperty("url")
        public String url;

        /** Display title for a URL-card attachment. */
        @JsonProperty("display_title")
        public String displayTitle;

        /** Encrypted banner (preview) image for a URL-card attachment. */
        @JsonProperty("banner_image")
        public UrlAttachmentImageDescriptor bannerImage;

        /** Encrypted favicon image for a URL-card attachment. */
        @JsonProperty("favicon_image")
        public UrlAttachmentImageDescriptor faviconImage;

        /** Numeric post (tweet) ID for a post attachment. */
        @JsonProperty("rest_id")
        public String restId;

        /** Canonical post (tweet) URL for a post attachment. */
        @JsonProperty("post_url")
        public String postUrl;

        /** Create a media attachment. */
        public static AttachmentDescriptor media(
                String mediaHashKey,
                long width,
                long height,
                long filesizeBytes,
                String filename,
                Integer mediaType,
                Long durationMillis) {
            AttachmentDescriptor a = new AttachmentDescriptor();
            a.attachmentType = "media";
            a.mediaHashKey = mediaHashKey;
            a.width = width;
            a.height = height;
            a.filesizeBytes = filesizeBytes;
            a.filename = filename;
            a.mediaType = mediaType;
            a.durationMillis = durationMillis;
            return a;
        }

        /** Create a URL card attachment. */
        public static AttachmentDescriptor urlCard(String url, String displayTitle) {
            AttachmentDescriptor a = new AttachmentDescriptor();
            a.attachmentType = "url";
            a.url = url;
            a.displayTitle = displayTitle;
            return a;
        }

        /**
         * Create a URL card attachment with encrypted preview images. Supplying a display
         * title plus a banner image makes receiving clients render a full clickable preview
         * card: start the image's upload to the conversation's media store, reference the
         * media hash key it returns, then encrypt the image with {@link Chat#encryptFile} and
         * the message's {@link SendPayload#eventB64} and finish the upload.
         */
        public static AttachmentDescriptor urlCard(
                String url,
                String displayTitle,
                UrlAttachmentImageDescriptor bannerImage,
                UrlAttachmentImageDescriptor faviconImage) {
            AttachmentDescriptor a = urlCard(url, displayTitle);
            a.bannerImage = bannerImage;
            a.faviconImage = faviconImage;
            return a;
        }

        /** Create a post/tweet attachment. */
        public static AttachmentDescriptor post(String restId, String postUrl) {
            AttachmentDescriptor a = new AttachmentDescriptor();
            a.attachmentType = "post";
            a.restId = restId;
            a.postUrl = postUrl;
            return a;
        }
    }

    /**
     * An encrypted preview image (banner or favicon) referenced by a URL card
     * attachment via its media hash key.
     *
     * <p>{@code filesizeBytes} and {@code filename} are required alongside
     * {@code mediaHashKey}: receiving clients' shared ingest silently discards
     * the whole preview image when either is missing on the wire.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class UrlAttachmentImageDescriptor {
        /** Media hash key the image's upload started with. */
        @JsonProperty("media_hash_key")
        public String mediaHashKey = "";

        /** Size of the encrypted image in bytes: {@code encryptedFileSize} of the image's size. Required. */
        @JsonProperty("filesize_bytes")
        public long filesizeBytes;

        /** Original filename of the image. Required. */
        @JsonProperty("filename")
        public String filename = "";

        /** Image width in pixels. */
        @JsonProperty("width")
        public Long width;

        /** Image height in pixels. */
        @JsonProperty("height")
        public Long height;

        /** Create an image descriptor with the required fields. */
        public static UrlAttachmentImageDescriptor of(
                String mediaHashKey, long filesizeBytes, String filename) {
            UrlAttachmentImageDescriptor d = new UrlAttachmentImageDescriptor();
            d.mediaHashKey = mediaHashKey;
            d.filesizeBytes = filesizeBytes;
            d.filename = filename;
            return d;
        }
    }

    /**
     * A quick reply carried by a text message: set exactly one of
     * {@link #request} (offering selectable options) or {@link #response}
     * (selecting one). The JSON shape matches the {@code quick_reply} of
     * decrypted text content, so a received value converts with
     * {@code new ObjectMapper().treeToValue(node, QuickReply.class)} and can be
     * sent back unchanged.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class QuickReply {
        /** A request offering selectable options. */
        @JsonProperty("request")
        public QuickReplyRequest request;

        /** A response selecting one of the offered options. */
        @JsonProperty("response")
        public QuickReplyResponse response;

        /** Create a quick reply that offers {@code options}. */
        public static QuickReply request(QuickReplyOptionsRequest options) {
            QuickReply q = new QuickReply();
            q.request = new QuickReplyRequest();
            q.request.options = options;
            return q;
        }

        /** Create a quick reply that answers a request with {@code options}. */
        public static QuickReply response(QuickReplyOptionsResponse options) {
            QuickReply q = new QuickReply();
            q.response = new QuickReplyResponse();
            q.response.options = options;
            return q;
        }
    }

    /** A quick-reply request offering a set of selectable options. */
    public static final class QuickReplyRequest {
        /** The offered options. */
        @JsonProperty("options")
        public QuickReplyOptionsRequest options = new QuickReplyOptionsRequest();
    }

    /** A quick-reply response selecting a previously offered option. */
    public static final class QuickReplyResponse {
        /** The selected option. */
        @JsonProperty("options")
        public QuickReplyOptionsResponse options = new QuickReplyOptionsResponse();
    }

    /** The options offered by a quick-reply request. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class QuickReplyOptionsRequest {
        /** ID of this request. */
        @JsonProperty("id")
        public String id;

        /** The selectable options. */
        @JsonProperty("options")
        public List<QuickReplyOption> options;
    }

    /** The option selected in a quick-reply response. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class QuickReplyOptionsResponse {
        /** ID of the request being answered. */
        @JsonProperty("request_id")
        public String requestId;

        /** Opaque metadata for the selection. */
        @JsonProperty("metadata")
        public String metadata;

        /** ID of the selected option. */
        @JsonProperty("selected_option_id")
        public String selectedOptionId;
    }

    /** A single selectable quick-reply option. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class QuickReplyOption {
        /** ID of this option. */
        @JsonProperty("id")
        public String id;

        /** Text shown for the option. */
        @JsonProperty("label")
        public String label;

        /** Opaque metadata for this option. */
        @JsonProperty("metadata")
        public String metadata;

        /** Description shown with the option. */
        @JsonProperty("description")
        public String description;
    }

    /**
     * Parameters for {@link Chat#encryptMessage}.
     *
     * <p>The constructor takes the required fields; identity and key overrides
     * ({@link #senderId}/{@link #signingKeyVersion} and
     * {@link #conversationKey}/{@link #conversationKeyVersion}) are optional
     * and resolve from the session identity ({@link Chat#setIdentity}) and the
     * opt-in key cache ({@link Chat#setCacheKeys}) when null.
     */
    public static final class EncryptMessageParams {
        /** ID of the conversation the message belongs to. */
        public final String conversationId;

        /** The plaintext message body. */
        public final String text;

        /** User ID of the sender; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Raw 32-byte conversation key; resolves from the key cache when null
         * (set together with {@link #conversationKeyVersion}).
         */
        public byte[] conversationKey;

        /** Version of the conversation key; resolves from the key cache when null. */
        public String conversationKeyVersion;

        /** Optional rich-text entities (URLs, mentions, hashtags, etc.). */
        public List<EntityDescriptor> entities;

        /**
         * Optional attachments: posts, links, and files (media, and link-card images). Each file
         * names the media hash key its upload started with; encrypt the files afterwards with
         * {@link Chat#encryptFile} or {@link Chat#fileEncryptor}. Upload each file for one
         * message only: reusing another message's uploads can give this message that message's
         * id.
         */
        public List<AttachmentDescriptor> attachments;

        /** Optional quick reply: a request offering options, or a response selecting one. */
        public QuickReply quickReply;

        /** Whether to send a push notification. Defaults to true. */
        public Boolean shouldNotify;

        /** Time-to-live for disappearing messages in milliseconds. */
        public Long ttlMsec;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param conversationId ID of the conversation the message belongs to.
         * @param text Plaintext message body to encrypt.
         */
        public EncryptMessageParams(String conversationId, String text) {
            this.conversationId = conversationId;
            this.text = text;
        }
    }

    /**
     * Parameters for {@link Chat#encryptReply}.
     *
     * <p>The preferred form passes the raw signed event being replied to
     * ({@code replyToEvent}) and lets the SDK derive the reply preview from
     * it; the {@code replyTo*} field overrides remain for callers that no
     * longer hold the raw event. Identity and key overrides resolve like
     * {@link EncryptMessageParams}.
     */
    public static final class EncryptReplyParams {
        /** ID of the conversation the reply belongs to. */
        public final String conversationId;

        /** The plaintext reply body. */
        public final String text;

        /**
         * Base64 raw signed event being replied to. The reply preview
         * (sequence id, sender, text, entities, attachments) is derived from
         * it and the raw event is embedded so recipients can validate the preview.
         */
        public final String replyToEvent;

        /** Base64 raw signed edit event, when the original was edited. */
        public String replyToEditEvent;

        /**
         * Base64 raw key-change events needed to decrypt the original when it
         * was encrypted under a different key version than this reply.
         */
        public List<String> replyToCkces;

        /** User ID of the sender; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Raw 32-byte conversation key; resolves from the key cache when null
         * (set together with {@link #conversationKeyVersion}).
         */
        public byte[] conversationKey;

        /** Version of the conversation key; resolves from the key cache when null. */
        public String conversationKeyVersion;

        /** Sequence ID of the message being replied to; derived from {@link #replyToEvent} when null. */
        public String replyToSequenceId;

        /** User ID of the message's sender, as digits (for the preview); derived from {@link #replyToEvent} when null. */
        public String replyToSenderId;

        /** Text of the message being replied to (for the preview); derived from {@link #replyToEvent} when null. */
        public String replyToText;

        /** Optional rich-text entities for the reply body. */
        public List<EntityDescriptor> entities;

        /** Optional attachments for the reply body, as in {@link EncryptMessageParams#attachments}. */
        public List<AttachmentDescriptor> attachments;

        /** Rich-text entities of the quoted message (for the preview); derived from {@link #replyToEvent} when null. */
        public List<EntityDescriptor> replyToEntities;

        /** Attachments of the quoted message (for the preview); derived from {@link #replyToEvent} when null. */
        public List<AttachmentDescriptor> replyToAttachments;

        /** Optional quick reply: a request offering options, or a response selecting one. */
        public QuickReply quickReply;

        /** Whether to send a push notification. Defaults to true. */
        public Boolean shouldNotify;

        /** Time-to-live for disappearing messages in milliseconds. */
        public Long ttlMsec;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param conversationId ID of the conversation the reply belongs to.
         * @param text Plaintext reply body to encrypt.
         * @param replyToEvent Base64 raw signed event being replied to. Pass
         *     null or "" only when supplying the {@code replyTo*} fields
         *     directly instead.
         */
        public EncryptReplyParams(String conversationId, String text, String replyToEvent) {
            this.conversationId = conversationId;
            this.text = text;
            this.replyToEvent = replyToEvent == null || replyToEvent.isEmpty() ? null : replyToEvent;
        }
    }

    /**
     * Parameters for {@link Chat#encryptAddReaction} and {@link Chat#encryptRemoveReaction}.
     *
     * <p>The preferred form passes the raw event being reacted to
     * ({@code targetEvent}) and lets the SDK derive the conversation id and
     * target sequence id from it; the explicit field overrides remain for
     * callers that no longer hold the raw event. The same instance can be
     * passed to both methods to add and later remove the same reaction.
     */
    public static final class EncryptReactionParams {
        /** Base64 raw event being reacted to; the conversation id and target sequence id are derived from it. */
        public final String targetEvent;

        /** The reaction emoji. */
        public final String emoji;

        /** ID of the conversation the reaction belongs to; derived from {@link #targetEvent} when null. */
        public String conversationId;

        /** Sequence ID of the message being reacted to; derived from {@link #targetEvent} when null. */
        public String targetMessageSequenceId;

        /** User ID of the sender; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Raw 32-byte conversation key; resolves from the key cache when null
         * (set together with {@link #conversationKeyVersion}).
         */
        public byte[] conversationKey;

        /** Version of the conversation key; resolves from the key cache when null. */
        public String conversationKeyVersion;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param targetEvent Base64 raw event being reacted to. Pass null or ""
         *     only when supplying {@link #conversationId} and
         *     {@link #targetMessageSequenceId} directly instead.
         * @param emoji The reaction emoji.
         */
        public EncryptReactionParams(String targetEvent, String emoji) {
            this.targetEvent = targetEvent == null || targetEvent.isEmpty() ? null : targetEvent;
            this.emoji = emoji;
        }
    }

    /**
     * Parameters for {@link Chat#encryptEdit}.
     *
     * <p>The preferred form passes the raw event of the message being edited
     * ({@code targetEvent}) and lets the SDK derive the conversation id and
     * target sequence id from it; the explicit field overrides remain for
     * callers that no longer hold the raw event.
     */
    public static final class EncryptEditParams {
        /** Base64 raw event being edited; the conversation id and target sequence id are derived from it. */
        public final String targetEvent;

        /** The replacement message text. */
        public final String updatedText;

        /** Rich-text entities for the replacement text; null clears any entities the original carried. */
        public List<EntityDescriptor> entities;

        /** ID of the conversation the edit belongs to; derived from {@link #targetEvent} when null. */
        public String conversationId;

        /** Sequence ID of the message being edited; derived from {@link #targetEvent} when null. */
        public String targetMessageSequenceId;

        /** User ID of the sender; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Raw 32-byte conversation key; resolves from the key cache when null
         * (set together with {@link #conversationKeyVersion}).
         */
        public byte[] conversationKey;

        /** Version of the conversation key; resolves from the key cache when null. */
        public String conversationKeyVersion;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param targetEvent Base64 raw event being edited. Pass null or ""
         *     only when supplying {@link #conversationId} and
         *     {@link #targetMessageSequenceId} directly instead.
         * @param updatedText The replacement message text.
         */
        public EncryptEditParams(String targetEvent, String updatedText) {
            this.targetEvent = targetEvent == null || targetEvent.isEmpty() ? null : targetEvent;
            this.updatedText = updatedText;
        }
    }

    /** Parameters for {@link Chat#prepareConversationKeyChange}. */
    public static final class ConversationKeyChangeParams {
        /** Public keys for every participant the new key is encrypted for. */
        public final List<PublicKeyInput> publicKeys;

        /** User ID of the sender signing the change; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /** Conversation the change applies to; null derives the one-to-one id. */
        public String conversationId;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param publicKeys Public keys for every participant the new key is encrypted for.
         */
        public ConversationKeyChangeParams(List<PublicKeyInput> publicKeys) {
            this.publicKeys = publicKeys;
        }
    }

    /** Parameters for {@link Chat#prepareGroupMembersChange}. */
    public static final class GroupMembersChangeParams {
        /** Public keys for the updated roster. */
        public final List<PublicKeyInput> publicKeys;

        /** ID of the group conversation being modified. */
        public final String conversationId;

        /** IDs of the members being added. */
        public final List<String> newMemberIds;

        /** IDs of the current members. */
        public final List<String> currentMemberIds;

        /** IDs of the current admins. */
        public final List<String> currentAdminIds;

        /** IDs of the current pending members. */
        public final List<String> currentPendingMemberIds;

        /** User ID of the sender signing the change; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /** Current conversation title, if any. */
        public String currentTitle;

        /** Current conversation avatar URL, if any. */
        public String currentAvatarUrl;

        /** Current disappearing-message TTL in milliseconds, if any. */
        public Long currentTtlMsec;

        /** Current screen-capture-blocking state; null means unset. */
        public Boolean currentScreenCaptureBlockingEnabled;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param publicKeys Public keys for the updated roster.
         * @param conversationId ID of the group conversation being modified.
         * @param newMemberIds IDs of the members being added.
         * @param currentMemberIds IDs of the current members.
         * @param currentAdminIds IDs of the current admins.
         * @param currentPendingMemberIds IDs of the current pending members.
         */
        public GroupMembersChangeParams(
                List<PublicKeyInput> publicKeys,
                String conversationId,
                List<String> newMemberIds,
                List<String> currentMemberIds,
                List<String> currentAdminIds,
                List<String> currentPendingMemberIds) {
            this.publicKeys = publicKeys;
            this.conversationId = conversationId;
            this.newMemberIds = newMemberIds;
            this.currentMemberIds = currentMemberIds;
            this.currentAdminIds = currentAdminIds;
            this.currentPendingMemberIds = currentPendingMemberIds;
        }
    }

    /** Parameters for {@link Chat#prepareGroupCreate}. */
    public static final class GroupCreateParams {
        /** Public keys for the new roster. */
        public final List<PublicKeyInput> publicKeys;

        /** ID of the group conversation being created. */
        public final String conversationId;

        /** IDs of the initial members. */
        public final List<String> memberIds;

        /** IDs of the initial admins. */
        public final List<String> adminIds;

        /** User ID of the sender signing the create; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /** Group title, if any. */
        public String title;

        /** Group avatar URL, if any. */
        public String avatarUrl;

        /** Disappearing-message TTL in milliseconds, if any. */
        public Long ttlMsec;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param publicKeys Public keys for the new roster.
         * @param conversationId ID of the group conversation being created.
         * @param memberIds IDs of the initial members.
         * @param adminIds IDs of the initial admins.
         */
        public GroupCreateParams(
                List<PublicKeyInput> publicKeys,
                String conversationId,
                List<String> memberIds,
                List<String> adminIds) {
            this.publicKeys = publicKeys;
            this.conversationId = conversationId;
            this.memberIds = memberIds;
            this.adminIds = adminIds;
        }
    }

    /** Parameters for {@link Chat#setIdentity}. */
    public static final class SetIdentityParams {
        /** Your user ID: the sender of everything this chat signs. */
        public final String userId;

        /** The {@code public_key_version} the X API returned when your keys were registered. */
        public final String signingKeyVersion;

        /**
         * Create params with both fields.
         *
         * @param userId Your user ID.
         * @param signingKeyVersion Your registered {@code public_key_version}.
         */
        public SetIdentityParams(String userId, String signingKeyVersion) {
            this.userId = userId;
            this.signingKeyVersion = signingKeyVersion;
        }
    }

    /** Parameters for {@link Chat#importKeys}. */
    public static final class ImportKeysParams {
        /** The key blob {@link Chat#exportKeys} returned: 32 or 64 bytes. */
        public final byte[] keys;

        /**
         * The {@code public_key_version} the X API returned when the keys were registered; null
         * leaves the signing-key version unset.
         */
        public String signingKeyVersion;

        /**
         * Create params with the key blob; {@link #signingKeyVersion} defaults to null.
         *
         * @param keys The key blob {@link Chat#exportKeys} returned.
         */
        public ImportKeysParams(byte[] keys) {
            this.keys = keys;
        }

        /**
         * Create params with the key blob and its registered {@code public_key_version}.
         *
         * @param keys The key blob {@link Chat#exportKeys} returned.
         * @param signingKeyVersion The {@code public_key_version} the keys were registered under.
         */
        public ImportKeysParams(byte[] keys, String signingKeyVersion) {
            this.keys = keys;
            this.signingKeyVersion = signingKeyVersion;
        }
    }

    /** Parameters for {@link Chat#decryptEvent}. */
    public static final class DecryptEventParams {
        /** The base64 event, as delivered. */
        public final String eventB64;

        /**
         * Version &#8594; raw 32-byte conversation key, from {@link Chat#decryptEvents} or
         * {@link Chat#extractConversationKeys}. Null for events without message contents, or to
         * take the keys from the opt-in key cache ({@link Chat#setCacheKeys}).
         */
        public final Map<String, byte[]> conversationKeys;

        /**
         * Signing keys to verify the event with; null or empty uses the keys stored via
         * {@link Chat#setSigningKeys}. The SDK picks the sender's key for the version the event
         * carries.
         */
        public List<SigningKeyEntry> signingKeys;

        /**
         * Create params with the required fields; {@link #signingKeys} defaults to null.
         *
         * @param eventB64 The base64 event, as delivered.
         * @param conversationKeys Version &#8594; raw 32-byte conversation key.
         */
        public DecryptEventParams(String eventB64, Map<String, byte[]> conversationKeys) {
            this.eventB64 = eventB64;
            this.conversationKeys = conversationKeys;
        }

        /**
         * Create params without conversation keys, for events without message contents, or to
         * take the keys from the opt-in key cache.
         *
         * @param eventB64 The base64 event, as delivered.
         */
        public DecryptEventParams(String eventB64) {
            this(eventB64, null);
        }
    }

    /** Parameters for {@link Chat#decryptEvents}. */
    public static final class DecryptEventsParams {
        /**
         * The base64 events, as delivered. Their key changes supply the conversation keys the
         * messages among them are decrypted with.
         */
        public final List<String> events;

        /**
         * Signing keys of all participants; null or empty uses the keys stored via
         * {@link Chat#setSigningKeys}.
         */
        public List<SigningKeyEntry> signingKeys;

        /**
         * Create params with the required fields; {@link #signingKeys} defaults to null.
         *
         * @param events The base64 events, as delivered.
         */
        public DecryptEventsParams(List<String> events) {
            this.events = events;
        }
    }

    /** Parameters for {@link Chat#encryptFile}. */
    public static final class EncryptFileParams {
        /** The file to encrypt. */
        public final byte[] file;

        /**
         * The {@link SendPayload#eventB64} of the payload that {@link Chat#encryptMessage} or
         * {@link Chat#encryptReply} returned for the message carrying the file.
         */
        public final String eventB64;

        /** The media hash key the file's upload started with, as listed in the message's attachments. */
        public final String mediaHashKey;

        /**
         * The raw 32-byte conversation key the message was encrypted under; with {@link
         * #conversationKeyVersion} null too, it resolves from the key cache, as for {@link
         * EncryptMessageParams}.
         */
        public byte[] conversationKey;

        /** The version of {@link #conversationKey}: the message's key version. */
        public String conversationKeyVersion;

        /**
         * Create params with the required fields; the conversation key pair defaults to the key cache.
         *
         * @param file The file to encrypt.
         * @param eventB64 The {@link SendPayload#eventB64} of the message carrying the file.
         * @param mediaHashKey The media hash key the file's upload started with.
         */
        public EncryptFileParams(byte[] file, String eventB64, String mediaHashKey) {
            this.file = file;
            this.eventB64 = eventB64;
            this.mediaHashKey = mediaHashKey;
        }
    }

    /**
     * Parameters for {@link Chat#fileEncryptor}: those of {@link EncryptFileParams} apart from the
     * file, which is fed to the encryptor.
     */
    public static final class FileEncryptorParams {
        /** The {@link SendPayload#eventB64} of the message carrying the file. */
        public final String eventB64;

        /** The media hash key the file's upload started with, as listed in the message's attachments. */
        public final String mediaHashKey;

        /** The raw 32-byte conversation key the message was encrypted under; null resolves it from the key cache. */
        public byte[] conversationKey;

        /** The version of {@link #conversationKey}: the message's key version. */
        public String conversationKeyVersion;

        /**
         * Create params with the required fields; the conversation key pair defaults to the key cache.
         *
         * @param eventB64 The {@link SendPayload#eventB64} of the message carrying the file.
         * @param mediaHashKey The media hash key the file's upload started with.
         */
        public FileEncryptorParams(String eventB64, String mediaHashKey) {
            this.eventB64 = eventB64;
            this.mediaHashKey = mediaHashKey;
        }
    }

    /** Parameters for {@link Chat#decryptFile}. */
    public static final class DecryptFileParams {
        /** The encrypted file, as downloaded. */
        public final byte[] encrypted;

        /** The base64 event of the message that carries the file, as passed to {@link Chat#decryptEvent}. */
        public final String eventB64;

        /**
         * The conversation's key map, as passed to {@link Chat#decryptEvent}; it must hold the key
         * for the message's version.
         */
        public final Map<String, byte[]> conversationKeys;

        /**
         * The file's media hash key from the decrypted message: a media attachment, a link card's
         * banner or favicon, or media quoted in its reply preview.
         */
        public final String mediaHashKey;

        /**
         * Create params with the required fields.
         *
         * @param encrypted The encrypted file, as downloaded.
         * @param eventB64 The base64 event of the message that carries the file.
         * @param conversationKeys Version &#8594; raw 32-byte conversation key.
         * @param mediaHashKey The file's media hash key from the decrypted message.
         */
        public DecryptFileParams(
                byte[] encrypted, String eventB64, Map<String, byte[]> conversationKeys, String mediaHashKey) {
            this.encrypted = encrypted;
            this.eventB64 = eventB64;
            this.conversationKeys = conversationKeys;
            this.mediaHashKey = mediaHashKey;
        }
    }

    /**
     * Parameters for {@link Chat#fileDecryptor}: those of {@link DecryptFileParams} apart from the
     * encrypted file, which is fed to the decryptor.
     */
    public static final class FileDecryptorParams {
        /** The base64 event of the message that carries the file, as passed to {@link Chat#decryptEvent}. */
        public final String eventB64;

        /**
         * The conversation's key map, as passed to {@link Chat#decryptEvent}; it must hold the key
         * for the message's version.
         */
        public final Map<String, byte[]> conversationKeys;

        /**
         * The file's media hash key from the decrypted message: a media attachment, a link card's
         * banner or favicon, or media quoted in its reply preview.
         */
        public final String mediaHashKey;

        /**
         * Create params with the required fields.
         *
         * @param eventB64 The base64 event of the message that carries the file.
         * @param conversationKeys Version &#8594; raw 32-byte conversation key.
         * @param mediaHashKey The file's media hash key from the decrypted message.
         */
        public FileDecryptorParams(String eventB64, Map<String, byte[]> conversationKeys, String mediaHashKey) {
            this.eventB64 = eventB64;
            this.conversationKeys = conversationKeys;
            this.mediaHashKey = mediaHashKey;
        }
    }

    /**
     * Parameters for {@link Chat#prepareMessageDelete}.
     *
     * <p>A delete is a signed plaintext event, not an encrypted message, so no
     * conversation key is involved: the result is an action signature the
     * caller submits alongside the delete request.
     */
    public static final class MessageDeleteParams {
        /** ID of the conversation the messages belong to. */
        public final String conversationId;

        /** Sequence IDs of the messages to delete. */
        public final List<String> sequenceIds;

        /** Delete for every participant (true, own messages only) or only from the caller's view (false). */
        public final boolean deleteForAll;

        /** User ID of the sender signing the delete; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param conversationId ID of the conversation the messages belong to.
         * @param sequenceIds Sequence IDs of the messages to delete.
         * @param deleteForAll Delete for every participant (true, own messages
         *     only) or only from the caller's view (false).
         */
        public MessageDeleteParams(String conversationId, List<String> sequenceIds, boolean deleteForAll) {
            this.conversationId = conversationId;
            this.sequenceIds = sequenceIds;
            this.deleteForAll = deleteForAll;
        }
    }

    /**
     * Parameters for {@link Chat#prepareMarkConversationRead}.
     *
     * <p>A read receipt is a signed plaintext event, not an encrypted message,
     * so no conversation key is involved: the result is an action signature
     * the caller submits alongside the mark-read request.
     */
    public static final class MarkConversationReadParams {
        /** ID of the conversation being marked read. */
        public final String conversationId;

        /** Sequence ID of the newest event read. */
        public final String seenUntilSequenceId;

        /** When the conversation was read, in milliseconds since the Unix epoch; the current time when null. */
        public Long seenAtMsec;

        /** User ID of the sender signing the read receipt; resolves from the session identity when null. */
        public String senderId;

        /** Version of the sender's signing key; resolves from the session identity when null. */
        public String signingKeyVersion;

        /**
         * Create params with the required fields; all optional fields default to null.
         *
         * @param conversationId ID of the conversation being marked read.
         * @param seenUntilSequenceId Sequence ID of the newest event read.
         */
        public MarkConversationReadParams(String conversationId, String seenUntilSequenceId) {
            this.conversationId = conversationId;
            this.seenUntilSequenceId = seenUntilSequenceId;
        }
    }
}
