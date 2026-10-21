// Integration tests for the ChatXdk .NET bindings.
//
// These tests require the native library (chat_xdk_dotnet.dylib / .so / .dll)
// to be built and on the library path:
//
//   cargo build -p chat-xdk-dotnet --release
//
// Then copy the resulting library next to the test assembly (or set
// DYLD_LIBRARY_PATH / LD_LIBRARY_PATH / PATH) before running:
//
//   dotnet test
//
// The tests intentionally do NOT make network calls — they test crypto
// operations that work without a real Juicebox backend by using
// ImportKeys / ExportKeys instead of Setup / Unlock.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace ChatXdk.Tests
{
    public class ChatTests
    {
        // Helpers

        /// <summary>Deterministic cross-binding vectors from tests/fixtures/sdk_vectors.json.</summary>
        private sealed class SdkVectors
        {
            [JsonPropertyName("private_keys_concat_b64")] public string PrivateKeysConcatB64 { get; init; } = "";
            [JsonPropertyName("message_utf8")] public string MessageUtf8 { get; init; } = "";
            [JsonPropertyName("conversation_key_b64")] public string ConversationKeyB64 { get; init; } = "";
            [JsonPropertyName("identity_public_b64")] public string IdentityPublicB64 { get; init; } = "";
            [JsonPropertyName("signing_public_b64")] public string SigningPublicB64 { get; init; } = "";
            [JsonPropertyName("signature_b64")] public string SignatureB64 { get; init; } = "";
            [JsonPropertyName("identity_public_key_signature_b64")] public string IdentityPublicKeySignatureB64 { get; init; } = "";
            [JsonPropertyName("event_failure_b64")] public string EventFailureB64 { get; init; } = "";
            [JsonPropertyName("event_key_change_b64")] public string EventKeyChangeB64 { get; init; } = "";
            [JsonPropertyName("event_message_b64")] public string EventMessageB64 { get; init; } = "";
            [JsonPropertyName("event_reply_valid_b64")] public string EventReplyValidB64 { get; init; } = "";
            [JsonPropertyName("event_reply_forged_b64")] public string EventReplyForgedB64 { get; init; } = "";
            [JsonPropertyName("event_reply_text")] public string EventReplyText { get; init; } = "";
            [JsonPropertyName("event_conversation_id")] public string EventConversationId { get; init; } = "";
            [JsonPropertyName("event_garbage_b64")] public string EventGarbageB64 { get; init; } = "";
            [JsonPropertyName("event_sender_id")] public string EventSenderId { get; init; } = "";
            [JsonPropertyName("event_conversation_key_version")] public string EventConversationKeyVersion { get; init; } = "";
            [JsonPropertyName("event_signing_key_version")] public string EventSigningKeyVersion { get; init; } = "";
            [JsonPropertyName("event_recipient_key_version")] public string EventRecipientKeyVersion { get; init; } = "";
            [JsonPropertyName("event_message_text")] public string EventMessageText { get; init; } = "";

            [JsonPropertyName("message_key_conversation_key_hex")] public string MessageKeyConversationKeyHex { get; init; } = "";
            [JsonPropertyName("message_key_conversation_key_version")] public string MessageKeyConversationKeyVersion { get; init; } = "";
            [JsonPropertyName("message_key_sender_id")] public string MessageKeySenderId { get; init; } = "";
            [JsonPropertyName("message_key_short_conversation_key_hex")] public string MessageKeyShortConversationKeyHex { get; init; } = "";
            [JsonPropertyName("message_key_short_conversation_key_version")] public string MessageKeyShortConversationKeyVersion { get; init; } = "";
            [JsonPropertyName("message_key_short_sender_id")] public string MessageKeyShortSenderId { get; init; } = "";
            [JsonPropertyName("event_message_key_b64")] public string EventMessageKeyB64 { get; init; } = "";
            [JsonPropertyName("event_message_key_text")] public string EventMessageKeyText { get; init; } = "";
            [JsonPropertyName("event_message_key_short_b64")] public string EventMessageKeyShortB64 { get; init; } = "";
            [JsonPropertyName("event_message_key_short_text")] public string EventMessageKeyShortText { get; init; } = "";
            [JsonPropertyName("event_key_change_message_key_b64")] public string EventKeyChangeMessageKeyB64 { get; init; } = "";
            [JsonPropertyName("event_reply_message_key_b64")] public string EventReplyMessageKeyB64 { get; init; } = "";
            [JsonPropertyName("event_reply_message_key_text")] public string EventReplyMessageKeyText { get; init; } = "";
            [JsonPropertyName("media_first_hash_key")] public string MediaFirstHashKey { get; init; } = "";
            [JsonPropertyName("media_first_encrypted_b64")] public string MediaFirstEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_first_plaintext_b64")] public string MediaFirstPlaintextB64 { get; init; } = "";
            [JsonPropertyName("media_second_hash_key")] public string MediaSecondHashKey { get; init; } = "";
            [JsonPropertyName("media_second_encrypted_b64")] public string MediaSecondEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_second_plaintext_b64")] public string MediaSecondPlaintextB64 { get; init; } = "";
            [JsonPropertyName("media_short_hash_key")] public string MediaShortHashKey { get; init; } = "";
            [JsonPropertyName("media_short_encrypted_b64")] public string MediaShortEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_short_plaintext_b64")] public string MediaShortPlaintextB64 { get; init; } = "";
            [JsonPropertyName("event_link_card_b64")] public string EventLinkCardB64 { get; init; } = "";
            [JsonPropertyName("media_banner_hash_key")] public string MediaBannerHashKey { get; init; } = "";
            [JsonPropertyName("media_banner_encrypted_b64")] public string MediaBannerEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_banner_plaintext_b64")] public string MediaBannerPlaintextB64 { get; init; } = "";
            [JsonPropertyName("media_favicon_hash_key")] public string MediaFaviconHashKey { get; init; } = "";
            [JsonPropertyName("media_favicon_encrypted_b64")] public string MediaFaviconEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_favicon_plaintext_b64")] public string MediaFaviconPlaintextB64 { get; init; } = "";
            [JsonPropertyName("event_conversation_key_media_b64")] public string EventConversationKeyMediaB64 { get; init; } = "";
            [JsonPropertyName("media_conversation_key_hash_key")] public string MediaConversationKeyHashKey { get; init; } = "";
            [JsonPropertyName("media_conversation_key_encrypted_b64")] public string MediaConversationKeyEncryptedB64 { get; init; } = "";
            [JsonPropertyName("media_conversation_key_plaintext_b64")] public string MediaConversationKeyPlaintextB64 { get; init; } = "";
            [JsonPropertyName("event_unencrypted_b64")] public string EventUnencryptedB64 { get; init; } = "";
            [JsonPropertyName("media_unencrypted_hash_key")] public string MediaUnencryptedHashKey { get; init; } = "";
            [JsonPropertyName("payload_message_v10_cev1")] public string PayloadMessageV10Cev1 { get; init; } = "";
            [JsonPropertyName("payload_message_v10")] public string PayloadMessageV10 { get; init; } = "";
            [JsonPropertyName("signature_v10_cev1_public_key_b64")] public string SignatureV10Cev1PublicKeyB64 { get; init; } = "";
            [JsonPropertyName("signature_v10_cev1_b64")] public string SignatureV10Cev1B64 { get; init; } = "";
        }

        private static SdkVectors LoadVectors()
        {
            // Walk up from the test assembly to the repo root that holds the fixture.
            var dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "tests", "fixtures", "sdk_vectors.json")))
                dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            var json = File.ReadAllText(Path.Combine(dir!, "tests", "fixtures", "sdk_vectors.json"));
            return JsonSerializer.Deserialize<SdkVectors>(json)!;
        }

        /// <summary>
        /// Create a Chat that already has keys loaded (without Juicebox).
        /// </summary>
        private static Chat CreateUnlocked()
        {
            var chat = new Chat();
            // GenerateKeypairs populates the in-memory keys.
            chat.GenerateKeypairs();
            // ExportKeys + ImportKeys is the round-trip that bypasses Juicebox.
            var exported = chat.ExportKeys();
            Assert.NotNull(exported);
            chat.ImportKeys(new ImportKeysParams(exported!));
            return chat;
        }

        /// <summary>
        /// Produce a fresh conversation key via a prepared key change (for crypto tests).
        /// </summary>
        private static byte[] NewConvKey(Chat chat)
        {
            var prep = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = chat.GetPublicKeys().Identity, KeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });
            return prep.ConversationKey!;
        }

        /// <summary>Signing keys matching the fixture's event vectors.</summary>
        private static SigningKeyEntry[] EventSigningKeys(SdkVectors v) => SigningKeysFor(v, v.EventSenderId);

        /// <summary>The key map of the fixture conversation key, which opens the
        /// conversation-key media message and the reply vectors.</summary>
        private static Dictionary<string, byte[]> ConversationKeys(SdkVectors v) =>
            new() { [v.EventConversationKeyVersion] = Convert.FromBase64String(v.ConversationKeyB64) };

        /// <summary>The key map that opens the message-key and link-card vectors.</summary>
        private static Dictionary<string, byte[]> MessageKeyConversationKeys(SdkVectors v) =>
            new() { [v.MessageKeyConversationKeyVersion] = ChatXdkUtilities.HexToBytes(v.MessageKeyConversationKeyHex) };

        /// <summary>Decrypt media whole and in 700-byte chunks on a fresh instance,
        /// checking both agree.</summary>
        private static byte[] OpenMedia(
            string eventB64, Dictionary<string, byte[]> keys, string mediaHashKey, string encryptedB64)
        {
            using var chat = new Chat();
            var encrypted = Convert.FromBase64String(encryptedB64);
            var whole = chat.DecryptFile(new DecryptFileParams(encrypted, eventB64, keys, mediaHashKey));
            using var decryptor = chat.FileDecryptor(new FileDecryptorParams(eventB64, keys, mediaHashKey));
            var incremental = new List<byte>();
            for (var i = 0; i < encrypted.Length; i += 700)
                incremental.AddRange(decryptor.Push(encrypted[i..Math.Min(i + 700, encrypted.Length)]));
            incremental.AddRange(decryptor.Finish());
            Assert.Equal(whole, incremental.ToArray());
            return whole;
        }

        /// <summary>The fixture signing key, registered to each of <paramref name="userIds"/>.</summary>
        private static SigningKeyEntry[] SigningKeysFor(SdkVectors v, params string[] userIds) =>
            userIds.Select(userId => new SigningKeyEntry
            {
                UserId = userId,
                PublicKeyVersion = v.EventSigningKeyVersion,
                PublicKey = v.SigningPublicB64,
                IdentityPublicKey = v.IdentityPublicB64,
                IdentityPublicKeySignature = v.IdentityPublicKeySignatureB64,
            }).ToArray();

        // Lifecycle

        [Fact]
        public void Dispose_IsIdempotent()
        {
            var chat = new Chat();
            chat.Dispose();
            chat.Dispose(); // must not throw
        }

        [Fact]
        public void ThrowsAfterDispose()
        {
            var chat = new Chat();
            chat.Dispose();
            Assert.Throws<ObjectDisposedException>(() => _ = chat.IsUnlocked);
        }

        // Juicebox configuration

        [Fact]
        public void UpdateConfig_AcceptsXApiJuiceboxConfigShape()
        {
            using var chat = new Chat();

            // The X API juicebox_config object (key_store_token_map_json +
            // token_map) must be accepted as-is; the embedded config carries
            // realm public keys and server thresholds that the realms require.
            var xApiConfig = @"{
                ""key_store_token_map_json"": ""{\""realms\"":[{\""id\"":\""aa11\"",\""address\"":\""https://realm-b.example/\""},{\""id\"":\""bb22\"",\""address\"":\""https://realm-east.example/\"",\""public_key\"":\""e8b2\""}],\""register_threshold\"":2,\""recover_threshold\"":2,\""pin_hashing_mode\"":\""Standard2019\""}"",
                ""max_guess_count"": 20,
                ""token_map"": [
                    {""key"": ""aa11"", ""value"": {""address"": ""https://realm-b.example/"", ""token"": ""t1""}},
                    {""key"": ""bb22"", ""value"": {""address"": ""https://realm-east.example/"", ""token"": ""t2""}}
                ]
            }";
            chat.UpdateConfig(xApiConfig); // must not throw
        }

        [Fact]
        public void UpdateConfig_RejectsMalformedKeyStoreTokenMapJson()
        {
            using var chat = new Chat();

            // A malformed embedded config must error, not silently fall back
            // to the lossy token_map derivation.
            var badConfig = @"{
                ""key_store_token_map_json"": ""not json"",
                ""token_map"": [
                    {""key"": ""aa11"", ""value"": {""address"": ""https://realm-b.example/"", ""token"": ""t1""}}
                ]
            }";
            var ex = Assert.Throws<ChatXdkException>(() => chat.UpdateConfig(badConfig));
            Assert.Contains("Invalid key_store_token_map_json", ex.Message);
        }

        [Fact]
        public void GuessesRemaining_ParsedFromInvalidPinMessage()
        {
            // The core's invalid-PIN unlock error carries the stable
            // "guesses_remaining=N" token in the message; 0 means exhausted.
            Assert.Equal(3,
                new ChatXdkException("Juicebox error: Invalid PIN: guesses_remaining=3").GuessesRemaining);
            Assert.Equal(0,
                new ChatXdkException("Juicebox error: Invalid PIN: guesses_remaining=0").GuessesRemaining);
            Assert.Null(new ChatXdkException("Juicebox error: Invalid PIN").GuessesRemaining);
            // The count is read only from the invalid-PIN form, not from
            // unrelated messages that happen to contain the token.
            Assert.Null(new ChatXdkException("Delete failed: guesses_remaining=7").GuessesRemaining);
        }

        [Fact]
        public void GuessesRemaining_NullOnNonPinErrors()
        {
            using var chat = new Chat();
            var ex = Assert.Throws<ChatXdkException>(() => chat.UpdateConfig("not json"));
            Assert.Null(ex.GuessesRemaining);
        }

        // Key generation

        [Fact]
        public void GenerateKeypairs_ReturnsValidPayload()
        {
            using var chat = new Chat();
            var payload = chat.GenerateKeypairs();

            Assert.NotEmpty(payload.PublicKey.PublicKey);
            Assert.NotEmpty(payload.PublicKey.SigningPublicKey);
            Assert.NotEmpty(payload.PublicKey.IdentityPublicKeySignature);
            Assert.Equal("CustomPin", payload.PublicKey.RegistrationMethod);

            // Fingerprint: SHA-256 → 32 bytes → 43 URL-safe base64 chars (no padding)
            Assert.NotNull(payload.PublicKey.PublicKeyFingerprint);
            Assert.Equal(43, payload.PublicKey.PublicKeyFingerprint!.Length);
        }

        [Fact]
        public void GeneratedKeys_SignOnlyWithTheRegisteredVersion()
        {
            using var chat = new Chat();
            chat.GenerateKeypairs();
            var deleteParams = new MessageDeleteParams(
                "1234-5678", new[] { "seq-1" }, deleteForAll: false)
            {
                SenderId = "1234",
            };
            var ex = Assert.Throws<ChatXdkException>(() => chat.PrepareMessageDelete(deleteParams));
            Assert.Contains("signing_key_version", ex.Message);

            chat.SetIdentity(new SetIdentityParams("1234", "1700000000123"));
            Assert.Equal("1700000000123", chat.PrepareMessageDelete(deleteParams).PublicKeyVersion);

            // Restored keys carry the version passed to ImportKeys, and none
            // without it.
            var keys = chat.ExportKeys()!;
            using var restored = new Chat();
            restored.ImportKeys(new ImportKeysParams(keys) { SigningKeyVersion = "1700000000456" });
            Assert.Equal("1700000000456", restored.PrepareMessageDelete(deleteParams).PublicKeyVersion);
            restored.ImportKeys(new ImportKeysParams(keys));
            Assert.Throws<ChatXdkException>(() => restored.PrepareMessageDelete(deleteParams));
        }

        [Fact]
        public void IsUnlocked_TrueAfterImport()
        {
            using var chat = CreateUnlocked();
            Assert.True(chat.IsUnlocked);
            Assert.True(chat.HasIdentityKey);
        }

        [Fact]
        public void Lock_ClearsKeys()
        {
            using var chat = CreateUnlocked();
            Assert.True(chat.IsUnlocked);
            chat.Lock();
            Assert.False(chat.IsUnlocked);
        }

        [Fact]
        public void GetPublicKeys_ReturnsNonEmptyStrings()
        {
            using var chat = CreateUnlocked();
            var keys = chat.GetPublicKeys();
            Assert.NotEmpty(keys.Identity);
            Assert.NotEmpty(keys.Signing);
        }

        [Fact]
        public void GetPublicKeyFingerprint_Returns43Chars()
        {
            using var chat = CreateUnlocked();
            var fp = chat.GetPublicKeyFingerprint();
            Assert.Equal(43, fp.Length);
        }

        [Fact]
        public void ExportImport_RoundTrip()
        {
            using var chat = CreateUnlocked();
            var original = chat.GetPublicKeys();

            var exported = chat.ExportKeys();
            Assert.NotNull(exported);
            Assert.Equal(64, exported!.Length); // identity(32) + signing(32)

            chat.Lock();
            Assert.False(chat.IsUnlocked);

            chat.ImportKeys(new ImportKeysParams(exported));
            Assert.True(chat.IsUnlocked);

            var reimported = chat.GetPublicKeys();
            Assert.Equal(original.Identity, reimported.Identity);
            Assert.Equal(original.Signing, reimported.Signing);
        }

        [Fact]
        public void ImportInvalidKeys_Throws()
        {
            using var chat = new Chat();
            Assert.Throws<ChatXdkException>(() => chat.ImportKeys(new ImportKeysParams(new byte[16])));
            Assert.Throws<ChatXdkException>(() => chat.ImportKeys(new ImportKeysParams(Array.Empty<byte>())));
        }

        [Fact]
        public void ExportKeys_IdentityOnly_Returns32Bytes()
        {
            using var source = CreateUnlocked();
            var identityOnly = source.ExportKeys()!.Take(32).ToArray();

            // Identity-only sessions can export (32 bytes), matching core;
            // only a session with no identity key at all returns null.
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(identityOnly));
            var exported = chat.ExportKeys();
            Assert.NotNull(exported);
            Assert.Equal(identityOnly, exported);
        }

        [Fact]
        public void EncryptMessage_MediaAttachment_MissingRequiredField_Throws()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            // Core requires the media fields; an attachment missing one is
            // rejected rather than silently defaulted.
            Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(new EncryptMessageParams("conv-1", "bad attachment")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Attachments = new List<AttachmentDescriptor>
                {
                    new AttachmentDescriptor { AttachmentType = "media", MediaHashKey = "h" },
                },
            }));
        }

        [Fact]
        public void EncryptMessage_MixedAttachmentTypes_Throws()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            // Only image/gif/video media may appear in multiples; any other
            // attachment type must be the message's only attachment.
            var ex = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(new EncryptMessageParams("conv-1", "mixed attachments")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Attachments = new List<AttachmentDescriptor>
                {
                    AttachmentDescriptor.Media("hash", 100, 100, 1000, "pic.jpg", mediaType: 1),
                    AttachmentDescriptor.UrlCard("https://example.com"),
                },
            }));
            Assert.Contains("attachment combination", ex.Message);
        }

        // Encrypt / decrypt message

        [Fact]
        public void EncryptMessage_ReturnsValidPayload()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Hello from .NET!")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
            });

            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.Signature);
            Assert.NotEmpty(payload.EncodedEventSignature);
            Assert.Equal("1", payload.ConversationKeyVersion);
            Assert.Equal("7", payload.SignatureInfo.SignatureVersion);
            Assert.True(payload.ShouldNotify);
            Assert.NotEmpty(payload.XdkVersion);
            // The SDK generates and returns the message id.
            Assert.NotEmpty(payload.MessageId);
        }

        [Fact]
        public void EncryptMessage_ShouldNotifyFalse_PropagatesCorrectly()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Silent message")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                ShouldNotify = false,
            });

            Assert.False(payload.ShouldNotify);
        }

        [Fact]
        public void EncryptMessage_WithTtl_Succeeds()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Disappearing!")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                TtlMsec = 30_000,
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        [Fact]
        public void EncryptMessage_WithEntities_Succeeds()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Hello @world https://x.com")
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Entities = new List<EntityDescriptor>
                {
                    new() { Start = 6, End = 12, EntityType = "mention" },
                    new() { Start = 13, End = 26, EntityType = "url" },
                },
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        [Fact]
        public void EncryptMessage_WithMediaAttachment_Succeeds()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("1001", "66"));
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Check this out")
            {
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Attachments = new List<AttachmentDescriptor>
                {
                    AttachmentDescriptor.Media("hash123", 1920, 1080, 512_000, "photo.jpg", mediaType: 1),
                },
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        [Fact]
        public void EncryptMessage_UrlAttachmentWithBannerImage_Succeeds()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var attachment = AttachmentDescriptor.UrlCard(
                "https://example.com/product",
                "Example Product",
                bannerImage: new UrlAttachmentImageDescriptor
                {
                    MediaHashKey = "banner-hash",
                    FilesizeBytes = 24_000,
                    Filename = "banner.jpg",
                    Width = 1200,
                    Height = 630,
                },
                faviconImage: new UrlAttachmentImageDescriptor
                {
                    MediaHashKey = "favicon-hash",
                    FilesizeBytes = 1_200,
                    Filename = "favicon.ico",
                });

            // The [JsonPropertyName] attributes are what carry the banner to
            // core across the FFI; serialize the descriptor and confirm the
            // snake_case keys core deserializes are present, so a rename can't
            // silently drop the image (core ignores unknown keys).
            var json = System.Text.Json.JsonSerializer.Serialize(attachment);
            foreach (var key in new[]
                { "banner_image", "favicon_image", "media_hash_key", "filesize_bytes", "filename" })
            {
                Assert.Contains(key, json);
            }

            chat.SetIdentity(new SetIdentityParams("1001", "66"));
            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Check this out")
            {
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Attachments = new List<AttachmentDescriptor> { attachment },
            });

            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.Signature);
        }

        // EncryptReply

        [Fact]
        public void EncryptReply_ReturnsValidPayload()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            // Explicit-field form: no raw event in hand, so the preview fields
            // are supplied directly ("" reply target).
            var payload = chat.EncryptReply(new EncryptReplyParams("conv-1", "This is a reply", replyToEvent: null)
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                ReplyToSequenceId = "seq-42",
                ReplyToSenderId = "12345",
                ReplyToText = "Original message",
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        [Fact]
        public void UserIds_AreDigitStrings()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            var ex = Assert.Throws<ChatXdkException>(
                () => chat.SetIdentity(new SetIdentityParams("user-1", "1")));
            Assert.Contains("Invalid user_id 'user-1'", ex.Message);
            ex = Assert.Throws<ChatXdkException>(
                () => chat.SetIdentity(new SetIdentityParams("1001", "v1")));
            Assert.Contains("Invalid signing_key_version 'v1'", ex.Message);
            ex = Assert.Throws<ChatXdkException>(() => chat.EncryptReply(
                new EncryptReplyParams("conv-1", "reply", replyToEvent: null)
                {
                    SenderId = "1001",
                    SigningKeyVersion = "1",
                    ConversationKey = ckey,
                    ConversationKeyVersion = "1",
                    ReplyToSequenceId = "seq-42",
                    ReplyToSenderId = "12x",
                }));
            Assert.Contains("Invalid reply_to_sender_id '12x'", ex.Message);
        }

        // EncryptAdd/RemoveReaction

        [Fact]
        public void EncryptAddReaction_ReturnsValidPayload()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            // Explicit-field form: conversation id + target sequence id instead
            // of the raw target event.
            var payload = chat.EncryptAddReaction(new EncryptReactionParams(targetEvent: null, "👍")
            {
                ConversationId = "conv-1",
                TargetMessageSequenceId = "seq-99",
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        [Fact]
        public void EncryptRemoveReaction_ReturnsValidPayload()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptRemoveReaction(new EncryptReactionParams(targetEvent: null, "👍")
            {
                ConversationId = "conv-1",
                TargetMessageSequenceId = "seq-99",
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        // EncryptEdit

        [Fact]
        public void EncryptEdit_ReturnsValidPayload()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            // Explicit-field form: conversation id + target sequence id instead
            // of the raw target event.
            var payload = chat.EncryptEdit(new EncryptEditParams(targetEvent: null, "see https://example.com")
            {
                ConversationId = "conv-1",
                TargetMessageSequenceId = "seq-99",
                Entities = new[] { new EntityDescriptor { Start = 4, End = 23, EntityType = "url" } },
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
            });

            Assert.NotEmpty(payload.MessageId);
            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.Signature);
            Assert.NotEmpty(payload.EncodedEventSignature);
        }

        // PrepareMessageDelete

        [Fact]
        public void PrepareMessageDelete_SignsCanonicalPayload()
        {
            using var chat = CreateUnlocked();

            // A 1:1 id is signed in its canonical colon form; delete-for-all
            // signs the wire action 2.
            var sig = chat.PrepareMessageDelete(new MessageDeleteParams(
                "222-111", new[] { "seq-10", "seq-11" }, deleteForAll: true)
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            });

            Assert.NotEmpty(sig.MessageId);
            Assert.NotEmpty(sig.EncodedMessageEventDetail);
            Assert.NotEmpty(sig.Signature);
            Assert.Equal(
                $"MessageDeleteEvent,{sig.MessageId},111,111:222,2,seq-10,seq-11",
                sig.SignaturePayload);
        }

        [Fact]
        public void PrepareMessageDelete_ForSelf()
        {
            using var chat = CreateUnlocked();

            // Group ids pass through unchanged; delete-for-self signs the wire
            // action 1.
            var sig = chat.PrepareMessageDelete(new MessageDeleteParams(
                "g999", new[] { "seq-1" }, deleteForAll: false)
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            });

            Assert.Equal(
                $"MessageDeleteEvent,{sig.MessageId},111,g999,1,seq-1",
                sig.SignaturePayload);
        }

        // PrepareMarkConversationRead

        [Fact]
        public void PrepareMarkConversationRead_SignsCanonicalPayload()
        {
            using var chat = CreateUnlocked();

            // A 1:1 id is signed in its canonical colon form, followed by the
            // read point and its time.
            var sig = chat.PrepareMarkConversationRead(new MarkConversationReadParams(
                "222-111", "2011626338877079553")
            {
                SeenAtMsec = 1700000000123,
                SenderId = "111",
                SigningKeyVersion = "1",
            });

            Assert.NotEmpty(sig.MessageId);
            Assert.NotEmpty(sig.EncodedMessageEventDetail);
            Assert.Equal("1", sig.PublicKeyVersion);
            Assert.Equal(
                $"MarkConversationReadEvent,{sig.MessageId},111,111:222,2011626338877079553,1700000000123",
                sig.SignaturePayload);
            var signature = Convert.FromBase64String(
                sig.Signature.PadRight(sig.Signature.Length + (4 - sig.Signature.Length % 4) % 4, '='));
            Assert.True(chat.Verify(
                chat.GetPublicKeys().Signing, signature, System.Text.Encoding.UTF8.GetBytes(sig.SignaturePayload)));
        }

        [Fact]
        public void PrepareMarkConversationRead_DefaultsToSessionIdentityAndNow()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("111", "7"));

            var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var sig = chat.PrepareMarkConversationRead(new MarkConversationReadParams("g999", "seq-1"));
            var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            Assert.Equal("7", sig.PublicKeyVersion);
            var prefix = $"MarkConversationReadEvent,{sig.MessageId},111,g999,seq-1,";
            Assert.StartsWith(prefix, sig.SignaturePayload);
            var seenAt = long.Parse(sig.SignaturePayload.Substring(prefix.Length));
            Assert.InRange(seenAt, before, after);
        }

        [Fact]
        public void PrepareMarkConversationRead_RejectsEmptySeenUntil()
        {
            using var chat = CreateUnlocked();

            var ex = Assert.Throws<ChatXdkException>(() => chat.PrepareMarkConversationRead(
                new MarkConversationReadParams("g999", "")
                {
                    SenderId = "111",
                    SigningKeyVersion = "1",
                }));
            Assert.Contains("seen_until_sequence_id is empty", ex.Message);
        }

        // Conversation key encrypt / decrypt

        [Fact]
        public void PrepareConversationKeyChange_Returns32ByteKey()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            Assert.Equal(32, ckey.Length);
        }

        [Fact]
        public void PrepareConversationKeyChange_DecryptRoundTrip()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });

            Assert.Single(prepared.ParticipantKeys);
            Assert.Single(prepared.ActionSignatures);
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            Assert.Equal("", prepared.ActionSignatures[0].SignaturePayload);

            var decrypted = chat.DecryptConversationKey(prepared.ParticipantKeys[0].EncryptedKey);
            Assert.Equal(prepared.ConversationKey, decrypted);
        }

        // File encrypt / decrypt

        // A message with files is built first; each file is then encrypted from the returned
        // EventB64 and the media hash key its attachment names.

        private static AttachmentDescriptor Photo(string mediaHashKey) =>
            AttachmentDescriptor.Media(mediaHashKey, 4, 3, 64, mediaHashKey + ".jpg", mediaType: 1);

        /// <summary>Send a v1 message carrying <paramref name="attachments"/>, check it
        /// verifies, and return its payload.</summary>
        private static SendPayload SendFiles(Chat chat, SdkVectors v, string text, params AttachmentDescriptor[] attachments)
        {
            chat.ApplyFeatureConfig("{\"features\":{\"v1_send\":true}}", chat.FeatureBucket());
            var payload = chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, text)
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
                Attachments = attachments,
            });
            Assert.Equal("10", payload.SignatureInfo.SignatureVersion);
            Assert.Equal(text, DecryptOwnContent(chat, v, payload).GetProperty("text").GetString());
            return payload;
        }

        /// <summary>The event as delivered: <paramref name="eventB64"/> with the sequence id the
        /// server assigns, prepended as Thrift string field 1.</summary>
        private static string Delivered(string eventB64, string sequenceId)
        {
            var id = System.Text.Encoding.UTF8.GetBytes(sequenceId);
            var header = new byte[] { 11, 0, 1, (byte)(id.Length >> 24), (byte)(id.Length >> 16), (byte)(id.Length >> 8), (byte)id.Length };
            return Convert.ToBase64String(header.Concat(id).Concat(Convert.FromBase64String(eventB64)).ToArray());
        }

        [Fact]
        public void EncryptDecryptFile_RoundTrip()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var plaintext = new byte[1024];
            new Random(42).NextBytes(plaintext);
            var payload = SendFiles(chat, v, "a photo", Photo("photo"));

            // A chat with no identity encrypts the file from the payload.
            using var worker = new Chat();
            var encrypted = worker.EncryptFile(new EncryptFileParams(plaintext, payload.EventB64, ConversationKeys(v), "photo"));
            Assert.NotEqual(plaintext, encrypted);
            Assert.Equal(ChatXdkUtilities.EncryptedFileSize((ulong)plaintext.Length), (ulong)encrypted.Length);
            Assert.Equal(plaintext, chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, ConversationKeys(v), "photo")));
        }

        [Fact]
        public void DecryptFile_WrongKey_Throws()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var payload = SendFiles(chat, v, "a photo", Photo("photo"));
            var wrongKeys = new Dictionary<string, byte[]> { [v.EventConversationKeyVersion] = NewConvKey(chat) };
            var ex = Assert.Throws<ChatXdkException>(() => chat.DecryptFile(
                new DecryptFileParams(new byte[64], payload.EventB64, wrongKeys, "photo")));
            Assert.Contains("does not decrypt the message", ex.Message);
        }

        [Fact]
        public void FileDecryptor_RoundTripAndTruncation()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var plaintext = Enumerable.Repeat((byte)0xAB, 5000).ToArray();
            var payload = SendFiles(chat, v, "two photos", Photo("first"), Photo("second"));

            using var encryptor = chat.FileEncryptor(new FileEncryptorParams(payload.EventB64, ConversationKeys(v), "second"));
            var ciphertext = new List<byte>();
            for (var i = 0; i < plaintext.Length; i += 700)
                ciphertext.AddRange(encryptor.Push(plaintext[i..Math.Min(i + 700, plaintext.Length)]));
            ciphertext.AddRange(encryptor.Finish());
            var encrypted = ciphertext.ToArray();

            Assert.Throws<ChatXdkException>(() => chat.DecryptFile(
                new DecryptFileParams(encrypted, payload.EventB64, ConversationKeys(v), "first")));
            using var decryptor = chat.FileDecryptor(new FileDecryptorParams(payload.EventB64, ConversationKeys(v), "second"));
            var output = new List<byte>();
            for (var i = 0; i < encrypted.Length; i += 333)
                output.AddRange(decryptor.Push(encrypted[i..Math.Min(i + 333, encrypted.Length)]));
            output.AddRange(decryptor.Finish());
            Assert.Equal(plaintext, output.ToArray());

            using var truncated = chat.FileDecryptor(new FileDecryptorParams(payload.EventB64, ConversationKeys(v), "second"));
            truncated.Push(encrypted[..^4]);
            var ex = Assert.Throws<ChatXdkException>(() => truncated.Finish());
            Assert.Contains("truncated", ex.Message);
        }

        [Fact]
        public void EncryptFile_LinkCardImagesTakeTheCardsKey()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var payload = SendFiles(chat, v, "a link", AttachmentDescriptor.UrlCard(
                "https://example.com",
                bannerImage: new UrlAttachmentImageDescriptor { MediaHashKey = "banner", FilesizeBytes = 12, Filename = "banner.png" },
                faviconImage: new UrlAttachmentImageDescriptor { MediaHashKey = "favicon", FilesizeBytes = 13, Filename = "favicon.png" }));
            foreach (var name in new[] { "banner", "favicon" })
            {
                var encrypted = chat.EncryptFile(new EncryptFileParams(
                    System.Text.Encoding.UTF8.GetBytes(name + " bytes"), payload.EventB64, ConversationKeys(v), name));
                Assert.Equal(name + " bytes", System.Text.Encoding.UTF8.GetString(
                    chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, ConversationKeys(v), name))));
            }
        }

        [Fact]
        public void AMessageWithFiles_TakesTheIdItsFilesDerive()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var draft = SendFiles(chat, v, "draft", Photo("photo-a"), Photo("photo-b"));
            Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", draft.MessageId);
            var encrypted = chat.EncryptFile(new EncryptFileParams(
                System.Text.Encoding.UTF8.GetBytes("photo b"), draft.EventB64, ConversationKeys(v), "photo-b"));

            // Building the message again gives the same id, so its encrypted files stay valid.
            var rebuilt = SendFiles(chat, v, "final text", Photo("photo-a"), Photo("photo-b"));
            Assert.Equal(draft.MessageId, rebuilt.MessageId);
            Assert.Equal("photo b", System.Text.Encoding.UTF8.GetString(
                chat.DecryptFile(new DecryptFileParams(encrypted, rebuilt.EventB64, ConversationKeys(v), "photo-b"))));

            Assert.NotEqual(draft.MessageId, SendFiles(chat, v, "draft", Photo("photo-b"), Photo("photo-a")).MessageId);
            Assert.NotEqual(SendFiles(chat, v, "no files").MessageId, SendFiles(chat, v, "no files").MessageId);
        }

        [Fact]
        public void FileSendInput_IsChecked()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var ckey = Convert.FromBase64String(v.ConversationKeyB64);

            var ex = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "twice")
                {
                    ConversationKey = ckey,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    Attachments = new[] { Photo("photo"), Photo("photo") },
                }));
            Assert.Contains("media_hash_key 'photo' is in more than one attachment", ex.Message);

            var payload = SendFiles(chat, v, "a photo", Photo("photo"));
            Assert.Contains("is not one of the message's files", Assert.Throws<ChatXdkException>(
                () => chat.EncryptFile(new EncryptFileParams(new byte[] { 1 }, payload.EventB64, ConversationKeys(v), "other"))).Message);
            Assert.Contains("is not 32 bytes", Assert.Throws<ChatXdkException>(
                () => chat.EncryptFile(new EncryptFileParams(new byte[] { 1 }, payload.EventB64,
                    new Dictionary<string, byte[]> { [v.EventConversationKeyVersion] = new byte[3] }, "photo"))).Message);

            // A reply needs the delivered event, which carries the sequence id; the files it
            // quotes belong to the quoted message.
            Assert.Contains("reply_to_event carries no sequence_id", Assert.Throws<ChatXdkException>(
                () => chat.EncryptReply(new EncryptReplyParams(v.EventConversationId, "too early", payload.EventB64)
                {
                    ConversationKey = ckey,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                })).Message);
            var reply = chat.EncryptReply(new EncryptReplyParams(v.EventConversationId, "and mine", Delivered(payload.EventB64, "100"))
            {
                ConversationKey = ckey,
                ConversationKeyVersion = v.EventConversationKeyVersion,
                Attachments = new[] { Photo("reply-photo") },
            });
            Assert.Contains("is media the reply quotes", Assert.Throws<ChatXdkException>(
                () => chat.EncryptFile(new EncryptFileParams(new byte[] { 1 }, reply.EventB64, ConversationKeys(v), "photo"))).Message);

            using var noIdentity = new Chat();
            noIdentity.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));
            Assert.Contains("set_identity", Assert.Throws<ChatXdkException>(
                () => noIdentity.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "a photo")
                {
                    ConversationKey = ckey,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    Attachments = new[] { Photo("photo") },
                })).Message);
        }

        // Sign / verify

        [Fact]
        public void SignVerify_ValidData_ReturnsTrue()
        {
            using var chat = CreateUnlocked();
            var data = System.Text.Encoding.UTF8.GetBytes("test data");
            var signature = chat.Sign(data);
            Assert.Equal(64, signature.Length);

            var publicKeys = chat.GetPublicKeys();
            Assert.True(chat.Verify(publicKeys.Signing, signature, data));
        }

        [Fact]
        public void SignVerify_TamperedData_ReturnsFalse()
        {
            using var chat = CreateUnlocked();
            var signature = chat.Sign(System.Text.Encoding.UTF8.GetBytes("original"));
            var publicKeys = chat.GetPublicKeys();
            Assert.False(chat.Verify(publicKeys.Signing, signature,
                System.Text.Encoding.UTF8.GetBytes("tampered")));
        }

        // Group signatures

        [Fact]
        public void PrepareGroupMembersChange_ReturnsSignedChange()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "910006" },
                new[] { "910002" },
                new[] { "910002" },
                Array.Empty<string>())
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                CurrentTitle = "Test Group",
            });

            Assert.Equal("g123", prepared.ConversationId);
            // A member add emits two signed actions: the key change and the add.
            Assert.Equal(2, prepared.ActionSignatures.Count);
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            Assert.Equal("", prepared.ActionSignatures[0].SignaturePayload);
            Assert.NotEmpty(prepared.ActionSignatures[0].EncodedMessageEventDetail);
            Assert.StartsWith("GroupChangeEvent.GroupMemberAddChange,", prepared.ActionSignatures[1].SignaturePayload);
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
            // Unset screen-capture blocking signs as the trailing null sentinel.
            Assert.EndsWith(",null", prepared.ActionSignatures[1].SignaturePayload);
        }

        [Fact]
        public void PrepareGroupMembersChange_SignsScreenCaptureBlocking()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "910006" },
                new[] { "910002" },
                new[] { "910002" },
                Array.Empty<string>())
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                CurrentScreenCaptureBlockingEnabled = true,
            });

            // The group's screen-capture-blocking state fills the trailing signed slot.
            Assert.StartsWith("GroupChangeEvent.GroupMemberAddChange,", prepared.ActionSignatures[1].SignaturePayload);
            Assert.EndsWith(",true", prepared.ActionSignatures[1].SignaturePayload);
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
        }

        [Fact]
        public void PrepareGroupCreate_ReturnsSignedChange()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupCreate(new GroupCreateParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "910002", "910005" },
                new[] { "910002" })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                Title = "Test Group",
            });

            Assert.Equal("g123", prepared.ConversationId);
            // A group create emits two signed actions: the key change and the create.
            Assert.Equal(2, prepared.ActionSignatures.Count);
            // Empty: the payload embeds the plaintext conversation key and is withheld.
            Assert.Equal("", prepared.ActionSignatures[0].SignaturePayload);
            Assert.NotEmpty(prepared.ActionSignatures[0].EncodedMessageEventDetail);
            Assert.StartsWith("GroupChangeEvent.GroupCreate,", prepared.ActionSignatures[1].SignaturePayload);
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
        }

        [Fact]
        public void PrepareConversationKeyChange_DerivesOneToOneId()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(new[]
            {
                new PublicKeyInput { UserId = "1491585161162473473", PublicKey = publicKeys.Identity, KeyVersion = "1" },
                new PublicKeyInput { UserId = "17380288", PublicKey = publicKeys.Identity, KeyVersion = "1" },
            })
            {
                SenderId = "1491585161162473473",
                SigningKeyVersion = "1",
            });

            Assert.Equal("17380288:1491585161162473473", prepared.ConversationId);
        }

        [Fact]
        public void PrepareConversationKeyChange_DeriveAndDecryptRoundTrip()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            // No ConversationId set: the canonical one-to-one id is derived from
            // the two participants. Both entries reuse our identity key so every
            // participant key decrypts locally.
            var prepared = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(new[]
            {
                new PublicKeyInput { UserId = "17380288", PublicKey = publicKeys.Identity, KeyVersion = "1" },
                new PublicKeyInput { UserId = "1491585161162473473", PublicKey = publicKeys.Identity, KeyVersion = "1" },
            })
            {
                SenderId = "17380288",
                SigningKeyVersion = "1",
            });

            Assert.Equal("17380288:1491585161162473473", prepared.ConversationId);
            Assert.Equal(2, prepared.ParticipantKeys.Count);
            foreach (var pk in prepared.ParticipantKeys)
            {
                var decrypted = chat.DecryptConversationKey(pk.EncryptedKey);
                Assert.Equal(prepared.ConversationKey, decrypted);
            }
        }

        // Error handling

        [Fact]
        public void OperationsFailWhenLocked()
        {
            using var chat = new Chat();
            Assert.Throws<ChatXdkException>(() => chat.GetPublicKeys());
            Assert.Throws<ChatXdkException>(() => chat.Sign(new byte[] { 1, 2, 3 }));
            // ExportKeys returns null (not throws) when locked
            Assert.Null(chat.ExportKeys());
        }

        // P/Invoke plumbing smoke only: the flag crosses the boundary without a
        // crash. The policy's behavior is pinned by
        // Vectors_DecryptEvents_BatchAndSingleEventContracts (default reject)
        // and the Rust core suite.
        [Fact]
        public void SetRejectUnverified_DoesNotThrow()
        {
            using var chat = CreateUnlocked();
            chat.SetRejectUnverified(true);
            chat.SetRejectUnverified(false);
        }

        // Deterministic cross-binding fixture pins (tests/fixtures/sdk_vectors.json)

        [Fact]
        public void Vectors_PublicKeysAndSignature_MatchFixture()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));
            Assert.True(chat.IsUnlocked);

            var keys = chat.GetPublicKeys();
            Assert.Equal(v.IdentityPublicB64, keys.Identity);
            Assert.Equal(v.SigningPublicB64, keys.Signing);

            // ECDSA here is deterministic (RFC 6979): the signature must match
            // the fixture byte-for-byte, verify, and reject a tampered message.
            var message = System.Text.Encoding.UTF8.GetBytes(v.MessageUtf8);
            var signature = chat.Sign(message);
            Assert.Equal(v.SignatureB64, Convert.ToBase64String(signature));
            Assert.True(chat.Verify(v.SigningPublicB64, signature, message));
            Assert.False(chat.Verify(v.SigningPublicB64, signature,
                System.Text.Encoding.UTF8.GetBytes(v.MessageUtf8 + "!")));
        }

        [Fact]
        public void Vectors_VerifyKeyBinding_ValidAndTampered()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));

            Assert.True(chat.VerifyKeyBinding(
                v.IdentityPublicB64, v.SigningPublicB64, v.IdentityPublicKeySignatureB64));

            var tampered = Convert.FromBase64String(v.IdentityPublicKeySignatureB64);
            tampered[0] ^= 0xFF;
            Assert.False(chat.VerifyKeyBinding(
                v.IdentityPublicB64, v.SigningPublicB64, Convert.ToBase64String(tampered)));
            // Wrong key in the identity slot: the binding no longer verifies.
            Assert.False(chat.VerifyKeyBinding(
                v.SigningPublicB64, v.SigningPublicB64, v.IdentityPublicKeySignatureB64));
        }

        [Fact]
        public void MatchesRegisteredKey_BothEncodings()
        {
            using var chat = new Chat();
            var payload = chat.GenerateKeypairs();

            // SPKI/DER form (registration payload) and raw SEC1 form
            // (GetPublicKeys) both identify the loaded key.
            Assert.True(chat.MatchesRegisteredKey(payload.PublicKey.PublicKey));
            Assert.True(chat.MatchesRegisteredKey(chat.GetPublicKeys().Identity));

            using var other = new Chat();
            var otherPayload = other.GenerateKeypairs();
            Assert.False(chat.MatchesRegisteredKey(otherPayload.PublicKey.PublicKey));

            // No identity loaded and invalid base64 throw rather than return false.
            using var locked = new Chat();
            Assert.Throws<ChatXdkException>(() => locked.MatchesRegisteredKey(payload.PublicKey.PublicKey));
            Assert.Throws<ChatXdkException>(() => chat.MatchesRegisteredKey("not base64!!"));
        }

        [Fact]
        public void Vectors_DecryptEvents_BatchAndSingleEventContracts()
        {
            var v = LoadVectors();
            using var chat = new Chat(); // default reject-unverified policy
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });

            var signingKeys = EventSigningKeys(v);

            // Batch path never throws: the garbage event is collected as an
            // indexed error, the signed KeyChange's key is adopted, and the
            // message verifies with the fixture text.
            var result = chat.DecryptEvents(
                new DecryptEventsParams(new[] { v.EventKeyChangeB64, v.EventMessageB64, v.EventGarbageB64 })
                {
                    SigningKeys = signingKeys,
                });

            Assert.Single(result.Errors);
            Assert.Contains("2", result.Errors.Keys);

            Assert.Equal(v.EventConversationKeyVersion, result.ConversationKeys.LatestVersion);
            Assert.Equal(
                Convert.FromBase64String(v.ConversationKeyB64),
                result.ConversationKeys.Keys[v.EventConversationKeyVersion]);

            var keyChanges = result.Messages
                .Where(m => m.Event.GetProperty("type").GetString() == "KeyChange")
                .Select(m => m.Event)
                .ToList();
            Assert.Single(keyChanges);
            Assert.True(keyChanges[0].GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventConversationKeyVersion,
                keyChanges[0].GetProperty("key_version").GetString());

            var messages = result.Messages
                .Where(m => m.Event.GetProperty("type").GetString() == "Message")
                .Select(m => m.Event)
                .ToList();
            Assert.Single(messages);
            Assert.Equal(v.EventMessageText,
                messages[0].GetProperty("content").GetProperty("text").GetString());
            Assert.True(messages[0].GetProperty("verified").GetBoolean());

            // Single-event path with pre-cached keys verifies the same message …
            var single = chat.DecryptEvent(
                new DecryptEventParams(v.EventMessageB64, result.ConversationKeys.Keys) { SigningKeys = signingKeys });
            Assert.Equal("Message", single.GetProperty("type").GetString());
            Assert.Equal(v.EventMessageText,
                single.GetProperty("content").GetProperty("text").GetString());
            Assert.True(single.GetProperty("verified").GetBoolean());

            // … and throws on the garbage event.
            Assert.Throws<ChatXdkException>(() =>
                chat.DecryptEvent(new DecryptEventParams(v.EventGarbageB64, new Dictionary<string, byte[]>())
                {
                    SigningKeys = signingKeys,
                }));
        }

        // Failure events are unsigned by protocol: the fixture failure decodes
        // with no conversation or signing keys, and the JSON carries the
        // PascalCase discriminator values.
        [Fact]
        public void Vectors_FailureEvent_DecodesTypeAndRateLimitTier()
        {
            var v = LoadVectors();
            using var chat = new Chat(); // default reject-unverified policy

            var e = chat.DecryptEvent(new DecryptEventParams(v.EventFailureB64, new Dictionary<string, byte[]>()));
            Assert.Equal("Failure", e.GetProperty("type").GetString());
            Assert.Equal("RateLimitUpsell", e.GetProperty("failure").GetString());
            Assert.Equal("Premium", e.GetProperty("rate_limit_tier").GetString());
            Assert.Equal(v.EventSenderId, e.GetProperty("sender_id").GetString());
        }

        // Session identity: SetIdentity supplies sender_id and signing_key_version;
        // an encrypt with only the conversation key explicit signs with the
        // session values, and without any identity the call fails loudly.
        [Fact]
        public void Vectors_SetIdentity_ResolvesSenderAndSigningVersion()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });

            // No identity set: the error names the missing sender_id.
            var ex = Assert.Throws<ChatXdkException>(() =>
                chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "no identity")
                {
                    ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                }));
            Assert.Contains("sender_id", ex.Message);

            chat.SetIdentity(new SetIdentityParams(v.EventSenderId, v.EventSigningKeyVersion));
            var payload = chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "session identity")
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            });
            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.MessageId);
            Assert.Equal(v.EventSigningKeyVersion, payload.SignatureInfo.PublicKeyVersion);
        }

        // Conversation-key cache: after decrypting the verified fixture KeyChange
        // with the cache enabled, an encrypt with no explicit key resolves the
        // cached key; with the cache off the same call fails.
        [Fact]
        public void Vectors_SetCacheKeys_ResolvesConversationKeyFromDecryptedKeyChange()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });
            chat.SetIdentity(new SetIdentityParams(v.EventSenderId, v.EventSigningKeyVersion));

            chat.SetCacheKeys(true);
            chat.DecryptEvents(new DecryptEventsParams(new[] { v.EventKeyChangeB64 }) { SigningKeys = EventSigningKeys(v) });

            // With no conversation keys, DecryptEvent takes the key from the cache.
            var fromCache = chat.DecryptEvent(new DecryptEventParams(v.EventMessageB64) { SigningKeys = EventSigningKeys(v) });
            Assert.Equal(v.EventMessageText, fromCache.GetProperty("content").GetProperty("text").GetString());

            var payload = chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "from the key cache"));
            Assert.Equal(v.EventConversationKeyVersion, payload.ConversationKeyVersion);
            Assert.NotEmpty(payload.EncryptedContent);

            // Disabling clears the cache, so the same short form now fails.
            chat.SetCacheKeys(false);
            var ex = Assert.Throws<ChatXdkException>(() =>
                chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "no cache")));
            Assert.Contains("conversation key", ex.Message);
        }

        // Signing-key store: SetSigningKeys makes decrypt calls that omit their
        // signingKeys argument verify against the stored keys.
        [Fact]
        public void Vectors_SetSigningKeys_DecryptWithoutExplicitKeysVerifies()
        {
            var v = LoadVectors();
            using var chat = new Chat(); // default reject-unverified policy
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });
            chat.SetSigningKeys(EventSigningKeys(v));

            var result = chat.DecryptEvents(new DecryptEventsParams(new[] { v.EventKeyChangeB64 }));
            Assert.Empty(result.Errors);

            var single = chat.DecryptEvent(new DecryptEventParams(v.EventMessageB64, result.ConversationKeys.Keys));
            Assert.Equal("Message", single.GetProperty("type").GetString());
            Assert.Equal(v.EventMessageText,
                single.GetProperty("content").GetProperty("text").GetString());
            Assert.True(single.GetProperty("verified").GetBoolean());
        }

        // Reply preview validation: the genuine embedded original validates,
        // the forged preview is flagged Invalid (both still decrypt).
        [Fact]
        public void Vectors_ReplyPreviewValidation_ValidAndForged()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });

            var result = chat.DecryptEvents(
                new DecryptEventsParams(new[] { v.EventKeyChangeB64, v.EventReplyValidB64, v.EventReplyForgedB64 })
                {
                    SigningKeys = EventSigningKeys(v),
                });
            Assert.Empty(result.Errors);

            var messages = result.Messages
                .Where(m => m.Event.GetProperty("type").GetString() == "Message")
                .Select(m => m.Event)
                .ToList();
            Assert.Equal(2, messages.Count);

            Assert.Equal(v.EventReplyText,
                messages[0].GetProperty("content").GetProperty("text").GetString());
            Assert.Equal("Valid",
                messages[0].GetProperty("reply_preview_validation").GetString());
            Assert.Equal("Invalid",
                messages[1].GetProperty("reply_preview_validation").GetString());
        }

        // Reply-by-event: passing the raw original event derives the preview
        // (the SDK decrypts the original with the reply's own key).
        [Fact]
        public void Vectors_EncryptReply_ByRawEvent_Succeeds()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });
            chat.SetIdentity(new SetIdentityParams(v.EventSenderId, v.EventSigningKeyVersion));

            var payload = chat.EncryptReply(new EncryptReplyParams(v.EventConversationId, "a reply", v.EventMessageB64)
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            });
            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.MessageId);
        }

        // Message-key vectors: their contents and media are encrypted directly
        // under the known message and attachment keys, so they open only if the
        // SDK derives the same keys from the conversation key.
        [Fact]
        public void Vectors_MessageKeyEvent_DecryptsWithTheConversationKey()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            var e = chat.DecryptEvent(
                new DecryptEventParams(v.EventMessageKeyB64, MessageKeyConversationKeys(v))
                {
                    SigningKeys = SigningKeysFor(v, v.MessageKeySenderId),
                });
            Assert.Equal("Message", e.GetProperty("type").GetString());
            Assert.True(e.GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventMessageKeyText,
                e.GetProperty("content").GetProperty("text").GetString());
            Assert.Equal(
                new[] { v.MediaFirstHashKey, v.MediaSecondHashKey },
                e.GetProperty("media_hashes").EnumerateArray()
                    .Select(h => h.GetProperty("media_hash_key").GetString()));
        }

        [Fact]
        public void Vectors_SeveralMediaFiles_OpenFromTheirMessage()
        {
            var v = LoadVectors();
            var keys = MessageKeyConversationKeys(v);
            Assert.Equal(
                Convert.FromBase64String(v.MediaFirstPlaintextB64),
                OpenMedia(v.EventMessageKeyB64, keys, v.MediaFirstHashKey, v.MediaFirstEncryptedB64));
            Assert.Equal(
                Convert.FromBase64String(v.MediaSecondPlaintextB64),
                OpenMedia(v.EventMessageKeyB64, keys, v.MediaSecondHashKey, v.MediaSecondEncryptedB64));
        }

        [Fact]
        public void Vectors_OneMediaFile_OpensFromItsMessage()
        {
            var v = LoadVectors();
            var keys = new Dictionary<string, byte[]>
            {
                [v.MessageKeyShortConversationKeyVersion] =
                    ChatXdkUtilities.HexToBytes(v.MessageKeyShortConversationKeyHex),
            };
            Assert.Equal(
                Convert.FromBase64String(v.MediaShortPlaintextB64),
                OpenMedia(v.EventMessageKeyShortB64, keys, v.MediaShortHashKey, v.MediaShortEncryptedB64));
        }

        [Fact]
        public void Vectors_LinkCardImages_OpenFromTheirMessage()
        {
            var v = LoadVectors();
            var keys = MessageKeyConversationKeys(v);
            Assert.Equal(
                Convert.FromBase64String(v.MediaBannerPlaintextB64),
                OpenMedia(v.EventLinkCardB64, keys, v.MediaBannerHashKey, v.MediaBannerEncryptedB64));
            Assert.Equal(
                Convert.FromBase64String(v.MediaFaviconPlaintextB64),
                OpenMedia(v.EventLinkCardB64, keys, v.MediaFaviconHashKey, v.MediaFaviconEncryptedB64));
        }

        [Fact]
        public void Vectors_ConversationKeyMedia_OpensFromItsMessage()
        {
            var v = LoadVectors();
            Assert.Equal(
                Convert.FromBase64String(v.MediaConversationKeyPlaintextB64),
                OpenMedia(v.EventConversationKeyMediaB64, ConversationKeys(v), v.MediaConversationKeyHashKey, v.MediaConversationKeyEncryptedB64));
        }

        [Fact]
        public void Vectors_MediaErrors_SayWhatToPass()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            var mkKeys = MessageKeyConversationKeys(v);
            var first = Convert.FromBase64String(v.MediaFirstEncryptedB64);
            var second = Convert.FromBase64String(v.MediaSecondEncryptedB64);
            var cases = new (byte[] Encrypted, string Event, Dictionary<string, byte[]> Keys, string MediaHashKey, string Expected)[]
            {
                (first, v.EventMessageKeyB64, ConversationKeys(v), v.MediaFirstHashKey,
                    $"no key for version '{v.MessageKeyConversationKeyVersion}'"),
                (first, v.EventMessageKeyB64, mkKeys, "not-a-hash-key", "is not in the message"),
                (first, v.EventKeyChangeB64, mkKeys, v.MediaFirstHashKey, "the event is not a message"),
                (first, v.EventMessageB64, ConversationKeys(v), v.MediaFirstHashKey, "the message has no media"),
                (second, v.EventMessageKeyB64, mkKeys, v.MediaFirstHashKey,
                    $"encrypted file of media_hash_key '{v.MediaFirstHashKey}'"),
                (first[..(first.Length / 2)], v.EventMessageKeyB64, mkKeys, v.MediaFirstHashKey, "truncated"),
                (first, v.EventUnencryptedB64, mkKeys, v.MediaUnencryptedHashKey, "the message is not encrypted"),
                (first, v.EventMessageKeyB64,
                    new Dictionary<string, byte[]> { [v.MessageKeyConversationKeyVersion] = new byte[3] },
                    v.MediaFirstHashKey, "is not 32 bytes"),
            };
            foreach (var c in cases)
            {
                var ex = Assert.Throws<ChatXdkException>(
                    () => chat.DecryptFile(new DecryptFileParams(c.Encrypted, c.Event, c.Keys, c.MediaHashKey)));
                Assert.Contains(c.Expected, ex.Message);
            }
            var decryptorEx = Assert.Throws<ChatXdkException>(
                () => chat.FileDecryptor(new FileDecryptorParams(v.EventMessageKeyB64, ConversationKeys(v), v.MediaFirstHashKey)));
            Assert.Contains("no key for version", decryptorEx.Message);
        }

        [Fact]
        public void Vectors_MessageKeyEvent_DecryptsInABatchWithItsKeyChange()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });

            var result = chat.DecryptEvents(
                new DecryptEventsParams(new[] { v.EventKeyChangeMessageKeyB64, v.EventMessageKeyB64 })
                {
                    SigningKeys = SigningKeysFor(v, v.EventSenderId, v.MessageKeySenderId),
                });
            Assert.Empty(result.Errors);

            var key = result.ConversationKeys.Keys[v.MessageKeyConversationKeyVersion];
            Assert.Equal(ChatXdkUtilities.HexToBytes(v.MessageKeyConversationKeyHex), key);
            var texts = result.Messages
                .Where(m => m.Event.GetProperty("type").GetString() == "Message")
                .Select(m => m.Event.GetProperty("content").GetProperty("text").GetString())
                .ToList();
            Assert.Equal(new[] { v.EventMessageKeyText }, texts);
            Assert.Equal(
                Convert.FromBase64String(v.MediaSecondPlaintextB64),
                OpenMedia(v.EventMessageKeyB64, result.ConversationKeys.Keys, v.MediaSecondHashKey,
                    v.MediaSecondEncryptedB64));
        }

        [Fact]
        public void Vectors_ShortSenderMessageKeyEvent_VerifiesAtV11()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            var e = chat.DecryptEvent(
                new DecryptEventParams(
                    v.EventMessageKeyShortB64,
                    new Dictionary<string, byte[]>
                    {
                        [v.MessageKeyShortConversationKeyVersion] =
                            ChatXdkUtilities.HexToBytes(v.MessageKeyShortConversationKeyHex),
                    })
                {
                    SigningKeys = SigningKeysFor(v, v.MessageKeyShortSenderId),
                });
            Assert.True(e.GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventMessageKeyShortText,
                e.GetProperty("content").GetProperty("text").GetString());
        }

        [Fact]
        public void Vectors_ReplyCarryingAMessageKey_ValidatesAndOpensTheQuotedMedia()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            var key = Convert.FromBase64String(v.ConversationKeyB64);
            var e = chat.DecryptEvent(
                new DecryptEventParams(
                    v.EventReplyMessageKeyB64,
                    new Dictionary<string, byte[]> { [v.EventConversationKeyVersion] = key })
                {
                    SigningKeys = SigningKeysFor(v, v.EventSenderId, v.MessageKeySenderId),
                });
            Assert.True(e.GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventReplyMessageKeyText,
                e.GetProperty("content").GetProperty("text").GetString());
            Assert.Equal("Valid", e.GetProperty("reply_preview_validation").GetString());
            Assert.Equal(
                Convert.FromBase64String(v.MediaFirstPlaintextB64),
                OpenMedia(v.EventReplyMessageKeyB64, ConversationKeys(v), v.MediaFirstHashKey,
                    v.MediaFirstEncryptedB64));
        }

        [Fact]
        public void Vectors_KnownSignature_CoversTheContentsEncryptionVersion()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            var signature = Convert.FromBase64String(v.SignatureV10Cev1B64);
            Assert.True(chat.Verify(v.SignatureV10Cev1PublicKeyB64, signature,
                System.Text.Encoding.UTF8.GetBytes(v.PayloadMessageV10Cev1)));
            Assert.False(chat.Verify(v.SignatureV10Cev1PublicKeyB64, signature,
                System.Text.Encoding.UTF8.GetBytes(v.PayloadMessageV10)));
        }

        // Absent-value normalization: an empty title/avatar is "not set" and
        // signs the null sentinel, exactly like leaving the field null.
        [Fact]
        public void PrepareGroupCreate_EmptyTitle_SignsNullSentinel()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            foreach (var title in new string?[] { "", null })
            {
                var prepared = chat.PrepareGroupCreate(new GroupCreateParams(
                    new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                    "g123",
                    new[] { "910002", "910005" },
                    new[] { "910002" })
                {
                    SenderId = "910002",
                    SigningKeyVersion = "1",
                    Title = title,
                    AvatarUrl = title,
                });
                // Trailing slots: title, avatar_url, ttl — all unset → null sentinels.
                Assert.EndsWith(",null,null,null", prepared.ActionSignatures[1].SignaturePayload);
            }
        }

        // Comma-injection rejection: the signature payload is comma-joined
        // with no escaping, so a comma-containing title must fail.
        [Fact]
        public void PrepareGroupCreate_CommaTitle_Throws()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            Assert.Throws<ChatXdkException>(() => chat.PrepareGroupCreate(new GroupCreateParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "910002", "910005" },
                new[] { "910002" })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                Title = "Team, the sequel",
            }));
        }

        // Error contracts and marshaling edge cases

        // Verify() must throw (not return false) when the SDK is locked.
        [Fact]
        public void Verify_WhenLocked_ThrowsChatXdkException()
        {
            using var chat = new Chat(); // locked — no keys
            // Any valid-looking base64 signature; doesn't matter since the SDK is locked.
            var fakeSignature = new byte[64];
            Assert.Throws<ChatXdkException>(() =>
                chat.Verify("anInvalidKey", fakeSignature, new byte[] { 1 }));
        }

        // Verify() must throw on a malformed public key, not return false.
        [Fact]
        public void Verify_MalformedPublicKey_ThrowsChatXdkException()
        {
            using var chat = CreateUnlocked();
            var data = System.Text.Encoding.UTF8.GetBytes("data");
            var sig = chat.Sign(data);
            // "notAPublicKey" is not valid base64 SEC1/SPKI — Rust returns -1.
            Assert.Throws<ChatXdkException>(() =>
                chat.Verify("notAPublicKey", sig, data));
        }

        // Finalizer: the native handle must be freed without explicit Dispose().
        // We can only smoke-test that the object can be garbage collected without
        // throwing. A full leak test would require a memory profiler.
        [Fact]
        public void Finalizer_AllowsObjectToBeGarbageCollected()
        {
            // Allocate without using, let it go out of scope.
            // The GC + finalizer should free the native handle.
            static void CreateAndAbandon()
            {
                var chat = new Chat();
                chat.GenerateKeypairs(); // use it briefly
                // NOT disposing — finalizer must clean up
            }
            CreateAndAbandon();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            // No exception = pass
        }

        // Sign() must not crash on a null argument.
        [Fact]
        public void Sign_NullData_ThrowsArgumentNullException()
        {
            using var chat = CreateUnlocked();
            Assert.Throws<ArgumentNullException>(() => chat.Sign(null!));
        }

        // Verify() must not crash on null arguments.
        [Fact]
        public void Verify_NullArguments_ThrowsArgumentNullException()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();
            var data = System.Text.Encoding.UTF8.GetBytes("data");
            var sig = chat.Sign(data);

            Assert.Throws<ArgumentNullException>(() => chat.Verify(publicKeys.Signing, null!, data));
            Assert.Throws<ArgumentNullException>(() => chat.Verify(publicKeys.Signing, sig, null!));
        }

        // Sign() with an empty byte array must succeed — the FFI accepts zero-length data.
        [Fact]
        public void Sign_EmptyData_Succeeds()
        {
            using var chat = CreateUnlocked();
            var sig = chat.Sign(Array.Empty<byte>());
            Assert.Equal(64, sig.Length);

            var publicKeys = chat.GetPublicKeys();
            Assert.True(chat.Verify(publicKeys.Signing, sig, Array.Empty<byte>()));
        }

        // AttachmentDescriptor.Media with Width=0 must emit "width":0, not omit the field.
        [Fact]
        public void EncryptMessage_MediaAttachment_ZeroDimensions_Succeeds()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("1001", "66"));
            var ckey = NewConvKey(chat);

            // Width=0 and Height=0 are unusual but must not cause a serialization bug.
            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Attachment with zero dimensions")
            {
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Attachments = new List<AttachmentDescriptor>
                {
                    AttachmentDescriptor.Media(
                        mediaHashKey: "hash_abc",
                        width: 0,
                        height: 0,
                        filesizeBytes: 1024,
                        filename: "file.bin"),
                },
            });

            Assert.NotEmpty(payload.EncryptedContent);
        }

        // Verify the correct sign/verify contract end-to-end
        [Fact]
        public void SignVerify_CorrectPublicKey_ReturnsTrue()
        {
            using var chat = CreateUnlocked();
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var sig = chat.Sign(data);
            var keys = chat.GetPublicKeys();
            Assert.True(chat.Verify(keys.Signing, sig, data));
        }

        [Fact]
        public void SignVerify_WrongPublicKey_ReturnsFalse()
        {
            using var chatA = CreateUnlocked();
            using var chatB = CreateUnlocked();
            var data = new byte[] { 0xAA, 0xBB };
            var sig = chatA.Sign(data);
            var keysB = chatB.GetPublicKeys();
            // chatB's key doesn't match chatA's signature → false (not throw)
            Assert.False(chatA.Verify(keysB.Signing, sig, data));
        }

        // ChatXdkUtilities (stateless helpers)

        [Fact]
        public void Utilities_EncryptedFileSize()
        {
            Assert.Equal(24UL, ChatXdkUtilities.EncryptedFileSize(0));
            Assert.Equal(42UL, ChatXdkUtilities.EncryptedFileSize(1));
            Assert.Equal(1065UL, ChatXdkUtilities.EncryptedFileSize(1024));
            Assert.Equal(1083UL, ChatXdkUtilities.EncryptedFileSize(1025));
            Assert.Throws<ChatXdkException>(() => ChatXdkUtilities.EncryptedFileSize(ulong.MaxValue));
        }

        [Fact]
        public void Utilities_Base64_RoundTrip()
        {
            var data = new byte[] { 1, 2, 3, 4, 250, 0, 128 };
            var b64 = ChatXdkUtilities.BytesToBase64(data);
            // Standard base64 — matches the BCL encoder for the same bytes.
            Assert.Equal(Convert.ToBase64String(data), b64);

            var roundTripped = ChatXdkUtilities.Base64ToBytes(b64);
            Assert.Equal(data, roundTripped);
        }

        [Fact]
        public void Utilities_Hex_RoundTrip()
        {
            var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            var hex = ChatXdkUtilities.BytesToHex(data);
            Assert.Equal("deadbeef", hex); // lowercase hex

            var roundTripped = ChatXdkUtilities.HexToBytes(hex);
            Assert.Equal(data, roundTripped);
        }

        // Minimal PNG: 8-byte signature + IHDR chunk declaring a 16x16 image.
        private static readonly byte[] PngHeader16x16 = new byte[]
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D,                         // IHDR length (13)
            0x49, 0x48, 0x44, 0x52,                         // "IHDR"
            0x00, 0x00, 0x00, 0x10,                         // width  = 16
            0x00, 0x00, 0x00, 0x10,                         // height = 16
            0x08, 0x06, 0x00, 0x00, 0x00,                   // bit depth/color/compression/filter/interlace
        };

        [Fact]
        public void Utilities_DetectMimeType_Png()
        {
            var mime = ChatXdkUtilities.DetectMimeType(PngHeader16x16);
            Assert.Equal("image/png", mime);
        }

        [Fact]
        public void Utilities_DetectImageDimensions_Png()
        {
            var dims = ChatXdkUtilities.DetectImageDimensions(PngHeader16x16);
            Assert.NotNull(dims);
            Assert.Equal(16u, dims!.Width);
            Assert.Equal(16u, dims.Height);
        }

        // Generic UTF-8 metadata encrypt / decrypt

        [Fact]
        public void EncryptDecrypt_Utf8_RoundTrip()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            const string plaintext = "metadata payload 🌟 with unicode";

            var ciphertext = chat.Encrypt(plaintext, ckey);
            Assert.NotEmpty(ciphertext);
            Assert.NotEqual(plaintext, ciphertext);

            var decrypted = chat.Decrypt(ciphertext, ckey);
            Assert.Equal(plaintext, decrypted);
        }

        // Conversation key preparation / extraction shapes

        [Fact]
        public void PrepareConversationKeyChange_ReturnsExpectedShape()
        {
            using var chat = CreateUnlocked();
            var keys = chat.GetPublicKeys();

            var prepared = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", PublicKey = keys.Identity, KeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });

            Assert.NotNull(prepared);
            Assert.Equal("conv-1", prepared.ConversationId);
            Assert.NotNull(prepared.ConversationKey);
            Assert.Equal(32, prepared.ConversationKey!.Length);
            Assert.Single(prepared.ParticipantKeys);
            Assert.NotEmpty(prepared.ParticipantKeys[0].EncryptedKey);
            Assert.Single(prepared.ActionSignatures);
        }

        [Fact]
        public void ExtractConversationKeys_EmptyEvents_ReturnsEmptyBundle()
        {
            using var chat = CreateUnlocked();
            var bundle = chat.ExtractConversationKeys(Array.Empty<string>());

            Assert.NotNull(bundle);
            Assert.Empty(bundle.Keys);
            Assert.Null(bundle.LatestVersion);
        }

        // DecryptEvents — empty batch

        [Fact]
        public void DecryptEvents_EmptyList_ReturnsNonNullResult()
        {
            using var chat = CreateUnlocked();
            var result = chat.DecryptEvents(new DecryptEventsParams(Array.Empty<string>()));

            Assert.NotNull(result);
            Assert.Empty(result.Messages);
            Assert.Empty(result.Errors);
        }

        [Fact]
        public void DecryptEvents_MalformedSigningKeyEntry_Throws()
        {
            using var chat = CreateUnlocked();
            // A null UserId is omitted from the serialized JSON, so the entry is
            // missing a required field. That must be surfaced rather than silently
            // dropped (which would weaken verification by skipping it).
            var malformed = new[]
            {
                new SigningKeyEntry
                {
                    UserId = null!,
                    PublicKeyVersion = "1",
                    PublicKey = "AA==",
                    IdentityPublicKey = "AA==",
                    IdentityPublicKeySignature = "AA==",
                },
            };

            var ex = Assert.Throws<ChatXdkException>(
                () => chat.DecryptEvents(new DecryptEventsParams(Array.Empty<string>()) { SigningKeys = malformed }));
            Assert.Contains("Invalid params JSON: missing field `user_id`", ex.Message);
        }

        // Quick replies

        private static QuickReply SampleQuickReply(string kind) => kind == "request"
            ? new QuickReply
            {
                Request = new QuickReplyRequest
                {
                    Options = new QuickReplyOptionsRequest
                    {
                        Id = "qr-1",
                        Options = new[]
                        {
                            new QuickReplyOption { Id = "yes", Label = "Yes", Metadata = "m-yes", Description = "Confirm" },
                            new QuickReplyOption { Id = "no", Label = "No", Metadata = "m-no", Description = "Decline" },
                        },
                    },
                },
            }
            : new QuickReply
            {
                Response = new QuickReplyResponse
                {
                    Options = new QuickReplyOptionsResponse
                    {
                        RequestId = "qr-1",
                        Metadata = "m-yes",
                        SelectedOptionId = "yes",
                    },
                },
            };

        private static Chat QuickReplyChat(SdkVectors v)
        {
            var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));
            chat.SetIdentity(new SetIdentityParams(v.EventSenderId, v.EventSigningKeyVersion));
            return chat;
        }

        private static JsonElement DecryptOwnContent(Chat chat, SdkVectors v, SendPayload payload)
        {
            var evt = chat.DecryptEvent(
                new DecryptEventParams(
                    payload.EventB64,
                    new Dictionary<string, byte[]>
                    {
                        [v.EventConversationKeyVersion] = Convert.FromBase64String(v.ConversationKeyB64),
                    })
                {
                    SigningKeys = EventSigningKeys(v),
                });
            Assert.True(evt.GetProperty("verified").GetBoolean());
            Assert.Equal(payload.MessageId, evt.GetProperty("id").GetString());
            return evt.GetProperty("content");
        }

        private static void AssertJsonEqual(string expected, JsonElement actual) =>
            Assert.True(
                System.Text.Json.Nodes.JsonNode.DeepEquals(
                    System.Text.Json.Nodes.JsonNode.Parse(expected),
                    System.Text.Json.Nodes.JsonNode.Parse(actual.GetRawText())),
                $"expected {expected}, got {actual.GetRawText()}");

        [Theory]
        [InlineData("request")]
        [InlineData("response")]
        public void EncryptMessage_QuickReply_RoundTripsThroughDecrypt(string kind)
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var key = Convert.FromBase64String(v.ConversationKeyB64);
            var sent = SampleQuickReply(kind);
            var sentJson = JsonSerializer.Serialize(sent);

            var content = DecryptOwnContent(chat, v, chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "Continue?")
                {
                    ConversationKey = key,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    QuickReply = sent,
                }));
            Assert.Equal("Continue?", content.GetProperty("text").GetString());
            AssertJsonEqual(sentJson, content.GetProperty("quick_reply"));

            // A received quick reply can be sent back unchanged.
            var received = content.GetProperty("quick_reply").Deserialize<QuickReply>();
            Assert.NotNull(received);
            var resent = DecryptOwnContent(chat, v, chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "again")
                {
                    ConversationKey = key,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    QuickReply = received,
                }));
            AssertJsonEqual(sentJson, resent.GetProperty("quick_reply"));
        }

        [Fact]
        public void EncryptMessage_WithoutQuickReply_DecryptsWithoutOne()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);

            var content = DecryptOwnContent(chat, v, chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "plain")
                {
                    ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                }));
            Assert.False(content.TryGetProperty("quick_reply", out _));
        }

        [Fact]
        public void EncryptReply_QuickReply_RoundTripsThroughDecrypt()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var sent = SampleQuickReply("response");

            var content = DecryptOwnContent(chat, v, chat.EncryptReply(
                new EncryptReplyParams(v.EventConversationId, "Yes", null)
                {
                    ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    ReplyToSequenceId = "seq-orig",
                    ReplyToSenderId = v.EventSenderId,
                    ReplyToText = "Continue?",
                    QuickReply = sent,
                }));
            AssertJsonEqual(JsonSerializer.Serialize(sent), content.GetProperty("quick_reply"));
        }

        [Theory]
        [InlineData("neither")]
        [InlineData("both")]
        public void EncryptMessage_InvalidQuickReply_Throws(string kind)
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var quickReply = kind == "both"
                ? new QuickReply
                {
                    Request = SampleQuickReply("request").Request,
                    Response = SampleQuickReply("response").Response,
                }
                : new QuickReply();

            var ex = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "bad")
                {
                    ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    QuickReply = quickReply,
                }));
            Assert.Contains("Invalid quick reply", ex.Message);
        }
    }
}
