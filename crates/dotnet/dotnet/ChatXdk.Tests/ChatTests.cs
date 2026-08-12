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
            chat.ImportKeys(exported!);
            return chat;
        }

        /// <summary>
        /// Produce a fresh conversation key via a prepared key change (for crypto tests).
        /// </summary>
        private static byte[] NewConvKey(Chat chat)
        {
            var prep = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(
                new[] { new PublicKeyInput { UserId = "me", PublicKey = chat.GetPublicKeys().Identity, KeyVersion = "1" } })
            {
                SenderId = "me",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });
            return prep.ConversationKey!;
        }

        /// <summary>Signing keys matching the fixture's event vectors.</summary>
        private static SigningKeyEntry[] EventSigningKeys(SdkVectors v) => new[]
        {
            new SigningKeyEntry
            {
                UserId = v.EventSenderId,
                PublicKeyVersion = v.EventSigningKeyVersion,
                PublicKey = v.SigningPublicB64,
                IdentityPublicKey = v.IdentityPublicB64,
                IdentityPublicKeySignature = v.IdentityPublicKeySignatureB64,
            },
        };

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
            Assert.True(payload.GenerateVersion);

            // Fingerprint: SHA-256 → 32 bytes → 43 URL-safe base64 chars (no padding)
            Assert.NotNull(payload.PublicKey.PublicKeyFingerprint);
            Assert.Equal(43, payload.PublicKey.PublicKeyFingerprint!.Length);
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

            chat.ImportKeys(exported);
            Assert.True(chat.IsUnlocked);

            var reimported = chat.GetPublicKeys();
            Assert.Equal(original.Identity, reimported.Identity);
            Assert.Equal(original.Signing, reimported.Signing);
        }

        [Fact]
        public void ImportInvalidKeys_Throws()
        {
            using var chat = new Chat();
            Assert.Throws<ChatXdkException>(() => chat.ImportKeys(new byte[16]));
            Assert.Throws<ChatXdkException>(() => chat.ImportKeys(Array.Empty<byte>()));
        }

        [Fact]
        public void ExportKeys_IdentityOnly_Returns32Bytes()
        {
            using var source = CreateUnlocked();
            var identityOnly = source.ExportKeys()!.Take(32).ToArray();

            // Identity-only sessions can export (32 bytes), matching core;
            // only a session with no identity key at all returns null.
            using var chat = new Chat();
            chat.ImportKeys(identityOnly);
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
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
            });

            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.Signature);
            Assert.NotEmpty(payload.EncodedEventSignature);
            Assert.Equal("v1", payload.ConversationKeyVersion);
            Assert.Equal("7", payload.SignatureInfo.SignatureVersion);
            Assert.True(payload.ShouldNotify);
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
            var ckey = NewConvKey(chat);

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Check this out")
            {
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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

            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Check this out")
            {
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
                ReplyToSequenceId = "seq-42",
                ReplyToSenderId = 12345,
                ReplyToText = "Original message",
            });

            Assert.NotEmpty(payload.EncryptedContent);
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                SenderId = "user-1",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } })
            {
                SenderId = "me",
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

        // Stream encrypt / decrypt

        [Fact]
        public void EncryptDecryptStream_RoundTrip()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            var plaintext = new byte[1024];
            new Random(42).NextBytes(plaintext);

            var encrypted = chat.EncryptStream(plaintext, ckey);
            Assert.NotEqual(plaintext, encrypted);

            var decrypted = chat.DecryptStream(encrypted, ckey);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptStream_WrongKey_Throws()
        {
            using var chat = CreateUnlocked();
            var ckey1 = NewConvKey(chat);
            var ckey2 = NewConvKey(chat);
            var plaintext = System.Text.Encoding.UTF8.GetBytes("secret content");

            var encrypted = chat.EncryptStream(plaintext, ckey1);
            Assert.Throws<ChatXdkException>(() => chat.DecryptStream(encrypted, ckey2));
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "new-1" },
                new[] { "me" },
                new[] { "me" },
                Array.Empty<string>())
            {
                SenderId = "me",
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "new-1" },
                new[] { "me" },
                new[] { "me" },
                Array.Empty<string>())
            {
                SenderId = "me",
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "me", "friend" },
                new[] { "me" })
            {
                SenderId = "me",
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64));
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64));

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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);

            var signingKeys = EventSigningKeys(v);

            // Batch path never throws: the garbage event is collected as an
            // indexed error, the signed KeyChange's key is adopted, and the
            // message verifies with the fixture text.
            var result = chat.DecryptEvents(
                new[] { v.EventKeyChangeB64, v.EventMessageB64, v.EventGarbageB64 },
                signingKeys);

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
                v.EventMessageB64, result.ConversationKeys, signingKeys);
            Assert.Equal("Message", single.GetProperty("type").GetString());
            Assert.Equal(v.EventMessageText,
                single.GetProperty("content").GetProperty("text").GetString());
            Assert.True(single.GetProperty("verified").GetBoolean());

            // … and throws on the garbage event.
            Assert.Throws<ChatXdkException>(() =>
                chat.DecryptEvent(v.EventGarbageB64, (ConversationKeyBundle?)null, signingKeys));
        }

        // Failure events are unsigned by protocol: the fixture failure decodes
        // with no conversation or signing keys, and the JSON carries the
        // PascalCase discriminator values.
        [Fact]
        public void Vectors_FailureEvent_DecodesTypeAndRateLimitTier()
        {
            var v = LoadVectors();
            using var chat = new Chat(); // default reject-unverified policy

            var e = chat.DecryptEvent(
                v.EventFailureB64, (ConversationKeyBundle?)null, Array.Empty<SigningKeyEntry>());
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);

            // No identity set: the error names the missing sender_id.
            var ex = Assert.Throws<ChatXdkException>(() =>
                chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "no identity")
                {
                    ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                }));
            Assert.Contains("sender_id", ex.Message);

            chat.SetIdentity(v.EventSenderId, v.EventSigningKeyVersion);
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);
            chat.SetIdentity(v.EventSenderId, v.EventSigningKeyVersion);

            chat.SetCacheKeys(true);
            chat.DecryptEvents(new[] { v.EventKeyChangeB64 }, EventSigningKeys(v));

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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);
            chat.SetSigningKeys(EventSigningKeys(v));

            var result = chat.DecryptEvents(new[] { v.EventKeyChangeB64 });
            Assert.Empty(result.Errors);

            var single = chat.DecryptEvent(v.EventMessageB64, result.ConversationKeys);
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);

            var result = chat.DecryptEvents(
                new[] { v.EventKeyChangeB64, v.EventReplyValidB64, v.EventReplyForgedB64 },
                EventSigningKeys(v));
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
            chat.ImportKeys(Convert.FromBase64String(v.PrivateKeysConcatB64), v.EventRecipientKeyVersion);
            chat.SetIdentity(v.EventSenderId, v.EventSigningKeyVersion);

            var payload = chat.EncryptReply(new EncryptReplyParams(v.EventConversationId, "a reply", v.EventMessageB64)
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            });
            Assert.NotEmpty(payload.EncryptedContent);
            Assert.NotEmpty(payload.MessageId);
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
                    new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                    "g123",
                    new[] { "me", "friend" },
                    new[] { "me" })
                {
                    SenderId = "me",
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = publicKeys.Identity, KeyVersion = "1" } },
                "g123",
                new[] { "me", "friend" },
                new[] { "me" })
            {
                SenderId = "me",
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
            var ckey = NewConvKey(chat);

            // Width=0 and Height=0 are unusual but must not cause a serialization bug.
            var payload = chat.EncryptMessage(new EncryptMessageParams("conv-1", "Attachment with zero dimensions")
            {
                SenderId = "me",
                SigningKeyVersion = "s1",
                ConversationKey = ckey,
                ConversationKeyVersion = "v1",
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
                new[] { new PublicKeyInput { UserId = "me", PublicKey = keys.Identity, KeyVersion = "1" } })
            {
                SenderId = "me",
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
            var result = chat.DecryptEvents(Array.Empty<string>());

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
                () => chat.DecryptEvents(Array.Empty<string>(), malformed));
            Assert.Contains("Invalid signing keys JSON", ex.Message);
        }
    }
}
