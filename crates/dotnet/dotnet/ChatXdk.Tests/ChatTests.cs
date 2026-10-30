// Integration tests for the ChatXdk .NET bindings.
//
// These tests require the native library (chat_xdk_ffi.dylib / .so / .dll)
// to be built and on the library path:
//
//   cargo build -p chat-xdk-ffi --release
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
            [JsonPropertyName("event_group_description_b64")] public string EventGroupDescriptionB64 { get; init; } = "";
            [JsonPropertyName("event_group_description")] public string EventGroupDescription { get; init; } = "";
            [JsonPropertyName("event_group_id")] public string EventGroupId { get; init; } = "";
            [JsonPropertyName("event_group_create_b64")] public string EventGroupCreateB64 { get; init; } = "";
            [JsonPropertyName("event_group_create_conversation_key_b64")] public string EventGroupCreateConversationKeyB64 { get; init; } = "";
            [JsonPropertyName("event_group_create_conversation_key_version")] public string EventGroupCreateConversationKeyVersion { get; init; } = "";
            [JsonPropertyName("event_group_create_encrypted_title")] public string EventGroupCreateEncryptedTitle { get; init; } = "";
            [JsonPropertyName("event_group_title")] public string EventGroupTitle { get; init; } = "";
            [JsonPropertyName("event_group_avatar_change_b64")] public string EventGroupAvatarChangeB64 { get; init; } = "";
            [JsonPropertyName("event_group_avatar_url")] public string EventGroupAvatarUrl { get; init; } = "";
            [JsonPropertyName("event_group_removal_flow_b64")] public string[] EventGroupRemovalFlowB64 { get; init; } = Array.Empty<string>();
            [JsonPropertyName("event_group_removal_dropped_indices")] public int[] EventGroupRemovalDroppedIndices { get; init; } = Array.Empty<int>();
            [JsonPropertyName("event_group_removal_conversation_key_version")] public string EventGroupRemovalConversationKeyVersion { get; init; } = "";
            [JsonPropertyName("event_group_removed_member_id")] public string EventGroupRemovedMemberId { get; init; } = "";
            [JsonPropertyName("event_group_renamed_title")] public string EventGroupRenamedTitle { get; init; } = "";
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

        private static JsonDocument LoadFixture(string name)
        {
            var dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "tests", "fixtures", name)))
                dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, "tests", "fixtures", name)));
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
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = chat.GetPublicKeys().Identity, PublicKeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });
            return prep.ConversationKey;
        }

        /// <summary>Signing keys matching the fixture's event vectors.</summary>
        private static SigningKeyEntry[] EventSigningKeys(SdkVectors v) => SigningKeysFor(v, v.EventSenderId);

        /// <summary>The key map of the fixture conversation key, which opens the
        /// conversation-key media message and the reply vectors.</summary>
        private static Dictionary<string, byte[]> ConversationKeys(SdkVectors v) =>
            new() { [v.EventConversationKeyVersion] = Convert.FromBase64String(v.ConversationKeyB64) };

        /// <summary>The one <c>action_signatures</c> entry of a prepared delete or read receipt.</summary>
        private static ActionSignature OnlyAction(PreparedAction prepared) => Assert.Single(prepared.ActionSignatures);

        /// <summary>
        /// Whether <paramref name="sig"/>'s signature verifies, under the signer's own signing key,
        /// over <paramref name="payload"/>: the comma-joined fields its event signs.
        /// </summary>
        private static bool Signs(Chat chat, ActionSignature sig, string payload)
        {
            var signed = sig.MessageEventSignature.Signature;
            var signature = Convert.FromBase64String(signed.PadRight(signed.Length + (4 - signed.Length % 4) % 4, '='));
            return chat.Verify(
                sig.MessageEventSignature.SigningPublicKey, signature, System.Text.Encoding.UTF8.GetBytes(payload));
        }

        /// <summary>File-encryption params under the fixture conversation key.</summary>
        private static EncryptFileParams EncryptFileParamsFor(SdkVectors v, byte[] file, string eventB64, string mediaHashKey) =>
            new(file, eventB64, mediaHashKey)
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            };

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
        public void Errors_CarryTheirKind()
        {
            using var chat = new Chat();
            var config = Assert.Throws<ChatXdkException>(() => chat.UpdateConfig("not json"));
            Assert.Equal(ChatXdkErrorKind.InvalidInput, config.Kind);
            Assert.Null(config.GuessesRemaining);
            Assert.Equal(ChatXdkErrorKind.InvalidInput,
                Assert.Throws<ChatXdkException>(() => chat.Setup(System.Text.Encoding.UTF8.GetBytes("123"))).Kind);
            Assert.Equal(ChatXdkErrorKind.Parse,
                Assert.Throws<ChatXdkException>(() => chat.DecryptEvent(new DecryptEventParams("not base64!"))).Kind);
            Assert.Equal(ChatXdkErrorKind.InvalidState,
                Assert.Throws<ChatXdkException>(() => chat.Sign(new byte[] { 1 })).Kind);
            Assert.Throws<ArgumentNullException>(() => new Chat(null!));
        }

        [Fact]
        public async Task JuiceboxCalls_WithoutAConfig_FailWithTheCoresInvalidStateError()
        {
            using var chat = new Chat();
            chat.GenerateKeypairs();
            const string want = "Invalid state: no Juicebox config: pass the juicebox_config the X API "
                + "returns when you create the chat, or call update_config() first";
            var pin = System.Text.Encoding.UTF8.GetBytes("2580");
            var newPin = System.Text.Encoding.UTF8.GetBytes("1359");
            var failures = new[]
            {
                Assert.Throws<ChatXdkException>(() => chat.Setup(pin)),
                Assert.Throws<ChatXdkException>(() => chat.Unlock(pin)),
                Assert.Throws<ChatXdkException>(() => chat.ChangePin(pin, newPin)),
                Assert.Throws<ChatXdkException>(() => chat.Delete()),
                await Assert.ThrowsAsync<ChatXdkException>(() => chat.UnlockAsync(pin)),
            };
            foreach (var e in failures)
            {
                Assert.Equal(ChatXdkErrorKind.InvalidState, e.Kind);
                Assert.Equal(want, e.Message);
            }
            Assert.True(chat.IsUnlocked);
        }

        [Fact]
        public void Errors_ReadTheInvalidPinCount()
        {
            var wrongPin = ChatXdkException.FromDocument(
                "{\"kind\":\"invalid_pin\",\"message\":\"Juicebox error: Invalid PIN: guesses_remaining=3\",\"guesses_remaining\":3}");
            Assert.Equal(ChatXdkErrorKind.InvalidPin, wrongPin.Kind);
            Assert.Equal(3, wrongPin.GuessesRemaining);
            Assert.Equal("Juicebox error: Invalid PIN: guesses_remaining=3", wrongPin.Message);
            var noCount = ChatXdkException.FromDocument(
                "{\"kind\":\"invalid_pin\",\"message\":\"Juicebox error: Invalid PIN\"}");
            Assert.Null(noCount.GuessesRemaining);
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
            Assert.Equal(
                "1700000000123",
                OnlyAction(chat.PrepareMessageDelete(deleteParams)).MessageEventSignature.PublicKeyVersion);

            // Restored keys carry the version passed to ImportKeys, and none
            // without it.
            var keys = chat.ExportKeys();
            using var restored = new Chat();
            restored.ImportKeys(new ImportKeysParams(keys) { SigningKeyVersion = "1700000000456" });
            Assert.Equal(
                "1700000000456",
                OnlyAction(restored.PrepareMessageDelete(deleteParams)).MessageEventSignature.PublicKeyVersion);
            restored.ImportKeys(new ImportKeysParams(keys));
            Assert.Throws<ChatXdkException>(() => restored.PrepareMessageDelete(deleteParams));
        }

        [Fact]
        public void UnsetFields_AreOmitted_NotSentAsNull()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("1234", "1700000000123"));
            // A required field left null is omitted, so the core names it.
            var ex = Assert.Throws<ChatXdkException>(() => chat.PrepareMessageDelete(
                new MessageDeleteParams("1234-5678", null!, deleteForAll: false)));
            Assert.Equal(ChatXdkErrorKind.InvalidInput, ex.Kind);
            Assert.Contains("missing field `sequence_ids`", ex.Message);
            // Unset optional fields resolve from the session identity.
            Assert.Equal(
                "1700000000123",
                OnlyAction(chat.PrepareMessageDelete(new MessageDeleteParams(
                    "1234-5678", new[] { "seq-1" }, deleteForAll: false))).MessageEventSignature.PublicKeyVersion);
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
            var identityOnly = source.ExportKeys().Take(32).ToArray();

            // Identity-only sessions can export (32 bytes), matching core;
            // only a session with no identity key at all returns null.
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(identityOnly));
            var exported = chat.ExportKeys();
            Assert.NotNull(exported);
            Assert.Equal(identityOnly, exported);
        }

        [Fact]
        public void Descriptors_TakeTheirRequiredValuesInConstructors()
        {
            Assert.Empty(typeof(AttachmentDescriptor).GetConstructors());
            foreach (var (type, required) in new[]
            {
                (typeof(EntityDescriptor), new[] { "Start", "End", "EntityType" }),
                (typeof(UrlAttachmentImageDescriptor), new[] { "MediaHashKey", "FilesizeBytes", "Filename" }),
            })
            {
                var constructor = Assert.Single(type.GetConstructors());
                Assert.Equal(
                    required.Select(name => name.ToLowerInvariant()),
                    constructor.GetParameters().Select(p => p.Name!.ToLowerInvariant()));
                Assert.All(required, name => Assert.Null(type.GetProperty(name)!.GetSetMethod()));
            }
            Assert.All(typeof(AttachmentDescriptor).GetProperties(), p => Assert.Null(p.GetSetMethod()));
        }

        [Fact]
        public void EncryptMessage_FileWithoutANameOrASize_FailsWithInvalidInput()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            const string noName = "has an empty filename: pass the file's original name";
            const string noSize = "has filesize_bytes 0: pass the encrypted file's size, which encrypted_file_size gives";
            var cases = new (AttachmentDescriptor Attachment, string Message)[]
            {
                (AttachmentDescriptor.Media("photo", 100, 100, 1000, ""), $"media_hash_key 'photo' {noName}"),
                (AttachmentDescriptor.Media("photo", 100, 100, 0, "photo.jpg"), $"media_hash_key 'photo' {noSize}"),
                (AttachmentDescriptor.UrlCard("https://example.com", "Example",
                    bannerImage: new UrlAttachmentImageDescriptor("banner", 1000, "")), $"media_hash_key 'banner' {noName}"),
                (AttachmentDescriptor.UrlCard("https://example.com", "Example",
                    faviconImage: new UrlAttachmentImageDescriptor("favicon", 0, "favicon.png")), $"media_hash_key 'favicon' {noSize}"),
            };
            foreach (var (attachment, message) in cases)
            {
                var e = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(new EncryptMessageParams("conv-1", "a file")
                {
                    SenderId = "1001",
                    SigningKeyVersion = "66",
                    ConversationKey = ckey,
                    ConversationKeyVersion = "1",
                    Attachments = new[] { attachment },
                }));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, e.Kind);
                Assert.Equal(message, e.Message);
            }
        }

        [Fact]
        public void EncryptMessage_InvalidOffsetsLinksPostsAndDimensions_FailWithInvalidInput()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            EncryptMessageParams Params(
                string text,
                IReadOnlyList<EntityDescriptor>? entities,
                IReadOnlyList<AttachmentDescriptor>? attachments) => new(conversationId: "conv-1", text)
            {
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
                Entities = entities,
                Attachments = attachments,
            };
            var banner = new UrlAttachmentImageDescriptor("banner", 1000, "b.png") { Height = -1 };
            var cases = new (EntityDescriptor[]? Entities, AttachmentDescriptor[]? Attachments, string Message)[]
            {
                (new[] { new EntityDescriptor(-1, 4, "mention") }, null,
                    "Invalid entity offsets -1..4: offsets count bytes of the UTF-8 text, from 0"),
                (new[] { new EntityDescriptor(5, 3, "mention") }, null,
                    "Invalid entity offsets 5..3: end is before start"),
                (new[] { new EntityDescriptor(3, 8, "mention") }, null,
                    "Invalid entity offsets 3..8: end is past the end of the text, which is 7 bytes of UTF-8"),
                (null, new[] { AttachmentDescriptor.UrlCard("") },
                    "a URL card's url is empty: pass the link the card shows"),
                (null, new[] { AttachmentDescriptor.Post() },
                    "a post attachment has neither rest_id nor post_url: pass the post's id or its URL"),
                (null, new[] { AttachmentDescriptor.Media("photo", -1, 100, 1000, "photo.jpg") },
                    "media_hash_key 'photo' has width -1: pass the width in pixels, 0 or more"),
                (null, new[] { AttachmentDescriptor.UrlCard("https://example.com", bannerImage: banner) },
                    "media_hash_key 'banner' has height -1: pass the height in pixels, 0 or more"),
            };
            foreach (var (entities, attachments, message) in cases)
            {
                var e = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(Params("hi @bob", entities, attachments)));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, e.Kind);
                Assert.Equal(message, e.Message);
            }
            // Offsets count UTF-8 bytes: "é @bob" is 7 bytes, and "@bob" is bytes 3..7.
            chat.EncryptMessage(Params("é @bob", new[] { new EntityDescriptor(3, 7, "mention") }, null));
        }

        [Fact]
        public void Chat_EmptyJuiceboxConfig_FailsWithTheNoConfigError()
        {
            const string want = "Invalid state: no Juicebox config: pass the juicebox_config the X API "
                + "returns when you create the chat, or call update_config() first";
            foreach (var empty in new[] { "", "  " })
            {
                var e = Assert.Throws<ChatXdkException>(() => new Chat(empty));
                Assert.Equal(ChatXdkErrorKind.InvalidState, e.Kind);
                Assert.Equal(want, e.Message);
            }
            using var chat = new Chat();
            var update = Assert.Throws<ChatXdkException>(() => chat.UpdateConfig(""));
            Assert.Equal(ChatXdkErrorKind.InvalidState, update.Kind);
            Assert.Equal(want, update.Message);
        }

        [Fact]
        public void EncryptMessage_UnknownOrEmptyEntityType_FailsWithInvalidInput()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            foreach (var entityType in new[] { "bogus", "" })
            {
                var e = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(new EncryptMessageParams("conv-1", "hi @bob")
                {
                    SenderId = "1001",
                    SigningKeyVersion = "66",
                    ConversationKey = ckey,
                    ConversationKeyVersion = "1",
                    Entities = new[] { new EntityDescriptor(3, 7, entityType) },
                }));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, e.Kind);
                Assert.Equal(
                    $"Invalid entity_type '{entityType}': pass url, mention, hashtag, cashtag, email, address or phone_number",
                    e.Message);
            }
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
            Assert.NotEmpty(payload.Signature);
            Assert.NotEmpty(payload.EncodedMessageEventSignature);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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
                    new(6, 12, "mention"),
                    new(13, 26, "url"),
                },
            });

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
        }

        [Fact]
        public void EncryptMessage_UrlAttachmentWithBannerImage_Succeeds()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);

            var attachment = AttachmentDescriptor.UrlCard(
                "https://example.com/product",
                "Example Product",
                bannerImage: new UrlAttachmentImageDescriptor("banner-hash", 24_000, "banner.jpg")
                {
                    Width = 1200,
                    Height = 630,
                },
                faviconImage: new UrlAttachmentImageDescriptor("favicon-hash", 1_200, "favicon.ico"));

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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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
                Entities = new[] { new EntityDescriptor(4, 23, "url") },
                SenderId = "1001",
                SigningKeyVersion = "66",
                ConversationKey = ckey,
                ConversationKeyVersion = "1",
            });

            Assert.NotEmpty(payload.MessageId);
            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
            Assert.NotEmpty(payload.Signature);
            Assert.NotEmpty(payload.EncodedMessageEventSignature);
        }

        [Fact]
        public void SendPayload_TakesTheRequestFieldNames()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v);
            var payload = chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "hi")
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            });

            var json = JsonSerializer.SerializeToElement(payload);
            Assert.Equal(payload.MessageId, json.GetProperty("message_id").GetString());
            Assert.Equal(payload.EncodedMessageCreateEvent, json.GetProperty("encoded_message_create_event").GetString());
            Assert.Equal(payload.EncodedMessageEventSignature, json.GetProperty("encoded_message_event_signature").GetString());
            Assert.NotEmpty(payload.XdkVersion);
            Assert.Equal(payload.XdkVersion, json.GetProperty("xdk_version").GetString());
            var roundTrip = json.Deserialize<SendPayload>()!;
            Assert.Equal(payload.EncodedMessageCreateEvent, roundTrip.EncodedMessageCreateEvent);
            Assert.Equal(payload.EncodedMessageEventSignature, roundTrip.EncodedMessageEventSignature);
        }

        // PrepareMessageDelete

        [Fact]
        public void PrepareMessageDelete_SignsCanonicalPayload()
        {
            using var chat = CreateUnlocked();

            // A 1:1 id is signed in its canonical colon form; delete-for-all
            // signs the wire action 2.
            var prepared = chat.PrepareMessageDelete(new MessageDeleteParams(
                "222-111", new[] { "seq-10", "seq-11" }, deleteForAll: true)
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            });
            var sig = OnlyAction(prepared);

            Assert.NotEmpty(sig.MessageId);
            Assert.NotEmpty(sig.EncodedMessageEventDetail);
            // The signature is nested as the request's action_signatures carry it.
            Assert.NotEmpty(sig.MessageEventSignature.Signature);
            Assert.Equal("7", sig.MessageEventSignature.SignatureVersion);
            Assert.Equal("1", sig.MessageEventSignature.PublicKeyVersion);
            Assert.Equal(chat.GetPublicKeys().Signing, sig.MessageEventSignature.SigningPublicKey);
            var entry = JsonSerializer.SerializeToElement(prepared).GetProperty("action_signatures")[0];
            Assert.False(entry.TryGetProperty("signature", out _));
            Assert.Equal(
                sig.MessageEventSignature.SigningPublicKey,
                entry.GetProperty("message_event_signature").GetProperty("signing_public_key").GetString());
            Assert.True(Signs(chat, sig, $"MessageDeleteEvent,{sig.MessageId},111,111:222,2,seq-10,seq-11"));
        }

        [Fact]
        public void GroupActions_SignVerifierPayloads()
        {
            using var chat = CreateUnlocked();
            var keys = chat.GetPublicKeys();
            var remaining = new[]
            {
                new PublicKeyInput { UserId = "111", IdentityPublicKey = keys.Identity, PublicKeyVersion = "1" },
            };
            var rotated = chat.PrepareGroupMembersRemove(new GroupMembersRemoveParams(remaining, "g100", new[] { "910007" })
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            });
            Assert.Equal(32, rotated.ConversationKey.Length);
            Assert.Single(rotated.ConversationParticipantKeys);
            Assert.Equal(2, rotated.ActionSignatures.Count);
            Assert.Equal("7", rotated.ActionSignatures[0].MessageEventSignature.SignatureVersion);
            var removal = rotated.ActionSignatures[0];
            Assert.True(Signs(chat, removal, $"GroupChangeEvent.GroupMemberRemoveChange,{removal.MessageId},111,g100,910007"));
            var noKeys = Assert.Throws<ChatXdkException>(() => chat.PrepareGroupMembersRemove(
                new GroupMembersRemoveParams(Array.Empty<PublicKeyInput>(), "g100", new[] { "910007" })
                {
                    SenderId = "111",
                    SigningKeyVersion = "1",
                }));
            Assert.Equal("public_keys is empty: pass the public keys of the remaining members", noKeys.Message);

            var left = chat.PrepareGroupLeave(new GroupLeaveParams("g100")
            {
                SenderId = "111",
                SigningKeyVersion = "1",
                PromoteAdminId = "910008",
                ConversationKeyVersion = "7",
            });
            Assert.Equal(3, left.ActionSignatures.Count);
            var (leaving, promoting, deleting) = (left.ActionSignatures[0], left.ActionSignatures[1], left.ActionSignatures[2]);
            Assert.Equal("7", leaving.MessageEventSignature.SignatureVersion);
            Assert.True(Signs(chat, leaving,
                $"GroupChangeEvent.GroupMemberRemoveChange,{leaving.MessageId},111,g100,111"));

            using (var v1 = FeatureTestEnvironment.V1Chat())
            {
                v1.ImportKeys(new ImportKeysParams(chat.ExportKeys()!));
                FeatureTestEnvironment.WaitForV1(v1);
                var v1Left = v1.PrepareGroupLeave(new GroupLeaveParams("g100") { SenderId = "111", SigningKeyVersion = "1" });
                var (v1Removal, v1Delete) = (v1Left.ActionSignatures[0], v1Left.ActionSignatures[1]);
                Assert.Equal("10", v1Removal.MessageEventSignature.SignatureVersion);
                Assert.True(Signs(v1, v1Removal,
                    $"GroupChangeEvent.GroupMemberRemoveChange,{v1Removal.MessageId},111,g100,111,signature_version=10"));
                Assert.Equal("10", v1Delete.MessageEventSignature.SignatureVersion);
                Assert.True(Signs(v1, v1Delete, $"ConversationDeleteEvent,{v1Delete.MessageId},111,g100,signature_version=10"));
            }
            Assert.True(Signs(chat, promoting, $"GroupChangeEvent.GroupAdminAddChange,{promoting.MessageId},111,g100,910008"));
            Assert.True(Signs(chat, deleting, $"ConversationDeleteEvent,{deleting.MessageId},111,g100"));

            var metadata = new (PreparedGroupMetadataChange Prepared, string Prefix, string Plaintext)[]
            {
                (chat.PrepareGroupTitleChange(new GroupTitleChangeParams("g100", "Board: layoffs, Q3")
                {
                    SenderId = "111",
                    SigningKeyVersion = "1",
                    ConversationKey = rotated.ConversationKey,
                    ConversationKeyVersion = rotated.ConversationKeyVersion,
                }), "GroupChangeEvent.GroupTitleChange,", "Board: layoffs, Q3"),
                (chat.PrepareGroupDescriptionChange(new GroupDescriptionChangeParams("g100", "Rules: be kind")
                {
                    SenderId = "111",
                    SigningKeyVersion = "1",
                    ConversationKey = rotated.ConversationKey,
                    ConversationKeyVersion = rotated.ConversationKeyVersion,
                }), "GroupChangeEvent.GroupDescriptionChange,", "Rules: be kind"),
            };
            foreach (var (prepared, prefix, plaintext) in metadata)
            {
                Assert.Equal(rotated.ConversationKeyVersion, prepared.ConversationKeyVersion);
                var sig = Assert.Single(prepared.ActionSignatures);
                Assert.True(Signs(chat, sig,
                    $"{prefix}{sig.MessageId},111,g100,{prepared.ConversationKeyVersion},{prepared.EncryptedValue}"));
                Assert.Equal(plaintext, chat.Decrypt(prepared.EncryptedValue, rotated.ConversationKey));
            }
            const string avatarUrl = "https://ton.x.com/xchat_media/g100/avatar";
            var avatar = OnlyAction(chat.PrepareGroupAvatarChange(
                new GroupAvatarChangeParams("g100", avatarUrl, rotated.ConversationKeyVersion)
                {
                    SenderId = "111",
                    SigningKeyVersion = "1",
                }));
            Assert.True(Signs(chat, avatar,
                $"GroupChangeEvent.GroupAvatarUrlChange,{avatar.MessageId},111,g100,{rotated.ConversationKeyVersion},{avatarUrl}"));
            var uncached = Assert.Throws<ChatXdkException>(() => chat.PrepareGroupTitleChange(
                new GroupTitleChangeParams("g100", "Board") { SenderId = "111", SigningKeyVersion = "1" }));
            Assert.Contains("no cached conversation key for 'g100'", uncached.Message);

            var withTitle = chat.PrepareGroupMembersRemove(new GroupMembersRemoveParams(remaining, "g100", new[] { "910007" })
            {
                SenderId = "111",
                SigningKeyVersion = "1",
                Title = "Board",
            });
            Assert.Equal(3, withTitle.ActionSignatures.Count);
            var rotatedTitle = withTitle.ActionSignatures[1];
            Assert.Equal("7", rotatedTitle.MessageEventSignature.SignatureVersion);
            Assert.NotEmpty(rotatedTitle.EncodedMessageEventDetail);

            var blocking = OnlyAction(chat.PrepareScreenCapture(new ScreenCaptureParams("g100", ScreenCaptureChange.BlockingEnabled)
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            }));
            Assert.True(Signs(chat, blocking,
                $"ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,{blocking.MessageId},111,g100"));
        }

        // The group and conversation-metadata actions each sign one action at signature
        // version 7 over the event name, the action's message id, the sender, the
        // conversation and the signed fields, and the signature verifies with the signer's
        // signing key.
        [Fact]
        public void GroupActions_SignEachAction()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("111", "1"));
            var signingKey = chat.GetPublicKeys().Signing;
            (ActionSignature, string) Action(PreparedAction prepared, string fields) => (OnlyAction(prepared), fields);
            var cases = new (string Name, string Event, Func<(ActionSignature Action, string Fields)> Prepare)[]
            {
                ("avatar", "GroupChangeEvent.GroupAvatarUrlChange",
                    () => Action(chat.PrepareGroupAvatarChange(new GroupAvatarChangeParams("g100", "https://img/a.png", "4")),
                        ",g100,4,https://img/a.png")),
                ("description", "GroupChangeEvent.GroupDescriptionChange", () =>
                {
                    var changed = chat.PrepareGroupDescriptionChange(new GroupDescriptionChangeParams("g100", "Ships the app")
                    {
                        ConversationKey = new byte[32],
                        ConversationKeyVersion = "4",
                    });
                    return (Assert.Single(changed.ActionSignatures), ",g100,4," + changed.EncryptedValue);
                }),
                ("admins add", "GroupChangeEvent.GroupAdminAddChange",
                    () => Action(chat.PrepareGroupAdminsAdd(new GroupAdminsAddParams("g100", new[] { "910008", "910009" })),
                        ",g100,910008,910009")),
                ("admins remove", "GroupChangeEvent.GroupAdminRemoveChange",
                    () => Action(chat.PrepareGroupAdminsRemove(new GroupAdminsRemoveParams("g100", new[] { "910008" })),
                        ",g100,910008")),
                ("invite enable", "GroupChangeEvent.GroupInviteEnable",
                    () => Action(chat.PrepareGroupInviteEnable(new GroupInviteEnableParams("g100", "https://x.com/i/invite/abc")),
                        ",g100,https://x.com/i/invite/abc,null,null")),
                ("invite disable", "GroupChangeEvent.GroupInviteDisable",
                    () => Action(chat.PrepareGroupInviteDisable(new GroupInviteDisableParams("g100")), ",g100,111")),
                ("join request", "GroupChangeEvent.GroupJoinRequest",
                    () => Action(chat.PrepareGroupJoinRequest(new GroupJoinRequestParams("g100")), ",g100,111")),
                ("join reject", "GroupChangeEvent.GroupJoinReject",
                    () => Action(chat.PrepareGroupJoinReject(new GroupJoinRejectParams("g100", new[] { "910010" })),
                        ",g100,910010")),
                ("ttl change", "ConversationMetadataChangeEvent.MessageDurationChange",
                    () => Action(chat.PrepareMessageTtlChange(new MessageTtlChangeParams("g100", 86400000)), ",g100,86400000")),
                ("ttl remove", "ConversationMetadataChangeEvent.MessageDurationRemove",
                    () => Action(chat.PrepareMessageTtlRemove(new MessageTtlRemoveParams("g100")), ",g100")),
            };
            foreach (var (name, eventName, prepare) in cases)
            {
                var (action, fields) = prepare();
                var sig = action.MessageEventSignature;
                Assert.Equal("7", sig.SignatureVersion);
                Assert.Equal(signingKey, sig.SigningPublicKey);
                var payload = $"{eventName},{action.MessageId},111{fields}";
                Assert.True(Signs(chat, action, payload), $"{name}: {payload}");
            }
        }

        [Fact]
        public void PrepareMessageDelete_ForSelf()
        {
            using var chat = CreateUnlocked();

            // Group ids pass through unchanged; delete-for-self signs the wire
            // action 1.
            var sig = OnlyAction(chat.PrepareMessageDelete(new MessageDeleteParams(
                "g999", new[] { "seq-1" }, deleteForAll: false)
            {
                SenderId = "111",
                SigningKeyVersion = "1",
            }));

            Assert.True(Signs(chat, sig, $"MessageDeleteEvent,{sig.MessageId},111,g999,1,seq-1"));
        }

        // PrepareMarkConversationRead

        [Fact]
        public void PrepareMarkConversationRead_SignsCanonicalPayload()
        {
            using var chat = CreateUnlocked();

            // A 1:1 id is signed in its canonical colon form, followed by the
            // read point and its time.
            var sig = OnlyAction(chat.PrepareMarkConversationRead(new MarkConversationReadParams(
                "222-111", "2011626338877079553")
            {
                SeenAtMsec = 1700000000123,
                SenderId = "111",
                SigningKeyVersion = "1",
            }));

            Assert.NotEmpty(sig.MessageId);
            Assert.NotEmpty(sig.EncodedMessageEventDetail);
            Assert.Equal("1", sig.MessageEventSignature.PublicKeyVersion);
            Assert.Equal(chat.GetPublicKeys().Signing, sig.MessageEventSignature.SigningPublicKey);
            Assert.True(Signs(chat, sig,
                $"MarkConversationReadEvent,{sig.MessageId},111,111:222,2011626338877079553,1700000000123"));
        }

        [Fact]
        public void PrepareMarkConversationRead_DefaultsToSessionIdentityAndNow()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("111", "7"));

            var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var sig = OnlyAction(chat.PrepareMarkConversationRead(new MarkConversationReadParams("g999", "seq-1")));
            var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            Assert.Equal("7", sig.MessageEventSignature.PublicKeyVersion);
            var prefix = $"MarkConversationReadEvent,{sig.MessageId},111,g999,seq-1,";
            var signedNow = false;
            for (var seenAt = before; seenAt <= after && !signedNow; seenAt++)
                signedNow = Signs(chat, sig, $"{prefix}{seenAt}");
            Assert.True(signedNow, $"seen_at in [{before}, {after}]");
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
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });

            Assert.Single(prepared.ConversationParticipantKeys);
            Assert.Single(prepared.ActionSignatures);

            // The participant keys serialize under the request's field names.
            var json = JsonSerializer.SerializeToElement(prepared);
            var entry = Assert.Single(json.GetProperty("conversation_participant_keys").EnumerateArray());
            Assert.Equal(
                prepared.ConversationParticipantKeys[0].EncryptedConversationKey,
                entry.GetProperty("encrypted_conversation_key").GetString());

            var decrypted = chat.DecryptConversationKey(prepared.ConversationParticipantKeys[0].EncryptedConversationKey);
            Assert.Equal(prepared.ConversationKey, decrypted);
        }

        // The conversation key is secret: a prepared change carries it, but its JSON, the shape
        // a request body is built from, never does.
        [Fact]
        public void PreparedConversationChange_JsonLeavesOutTheKey()
        {
            using var chat = CreateUnlocked();
            chat.SetIdentity(new SetIdentityParams("910002", "1"));
            var publicKeys = new[]
            {
                new PublicKeyInput { UserId = "910002", IdentityPublicKey = chat.GetPublicKeys().Identity, PublicKeyVersion = "1" },
            };

            var prepared = new[]
            {
                chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(publicKeys)
                {
                    ConversationId = "910002:910005",
                }),
                chat.PrepareGroupCreate(new GroupCreateParams(
                    publicKeys, "g123", new[] { "910002", "910005" }, new[] { "910002" })),
                chat.PrepareGroupMembersRemove(new GroupMembersRemoveParams(publicKeys, "g123", new[] { "910005" })),
            };

            foreach (var change in prepared)
            {
                Assert.Equal(32, change.ConversationKey.Length);
                foreach (var options in new[] { new JsonSerializerOptions(), new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull } })
                {
                    var json = JsonSerializer.SerializeToElement(change, options);
                    Assert.False(json.TryGetProperty("conversation_key", out _), json.GetRawText());
                    Assert.Equal(
                        new[] { "conversation_id", "conversation_key_version", "conversation_participant_keys", "action_signatures" },
                        json.EnumerateObject().Select(p => p.Name).ToArray());
                }
            }
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
            FeatureTestEnvironment.WaitForV1(chat);
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
            using var chat = QuickReplyChat(v, v1: true);
            var plaintext = new byte[1024];
            new Random(42).NextBytes(plaintext);
            var payload = SendFiles(chat, v, "a photo", Photo("photo"));

            // A chat with no identity encrypts the file from the payload.
            using var worker = new Chat();
            var encrypted = worker.EncryptFile(EncryptFileParamsFor(v, plaintext, payload.EventB64, "photo"));
            Assert.NotEqual(plaintext, encrypted);
            Assert.Equal(ChatXdkUtilities.EncryptedFileSize((ulong)plaintext.Length), (ulong)encrypted.Length);
            Assert.Equal(plaintext, chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, ConversationKeys(v), "photo")));
        }

        [Fact]
        public void DecryptFile_WrongKey_Throws()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v, v1: true);
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
            using var chat = QuickReplyChat(v, v1: true);
            var plaintext = Enumerable.Repeat((byte)0xAB, 5000).ToArray();
            var payload = SendFiles(chat, v, "two photos", Photo("first"), Photo("second"));

            using var encryptor = chat.FileEncryptor(new FileEncryptorParams(payload.EventB64, "second")
            {
                ConversationKey = Convert.FromBase64String(v.ConversationKeyB64),
                ConversationKeyVersion = v.EventConversationKeyVersion,
            });
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
        public void FileWithKey_RoundTripsAtEveryFrameCount()
        {
            var key = Convert.FromBase64String(LoadVectors().ConversationKeyB64);
            using var chat = new Chat();
            foreach (var size in new[] { 0, 1, 1023, 1024, 1025, 3050 })
            {
                var file = Enumerable.Range(0, size).Select(i => (byte)(i % 251)).ToArray();
                var encrypted = chat.EncryptFileWithKey(new EncryptFileWithKeyParams(file, key));
                Assert.Equal(ChatXdkUtilities.EncryptedFileSize((ulong)size), (ulong)encrypted.Length);
                Assert.Equal(file, chat.DecryptFileWithKey(new DecryptFileWithKeyParams(encrypted, key)));
            }
        }

        [Fact]
        public void FileWithKey_OpensTheFiles05EncryptStreamEncrypted()
        {
            using var chat = new Chat();
            foreach (var version in new[] { "0_5_0", "0_5_2" })
            {
                using var fixture = LoadFixture($"compat_v{version}.json");
                var root = fixture.RootElement;
                var key = Convert.FromBase64String(root.GetProperty("conversation_key_b64").GetString()!);
                foreach (var name in new[] { "file", "avatar_file", "empty_file" })
                {
                    var entry = root.GetProperty(name);
                    Assert.Equal(
                        Convert.FromBase64String(entry.GetProperty("plaintext_b64").GetString()!),
                        chat.DecryptFileWithKey(new DecryptFileWithKeyParams(
                            Convert.FromBase64String(entry.GetProperty("ciphertext_b64").GetString()!), key)));
                }
            }
        }

        [Fact]
        public void FileWithKey_ErrorsCarryTheirKind()
        {
            var key = Convert.FromBase64String(LoadVectors().ConversationKeyB64);
            using var chat = new Chat();
            var encrypted = chat.EncryptFileWithKey(new EncryptFileWithKeyParams(new byte[1800], key));

            var shortKey = Assert.Throws<ChatXdkException>(
                () => chat.EncryptFileWithKey(new EncryptFileWithKeyParams(new byte[] { 1 }, key[..31])));
            Assert.Equal(ChatXdkErrorKind.InvalidInput, shortKey.Kind);
            Assert.Contains("expected 32 bytes, got 31", shortKey.Message);
            Assert.Equal(ChatXdkErrorKind.InvalidInput, Assert.Throws<ChatXdkException>(
                () => chat.DecryptFileWithKey(new DecryptFileWithKeyParams(encrypted, null!))).Kind);

            foreach (var bad in new[] { encrypted[..^1], encrypted[..(24 + 1041)], encrypted[..10] })
                Assert.Equal(ChatXdkErrorKind.Decryption, Assert.Throws<ChatXdkException>(
                    () => chat.DecryptFileWithKey(new DecryptFileWithKeyParams(bad, key))).Kind);
            Assert.Equal(ChatXdkErrorKind.Decryption, Assert.Throws<ChatXdkException>(
                () => chat.DecryptFileWithKey(new DecryptFileWithKeyParams(encrypted, new byte[32]))).Kind);
        }

        [Fact]
        public void EncryptFile_LinkCardImagesTakeTheCardsKey()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v, v1: true);
            var payload = SendFiles(chat, v, "a link", AttachmentDescriptor.UrlCard(
                "https://example.com",
                bannerImage: new UrlAttachmentImageDescriptor("banner", 12, "banner.png"),
                faviconImage: new UrlAttachmentImageDescriptor("favicon", 13, "favicon.png")));
            foreach (var name in new[] { "banner", "favicon" })
            {
                var encrypted = chat.EncryptFile(EncryptFileParamsFor(v, System.Text.Encoding.UTF8.GetBytes(name + " bytes"), payload.EventB64, name));
                Assert.Equal(name + " bytes", System.Text.Encoding.UTF8.GetString(
                    chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, ConversationKeys(v), name))));
            }
        }

        [Fact]
        public void AMessageWithFiles_TakesTheIdItsFilesDerive()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v, v1: true);
            var draft = SendFiles(chat, v, "draft", Photo("photo-a"), Photo("photo-b"));
            Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", draft.MessageId);
            var encrypted = chat.EncryptFile(EncryptFileParamsFor(v, System.Text.Encoding.UTF8.GetBytes("photo b"), draft.EventB64, "photo-b"));

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
            using var chat = QuickReplyChat(v, v1: true);
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
                () => chat.EncryptFile(EncryptFileParamsFor(v, new byte[] { 1 }, payload.EventB64, "other"))).Message);
            Assert.Contains("expected 32 bytes", Assert.Throws<ChatXdkException>(
                () => chat.EncryptFile(new EncryptFileParams(new byte[] { 1 }, payload.EventB64, "photo")
                {
                    ConversationKey = new byte[3],
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                })).Message);
            Assert.Contains(
                $"conversation_key_version '9' is not the message's key version '{v.EventConversationKeyVersion}'",
                Assert.Throws<ChatXdkException>(() => chat.EncryptFile(new EncryptFileParams(new byte[] { 1 }, payload.EventB64, "photo")
                {
                    ConversationKey = ckey,
                    ConversationKeyVersion = "9",
                })).Message);

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
                () => chat.EncryptFile(EncryptFileParamsFor(v, new byte[] { 1 }, reply.EventB64, "photo"))).Message);

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
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
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
            Assert.NotEmpty(prepared.ActionSignatures[0].EncodedMessageEventDetail);
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
            // The title goes out encrypted under the new key, the value the request
            // sends as encrypted_title; the signature covers the ciphertext. Unset
            // screen-capture blocking signs as the trailing null sentinel.
            var add = prepared.ActionSignatures[1];
            Assert.True(Signs(chat, add,
                $"GroupChangeEvent.GroupMemberAddChange,{add.MessageId},910002,g123,910006,910002,910002," +
                $"{prepared.EncryptedTitle},null,null,{prepared.ConversationKeyVersion},null"));
            Assert.Equal("Test Group", chat.Decrypt(prepared.EncryptedTitle!, prepared.ConversationKey));
            Assert.Null(prepared.EncryptedDescription);
            Assert.Equal("7", add.MessageEventSignature.SignatureVersion);
        }

        [Fact]
        public void PrepareGroupMembersChange_EncryptsTheDescription()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();
            const string avatarUrl = "https://ton.x.com/xchat_media/g123/avatar";

            var prepared = chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
                "g123",
                new[] { "910006" },
                new[] { "910002" },
                new[] { "910002" },
                Array.Empty<string>())
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                CurrentTitle = "Test Group",
                CurrentDescription = "Ships the app",
                CurrentAvatarUrl = avatarUrl,
            });

            Assert.Equal("Ships the app", chat.Decrypt(prepared.EncryptedDescription!, prepared.ConversationKey));
            // The description is signed at version 8, after the screen-capture slot;
            // the avatar URL is signed as passed.
            var add = prepared.ActionSignatures[1];
            Assert.Equal("8", add.MessageEventSignature.SignatureVersion);
            Assert.True(Signs(chat, add,
                $"GroupChangeEvent.GroupMemberAddChange,{add.MessageId},910002,g123,910006,910002,910002," +
                $"{prepared.EncryptedTitle},{avatarUrl},null,{prepared.ConversationKeyVersion},null,{prepared.EncryptedDescription}"));
        }

        [Fact]
        public void PrepareGroupMembersChange_SignsScreenCaptureBlocking()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
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
            var add = prepared.ActionSignatures[1];
            Assert.True(Signs(chat, add,
                $"GroupChangeEvent.GroupMemberAddChange,{add.MessageId},910002,g123,910006,910002,910002," +
                $"null,null,null,{prepared.ConversationKeyVersion},true"));
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
        }

        [Fact]
        public void PrepareGroupCreate_ReturnsSignedChange()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupCreate(new GroupCreateParams(
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
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
            Assert.NotEmpty(prepared.ActionSignatures[0].EncodedMessageEventDetail);
            Assert.NotEmpty(prepared.ActionSignatures[1].EncodedMessageEventDetail);
            // The title goes out encrypted under the new key, the value the request
            // sends as group_name; the signature covers the ciphertext.
            var create = prepared.ActionSignatures[1];
            Assert.True(Signs(chat, create,
                $"GroupChangeEvent.GroupCreate,{create.MessageId},910002,{prepared.ConversationKeyVersion}," +
                $"910002,910005,null,{prepared.EncryptedTitle},null"));
            Assert.Equal("Test Group", chat.Decrypt(prepared.EncryptedTitle!, prepared.ConversationKey));
            Assert.Null(prepared.EncryptedDescription);
        }

        [Fact]
        public void PrepareConversationKeyChange_DerivesOneToOneId()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareConversationKeyChange(new ConversationKeyChangeParams(new[]
            {
                new PublicKeyInput { UserId = "1491585161162473473", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" },
                new PublicKeyInput { UserId = "17380288", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" },
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
                new PublicKeyInput { UserId = "17380288", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" },
                new PublicKeyInput { UserId = "1491585161162473473", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" },
            })
            {
                SenderId = "17380288",
                SigningKeyVersion = "1",
            });

            Assert.Equal("17380288:1491585161162473473", prepared.ConversationId);
            Assert.Equal(2, prepared.ConversationParticipantKeys.Count);
            foreach (var pk in prepared.ConversationParticipantKeys)
            {
                var decrypted = chat.DecryptConversationKey(pk.EncryptedConversationKey);
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
            Assert.Equal(ChatXdkErrorKind.InvalidState,
                Assert.Throws<ChatXdkException>(() => chat.ExportKeys()).Kind);
        }

        // SetRejectUnverified decides whether a message from a sender whose signing key the
        // chat lacks is rejected or returned unverified.
        [Fact]
        public void SetRejectUnverified_DecidesWhetherUnverifiedMessagesAreRejected()
        {
            using var chat = CreateUnlocked();
            using var sender = CreateUnlocked();
            var conversationKey = new byte[32];
            var payload = sender.EncryptMessage(new EncryptMessageParams("910004:910005", "hi")
            {
                SenderId = "910005",
                SigningKeyVersion = "1",
                ConversationKey = conversationKey,
                ConversationKeyVersion = "1",
            });
            var received = new DecryptEventParams(
                payload.EventB64, new Dictionary<string, byte[]> { ["1"] = conversationKey });
            Assert.Throws<ChatXdkException>(() => chat.DecryptEvent(received));
            chat.SetRejectUnverified(false);
            var unverified = chat.DecryptEvent(received);
            Assert.Equal("hi", unverified.GetProperty("content").GetProperty("text").GetString());
            Assert.False(unverified.GetProperty("verified").GetBoolean());
            chat.SetRejectUnverified(true);
            Assert.Throws<ChatXdkException>(() => chat.DecryptEvent(received));
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

        // Sign refuses data only the SDK signs: an event signature payload and a public key.
        // Data that only resembles a payload is application data.
        [Fact]
        public void Sign_RefusesDataOnlyTheSdkSigns()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));

            const string keyChange = "ConversationKeyChangeEvent,mk1,1001,1001:1002,1800000000000,a2V5";
            foreach (var data in new[] { System.Text.Encoding.UTF8.GetBytes(keyChange), Convert.FromBase64String(v.IdentityPublicB64) })
            {
                var ex = Assert.Throws<ChatXdkException>(() => chat.Sign(data));
                Assert.Contains("only the SDK signs", ex.Message);
            }
            Assert.Equal(64, chat.Sign(System.Text.Encoding.UTF8.GetBytes(" " + keyChange)).Length);
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

            var keyChanges = result.Events
                .Where(m => m.Event.GetProperty("type").GetString() == "KeyChange")
                .Select(m => m.Event)
                .ToList();
            Assert.Single(keyChanges);
            Assert.True(keyChanges[0].GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventConversationKeyVersion,
                keyChanges[0].GetProperty("conversation_key_version").GetString());
            // The received participant keys read into the type a prepared change carries.
            var participantKeys = keyChanges[0].GetProperty("conversation_participant_keys")
                .Deserialize<List<ConversationParticipantKey>>()!;
            Assert.NotEmpty(participantKeys);
            foreach (var key in participantKeys)
            {
                Assert.False(string.IsNullOrEmpty(key.UserId));
                Assert.False(string.IsNullOrEmpty(key.EncryptedConversationKey));
                Assert.False(string.IsNullOrEmpty(key.PublicKeyVersion));
            }

            var messages = result.Events
                .Where(m => m.Event.GetProperty("type").GetString() == "Message")
                .Select(m => m.Event)
                .ToList();
            Assert.Single(messages);
            Assert.Equal(v.EventMessageText,
                messages[0].GetProperty("content").GetProperty("text").GetString());
            Assert.True(messages[0].GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventConversationKeyVersion,
                messages[0].GetProperty("conversation_key_version").GetString());

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
        // Reactions and edits name their target by its sequence id; a v0 edit
        // carries no target message id.
        [Fact]
        public void Vectors_ReactionsAndEdits_NameTheirTargetBySequenceId()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)));
            chat.SetIdentity(new SetIdentityParams(v.EventSenderId, v.EventSigningKeyVersion));
            var key = Convert.FromBase64String(v.ConversationKeyB64);

            JsonElement Content(SendPayload payload)
            {
                var e = chat.DecryptEvent(new DecryptEventParams(payload.EventB64, ConversationKeys(v))
                {
                    SigningKeys = EventSigningKeys(v),
                });
                Assert.True(e.GetProperty("verified").GetBoolean());
                return e.GetProperty("content");
            }

            var reaction = new EncryptReactionParams(v.EventMessageB64, "👍")
            {
                ConversationKey = key,
                ConversationKeyVersion = v.EventConversationKeyVersion,
            };
            var added = Content(chat.EncryptAddReaction(reaction));
            Assert.Equal("Reaction", added.GetProperty("content_type").GetString());
            Assert.Equal("1", added.GetProperty("target_message_sequence_id").GetString());
            var removed = Content(chat.EncryptRemoveReaction(reaction));
            Assert.Equal("ReactionRemoved", removed.GetProperty("content_type").GetString());
            Assert.Equal("1", removed.GetProperty("target_message_sequence_id").GetString());

            var edited = Content(chat.EncryptEdit(new EncryptEditParams(v.EventMessageB64, "fixed")
            {
                ConversationKey = key,
                ConversationKeyVersion = v.EventConversationKeyVersion,
            }));
            Assert.Equal("Edit", edited.GetProperty("content_type").GetString());
            Assert.Equal("1", edited.GetProperty("target_message_sequence_id").GetString());
            Assert.Equal("fixed", edited.GetProperty("updated_text").GetString());
            Assert.False(edited.TryGetProperty("target_message_id", out _));
        }

        // A v1 send built without the original event names it through the explicit fields,
        // and a media attachment carries the SHA-256 of its plaintext file: ReplyToMessageId,
        // TargetMessageId and PlaintextSha256 each read back from the decrypted send.
        [Fact]
        public void V1Sends_NameTheOriginalAndCarryTheFileHash_FromExplicitFields()
        {
            var v = LoadVectors();
            using var chat = QuickReplyChat(v, v1: true);
            var key = Convert.FromBase64String(v.ConversationKeyB64);
            var hash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("the photo's plaintext bytes")));

            var sent = SendFiles(chat, v, "a photo",
                AttachmentDescriptor.Media("hashed", 4, 3, 64, "hashed.jpg", 1, null, hash),
                Photo("unhashed"));
            var evt = chat.DecryptEvent(new DecryptEventParams(sent.EventB64, ConversationKeys(v))
            {
                SigningKeys = EventSigningKeys(v),
            });
            var attachments = evt.GetProperty("attachments");
            Assert.Equal(hash, attachments[0].GetProperty("plaintext_sha256").GetString());
            Assert.Equal(JsonValueKind.Null, attachments[1].GetProperty("plaintext_sha256").ValueKind);

            var replied = DecryptOwnContent(chat, v, chat.EncryptReply(
                new EncryptReplyParams(v.EventConversationId, "nice", null)
                {
                    ConversationKey = key,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    ReplyToSequenceId = "100",
                    ReplyToMessageId = sent.MessageId,
                    ReplyToSenderId = v.EventSenderId,
                    ReplyToText = "a photo",
                }));
            Assert.Equal(sent.MessageId,
                replied.GetProperty("replying_to_preview").GetProperty("replying_to_message_id").GetString());

            var edited = DecryptOwnContent(chat, v, chat.EncryptEdit(new EncryptEditParams(null, "a better photo")
            {
                ConversationId = v.EventConversationId,
                TargetMessageSequenceId = "100",
                TargetMessageId = sent.MessageId,
                ConversationKey = key,
                ConversationKeyVersion = v.EventConversationKeyVersion,
            }));
            Assert.Equal(sent.MessageId, edited.GetProperty("target_message_id").GetString());

            var ex = Assert.Throws<ChatXdkException>(() => chat.EncryptMessage(
                new EncryptMessageParams(v.EventConversationId, "a photo")
                {
                    ConversationKey = key,
                    ConversationKeyVersion = v.EventConversationKeyVersion,
                    Attachments = new[] { AttachmentDescriptor.Media("hashed", 4, 3, 64, "hashed.jpg", 1, null, "c2hvcnQ=") },
                }));
            Assert.Equal(ChatXdkErrorKind.InvalidInput, ex.Kind);
            Assert.Equal("media_hash_key 'hashed' has plaintext_sha256 'c2hvcnQ=': pass the base64 SHA-256 of the "
                + "file's plaintext bytes (32 bytes)", ex.Message);
        }

        // A signed group description change: DecryptEvent returns the
        // description decrypted under the fixture conversation key, and
        // without that key the change fails instead of coming back as
        // ciphertext.
        [Fact]
        public void Vectors_GroupDescriptionChange_DecryptsOnReceive()
        {
            var v = LoadVectors();
            using var chat = new Chat();

            var e = chat.DecryptEvent(new DecryptEventParams(v.EventGroupDescriptionB64, ConversationKeys(v))
            {
                SigningKeys = EventSigningKeys(v),
            });
            Assert.Equal("GroupChange", e.GetProperty("type").GetString());
            Assert.True(e.GetProperty("verified").GetBoolean());
            Assert.Equal(v.EventGroupId, e.GetProperty("conversation_id").GetString());
            var change = e.GetProperty("change");
            Assert.Equal("DescriptionChanged", change.GetProperty("change_type").GetString());
            var description = change.GetProperty("new_description").Deserialize<GroupText>()!;
            Assert.Equal("Text", description.Kind);
            Assert.Equal(v.EventGroupDescription, description.Text);

            // Without the key the description was encrypted under, the change still
            // decrypts, with the description unavailable.
            var keyless = chat.DecryptEvent(
                new DecryptEventParams(v.EventGroupDescriptionB64) { SigningKeys = EventSigningKeys(v) });
            var unavailable = keyless.GetProperty("change").GetProperty("new_description").Deserialize<GroupText>()!;
            Assert.Equal("Unavailable", unavailable.Kind);
            Assert.False(string.IsNullOrEmpty(unavailable.Raw));
            Assert.NotEqual(v.EventGroupDescription, unavailable.Raw);
        }

        [Fact]
        public void Vectors_GroupAvatarChange_CarriesTheMediaUrl()
        {
            var v = LoadVectors();
            using var chat = new Chat();

            // The avatar URL is not encrypted, so the change reads without any key.
            var e = chat.DecryptEvent(
                new DecryptEventParams(v.EventGroupAvatarChangeB64) { SigningKeys = EventSigningKeys(v) });
            Assert.True(e.GetProperty("verified").GetBoolean());
            var change = e.GetProperty("change");
            Assert.Equal("AvatarChanged", change.GetProperty("change_type").GetString());
            Assert.Equal(v.EventGroupAvatarUrl, change.GetProperty("new_avatar_url").GetString());
            Assert.Equal(v.EventConversationKeyVersion, change.GetProperty("conversation_key_version").GetString());
        }

        [Fact]
        public void Vectors_GroupRemoval_DropsTheTitleAndDescriptionReencryptions()
        {
            var v = LoadVectors();
            using var chat = new Chat();
            chat.ImportKeys(new ImportKeysParams(Convert.FromBase64String(v.PrivateKeysConcatB64)) { SigningKeyVersion = v.EventRecipientKeyVersion });
            var flow = v.EventGroupRemovalFlowB64;

            // Decrypt keeps the removal, its key change and a later rename, and
            // drops the title and description the removal re-encrypts.
            var result = chat.DecryptEvents(new DecryptEventsParams(flow) { SigningKeys = EventSigningKeys(v) });
            Assert.Equal(
                v.EventGroupRemovalDroppedIndices.Select(index => index.ToString()).ToArray(),
                result.Errors.Keys.OrderBy(int.Parse).ToArray());
            Assert.Equal(v.EventGroupRemovalConversationKeyVersion, result.ConversationKeys.LatestVersion);
            Assert.Equal(3, result.Events.Count);
            Assert.All(result.Events, e => Assert.True(e.Event.GetProperty("verified").GetBoolean()));
            var removal = result.Events[0].Event.GetProperty("change");
            Assert.Equal("MembersRemoved", removal.GetProperty("change_type").GetString());
            Assert.Equal(new[] { v.EventGroupRemovedMemberId }, removal.GetProperty("member_ids").Deserialize<string[]>());
            var keyChange = result.Events[1].Event;
            Assert.Equal("KeyChange", keyChange.GetProperty("type").GetString());
            Assert.Equal(v.EventGroupRemovalConversationKeyVersion, keyChange.GetProperty("conversation_key_version").GetString());
            var rename = result.Events[2].Event.GetProperty("change");
            Assert.Equal("TitleChanged", rename.GetProperty("change_type").GetString());
            var title = rename.GetProperty("new_title").Deserialize<GroupText>()!;
            Assert.Equal("Text", title.Kind);
            Assert.Equal(v.EventGroupRenamedTitle, title.Text);

            // The single-event path drops the same events, as invalid input.
            foreach (var index in v.EventGroupRemovalDroppedIndices)
            {
                var ex = Assert.Throws<ChatXdkException>(() => chat.DecryptEvent(
                    new DecryptEventParams(flow[index], result.ConversationKeys.Keys) { SigningKeys = EventSigningKeys(v) }));
                Assert.Equal(ChatXdkErrorKind.InvalidInput, ex.Kind);
                Assert.Equal(result.Errors[index.ToString()], ex.Message);
            }
        }

        [Fact]
        public void Vectors_GroupCreate_DecryptsItsTitleOnReceive()
        {
            var v = LoadVectors();
            using var chat = new Chat();

            var createKeys = new Dictionary<string, byte[]>
            {
                [v.EventGroupCreateConversationKeyVersion] = Convert.FromBase64String(v.EventGroupCreateConversationKeyB64),
            };
            var e = chat.DecryptEvent(new DecryptEventParams(v.EventGroupCreateB64, createKeys)
            {
                SigningKeys = EventSigningKeys(v),
            });
            Assert.Equal("GroupChange", e.GetProperty("type").GetString());
            Assert.True(e.GetProperty("verified").GetBoolean());
            var change = e.GetProperty("change");
            Assert.Equal("Created", change.GetProperty("change_type").GetString());
            var title = change.GetProperty("title").Deserialize<GroupText>()!;
            Assert.Equal("Text", title.Kind);
            Assert.Equal(v.EventGroupTitle, title.Text);
            Assert.Equal(JsonValueKind.Null, change.GetProperty("avatar_url").ValueKind);
            Assert.Equal(v.EventGroupCreateConversationKeyVersion, change.GetProperty("conversation_key_version").GetString());

            // Without the key the create seeded, the create still decrypts, on both paths,
            // with its title unavailable as the ciphertext it carries.
            var keyless = chat.DecryptEvent(
                new DecryptEventParams(v.EventGroupCreateB64) { SigningKeys = EventSigningKeys(v) });
            var keylessChange = keyless.GetProperty("change");
            Assert.Equal(v.EventSenderId, keylessChange.GetProperty("member_ids")[0].GetString());
            var unavailable = keylessChange.GetProperty("title").Deserialize<GroupText>()!;
            Assert.Equal("Unavailable", unavailable.Kind);
            Assert.Equal(v.EventGroupCreateEncryptedTitle, unavailable.Raw);
            var batch = chat.DecryptEvents(new DecryptEventsParams(new[] { v.EventGroupCreateB64 })
            {
                SigningKeys = EventSigningKeys(v),
            });
            Assert.Empty(batch.Errors);
            var batched = batch.Events[0].Event.GetProperty("change").GetProperty("title").Deserialize<GroupText>()!;
            Assert.Equal("Unavailable", batched.Kind);
            Assert.Equal(v.EventGroupCreateEncryptedTitle, batched.Raw);
        }

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
            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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
            Assert.NotEmpty(payload.EncodedMessageCreateEvent);

            // A file of a message sent from the cache encrypts under the same cached key.
            var photo = chat.EncryptMessage(new EncryptMessageParams(v.EventConversationId, "a photo")
            {
                Attachments = new[] { Photo("photo") },
            });
            var file = System.Text.Encoding.UTF8.GetBytes("photo bytes");
            var encrypted = chat.EncryptFile(new EncryptFileParams(file, photo.EventB64, "photo"));
            Assert.Equal(file, chat.DecryptFile(new DecryptFileParams(encrypted, photo.EventB64, ConversationKeys(v), "photo")));

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

            var messages = result.Events
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
            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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
            var texts = result.Events
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

        // Absent-value normalization: an empty title is "not set" and signs the
        // null sentinel, exactly like leaving the field null.
        [Fact]
        public void PrepareGroupCreate_EmptyTitle_SignsNullSentinel()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            foreach (var title in new string?[] { "", null })
            {
                var prepared = chat.PrepareGroupCreate(new GroupCreateParams(
                    new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
                    "g123",
                    new[] { "910002", "910005" },
                    new[] { "910002" })
                {
                    SenderId = "910002",
                    SigningKeyVersion = "1",
                    Title = title,
                });
                // Trailing slots: legacy upgrade, title, avatar_url — all unset → null sentinels.
                var create = prepared.ActionSignatures[1];
                Assert.True(Signs(chat, create,
                    $"GroupChangeEvent.GroupCreate,{create.MessageId},910002,{prepared.ConversationKeyVersion}," +
                    "910002,910005,null,null,null"));
                Assert.Null(prepared.EncryptedTitle);
            }
        }

        // The plaintext never enters the comma-joined signature payload, only its
        // base64 ciphertext does, so a title with a comma encrypts.
        [Fact]
        public void PrepareGroupCreate_EncryptsACommaTitle()
        {
            using var chat = CreateUnlocked();
            var publicKeys = chat.GetPublicKeys();

            var prepared = chat.PrepareGroupCreate(new GroupCreateParams(
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = publicKeys.Identity, PublicKeyVersion = "1" } },
                "g123",
                new[] { "910002", "910005" },
                new[] { "910002" })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                Title = "Team, the sequel",
            });
            Assert.Equal("Team, the sequel", chat.Decrypt(prepared.EncryptedTitle!, prepared.ConversationKey));
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

        // Verifying needs no loaded keys, and its error names the input, not the lock state.
        [Fact]
        public void Verify_NeedsNoLoadedKeys()
        {
            using var signer = CreateUnlocked();
            using var verifier = new Chat();
            var data = System.Text.Encoding.UTF8.GetBytes("data");
            var sig = signer.Sign(data);

            Assert.True(verifier.Verify(signer.GetPublicKeys().Signing, sig, data));
            var ex = Assert.Throws<ChatXdkException>(() => verifier.Verify("notAPublicKey", sig, data));
            Assert.Contains("public key", ex.Message);
            Assert.DoesNotContain("unlocked", ex.Message);
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

            Assert.NotEmpty(payload.EncodedMessageCreateEvent);
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

        // Group metadata the X API returns: the title a title change encrypts

        [Fact]
        public void Decrypt_ReadsTheTitleATitleChangeSends()
        {
            using var chat = CreateUnlocked();
            var ckey = NewConvKey(chat);
            const string plaintext = "metadata payload 🌟 with unicode";
            var parameters = new GroupTitleChangeParams("g100", plaintext)
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationKey = ckey,
                ConversationKeyVersion = "4",
            };

            var ciphertext = chat.PrepareGroupTitleChange(parameters).EncryptedValue;
            Assert.NotEmpty(ciphertext);
            Assert.NotEqual(plaintext, ciphertext);
            Assert.NotEqual(ciphertext, chat.PrepareGroupTitleChange(parameters).EncryptedValue);

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
                new[] { new PublicKeyInput { UserId = "910002", IdentityPublicKey = keys.Identity, PublicKeyVersion = "1" } })
            {
                SenderId = "910002",
                SigningKeyVersion = "1",
                ConversationId = "conv-1",
            });

            Assert.NotNull(prepared);
            Assert.Equal("conv-1", prepared.ConversationId);
            Assert.NotNull(prepared.ConversationKey);
            Assert.Equal(32, prepared.ConversationKey.Length);
            Assert.Single(prepared.ConversationParticipantKeys);
            Assert.NotEmpty(prepared.ConversationParticipantKeys[0].EncryptedConversationKey);
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
            Assert.Empty(result.Events);
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

        private static Chat QuickReplyChat(SdkVectors v, bool v1 = false)
        {
            var chat = v1 ? FeatureTestEnvironment.V1Chat() : new Chat();
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
