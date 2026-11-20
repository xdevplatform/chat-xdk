// The conversation-key cache and the signing-key store: what fills them and
// which calls read them.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;
using static ChatXdk.Tests.KeyChangeSignerTests;

namespace ChatXdk.Tests
{
    public class KeyCacheTests
    {
        /// <summary>A party whose chat has its user as session identity.</summary>
        private static Party Session(string userId)
        {
            var party = new Party(userId);
            party.Chat.SetIdentity(new SetIdentityParams(userId, KeyVersion));
            return party;
        }

        /// <summary>A party with a session identity whose key cache is on.</summary>
        private static Party Caching(string userId)
        {
            var party = Session(userId);
            party.Chat.SetCacheKeys(true);
            return party;
        }

        /// <summary>The key version <paramref name="party"/> encrypts under in the group when
        /// the call passes no key.</summary>
        private static string SendVersion(Party party) =>
            party.Chat.EncryptMessage(new EncryptMessageParams(Group, "hello")).ConversationKeyVersion;

        /// <summary>Asserts that a send from <paramref name="party"/> that passes no key fails
        /// because no key is cached.</summary>
        private static void AssertNoCachedKey(Party party)
        {
            var e = Assert.Throws<ChatXdkException>(() => SendVersion(party));
            Assert.Equal(ChatXdkErrorKind.InvalidState, e.Kind);
            Assert.Contains($"no cached conversation key for '{Group}'", e.Message);
        }

        /// <summary>Whether <paramref name="change"/> verifies as <paramref name="party"/>
        /// decrypts it on its own, with the signing keys of <paramref name="signers"/>.</summary>
        private static bool VerifiesKeyChange(Party party, KeyChange change, params Party[] signers)
        {
            var decrypted = party.Chat.DecryptEvent(new DecryptEventParams(change.EventB64)
            {
                SigningKeys = signers.Select(signer => signer.SigningKey).ToArray(),
            });
            Assert.Equal("KeyChange", decrypted.GetProperty("type").GetString());
            return decrypted.GetProperty("verified").GetBoolean();
        }

        /// <summary>The text of <paramref name="message"/> from <paramref name="author"/>, as
        /// <paramref name="reader"/> decrypts and verifies it on its own with no key map.</summary>
        private static string Read(Party reader, string message, Party author)
        {
            var decrypted = reader.Chat.DecryptEvent(new DecryptEventParams(message)
            {
                SigningKeys = new[] { author.SigningKey },
            });
            Assert.Equal("Message", decrypted.GetProperty("type").GetString());
            Assert.True(decrypted.GetProperty("verified").GetBoolean());
            return decrypted.GetProperty("content").GetProperty("text").GetString()!;
        }

        /// <summary>A key change <paramref name="signer"/> makes in the group for
        /// <paramref name="members"/> at a later key version than
        /// <paramref name="older"/>'s.</summary>
        private static KeyChange NewerKeyChange(Party signer, Party[] members, KeyChange older)
        {
            var change = NewKeyChange(signer, members, Group);
            while (ulong.Parse(change.Version) <= ulong.Parse(older.Version))
                change = NewKeyChange(signer, members, Group);
            return change;
        }

        /// <summary>Whether <paramref name="signed"/>'s signature verifies, under the signer's
        /// own signing key, over <paramref name="payload"/>: the comma-joined fields its event
        /// signs.</summary>
        private static bool Signs(Chat chat, ActionSignature signed, string payload)
        {
            var unpadded = signed.MessageEventSignature.Signature;
            var signature = Convert.FromBase64String(
                unpadded.PadRight(unpadded.Length + (4 - unpadded.Length % 4) % 4, '='));
            return chat.Verify(
                signed.MessageEventSignature.SigningPublicKey, signature, Encoding.UTF8.GetBytes(payload));
        }

        [Fact]
        public void DecryptEvent_KeyChangeThatVerifies_IsCached()
        {
            using var admin = new Party("5001");
            using var member = new Party("5002");
            using var bot = Caching("5003");
            var change = NewKeyChange(admin, new[] { admin, member, bot }, Group);
            var message = SentMessage(member, Group, change, "hello group");

            // Nothing is cached yet.
            AssertNoCachedKey(bot);

            Assert.True(VerifiesKeyChange(bot, change, admin));

            Assert.Equal(change.Version, SendVersion(bot));
            Assert.Equal("hello group", Read(bot, message, member));
        }

        [Fact]
        public void DecryptEvent_KeyChangeThatDoesNotVerify_IsNotCached()
        {
            using var admin = new Party("5001");
            using var bot = Caching("5003");
            bot.Chat.SetRejectUnverified(false);
            var change = NewKeyChange(admin, new[] { admin, bot }, Group);

            // Without the admin's signing keys the key change is returned unverified.
            Assert.False(VerifiesKeyChange(bot, change));
            AssertNoCachedKey(bot);
        }

        [Fact]
        public void PrepareCalls_CacheTheKeyTheyMake()
        {
            using var member = new Party("5002");
            using var joiner = new Party("5004");
            // The four calls that make a conversation key, as maker makes them.
            Func<PreparedConversationChange>[] Prepares(Party maker)
            {
                var both = new[] { maker.PublicKey, member.PublicKey };
                return new Func<PreparedConversationChange>[]
                {
                    () => maker.Chat.PrepareGroupCreate(new GroupCreateParams(
                        both, Group, new[] { maker.UserId, member.UserId }, new[] { maker.UserId })),
                    () => maker.Chat.PrepareGroupMembersChange(new GroupMembersChangeParams(
                        new[] { maker.PublicKey, member.PublicKey, joiner.PublicKey },
                        Group,
                        new[] { joiner.UserId },
                        new[] { maker.UserId, member.UserId },
                        new[] { maker.UserId },
                        Array.Empty<string>())),
                    () => maker.Chat.PrepareGroupMembersRemove(
                        new GroupMembersRemoveParams(both, Group, new[] { joiner.UserId })),
                    () => maker.Chat.PrepareConversationKeyChange(
                        new ConversationKeyChangeParams(both) { ConversationId = Group }),
                };
            }

            // With the cache on, a send that passes no key uses the key each call
            // made.
            using var admin = Caching("5001");
            foreach (var prepare in Prepares(admin))
                Assert.Equal(prepare().ConversationKeyVersion, SendVersion(admin));

            // With the cache off, the keys are not kept.
            using var uncached = Session("5001");
            foreach (var prepare in Prepares(uncached))
            {
                prepare();
                AssertNoCachedKey(uncached);
            }
        }

        [Fact]
        public void KeyCache_KeepsEveryVersion_AndSendsUseTheNewest()
        {
            using var admin = new Party("5001");
            using var member = new Party("5002");
            using var bot = Caching("5003");
            var members = new[] { admin, member, bot };
            var first = NewKeyChange(admin, members, Group);
            var second = NewerKeyChange(admin, members, first);

            // The older key change arrives last: it is kept for decryption and
            // does not become the key sends use.
            Assert.True(VerifiesKeyChange(bot, second, admin));
            Assert.True(VerifiesKeyChange(bot, first, admin));
            Assert.Equal(second.Version, SendVersion(bot));

            foreach (var change in new[] { first, second })
            {
                var text = $"under {change.Version}";
                Assert.Equal(text, Read(bot, SentMessage(member, Group, change, text), member));
            }
        }

        [Fact]
        public void FileDecryption_ReadsTheKeyCache()
        {
            using var sender = Caching("5001");
            var change = NewKeyChange(sender, new[] { sender }, Group);

            // A message and its file, encrypted under the cached key.
            var payload = sender.Chat.EncryptMessage(new EncryptMessageParams(Group, "a photo")
            {
                Attachments = new[] { AttachmentDescriptor.Media("photo", 4, 3, 64, "photo.jpg", mediaType: 1) },
            });
            Assert.Equal(change.Version, payload.ConversationKeyVersion);
            var file = Encoding.UTF8.GetBytes("photo bytes");
            var encrypted = sender.Chat.EncryptFile(new EncryptFileParams(file, payload.EventB64, "photo"));

            // No key map: the keys come from the cache.
            Assert.Equal(file, sender.Chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, "photo")));
            Assert.Equal(file, sender.Chat.DecryptFile(new DecryptFileParams(encrypted, payload.EventB64, null, "photo")));
            Assert.Equal(file, sender.Chat.DecryptFile(
                new DecryptFileParams(encrypted, payload.EventB64, new Dictionary<string, byte[]>(), "photo")));
            using (var decryptor = sender.Chat.FileDecryptor(new FileDecryptorParams(payload.EventB64, "photo")))
            {
                var streamed = new List<byte>(decryptor.Push(encrypted));
                streamed.AddRange(decryptor.Finish());
                Assert.Equal(file, streamed.ToArray());
            }

            // A key map that is passed is the only source: one without the
            // message's version fails though the cache holds that version.
            var otherVersion = new Dictionary<string, byte[]> { ["9"] = Enumerable.Repeat((byte)7, 32).ToArray() };
            var noKey = $"conversation_keys has no key for version '{change.Version}'";
            var whole = Assert.Throws<ChatXdkException>(() => sender.Chat.DecryptFile(
                new DecryptFileParams(encrypted, payload.EventB64, otherVersion, "photo")));
            Assert.Contains(noKey, whole.Message);
            var chunked = Assert.Throws<ChatXdkException>(() => sender.Chat.FileDecryptor(
                new FileDecryptorParams(payload.EventB64, otherVersion, "photo")));
            Assert.Contains(noKey, chunked.Message);
        }

        [Fact]
        public void PrepareGroupAvatarChange_WithNoKeyVersion_SignsTheNewestCachedVersion()
        {
            using var admin = Caching("5001");
            const string avatarUrl = "https://ton.x.com/xchat_media/g900/avatar";
            // Whether the avatar change admin prepares with parameters signs version.
            bool SignsVersion(GroupAvatarChangeParams parameters, string version)
            {
                var signed = Assert.Single(admin.Chat.PrepareGroupAvatarChange(parameters).ActionSignatures);
                return Signs(admin.Chat, signed,
                    $"GroupChangeEvent.GroupAvatarUrlChange,{signed.MessageId},{admin.UserId},{Group},{version},{avatarUrl}");
            }

            // With no key cached there is no version to sign.
            var e = Assert.Throws<ChatXdkException>(
                () => admin.Chat.PrepareGroupAvatarChange(new GroupAvatarChangeParams(Group, avatarUrl)));
            Assert.Equal(ChatXdkErrorKind.InvalidState, e.Kind);
            Assert.Contains(
                $"conversation_key_version is not set and no conversation key is cached for '{Group}'", e.Message);

            var first = NewKeyChange(admin, new[] { admin }, Group);
            var second = NewerKeyChange(admin, new[] { admin }, first);
            Assert.True(SignsVersion(new GroupAvatarChangeParams(Group, avatarUrl), second.Version));
            Assert.True(SignsVersion(new GroupAvatarChangeParams(Group, avatarUrl, null), second.Version));

            // A version that is passed is signed as is.
            Assert.True(SignsVersion(new GroupAvatarChangeParams(Group, avatarUrl, first.Version), first.Version));
        }

        [Fact]
        public void AddSigningKeys_AddsToTheStoredKeys_AndSetSigningKeysReplacesThem()
        {
            using var alice = new Party("5001");
            using var bob = new Party("5002");
            using var reader = new Party("5003");
            var change = NewKeyChange(alice, new[] { alice }, Group);
            var keys = new Dictionary<string, byte[]> { [change.Version] = change.Key };
            // Whether reader decrypts a message from author and verifies it with
            // the signing keys it stores.
            bool Reads(Party author)
            {
                try
                {
                    var decrypted = reader.Chat.DecryptEvent(
                        new DecryptEventParams(SentMessage(author, Group, change, "hi"), keys));
                    return decrypted.GetProperty("verified").GetBoolean();
                }
                catch (ChatXdkException)
                {
                    return false;
                }
            }

            reader.Chat.SetSigningKeys(new[] { alice.SigningKey });
            Assert.True(Reads(alice));
            Assert.False(Reads(bob));

            // Adding keeps what is stored.
            reader.Chat.AddSigningKeys(new[] { bob.SigningKey });
            Assert.True(Reads(alice));
            Assert.True(Reads(bob));

            // An entry for a stored user and key version replaces that entry alone.
            var wrong = new SigningKeyEntry
            {
                UserId = alice.UserId,
                PublicKeyVersion = bob.SigningKey.PublicKeyVersion,
                PublicKey = bob.SigningKey.PublicKey,
                IdentityPublicKey = bob.SigningKey.IdentityPublicKey,
                IdentityPublicKeySignature = bob.SigningKey.IdentityPublicKeySignature,
            };
            reader.Chat.AddSigningKeys(new[] { wrong });
            Assert.False(Reads(alice));
            Assert.True(Reads(bob));

            // Setting replaces the whole set.
            reader.Chat.SetSigningKeys(new[] { bob.SigningKey });
            Assert.False(Reads(alice));
            Assert.True(Reads(bob));
        }
    }
}
