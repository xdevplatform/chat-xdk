// DecryptEvents and the key changes of a batch: a key change needs its
// signer's keys to verify, the result says which key changes did not verify
// or could not be decrypted and why, and keys and the version to encrypt with
// are reported per conversation.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace ChatXdk.Tests
{
    public class KeyChangeSignerTests
    {
        /// <summary>A sequence id past the cut-over, where a key change that does not verify
        /// has its key dropped.</summary>
        private const string EnforcedSequence = "2100000000000000000";
        /// <summary>A sequence id before the cut-over, where the key is kept.</summary>
        private const string UnenforcedSequence = "100";
        private const string Group = "g900";
        private const string OtherGroup = "g901";
        private const string ThirdGroup = "g902";
        private const string KeyVersion = "1";

        /// <summary>A Thrift string field: its id, then the value's length and bytes.</summary>
        private static byte[] StringField(int id, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var header = new byte[]
            {
                11, (byte)(id >> 8), (byte)id,
                (byte)(bytes.Length >> 24), (byte)(bytes.Length >> 16), (byte)(bytes.Length >> 8), (byte)bytes.Length,
            };
            return header.Concat(bytes).ToArray();
        }

        /// <summary>A Thrift struct field: its id, then the struct as already serialized.</summary>
        private static byte[] StructField(int id, byte[] body) =>
            new byte[] { 12, (byte)(id >> 8), (byte)id }.Concat(body).ToArray();

        /// <summary>The event as delivered: <paramref name="eventB64"/> with the sequence id the
        /// server assigns, prepended as Thrift string field 1.</summary>
        private static string Delivered(string eventB64, string sequenceId) =>
            Convert.ToBase64String(StringField(1, sequenceId).Concat(Convert.FromBase64String(eventB64)).ToArray());

        /// <summary>A signed action as delivered: the event the server relays for
        /// <paramref name="action"/>, an entry of a prepared change's action signatures, from
        /// <paramref name="senderId"/> in <paramref name="conversationId"/>, with the sequence id
        /// the server assigns.</summary>
        private static string DeliveredAction(ActionSignature action, string senderId, string conversationId, string sequenceId)
        {
            var signed = action.MessageEventSignature;
            var signature = StringField(1, signed.Signature)
                .Concat(StringField(2, signed.PublicKeyVersion))
                .Concat(StringField(3, signed.SignatureVersion))
                .Append((byte)0)
                .ToArray();
            var delivered = StringField(1, sequenceId)
                .Concat(StringField(2, action.MessageId))
                .Concat(StringField(3, senderId))
                .Concat(StringField(4, conversationId))
                .Concat(StructField(7, Convert.FromBase64String(action.EncodedMessageEventDetail)))
                .Concat(StructField(9, signature))
                .Append((byte)0)
                .ToArray();
            return Convert.ToBase64String(delivered);
        }

        /// <summary>A chat with fresh keys as a user, and the keys others hold for it.</summary>
        private sealed class Party : IDisposable
        {
            public Party(string userId)
            {
                UserId = userId;
                Chat = new Chat();
                var registration = Chat.GenerateKeypairs().PublicKey;
                SigningKey = new SigningKeyEntry
                {
                    UserId = userId,
                    PublicKeyVersion = KeyVersion,
                    PublicKey = registration.SigningPublicKey,
                    IdentityPublicKey = registration.PublicKey,
                    IdentityPublicKeySignature = registration.IdentityPublicKeySignature,
                };
                PublicKey = new PublicKeyInput
                {
                    UserId = userId,
                    IdentityPublicKey = registration.PublicKey,
                    PublicKeyVersion = KeyVersion,
                };
            }

            public string UserId { get; }
            public Chat Chat { get; }
            public SigningKeyEntry SigningKey { get; }
            public PublicKeyInput PublicKey { get; }

            public void Dispose() => Chat.Dispose();
        }

        /// <summary>A key change as delivered, with its key.</summary>
        private sealed record KeyChange(
            ActionSignature Signed, string SignerId, string ConversationId, string EventB64, byte[] Key, string Version)
        {
            /// <summary>This key change as delivered before the cut-over with its key version
            /// rewritten to <paramref name="version"/>. The signature no longer verifies, and
            /// the key is kept.</summary>
            public KeyChange AtVersion(string version)
            {
                Assert.Equal(Version.Length, version.Length);
                var detail = Encoding.Latin1.GetString(Convert.FromBase64String(Signed.EncodedMessageEventDetail));
                var at = detail.IndexOf(Version, StringComparison.Ordinal);
                Assert.True(at >= 0);
                var rewritten = detail.Remove(at, Version.Length).Insert(at, version);
                var action = new ActionSignature
                {
                    MessageId = Signed.MessageId,
                    EncodedMessageEventDetail = Convert.ToBase64String(Encoding.Latin1.GetBytes(rewritten)),
                    MessageEventSignature = Signed.MessageEventSignature,
                };
                return this with
                {
                    EventB64 = DeliveredAction(action, SignerId, ConversationId, UnenforcedSequence),
                    Version = version,
                };
            }
        }

        /// <summary>The key change <paramref name="signer"/> makes in
        /// <paramref name="conversationId"/> for <paramref name="members"/>.</summary>
        private static KeyChange NewKeyChange(Party signer, IEnumerable<Party> members, string conversationId)
        {
            var prepared = signer.Chat.PrepareConversationKeyChange(
                new ConversationKeyChangeParams(members.Select(member => member.PublicKey).ToList())
                {
                    SenderId = signer.UserId,
                    SigningKeyVersion = KeyVersion,
                    ConversationId = conversationId,
                });
            var action = prepared.ActionSignatures[0];
            return new KeyChange(
                action,
                signer.UserId,
                conversationId,
                DeliveredAction(action, signer.UserId, conversationId, EnforcedSequence),
                prepared.ConversationKey,
                prepared.ConversationKeyVersion);
        }

        /// <summary>The message <paramref name="author"/> sends in
        /// <paramref name="conversationId"/> under the key of <paramref name="change"/>, as
        /// delivered.</summary>
        private static string SentMessage(Party author, string conversationId, KeyChange change, string text)
        {
            var payload = author.Chat.EncryptMessage(new EncryptMessageParams(conversationId, text)
            {
                SenderId = author.UserId,
                SigningKeyVersion = KeyVersion,
                ConversationKey = change.Key,
                ConversationKeyVersion = change.Version,
            });
            return Delivered(payload.EventB64, "2100000000000000001");
        }

        /// <summary>An admin who rotates a group's key, a member who sends a message under it,
        /// and the bot that receives both events.</summary>
        private sealed class Page : IDisposable
        {
            public Page()
            {
                Change = NewKeyChange(Admin, new[] { Admin, Member, Bot }, Group);
                Events = new[] { Change.EventB64, SentMessage(Member, Group, Change, "hello group") };
            }

            public Party Admin { get; } = new("5001");
            public Party Member { get; } = new("5002");
            public Party Bot { get; } = new("5003");
            public KeyChange Change { get; }
            public string[] Events { get; }

            /// <summary>The bot's DecryptEvents of <paramref name="events"/> with the signing
            /// keys of <paramref name="signers"/>.</summary>
            public DecryptEventsResult Decrypt(IReadOnlyList<string> events, params Party[] signers) =>
                DecryptWith(Bot.Chat, events, signers.Select(signer => signer.SigningKey).ToArray());

            /// <summary>A key change the admin makes for itself and the bot in the other group,
            /// at another key version than the page's.</summary>
            public KeyChange OtherKeyChange()
            {
                var members = new[] { Admin, Bot };
                var other = NewKeyChange(Admin, members, OtherGroup);
                while (other.Version == Change.Version)
                    other = NewKeyChange(Admin, members, OtherGroup);
                return other;
            }

            /// <summary>Asserts that the page's key change, and no other, did not verify for
            /// <paramref name="reason"/> and lost its key.</summary>
            public void AssertUnverified(DecryptEventsResult result, UnverifiedKeyChangeReason reason)
            {
                var (index, unverified) = Assert.Single(result.UnverifiedKeyChanges);
                Assert.Equal("0", index);
                Assert.Equal(reason, unverified.Reason);
                Assert.True(unverified.KeyDropped);
                Assert.Equal(Group, unverified.ConversationId);
                Assert.Equal(Change.Version, unverified.ConversationKeyVersion);
                Assert.Equal("5001", unverified.SenderId);
                Assert.Equal(KeyVersion, unverified.PublicKeyVersion);
            }

            public void Dispose()
            {
                Admin.Dispose();
                Member.Dispose();
                Bot.Dispose();
            }
        }

        private static DecryptEventsResult DecryptWith(
            Chat chat, IReadOnlyList<string> events, params SigningKeyEntry[] signingKeys) =>
            chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });

        /// <summary>The text of each message among a result's events.</summary>
        private static string[] Texts(DecryptEventsResult result) =>
            result.Events
                .Select(decrypted => decrypted.Event)
                .Where(decrypted => decrypted.GetProperty("type").GetString() == "Message")
                .Select(message => message.GetProperty("content").GetProperty("text").GetString()!)
                .ToArray();

        private static IEnumerable<KeyValuePair<string, string>> Sorted(IEnumerable<KeyValuePair<string, string>> versions) =>
            versions.OrderBy(pair => pair.Key, StringComparer.Ordinal);

        /// <summary>Asserts that <paramref name="actual"/> holds the keys of
        /// <paramref name="expected"/>, version by version, and no other.</summary>
        private static void AssertKeys(Dictionary<string, byte[]> expected, Dictionary<string, byte[]> actual)
        {
            Assert.Equal(
                expected.Keys.OrderBy(version => version, StringComparer.Ordinal),
                actual.Keys.OrderBy(version => version, StringComparer.Ordinal));
            foreach (var (version, key) in expected)
                Assert.Equal(key, actual[version]);
        }

        /// <summary>Asserts that <paramref name="actual"/> holds the keys of
        /// <paramref name="expected"/>, conversation by conversation, and no other.</summary>
        private static void AssertKeysByConversation(
            Dictionary<string, Dictionary<string, byte[]>> expected,
            Dictionary<string, Dictionary<string, byte[]>> actual)
        {
            Assert.Equal(
                expected.Keys.OrderBy(id => id, StringComparer.Ordinal),
                actual.Keys.OrderBy(id => id, StringComparer.Ordinal));
            foreach (var (conversationId, keys) in expected)
                AssertKeys(keys, actual[conversationId]);
        }

        [Fact]
        public void DecryptEvents_KeyChangeWithoutItsSignersKeys_IsReportedAndItsKeyDropped()
        {
            using var page = new Page();

            // The bot holds the keys of the member who wrote the message, not of the
            // admin who made the key change.
            var result = page.Decrypt(page.Events, page.Member);

            Assert.Empty(result.Events);
            Assert.Empty(result.ConversationKeys.Keys);
            Assert.Empty(result.ConversationKeys.KeysByConversation);
            Assert.Null(result.ConversationKeys.LatestVersion);
            Assert.Empty(result.ConversationKeys.LatestVersions);
            page.AssertUnverified(result, UnverifiedKeyChangeReason.MissingSigningKey);
            Assert.Empty(result.UndecryptableKeyChanges);
            Assert.Empty(result.RejectedSigningKeys);
            Assert.Contains("no signing key for sender 5001 at public_key_version 1", result.Errors["0"]);
            Assert.Contains(
                "no matching key found: the key change for that version, event 0 of the batch, did not verify",
                result.Errors["1"]);
        }

        [Fact]
        public void DecryptEvents_KeyChangeCheckedWithAnotherKey_IsReportedInvalid()
        {
            using var page = new Page();

            // A signing key under the admin's user id and key version that is not the
            // key the admin signed with.
            using var otherKey = new Party(page.Admin.UserId);
            var result = page.Decrypt(page.Events, page.Member, otherKey);

            Assert.Empty(result.Events);
            page.AssertUnverified(result, UnverifiedKeyChangeReason.InvalidSignature);
            Assert.Contains("ECDSA mismatch", result.Errors["0"]);
        }

        [Fact]
        public void DecryptEvents_SigningKeyWithAnInvalidBinding_IsReportedRejected()
        {
            using var page = new Page();

            // The admin's signing key with a binding signature that is not its
            // signature over the identity key.
            var unbound = new SigningKeyEntry
            {
                UserId = page.Admin.SigningKey.UserId,
                PublicKeyVersion = page.Admin.SigningKey.PublicKeyVersion,
                PublicKey = page.Admin.SigningKey.PublicKey,
                IdentityPublicKey = page.Admin.SigningKey.IdentityPublicKey,
                IdentityPublicKeySignature = page.Member.SigningKey.IdentityPublicKeySignature,
            };
            var result = DecryptWith(page.Bot.Chat, page.Events, page.Member.SigningKey, unbound);

            Assert.Empty(result.Events);
            var (index, rejected) = Assert.Single(result.RejectedSigningKeys);
            Assert.Equal("1", index);
            Assert.Equal("5001", rejected.UserId);
            Assert.Equal(KeyVersion, rejected.PublicKeyVersion);
            page.AssertUnverified(result, UnverifiedKeyChangeReason.RejectedSigningKey);
            Assert.Contains(
                "the signing key given for sender 5001 at public_key_version 1 was rejected: its identity binding does not verify",
                result.Errors["0"]);
        }

        [Fact]
        public void DecryptEvents_KeyChangeWithItsSignersKeys_VerifiesAndItsMessagesDecrypt()
        {
            using var page = new Page();

            var result = page.Decrypt(page.Events, page.Member, page.Admin);

            Assert.Empty(result.Errors);
            Assert.Empty(result.UnverifiedKeyChanges);
            Assert.Empty(result.UndecryptableKeyChanges);
            Assert.Empty(result.RejectedSigningKeys);
            Assert.Equal(
                new[] { "KeyChange", "Message" },
                result.Events.Select(decrypted => decrypted.Event.GetProperty("type").GetString()!));
            Assert.Equal(new[] { "hello group" }, Texts(result));
            var keys = result.ConversationKeys;
            Assert.Equal(page.Change.Version, keys.LatestVersion);
            var latest = Assert.Single(keys.LatestVersions);
            Assert.Equal(new KeyValuePair<string, string>(Group, page.Change.Version), latest);
            var groupKeys = new Dictionary<string, byte[]> { [page.Change.Version] = page.Change.Key };
            AssertKeys(groupKeys, keys.Keys);
            AssertKeysByConversation(
                new Dictionary<string, Dictionary<string, byte[]>> { [Group] = groupKeys },
                keys.KeysByConversation);
        }

        [Fact]
        public void DecryptEvents_KeyChangeThisChatCannotDecrypt_IsReportedWithWhy()
        {
            using var page = new Page();

            // A key change made for the admin and the member only: a chat whose
            // identity is the bot's finds no key for its user in it.
            using var outsider = new Party(page.Bot.UserId);
            outsider.Chat.SetIdentity(new SetIdentityParams(page.Bot.UserId, KeyVersion));
            var change = NewKeyChange(page.Admin, new[] { page.Admin, page.Member }, Group);
            var events = new[] { change.EventB64, SentMessage(page.Member, Group, change, "not for the bot") };
            var result = DecryptWith(outsider.Chat, events, page.Member.SigningKey, page.Admin.SigningKey);

            Assert.Empty(result.Events);
            Assert.Empty(result.UnverifiedKeyChanges);
            var (index, undecryptable) = Assert.Single(result.UndecryptableKeyChanges);
            Assert.Equal("0", index);
            Assert.Equal(UndecryptableKeyChangeReason.NotARecipient, undecryptable.Reason);
            Assert.Equal(Group, undecryptable.ConversationId);
            Assert.Equal(change.Version, undecryptable.ConversationKeyVersion);
            Assert.Equal("5001", undecryptable.SenderId);
            Assert.Contains(
                "event 0 of the batch, holds no key this chat can decrypt: it holds no key for this chat's user",
                result.Errors["1"]);
        }

        [Fact]
        public void DecryptEvents_KeysAndLatestVersions_AreReportedPerConversation()
        {
            using var page = new Page();
            var other = page.OtherKeyChange();
            var events = new[] { page.Change.EventB64, other.EventB64 };
            var versions = new Dictionary<string, string>
            {
                [Group] = page.Change.Version,
                [OtherGroup] = other.Version,
            };
            var keysByConversation = new Dictionary<string, Dictionary<string, byte[]>>
            {
                [Group] = new() { [page.Change.Version] = page.Change.Key },
                [OtherGroup] = new() { [other.Version] = other.Key },
            };

            // Each conversation has its own keys and its own version to encrypt
            // with, and no single version stands for both.
            var keys = page.Decrypt(events, page.Admin).ConversationKeys;
            Assert.Equal(Sorted(versions), Sorted(keys.LatestVersions));
            Assert.Null(keys.LatestVersion);
            AssertKeysByConversation(keysByConversation, keys.KeysByConversation);
            AssertKeys(
                new Dictionary<string, byte[]>
                {
                    [page.Change.Version] = page.Change.Key,
                    [other.Version] = other.Key,
                },
                keys.Keys);

            keys = page.Decrypt(new[] { other.EventB64 }, page.Admin).ConversationKeys;
            Assert.Equal(other.Version, keys.LatestVersion);
            var latest = Assert.Single(keys.LatestVersions);
            Assert.Equal(new KeyValuePair<string, string>(OtherGroup, other.Version), latest);

            // A batch of two conversations has no single version even when only
            // one of them has a verified key change.
            var stray = SentMessage(page.Admin, ThirdGroup, other, "hello third group");
            keys = page.Decrypt(new[] { page.Change.EventB64, stray }, page.Admin).ConversationKeys;
            Assert.Null(keys.LatestVersion);
            latest = Assert.Single(keys.LatestVersions);
            Assert.Equal(new KeyValuePair<string, string>(Group, page.Change.Version), latest);

            // ExtractConversationKeys checks no signature, and reports the same way.
            var extracted = page.Bot.Chat.ExtractConversationKeys(events);
            Assert.Equal(Sorted(versions), Sorted(extracted.LatestVersions));
            Assert.Null(extracted.LatestVersion);
            AssertKeysByConversation(keysByConversation, extracted.KeysByConversation);
            extracted = page.Bot.Chat.ExtractConversationKeys(new[] { other.EventB64 });
            Assert.Equal(other.Version, extracted.LatestVersion);
        }

        [Fact]
        public void DecryptEvents_KeysOfTwoConversationsAtOneVersion_StayApart()
        {
            using var page = new Page();
            var other = page.OtherKeyChange();
            var sameVersion = other.AtVersion(page.Change.Version);
            var events = new[]
            {
                page.Change.EventB64,
                sameVersion.EventB64,
                SentMessage(page.Admin, Group, page.Change, "hello group"),
                SentMessage(page.Admin, OtherGroup, sameVersion, "hello other group"),
            };

            // Each message decrypts under its own conversation's key, and a lookup
            // by version alone finds neither.
            var result = page.Decrypt(events, page.Admin);
            Assert.Equal(new[] { "hello group", "hello other group" }, Texts(result));
            Assert.Equal(new[] { "1" }, result.Errors.Keys);
            AssertKeysByConversation(
                new Dictionary<string, Dictionary<string, byte[]>>
                {
                    [Group] = new() { [page.Change.Version] = page.Change.Key },
                    [OtherGroup] = new() { [page.Change.Version] = other.Key },
                },
                result.ConversationKeys.KeysByConversation);
            Assert.Empty(result.ConversationKeys.Keys);
            var unverified = result.UnverifiedKeyChanges["1"];
            Assert.Equal(UnverifiedKeyChangeReason.InvalidSignature, unverified.Reason);
            Assert.False(unverified.KeyDropped);
        }
    }
}
