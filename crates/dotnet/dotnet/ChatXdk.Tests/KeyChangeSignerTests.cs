// DecryptEvents and the members who sign a batch's key changes: a key change
// needs its signer's keys to verify, the result says which key changes did
// not verify and why, and the version to encrypt with is reported per
// conversation.

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
        private const string Group = "g900";
        private const string OtherGroup = "g901";
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
        private sealed record KeyChange(string EventB64, byte[] Key, string Version);

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
            return new KeyChange(
                DeliveredAction(prepared.ActionSignatures[0], signer.UserId, conversationId, EnforcedSequence),
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
                Bot.Chat.DecryptEvents(new DecryptEventsParams(events)
                {
                    SigningKeys = signers.Select(signer => signer.SigningKey).ToList(),
                });

            public void Dispose()
            {
                Admin.Dispose();
                Member.Dispose();
                Bot.Dispose();
            }
        }

        private static IEnumerable<KeyValuePair<string, string>> Sorted(IEnumerable<KeyValuePair<string, string>> versions) =>
            versions.OrderBy(pair => pair.Key, StringComparer.Ordinal);

        [Fact]
        public void DecryptEvents_KeyChangeWithoutItsSignersKeys_IsReportedAndItsKeyDropped()
        {
            using var page = new Page();

            // The bot holds the keys of the member who wrote the message, not of the
            // admin who made the key change.
            var result = page.Decrypt(page.Events, page.Member);

            Assert.Empty(result.Events);
            Assert.Empty(result.ConversationKeys.Keys);
            Assert.Null(result.ConversationKeys.LatestVersion);
            Assert.Empty(result.ConversationKeys.LatestVersions);
            var unverified = Assert.Single(result.UnverifiedKeyChanges);
            Assert.Equal(0, unverified.Index);
            Assert.Equal(UnverifiedKeyChangeReason.MissingSigningKey, unverified.Reason);
            Assert.True(unverified.KeyDropped);
            Assert.Equal(Group, unverified.ConversationId);
            Assert.Equal(page.Change.Version, unverified.ConversationKeyVersion);
            Assert.Equal("5001", unverified.SenderId);
            Assert.Equal(KeyVersion, unverified.PublicKeyVersion);
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
            var unverified = Assert.Single(result.UnverifiedKeyChanges);
            Assert.Equal(UnverifiedKeyChangeReason.InvalidSignature, unverified.Reason);
            Assert.True(unverified.KeyDropped);
            Assert.Contains("ECDSA mismatch", result.Errors["0"]);
        }

        [Fact]
        public void DecryptEvents_KeyChangeWithItsSignersKeys_VerifiesAndItsMessagesDecrypt()
        {
            using var page = new Page();

            var result = page.Decrypt(page.Events, page.Member, page.Admin);

            Assert.Empty(result.Errors);
            Assert.Empty(result.UnverifiedKeyChanges);
            Assert.Equal(
                new[] { "KeyChange", "Message" },
                result.Events.Select(decrypted => decrypted.Event.GetProperty("type").GetString()!));
            Assert.Equal(
                "hello group",
                result.Events[1].Event.GetProperty("content").GetProperty("text").GetString());
            Assert.Equal(page.Change.Version, result.ConversationKeys.LatestVersion);
            var latest = Assert.Single(result.ConversationKeys.LatestVersions);
            Assert.Equal(new KeyValuePair<string, string>(Group, page.Change.Version), latest);
        }

        [Fact]
        public void DecryptEvents_LatestVersions_AreReportedPerConversation()
        {
            using var page = new Page();
            var members = new[] { page.Admin, page.Bot };
            var other = NewKeyChange(page.Admin, members, OtherGroup);
            while (other.Version == page.Change.Version)
                other = NewKeyChange(page.Admin, members, OtherGroup);
            var events = new[] { page.Change.EventB64, other.EventB64 };
            var versions = new Dictionary<string, string>
            {
                [Group] = page.Change.Version,
                [OtherGroup] = other.Version,
            };

            // Each conversation has its own version to encrypt with, and no single
            // one stands for both.
            var result = page.Decrypt(events, page.Admin);
            Assert.Empty(result.Errors);
            Assert.Equal(Sorted(versions), Sorted(result.ConversationKeys.LatestVersions));
            Assert.Null(result.ConversationKeys.LatestVersion);

            result = page.Decrypt(new[] { other.EventB64 }, page.Admin);
            Assert.Equal(other.Version, result.ConversationKeys.LatestVersion);
            var latest = Assert.Single(result.ConversationKeys.LatestVersions);
            Assert.Equal(new KeyValuePair<string, string>(OtherGroup, other.Version), latest);

            // ExtractConversationKeys checks no signature: its LatestVersion is the
            // batch's highest, and LatestVersions each conversation's.
            var extracted = page.Bot.Chat.ExtractConversationKeys(events);
            Assert.Equal(Sorted(versions), Sorted(extracted.LatestVersions));
            var highest = Math.Max(long.Parse(page.Change.Version), long.Parse(other.Version));
            Assert.Equal(highest.ToString(), extracted.LatestVersion);
        }
    }
}
