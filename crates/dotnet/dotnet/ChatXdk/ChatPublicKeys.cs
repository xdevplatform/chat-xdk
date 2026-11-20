using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ChatXdk
{
    // The calls that fetch users' public keys through ResolvePublicKeys. They await the hook,
    // which C# does not allow in an unsafe context, so they are in this part of the class, and
    // the calls into the native library are in the unsafe part. The native library never calls
    // the hook: each method here makes plain synchronous calls before and after it.
    public sealed partial class Chat
    {
        /// <summary>
        /// <see cref="DecryptEvents"/>, fetching the public keys the batch was missing through
        /// <see cref="ResolvePublicKeys"/>.
        ///
        /// <para>With a hook set and no <see cref="DecryptEventsParams.SigningKeys"/> passed,
        /// the call decrypts the batch, calls the hook with the
        /// <see cref="MissingPublicKeys"/> of the result, adds the records it returns with
        /// <see cref="AddPublicKeys"/> and decrypts the batch once more: the hook is called at
        /// most once. A sender whose keys the hook did not bring stays in
        /// <see cref="DecryptEventsResult.MissingSigningKeys"/>, and is not looked up again for
        /// a minute. With no hook, with signing keys passed, or with nothing missing, the
        /// result is that of <see cref="DecryptEvents"/>.</para>
        ///
        /// <para>An exception the hook throws is thrown to the caller.</para>
        /// </summary>
        public async Task<DecryptEventsResult> DecryptEventsAsync(DecryptEventsParams parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            var result = DecryptEvents(parameters);
            var resolve = _resolvePublicKeys;
            if (resolve == null || parameters.SigningKeys is { Count: > 0 })
                return result;
            var missing = MissingPublicKeys(result);
            if (missing.Count == 0)
                return result;
            await ResolveAsync(resolve, missing).ConfigureAwait(false);
            return DecryptEvents(parameters);
        }

        /// <summary>
        /// <see cref="PrepareConversationKeyChange"/>, fetching the participants' public keys
        /// through <see cref="ResolvePublicKeys"/>.
        ///
        /// <para>With a hook set and no <see cref="ConversationKeyChangeParams.PublicKeys"/>
        /// passed, the call first calls the hook with the participants who have no stored
        /// public key (<see cref="ConversationKeyChangeParams.MemberIds"/>, or the two users
        /// of a one-to-one conversation id) and adds the records it returns with
        /// <see cref="AddPublicKeys"/>. A participant whose keys the hook did not bring is not
        /// looked up again for a minute, and the call throws as
        /// <see cref="PrepareConversationKeyChange"/> does. An exception the hook throws is
        /// thrown to the caller.</para>
        /// </summary>
        public async Task<PreparedConversationChange> PrepareConversationKeyChangeAsync(
            ConversationKeyChangeParams parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            var resolve = _resolvePublicKeys;
            if (resolve != null && parameters.PublicKeys.Count == 0)
            {
                var missing = MissingPublicKeysFor(
                    "conversation_key_change", BuildPrepareConversationKeyChangeJson(parameters));
                await ResolveAsync(resolve, missing).ConfigureAwait(false);
            }
            return PrepareConversationKeyChange(parameters);
        }

        /// <summary>
        /// <see cref="PrepareGroupCreate"/>, fetching the roster's public keys through
        /// <see cref="ResolvePublicKeys"/>.
        ///
        /// <para>With a hook set and no <see cref="GroupCreateParams.PublicKeys"/> passed, the
        /// call first calls the hook with the members and admins who have no stored public key
        /// and adds the records it returns with <see cref="AddPublicKeys"/>. A user whose keys
        /// the hook did not bring is not looked up again for a minute, and the call throws as
        /// <see cref="PrepareGroupCreate"/> does. An exception the hook throws is thrown to the
        /// caller.</para>
        /// </summary>
        public async Task<PreparedConversationChange> PrepareGroupCreateAsync(GroupCreateParams parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            var resolve = _resolvePublicKeys;
            if (resolve != null && parameters.PublicKeys.Count == 0)
            {
                var missing = MissingPublicKeysFor("group_create", BuildPrepareGroupCreateJson(parameters));
                await ResolveAsync(resolve, missing).ConfigureAwait(false);
            }
            return PrepareGroupCreate(parameters);
        }

        /// <summary>
        /// <see cref="PrepareGroupMembersChange"/>, fetching the roster's public keys through
        /// <see cref="ResolvePublicKeys"/>.
        ///
        /// <para>With a hook set and no <see cref="GroupMembersChangeParams.PublicKeys"/>
        /// passed, the call first calls the hook with the current and new members who have no
        /// stored public key and adds the records it returns with <see cref="AddPublicKeys"/>.
        /// A user whose keys the hook did not bring is not looked up again for a minute, and
        /// the call throws as <see cref="PrepareGroupMembersChange"/> does. An exception the
        /// hook throws is thrown to the caller.</para>
        /// </summary>
        public async Task<PreparedConversationChange> PrepareGroupMembersChangeAsync(
            GroupMembersChangeParams parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            var resolve = _resolvePublicKeys;
            if (resolve != null && parameters.PublicKeys.Count == 0)
            {
                var missing = MissingPublicKeysFor(
                    "group_members_change", BuildPrepareGroupMembersChangeJson(parameters));
                await ResolveAsync(resolve, missing).ConfigureAwait(false);
            }
            return PrepareGroupMembersChange(parameters);
        }

        /// <summary>
        /// <see cref="PrepareGroupMembersRemove"/>, fetching the public keys of the members who
        /// stay through <see cref="ResolvePublicKeys"/>.
        ///
        /// <para>With a hook set and no <see cref="GroupMembersRemoveParams.PublicKeys"/>
        /// passed, the call first calls the hook with the
        /// <see cref="GroupMembersRemoveParams.RemainingMemberIds"/> who have no stored public
        /// key and adds the records it returns with <see cref="AddPublicKeys"/>. A user whose
        /// keys the hook did not bring is not looked up again for a minute, and the call throws
        /// as <see cref="PrepareGroupMembersRemove"/> does. An exception the hook throws is
        /// thrown to the caller.</para>
        /// </summary>
        public async Task<PreparedConversationChange> PrepareGroupMembersRemoveAsync(
            GroupMembersRemoveParams parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            var resolve = _resolvePublicKeys;
            if (resolve != null && parameters.PublicKeys.Count == 0)
            {
                var missing = MissingPublicKeysFor(
                    "group_members_remove", BuildPrepareGroupMembersRemoveJson(parameters));
                await ResolveAsync(resolve, missing).ConfigureAwait(false);
            }
            return PrepareGroupMembersRemove(parameters);
        }

        /// <summary>
        /// Call <paramref name="resolve"/> for <paramref name="userIds"/>, when there are any,
        /// and add the records it returns to the stored keys. A null result adds nothing.
        /// </summary>
        private async Task ResolveAsync(
            Func<IReadOnlyList<string>, Task<IReadOnlyDictionary<string, IReadOnlyList<PublicKeyRecord>>>> resolve,
            IReadOnlyList<string> userIds)
        {
            if (userIds.Count == 0)
                return;
            var pending = resolve(userIds);
            if (pending == null)
                return;
            var records = await pending.ConfigureAwait(false);
            if (records != null)
                AddPublicKeys(records);
        }
    }
}
