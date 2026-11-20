//! Other users' public keys: adding the records the X API returns to the
//! stored signing keys, saying whose keys a call was missing, reading the
//! keys a key change encrypts to from the store, and the hook that fetches
//! what is missing.
//!
//! The store is the signing-key store: an entry holds a user's signing key
//! and identity key at one key version, so it verifies that user's events
//! and, once its identity binding verifies, says which key to encrypt a
//! conversation key to.

use super::*;
use crate::params::GroupMembersRemoveParams;
use std::borrow::Cow;

/// How long a lookup of a user's public keys that did not bring the key it
/// was made for is remembered, in milliseconds. Until then
/// [`ChatCore::missing_public_keys`] and
/// [`ChatCore::missing_public_keys_for`] leave that key out, so a hook is
/// not called again for a key it cannot find.
pub const PUBLIC_KEYS_RETRY_MS: u64 = 60_000;

/// A hook that fetches users' public keys: given user ids, it returns each
/// user's records from `GET /2/users/{id}/public_keys`, by user id. A user
/// it has nothing for is left out.
pub type ResolvePublicKeys =
    std::sync::Arc<dyn Fn(&[String]) -> HashMap<String, Vec<PublicKeyRecord>> + Send + Sync>;

/// The public-key lookups made and not yet answered: a user and the key
/// version an event named, or `None` for any key of the user, with the time
/// on the core's clock until which the lookup is not repeated.
pub(super) type PublicKeyLookups = HashMap<(String, Option<String>), u64>;

/// A prepare call that makes a conversation key and encrypts it to its
/// members' identity keys, with its params.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum KeyChangeCall<'a> {
    /// [`ChatCore::prepare_conversation_key_change`].
    ConversationKeyChange(&'a ConversationKeyChangeParams),
    /// [`ChatCore::prepare_group_create`].
    GroupCreate(&'a GroupCreateParams),
    /// [`ChatCore::prepare_group_members_change`].
    GroupMembersChange(&'a GroupMembersChangeParams),
    /// [`ChatCore::prepare_group_members_remove`].
    GroupMembersRemove(&'a GroupMembersRemoveParams),
}

impl<'a> KeyChangeCall<'a> {
    /// The public keys the call passes.
    fn public_keys(self) -> &'a [PublicKeyInput] {
        match self {
            Self::ConversationKeyChange(params) => &params.public_keys,
            Self::GroupCreate(params) => &params.public_keys,
            Self::GroupMembersChange(params) => &params.public_keys,
            Self::GroupMembersRemove(params) => &params.public_keys,
        }
    }
}

impl ChatCore {
    /// Add users' public keys to the stored signing keys, as
    /// [`Self::add_signing_keys`] adds entries: `records` holds, by user id,
    /// the records `GET /2/users/{id}/public_keys` returns for that user.
    ///
    /// The decrypt calls verify with the stored keys when they are passed
    /// none, and the prepare calls that encrypt a new conversation key
    /// ([`KeyChangeCall`]) read their members' identity keys from them when
    /// they are passed no public keys. A record without a key version, an
    /// identity key or a signing key is left out.
    pub fn add_public_keys(&self, records: &HashMap<String, Vec<PublicKeyRecord>>) {
        let entries: Vec<SigningKeyEntry> = records
            .iter()
            .filter(|(user_id, _)| !user_id.is_empty())
            .flat_map(|(user_id, records)| {
                records
                    .iter()
                    .filter(|record| {
                        !record.public_key_version.is_empty()
                            && !record.public_key.is_empty()
                            && !record.signing_public_key.is_empty()
                    })
                    .map(move |record| {
                        SigningKeyEntry::new(
                            user_id.as_str(),
                            record.public_key_version.as_str(),
                            record.signing_public_key.as_str(),
                            record.public_key.as_str(),
                            record.identity_public_key_signature.as_str(),
                        )
                    })
            })
            .collect();
        self.add_signing_keys(&entries);
    }

    /// The users whose public keys `result` was missing: the sender of each
    /// event in its `missing_signing_keys`, once each, in batch order. Fetch
    /// their keys (`GET /2/users/{id}/public_keys`), add them with
    /// [`Self::add_public_keys`], and decrypt the batch again.
    ///
    /// A key this call returned a user for is not asked for again for
    /// [`PUBLIC_KEYS_RETRY_MS`]: a lookup that did not bring the key is not
    /// repeated with every batch. A key that arrives is no longer missing,
    /// and a key version not asked for before is asked for at once.
    pub fn missing_public_keys(&self, result: &DecryptEventsResult) -> Vec<String> {
        let mut by_index: Vec<(&usize, &MissingSigningKey)> =
            result.missing_signing_keys.iter().collect();
        by_index.sort_by_key(|(index, _)| **index);
        let missing: Vec<MissingSigningKey> =
            by_index.into_iter().map(|(_, key)| key.clone()).collect();
        self.missing_public_keys_among(&missing)
    }

    /// [`Self::missing_public_keys`] for the entries of a result's
    /// `missing_signing_keys`, in batch order.
    pub fn missing_public_keys_among(&self, missing: &[MissingSigningKey]) -> Vec<String> {
        self.users_to_look_up(
            missing
                .iter()
                .filter(|key| !key.user_id.is_empty())
                .map(|key| (key.user_id.clone(), Some(key.public_key_version.clone()))),
        )
    }

    /// The users whose public keys `call` would be missing: the members it
    /// encrypts its key to who have no stored key with a valid identity
    /// binding. Empty when the call passes its public keys. Fetch their
    /// keys, add them with [`Self::add_public_keys`], then make the call.
    ///
    /// As with [`Self::missing_public_keys`], a user this call returned is
    /// not returned again for [`PUBLIC_KEYS_RETRY_MS`] while the store still
    /// has no key for that user.
    pub fn missing_public_keys_for(&self, call: KeyChangeCall<'_>) -> Vec<String> {
        if !call.public_keys().is_empty() {
            return Vec::new();
        }
        let members = self.key_change_members(call);
        let (_, without) = self.stored_public_keys(&members);
        self.users_to_look_up(without.into_iter().map(|user_id| (user_id, None)))
    }

    /// Set the hook that fetches users' public keys, or remove it with
    /// `None`. With a hook set:
    ///
    /// - [`Self::decrypt_events`], when it is passed no signing keys, calls
    ///   the hook for [`Self::missing_public_keys`] of its result, adds
    ///   what it returns, and decrypts the batch once more.
    /// - The prepare calls of [`KeyChangeCall`], when they are passed no
    ///   public keys, call it for [`Self::missing_public_keys_for`] the
    ///   call and add what it returns before they read the stored keys.
    ///
    /// Setting a hook turns the key cache on ([`Self::set_cache_keys`]);
    /// turn it off again afterwards to keep it off. The hook runs on the
    /// calling thread, with no lock of this instance held.
    pub fn set_resolve_public_keys(&self, hook: Option<ResolvePublicKeys>) {
        let set = hook.is_some();
        *self
            .resolve_public_keys
            .write()
            .unwrap_or_else(|e| e.into_inner()) = hook;
        if set {
            self.set_cache_keys(true);
        }
    }

    /// The hook [`Self::set_resolve_public_keys`] set.
    pub(super) fn public_keys_hook(&self) -> Option<ResolvePublicKeys> {
        self.resolve_public_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The public keys `call` encrypts its key to: the keys it passes, or,
    /// when it passes none, the stored keys of its members, fetched first by
    /// the hook when one is set. A call that passes none and names no
    /// members gets its empty keys back, and reports them as it always has.
    pub(super) fn key_change_public_keys<'a>(
        &self,
        call: KeyChangeCall<'a>,
    ) -> Result<Cow<'a, [PublicKeyInput]>, SdkError> {
        let passed = call.public_keys();
        if !passed.is_empty() {
            return Ok(Cow::Borrowed(passed));
        }
        let members = self.key_change_members(call);
        if members.is_empty() {
            return Ok(Cow::Borrowed(passed));
        }
        if let Some(resolve) = self.public_keys_hook() {
            let missing = self.missing_public_keys_for(call);
            if !missing.is_empty() {
                self.add_public_keys(&resolve(&missing));
            }
        }
        let (public_keys, without) = self.stored_public_keys(&members);
        if !without.is_empty() {
            return Err(SdkError::InvalidInput(format!(
                "public_keys is empty and no public keys are stored for user(s) {}: pass \
                 public_keys, or add those users' keys with add_public_keys",
                without.join(", ")
            )));
        }
        Ok(Cow::Owned(public_keys))
    }

    /// The users `call` encrypts its key to when it passes no public keys:
    /// the members its params name, once each.
    fn key_change_members(&self, call: KeyChangeCall<'_>) -> Vec<String> {
        let named: Vec<&[String]> = match call {
            KeyChangeCall::ConversationKeyChange(params) if params.member_ids.is_empty() => {
                return self.one_to_one_users(params);
            }
            KeyChangeCall::ConversationKeyChange(params) => vec![params.member_ids.as_slice()],
            KeyChangeCall::GroupCreate(params) => {
                vec![params.member_ids.as_slice(), params.admin_ids.as_slice()]
            }
            KeyChangeCall::GroupMembersChange(params) => vec![
                params.current_member_ids.as_slice(),
                params.new_member_ids.as_slice(),
            ],
            KeyChangeCall::GroupMembersRemove(params) => {
                vec![params.remaining_member_ids.as_slice()]
            }
        };
        let mut members: Vec<String> = Vec::new();
        for user_id in named.into_iter().flatten() {
            if !user_id.is_empty() && !members.contains(user_id) {
                members.push(user_id.clone());
            }
        }
        members
    }

    /// The two users of the one-to-one conversation a key change names by
    /// its id, in any form the call accepts; none for a group's id, no id,
    /// or an id that needs a sender this instance cannot resolve.
    fn one_to_one_users(&self, params: &ConversationKeyChangeParams) -> Vec<String> {
        let Some(conversation_id) = params
            .conversation_id
            .as_deref()
            .filter(|id| !id.is_empty())
        else {
            return Vec::new();
        };
        let Ok(sender_id) = self.resolve_sender_id(params.sender_id.as_deref()) else {
            return Vec::new();
        };
        let is_user_id = |id: &str| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit());
        let canonical = crate::pipeline::canonical_conversation_id(conversation_id, &sender_id);
        match canonical.split_once(':') {
            Some((first, second)) if is_user_id(first) && is_user_id(second) => {
                vec![first.to_string(), second.to_string()]
            }
            _ => Vec::new(),
        }
    }

    /// The stored public keys of `user_ids` whose identity binding verifies,
    /// every key version of each, and the users among them with none.
    fn stored_public_keys(&self, user_ids: &[String]) -> (Vec<PublicKeyInput>, Vec<String>) {
        let stored = self
            .signing_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut public_keys = Vec::new();
        let mut without = Vec::new();
        for user_id in user_ids {
            let held = public_keys.len();
            for entry in stored.iter().filter(|entry| &entry.user_id == user_id) {
                // An identity key is only encrypted to once the signing key
                // it came with vouches for it, as verification requires.
                let bound = self
                    .verify_key_binding(
                        &entry.identity_public_key,
                        &entry.public_key,
                        &entry.identity_public_key_signature,
                    )
                    .unwrap_or(false);
                if bound {
                    public_keys.push(PublicKeyInput::new(
                        user_id.as_str(),
                        entry.identity_public_key.as_str(),
                        entry.public_key_version.as_str(),
                    ));
                }
            }
            if public_keys.len() == held {
                without.push(user_id.clone());
            }
        }
        (public_keys, without)
    }

    /// The users to look up now for `needs`, each a user and the key version
    /// needed (`None` for any key): the users of the needs no lookup is
    /// remembered for, once each, in order. Each of those needs is then
    /// remembered for [`PUBLIC_KEYS_RETRY_MS`].
    fn users_to_look_up(
        &self,
        needs: impl IntoIterator<Item = (String, Option<String>)>,
    ) -> Vec<String> {
        self.users_to_look_up_at(needs, crate::clock::now_ms())
    }

    /// [`Self::users_to_look_up`] at the time `now` on the core's clock.
    pub(super) fn users_to_look_up_at(
        &self,
        needs: impl IntoIterator<Item = (String, Option<String>)>,
        now: u64,
    ) -> Vec<String> {
        let mut lookups = self
            .public_key_lookups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lookups.retain(|_, until| *until > now);
        let mut users: Vec<String> = Vec::new();
        for need in needs {
            if lookups.contains_key(&need) {
                continue;
            }
            if !users.contains(&need.0) {
                users.push(need.0.clone());
            }
            lookups.insert(need, now.saturating_add(PUBLIC_KEYS_RETRY_MS));
        }
        users
    }
}
