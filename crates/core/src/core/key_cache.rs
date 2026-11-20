//! The conversation-key cache: what enters it and how calls read it.
//!
//! The cache keeps every key it is given per conversation, by key version,
//! under the id [`canonical_event_conversation_id`] files a conversation by.
//! A key enters from a key change whose signature verified, or from a key
//! change this instance prepared. Sends use a conversation's newest key;
//! decrypts use the key at the version an event names.

use super::*;
use std::sync::atomic::Ordering;

impl ChatCore {
    /// File `key` as the key of `conversation_id` at `version`, while the
    /// cache is on.
    fn cache_conversation_key(
        &self,
        conversation_id: &str,
        version: u64,
        key: &XChatConversationKey,
    ) {
        if !self.cache_keys.load(Ordering::Relaxed) {
            return;
        }
        let mut cache = self
            .conversation_key_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        // Re-check under the write lock: a concurrent set_cache_keys(false)
        // clears the cache, and inserting after that clear would leave a
        // populated cache while the feature is off.
        if self.cache_keys.load(Ordering::Relaxed) {
            cache
                .entry(canonical_event_conversation_id(conversation_id).into_owned())
                .or_default()
                .insert(version, key.clone());
        }
    }

    /// Record a key change of `conversation_id` whose signature verified
    /// over `key` at `version`: the conversation's verified high-water
    /// version never goes below it, and the key is cached. A version that is
    /// not a number records nothing.
    pub(super) fn record_verified_key(
        &self,
        conversation_id: &str,
        version: &str,
        key: &XChatConversationKey,
    ) {
        let Ok(number) = version.parse::<u64>() else {
            return;
        };
        let conversation_id = canonical_event_conversation_id(conversation_id);
        {
            let mut high_water = self
                .conversation_key_high_water
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let entry = high_water.entry(conversation_id.to_string()).or_insert(0);
            *entry = (*entry).max(number);
        }
        // The cache is read by the version as events carry it, so a version
        // written another way than its number reads is not cached.
        if number.to_string() == version {
            self.cache_conversation_key(&conversation_id, number, key);
        }
    }

    /// [`Self::record_verified_key`] for `key_change`, an event whose
    /// signature verified over `key`. Only a signature that covers the
    /// plaintext key ties the key to the key change, so one signed below
    /// [`crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION`] records
    /// nothing, nor does one without a conversation id.
    pub(super) fn record_verified_key_change(
        &self,
        key_change: &MessageEvent,
        version: &str,
        key: &XChatConversationKey,
    ) {
        let signs_the_key = signature_version(key_change)
            .is_some_and(|v| v >= crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION);
        if let (true, Some(conversation_id)) =
            (signs_the_key, key_change.conversation_id.as_deref())
        {
            self.record_verified_key(conversation_id, version, key);
        }
    }

    /// Cache the key a prepare call of this instance made for
    /// `conversation_id` at `version`, so the calls that follow encrypt
    /// under it and decrypt what comes back under it.
    pub(super) fn cache_prepared_key(
        &self,
        conversation_id: &str,
        version: &str,
        key: &XChatConversationKey,
    ) {
        if let Ok(version) = version.parse::<u64>() {
            self.cache_conversation_key(conversation_id, version, key);
        }
    }

    /// The newest cached key of the conversation `conversation_id`, in the
    /// form the cache files it by, with its version: the key sends use.
    pub(super) fn newest_cached_key(&self, conversation_id: &str) -> Option<CachedConversationKey> {
        if !self.cache_keys.load(Ordering::Relaxed) {
            return None;
        }
        let cache = self
            .conversation_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let (version, key) = cache.get(conversation_id)?.last_key_value()?;
        Some(CachedConversationKey {
            version: *version,
            key: key.clone(),
        })
    }

    /// The cached key of `conversation_id` at key version `version`. Used by
    /// the decrypt path when the caller's key map lacks that version.
    pub(super) fn cached_key_for(
        &self,
        conversation_id: &str,
        version: &str,
    ) -> Option<XChatConversationKey> {
        if !self.cache_keys.load(Ordering::Relaxed) {
            return None;
        }
        let number = version.parse::<u64>().ok()?;
        // A version is looked up as events carry it, so one written another
        // way than its number reads (a leading zero, a sign) matches none.
        if number.to_string() != version {
            return None;
        }
        let cache = self
            .conversation_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cache
            .get(canonical_event_conversation_id(conversation_id).as_ref())?
            .get(&number)
            .cloned()
    }

    /// Every cached key of `conversation_id`, by key version: the key map a
    /// decrypt call takes, for a caller that passes none.
    pub(super) fn cached_keys_of(
        &self,
        conversation_id: &str,
    ) -> HashMap<String, XChatConversationKey> {
        if !self.cache_keys.load(Ordering::Relaxed) {
            return HashMap::new();
        }
        let cache = self
            .conversation_key_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cache
            .get(canonical_event_conversation_id(conversation_id).as_ref())
            .map(|versions| {
                versions
                    .iter()
                    .map(|(version, key)| (version.to_string(), key.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}
