//! Event decryption: the single-event and batch paths.

use super::*;
use std::borrow::Cow;

/// The conversation keys a batch's key changes carry, each under the
/// conversation of its key change, so two conversations' keys at one key
/// version stay apart.
#[derive(Default)]
pub(super) struct BatchKeys {
    /// By conversation, then key version.
    by_conversation: HashMap<String, HashMap<String, XChatConversationKey>>,
    /// By key version, for key changes that carry no conversation id.
    unattributed: HashMap<String, XChatConversationKey>,
}

impl BatchKeys {
    /// The key a key change of `conversation` carries at `version`.
    pub(super) fn get(
        &self,
        conversation: Option<&str>,
        version: &str,
    ) -> Option<&XChatConversationKey> {
        match conversation {
            Some(conversation) => self.by_conversation.get(conversation)?.get(version),
            None => self.unattributed.get(version),
        }
    }

    /// File `key` as the key at `version` of `conversation`, replacing an
    /// earlier one filed there.
    fn insert(&mut self, conversation: Option<&str>, version: String, key: XChatConversationKey) {
        let versions = match conversation {
            Some(conversation) => self
                .by_conversation
                .entry(conversation.to_string())
                .or_default(),
            None => &mut self.unattributed,
        };
        versions.insert(version, key);
    }

    fn remove(&mut self, conversation: Option<&str>, version: &str) {
        match conversation {
            Some(conversation) => {
                if let Some(versions) = self.by_conversation.get_mut(conversation) {
                    versions.remove(version);
                    if versions.is_empty() {
                        self.by_conversation.remove(conversation);
                    }
                }
            }
            None => {
                self.unattributed.remove(version);
            }
        }
    }

    /// Every key by its version alone. A version that key changes of more
    /// than one conversation carry is left out: a lookup by version cannot
    /// say which conversation's key it wants.
    fn by_version(&self) -> HashMap<String, XChatConversationKey> {
        let mut keys: HashMap<String, XChatConversationKey> = HashMap::new();
        let mut shared: Vec<&str> = Vec::new();
        for versions in self.by_conversation.values().chain([&self.unattributed]) {
            for (version, key) in versions {
                if keys.insert(version.clone(), key.clone()).is_some() {
                    shared.push(version);
                }
            }
        }
        for version in shared {
            keys.remove(version);
        }
        keys
    }

    /// The result a decrypt call returns for these keys.
    fn into_result(
        self,
        latest_version: Option<String>,
        latest_versions: HashMap<String, String>,
    ) -> ConversationKeyResult {
        ConversationKeyResult {
            keys: self.by_version(),
            keys_by_conversation: self.by_conversation,
            latest_version,
            latest_versions,
        }
    }
}

/// What extracting a batch's conversation keys found.
#[derive(Default)]
pub(super) struct ExtractedKeys {
    /// The keys this identity decrypted.
    pub(super) keys: BatchKeys,
    /// The key changes whose key this identity could not decrypt, by their
    /// index in the batch.
    pub(super) undecryptable: HashMap<usize, UndecryptableKeyChange>,
    /// The conversations the batch's events belong to, in batch order.
    conversations: Vec<String>,
    /// The highest key version among `keys`.
    highest_version: Option<String>,
    /// The highest key version among `keys` of each conversation.
    highest_versions: HashMap<String, String>,
}

/// The signing keys a decrypt call verifies with.
pub(super) struct CheckedSigningKeys {
    /// The entries whose identity binding verifies.
    pub(super) verified: Vec<SigningKeyEntry>,
    /// The entries left out because theirs does not, by their index among
    /// the keys the call verifies with.
    pub(super) rejected: HashMap<usize, RejectedSigningKey>,
}

impl CheckedSigningKeys {
    /// The verified keys of `sender_id`.
    fn of_sender(&self, sender_id: Option<&str>) -> Vec<SigningKeyEntry> {
        match sender_id {
            Some(sender_id) => self
                .verified
                .iter()
                .filter(|key| key.user_id == sender_id)
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Whether the signing key that `event`'s signature names was given and
    /// rejected.
    fn rejected_key_of(&self, event: &MessageEvent) -> bool {
        let version = signature_key_version(event).unwrap_or("");
        event.sender_id.as_deref().is_some_and(|sender_id| {
            self.rejected
                .values()
                .any(|key| key.user_id == sender_id && key.public_key_version == version)
        })
    }
}

/// The conversation an event belongs to, as
/// [`canonical_event_conversation_id`] files it.
fn conversation_of(event: &MessageEvent) -> Option<Cow<'_, str>> {
    event
        .conversation_id
        .as_deref()
        .map(canonical_event_conversation_id)
}

/// The key versions of each conversation whose key change gave the batch no
/// key: one that did not verify and had its key dropped, or one this
/// identity could not decrypt.
fn lost_key_versions(
    unverified_key_changes: &HashMap<usize, UnverifiedKeyChange>,
    undecryptable_key_changes: &HashMap<usize, UndecryptableKeyChange>,
) -> Vec<(Option<String>, String)> {
    let dropped = unverified_key_changes
        .values()
        .filter(|change| change.key_dropped)
        .map(|change| (&change.conversation_id, &change.conversation_key_version));
    let undecryptable = undecryptable_key_changes
        .values()
        .map(|change| (&change.conversation_id, &change.conversation_key_version));
    dropped
        .chain(undecryptable)
        .map(|(conversation_id, version)| {
            let conversation = conversation_id
                .as_deref()
                .map(|id| canonical_event_conversation_id(id).into_owned());
            (conversation, version.clone())
        })
        .collect()
}

/// The keys an event of `conversation` decrypts with: the keys of its
/// conversation's key changes, and for a version its conversation has no key
/// change of, the batch's keys by version alone. A version in `lost` for the
/// conversation has a key change there, one that gave no key, so the event
/// has no key for it.
fn event_keys<'a>(
    conversation_keys: &'a ConversationKeyResult,
    conversation: Option<&str>,
    lost: &[(Option<String>, String)],
) -> Cow<'a, HashMap<String, XChatConversationKey>> {
    let by_version = &conversation_keys.keys;
    let own = conversation.and_then(|id| conversation_keys.keys_by_conversation.get(id));
    // Whether the batch's keys by version alone add `version` to the
    // conversation's own.
    let adds = |version: &String| {
        !own.is_some_and(|own| own.contains_key(version))
            && !lost
                .iter()
                .any(|(id, lost_version)| id.as_deref() == conversation && lost_version == version)
    };
    match own {
        Some(own) if !by_version.keys().any(adds) => Cow::Borrowed(own),
        None if by_version.keys().all(adds) => Cow::Borrowed(by_version),
        _ => Cow::Owned(
            by_version
                .iter()
                .filter(|(version, _)| adds(version))
                .chain(own.into_iter().flatten())
                .map(|(version, key)| (version.clone(), key.clone()))
                .collect(),
        ),
    }
}

impl ChatCore {
    // Events

    /// Extract and decrypt conversation keys from a batch of raw event strings.
    ///
    /// Parses each event, attempts to decrypt participant keys using the loaded
    /// identity key, and returns a `ConversationKeyResult` with:
    /// - `keys`: Map of key version → conversation key
    /// - `keys_by_conversation`: Map of conversation id → key version →
    ///   conversation key
    /// - `latest_version`: The highest key version, when every event of the
    ///   batch belongs to one conversation
    /// - `latest_versions`: Each conversation's highest key version
    ///
    /// Events that are not `KeyChange` events, or whose keys can't be decrypted
    /// by this identity key, are skipped; [`Self::decrypt_events`] reports
    /// the latter in `undecryptable_key_changes`.
    ///
    /// Returns an empty result if no keys are loaded.
    ///
    /// # Security
    ///
    /// This call adopts every decryptable key without checking signatures and
    /// reports the batch's highest version. [`Self::decrypt_events`] hardens
    /// this: only a key change whose signature verified sets its
    /// `latest_version`, held monotonic, so neither an unverified key change
    /// nor a replayed older one sets what callers encrypt with; per-message
    /// signatures are verified in [`Self::decrypt_event`].
    ///
    /// `latest_version` here is the highest version within this batch only.
    /// A batch whose events belong to more than one conversation has none:
    /// one version cannot name each conversation's key, and `latest_versions`
    /// holds the highest per conversation. Likewise `keys` leaves out a
    /// version that key changes of more than one conversation carry, and
    /// `keys_by_conversation` holds every key under its conversation.
    pub fn extract_conversation_keys(&self, events: &[&str]) -> ConversationKeyResult {
        let extracted = self.extract_batch_keys(events);
        let latest_version = match extracted.conversations.len() {
            0 | 1 => extracted.highest_version,
            _ => None,
        };
        extracted
            .keys
            .into_result(latest_version, extracted.highest_versions)
    }

    /// The conversation keys a batch's key changes carry for this identity,
    /// kept apart by conversation, and the key changes whose key it could
    /// not decrypt. Signatures are not checked.
    pub(super) fn extract_batch_keys(&self, events: &[&str]) -> ExtractedKeys {
        let mut extracted = ExtractedKeys::default();

        for (index, event_b64) in events.iter().enumerate() {
            let Ok(parsed) = Self::parse_event_b64(event_b64) else {
                continue;
            };
            let conversation = conversation_of(&parsed);
            if let Some(conversation) = conversation.as_deref() {
                if !extracted.conversations.iter().any(|c| c == conversation) {
                    extracted.conversations.push(conversation.to_string());
                }
            }
            let Some(MessageEventDetail::ConversationKeyChangeEvent(kce)) = &parsed.detail else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(ckey) = self.decrypt_key_change_ckey(kce) else {
                extracted.undecryptable.insert(
                    index,
                    UndecryptableKeyChange {
                        reason: self.undecryptable_reason(kce),
                        conversation_id: parsed.conversation_id.clone(),
                        conversation_key_version: version,
                        sender_id: parsed.sender_id.clone(),
                    },
                );
                continue;
            };

            if is_newer_key_version(extracted.highest_version.as_deref(), &version) {
                extracted.highest_version = Some(version.clone());
            }
            if let Some(conversation) = conversation.as_deref() {
                let current = extracted
                    .highest_versions
                    .get(conversation)
                    .map(String::as_str);
                if is_newer_key_version(current, &version) {
                    extracted
                        .highest_versions
                        .insert(conversation.to_string(), version.clone());
                }
            }
            extracted
                .keys
                .insert(conversation.as_deref(), version, ckey);
        }

        extracted
    }

    /// Why [`Self::decrypt_key_change_ckey`] finds no key for this identity
    /// in `key_change`.
    fn undecryptable_reason(
        &self,
        key_change: &crate::thrift::event::ConversationKeyChangeEvent,
    ) -> UndecryptableKeyChangeReason {
        if self.keypair_manager.get_identity_keypair().is_err() {
            return UndecryptableKeyChangeReason::Locked;
        }
        let entries = key_change
            .conversation_participant_keys
            .as_deref()
            .unwrap_or_default();
        // The entries that can be this chat's: its user's, or anyone's when
        // no session identity names the user.
        let user_id = self.session_user_id();
        let own: Vec<_> = entries
            .iter()
            .filter(|entry| user_id.is_none() || entry.user_id == user_id)
            .collect();
        if own.is_empty() {
            return UndecryptableKeyChangeReason::NotARecipient;
        }
        if let Some(key_version) = self.keypair_manager.get_key_version() {
            let none_at_key_version = own.iter().all(|entry| {
                entry
                    .public_key_version
                    .as_deref()
                    .is_some_and(|version| version != key_version)
            });
            if none_at_key_version {
                return UndecryptableKeyChangeReason::OtherKeyVersion;
            }
        }
        UndecryptableKeyChangeReason::DecryptionFailed
    }

    /// Keep the signing keys a decrypt call verifies with: `signing_keys`,
    /// or the keys stored via [`Self::set_signing_keys`] when it is empty,
    /// less the entries whose identity binding does not verify, so they
    /// can't be used for verification.
    pub(super) fn checked_signing_keys(
        &self,
        signing_keys: &[SigningKeyEntry],
    ) -> CheckedSigningKeys {
        let mut checked = CheckedSigningKeys {
            verified: Vec::new(),
            rejected: HashMap::new(),
        };
        for (index, key) in self
            .resolve_signing_keys(signing_keys)
            .into_iter()
            .enumerate()
        {
            let bound = self
                .verify_key_binding(
                    &key.identity_public_key,
                    &key.public_key,
                    &key.identity_public_key_signature,
                )
                .unwrap_or(false);
            if bound {
                checked.verified.push(key);
            } else {
                checked.rejected.insert(
                    index,
                    RejectedSigningKey {
                        user_id: key.user_id,
                        public_key_version: key.public_key_version,
                    },
                );
            }
        }
        checked
    }

    /// Check `event`'s signature against its sender's keys among
    /// `signing_keys`, as [`Self::check_event_signature`] does. A signing
    /// key that was given and rejected is reported as such, not as missing.
    fn check_sender_signature(
        &self,
        event: &MessageEvent,
        detail: &MessageEventDetail,
        signing_keys: &CheckedSigningKeys,
        plaintext_ckey_b64: Option<&str>,
    ) -> SignatureCheck {
        let sender_keys = signing_keys.of_sender(event.sender_id.as_deref());
        match self.check_event_signature(event, detail, &sender_keys, plaintext_ckey_b64) {
            SignatureCheck::MissingSigningKey if signing_keys.rejected_key_of(event) => {
                SignatureCheck::RejectedSigningKey
            }
            check => check,
        }
    }

    /// The key changes of a batch whose key this identity decrypted but
    /// whose signature does not verify, by their index in the batch, each
    /// with why. `keys` holds the keys [`Self::extract_batch_keys`] took
    /// from the batch, and every entry's `key_dropped` is left `false` for
    /// the caller to set once signature enforcement has run.
    ///
    /// Each key change is checked against the key its conversation holds for
    /// its version, as [`Self::enforce_ckey_signatures`] checks it, so an
    /// entry explains what enforcement does to that key. A key change signed
    /// below [`crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION`] signs a
    /// payload no recipient can rebuild, so it is unverifiable whichever
    /// signing keys are given.
    pub(super) fn unverified_key_changes(
        &self,
        events: &[&str],
        signing_keys: &CheckedSigningKeys,
        keys: &BatchKeys,
    ) -> HashMap<usize, UnverifiedKeyChange> {
        let mut unverified = HashMap::new();
        for (index, event_b64) in events.iter().enumerate() {
            let Ok(parsed) = Self::parse_event_b64(event_b64) else {
                continue;
            };
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(key) = keys.get(conversation_of(&parsed).as_deref(), &version) else {
                continue;
            };

            let unverifiable_version = signature_version(&parsed)
                .is_some_and(|v| v < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION);
            let reason = if unverifiable_version {
                UnverifiedKeyChangeReason::Unverifiable
            } else {
                // Base64 of a live conversation key; wiped on drop like the
                // sign-path payloads.
                let ckey_b64 = zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(key.encoded()));
                let check =
                    self.check_sender_signature(&parsed, detail, signing_keys, Some(&ckey_b64));
                match check {
                    SignatureCheck::Verified => continue,
                    SignatureCheck::MissingSigningKey => {
                        UnverifiedKeyChangeReason::MissingSigningKey
                    }
                    SignatureCheck::RejectedSigningKey => {
                        UnverifiedKeyChangeReason::RejectedSigningKey
                    }
                    SignatureCheck::Mismatch(_) => UnverifiedKeyChangeReason::InvalidSignature,
                    SignatureCheck::Unsigned
                    | SignatureCheck::UnacceptedVersion(_)
                    | SignatureCheck::NoConversationKey
                    | SignatureCheck::NoPayload => UnverifiedKeyChangeReason::Unverifiable,
                }
            };
            unverified.insert(
                index,
                UnverifiedKeyChange {
                    reason,
                    key_dropped: false,
                    conversation_id: parsed.conversation_id.clone(),
                    conversation_key_version: version,
                    sender_id: parsed.sender_id.clone(),
                    public_key_version: signature_key_version(&parsed).map(str::to_string),
                },
            );
        }
        unverified
    }

    /// Drop the conversation keys whose key change fails signature
    /// enforcement.
    ///
    /// A key change is rejected only when its sequence number is at or above
    /// the configured threshold, its signature version is missing or carries
    /// a verifiable plaintext-key payload, and its signature does not verify.
    /// Below the threshold, or for earlier signature versions whose payload
    /// cannot be reproduced, the key is kept. Does nothing while `floor` is
    /// at the maximum.
    pub(super) fn enforce_ckey_signatures(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        keys: &mut BatchKeys,
        floor: i64,
    ) {
        if floor == i64::MAX {
            return;
        }

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };

            let Some(seq) = parsed
                .sequence_id
                .as_deref()
                .and_then(|s| s.parse::<i64>().ok())
            else {
                continue;
            };
            if seq < floor {
                continue;
            }

            // A key change signed below CKEY_PLAINTEXT_SIGNATURE_VERSION can't
            // be verified, so its key is kept; one without a version fails
            // verification below.
            if signature_version(&parsed)
                .is_some_and(|v| v < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION)
            {
                continue;
            }

            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let conversation = conversation_of(&parsed);
            let Some(adopted) = keys.get(conversation.as_deref(), &version) else {
                continue;
            };
            // Base64 of a live conversation key; wiped on drop like the
            // sign-path payloads.
            let ckey_b64 = zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(adopted.encoded()));
            let sender_keys: Vec<SigningKeyEntry> = match parsed.sender_id.as_deref() {
                Some(sid) => signing_keys
                    .iter()
                    .filter(|k| k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            let verified = self
                .check_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64))
                .is_verified();
            if verified {
                self.raise_key_change_signature_floor_for(&parsed);
            } else {
                keys.remove(conversation.as_deref(), &version);
            }
        }
    }

    /// Record the newest key version whose key change verified, per
    /// conversation and monotonically across this instance's lifetime, cache
    /// the key of each key change that verified, and return the latest
    /// versions a batch reports: `latest_version` and `latest_versions`.
    ///
    /// A malicious relay can replay an old, validly signed key change to make a
    /// caller encrypt under a stale key, or inject a key change it cannot sign.
    /// Recording the highest *verified* version per conversation and never
    /// reporting a lower or unverified one defeats both, while every key in
    /// `keys` stays available for decryption. Only signature versions
    /// carrying a reproducible plaintext-key payload can be verified, so a
    /// batch whose conversations have no verified key change reports no
    /// latest version.
    ///
    /// `latest_versions` takes each of the batch's conversations that has a
    /// verified version. `latest_version` is that version when every event
    /// of the batch belongs to one conversation. A batch of more reports
    /// none, even when only one of its conversations has a verified version:
    /// the version does not say which conversation it belongs to, so a
    /// caller would encrypt for the others with a key that is not theirs.
    pub(super) fn apply_ckey_freshness(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        keys: &BatchKeys,
    ) -> (Option<String>, HashMap<String, String>) {
        let mut batch_conversations: Vec<String> = Vec::new();

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            let conversation = conversation_of(&parsed);
            if let Some(conv_id) = conversation.as_deref() {
                if !batch_conversations.iter().any(|c| c == conv_id) {
                    batch_conversations.push(conv_id.to_string());
                }
            }
            let Some(detail) = &parsed.detail else {
                continue;
            };
            let MessageEventDetail::ConversationKeyChangeEvent(kce) = detail else {
                continue;
            };
            let Some(conv_id) = conversation.as_deref() else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            if version.parse::<u64>().is_err() {
                continue;
            }

            match signature_version(&parsed) {
                Some(v) if v >= crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION => {}
                _ => continue,
            }

            let Some(adopted) = keys.get(Some(conv_id), &version) else {
                continue;
            };
            // Base64 of a live conversation key; wiped on drop like the
            // sign-path payloads.
            let ckey_b64 = zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(adopted.encoded()));
            let sender_keys: Vec<SigningKeyEntry> = match parsed.sender_id.as_deref() {
                Some(sid) => signing_keys
                    .iter()
                    .filter(|k| k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            if self
                .check_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64))
                .is_verified()
            {
                self.raise_key_change_signature_floor_for(&parsed);
                // Only a key whose key change verified here is recorded and
                // cached, never a merely adopted one.
                self.record_verified_key(conv_id, &version, adopted);
            }
        }

        let high_water = self
            .conversation_key_high_water
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let latest_versions: HashMap<String, String> = batch_conversations
            .iter()
            .filter_map(|c| {
                high_water
                    .get(c)
                    .map(|version_num| (c.clone(), version_num.to_string()))
            })
            .collect();
        let latest_version = match batch_conversations.as_slice() {
            [conversation] => latest_versions.get(conversation).cloned(),
            _ => None,
        };
        (latest_version, latest_versions)
    }

    /// Decrypt the conversation key carried in a `ConversationKeyChange` event
    /// using the loaded identity key.
    ///
    /// Tries each participant entry (preferring the one matching our key
    /// version, if known) and returns the first that decrypts with our
    /// identity private key. Returns `None` if locked or none decrypt.
    pub(super) fn decrypt_key_change_ckey(
        &self,
        kce: &crate::thrift::event::ConversationKeyChangeEvent,
    ) -> Option<XChatConversationKey> {
        let identity = self.keypair_manager.get_identity_keypair().ok()?;
        let participant_keys = kce.conversation_participant_keys.as_ref()?;
        let my_key_version = self.keypair_manager.get_key_version();

        for pk in participant_keys {
            // Skip entries targeting a different key version when ours is known.
            if let Some(ref my_ver) = my_key_version {
                if let Some(ref pk_ver) = pk.public_key_version {
                    if pk_ver != my_ver {
                        continue;
                    }
                }
            }
            let Some(encrypted_b64) = &pk.encrypted_conversation_key else {
                continue;
            };
            let Ok(encrypted_bytes) = base64_decode(encrypted_b64) else {
                continue;
            };
            if let Ok(ckey) =
                conversation_keys::decrypt_conversation_key(&encrypted_bytes, &identity.private)
            {
                return Some(ckey);
            }
        }
        None
    }

    /// Decrypt multiple events in batch.
    ///
    /// This is the recommended API for decrypting messages. It:
    /// 1. Extracts conversation keys from any KeyChange events
    /// 2. For each message, finds the correct signing key by matching sender_id + version
    /// 3. Decrypts the message using the appropriate conversation key
    ///
    /// `params.events` are the raw base64 events; `params.signing_keys` the
    /// known signing keys of the participants, or the keys stored via
    /// [`Self::set_signing_keys`] when unset or empty. They must include the
    /// keys of every member who signed a key change in the batch, whether or
    /// not that member sent a message in it: a key change sequenced at or
    /// after the enforcement cut-over whose signature does not verify has
    /// its key dropped, and every message under that key then fails.
    ///
    /// # Returns
    /// A `DecryptEventsResult` containing:
    /// * `events` - The events that decrypted, of every event type
    /// * `conversation_keys` - Extracted conversation keys (for caching),
    ///   each under its conversation in `keys_by_conversation` and, by
    ///   version alone, in `keys`. Its `latest_versions` holds, for each of
    ///   the batch's conversations, the newest version whose key change
    ///   verified, held monotonic for this instance's lifetime;
    ///   `latest_version` is that version when every event of the batch
    ///   belongs to one conversation, `None` until a key change verifies,
    ///   and `None` for a batch of more than one conversation. A key from a
    ///   key change that did not verify never becomes the latest; it still
    ///   decrypts unless it was dropped.
    /// * `errors` - Map of event index → error message for the events left
    ///   out of `events`: those that failed, and those decrypt drops, as
    ///   [`Self::decrypt_event`] describes
    /// * `unverified_key_changes` - The key changes whose signature did not
    ///   verify, each with why (no signing key for its sender, a signing key
    ///   that was rejected, an invalid signature, or a signature the SDK
    ///   cannot check), the sender and signing-key version to fetch, and
    ///   whether its key was dropped
    /// * `undecryptable_key_changes` - The key changes whose conversation key
    ///   this identity could not decrypt, each with why
    /// * `rejected_signing_keys` - The signing keys left out of verification
    ///   because their identity binding does not verify
    /// * `missing_signing_keys` - The signing keys the batch's events name
    ///   that were not among the keys the call verified with
    ///
    /// With a hook set ([`Self::set_resolve_public_keys`]) and no signing
    /// keys passed, the call fetches the public keys of
    /// [`Self::missing_public_keys`] of its result through the hook, adds
    /// them to the stored keys, and returns the result of decrypting the
    /// batch once more.
    pub fn decrypt_events(&self, params: &DecryptEventsParams) -> DecryptEventsResult {
        let events: Vec<&str> = params.events.iter().map(String::as_str).collect();
        let signing_keys = params.signing_keys.as_deref().unwrap_or_default();
        let result = self.decrypt_events_with(&events, signing_keys);
        // The hook fills the stored keys, which only a call that is passed
        // no signing keys verifies with.
        if !signing_keys.is_empty() {
            return result;
        }
        let Some(resolve) = self.public_keys_hook() else {
            return result;
        };
        let missing = self.missing_public_keys(&result);
        if missing.is_empty() {
            return result;
        }
        self.add_public_keys(&resolve(&missing));
        self.decrypt_events_with(&events, signing_keys)
    }

    /// [`Self::decrypt_events`] over borrowed inputs.
    pub(crate) fn decrypt_events_with(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
    ) -> DecryptEventsResult {
        let signing_keys = self.checked_signing_keys(signing_keys);

        // First pass: extract conversation keys, note the key changes whose
        // signature does not verify, then drop the keys of those that fail
        // signature enforcement.
        let ExtractedKeys {
            mut keys,
            undecryptable: undecryptable_key_changes,
            ..
        } = self.extract_batch_keys(events);
        let mut unverified_key_changes = self.unverified_key_changes(events, &signing_keys, &keys);
        self.enforce_ckey_signatures(
            events,
            &signing_keys.verified,
            &mut keys,
            CKEY_SIG_V6_ENFORCE_AFTER_SEQ,
        );
        for change in unverified_key_changes.values_mut() {
            let conversation = change
                .conversation_id
                .as_deref()
                .map(canonical_event_conversation_id);
            change.key_dropped = keys
                .get(conversation.as_deref(), &change.conversation_key_version)
                .is_none();
        }
        // Only a verified key change may set the reported latest version, and
        // a replayed older one cannot lower it.
        let (latest_version, latest_versions) =
            self.apply_ckey_freshness(events, &signing_keys.verified, &keys);
        let conversation_keys = keys.into_result(latest_version, latest_versions);
        let lost = lost_key_versions(&unverified_key_changes, &undecryptable_key_changes);
        let missing_signing_keys = self.missing_signing_keys(events, &signing_keys);

        let mut decrypted = Vec::new();
        let mut errors = HashMap::new();

        // Second pass: decrypt each event
        for (idx, event_b64) in events.iter().enumerate() {
            let parsed = match Self::parse_event_b64(event_b64) {
                Ok(p) => p,
                Err(e) => {
                    errors.insert(idx, e.to_string());
                    continue;
                }
            };

            let keys = event_keys(
                &conversation_keys,
                conversation_of(&parsed).as_deref(),
                &lost,
            );
            match self.decrypt_event_prefiltered(&parsed, &keys, &signing_keys) {
                Ok(event) => {
                    decrypted.push(DecryptedEvent {
                        event,
                        original_b64: Some((*event_b64).to_string()),
                    });
                }
                Err(e) => {
                    let error = self
                        .missing_key_error(
                            &parsed,
                            &e,
                            &keys,
                            &unverified_key_changes,
                            &undecryptable_key_changes,
                        )
                        .unwrap_or(e);
                    errors.insert(idx, error.to_string());
                }
            }
        }

        DecryptEventsResult {
            events: decrypted,
            conversation_keys,
            errors,
            unverified_key_changes,
            undecryptable_key_changes,
            rejected_signing_keys: signing_keys.rejected,
            missing_signing_keys,
        }
    }

    /// The signing keys the batch's events name that are not among
    /// `signing_keys`, by the index of the event: for each event of a kind
    /// whose signature decrypt checks, its sender's key at the key version
    /// its signature names, when no key of that sender at that version was
    /// given. A key that was given and rejected is not missing.
    fn missing_signing_keys(
        &self,
        events: &[&str],
        signing_keys: &CheckedSigningKeys,
    ) -> HashMap<usize, MissingSigningKey> {
        let mut missing = HashMap::new();
        for (index, event_b64) in events.iter().enumerate() {
            let Ok(parsed) = Self::parse_event_b64(event_b64) else {
                continue;
            };
            let Some(sender_id) = parsed.sender_id.as_deref() else {
                continue;
            };
            if !parsed.detail.as_ref().is_some_and(has_checked_signature) {
                continue;
            }
            let sender_keys = signing_keys.of_sender(Some(sender_id));
            let lacks_key = matches!(
                event_signature(&parsed, &sender_keys),
                Err(SignatureCheck::MissingSigningKey)
            );
            if lacks_key && !signing_keys.rejected_key_of(&parsed) {
                missing.insert(
                    index,
                    MissingSigningKey::new(
                        sender_id,
                        signature_key_version(&parsed).unwrap_or_default(),
                    ),
                );
            }
        }
        missing
    }

    /// The error of a message that found no conversation key although the
    /// batch holds the key change for its key version: one that did not
    /// verify and had its key dropped, or one whose key this identity could
    /// not decrypt. It names that key change and what kept its key from the
    /// batch, where `error` only reports that no key was found. `None` for
    /// any other failure.
    fn missing_key_error(
        &self,
        parsed: &MessageEvent,
        error: &SdkError,
        keys: &HashMap<String, XChatConversationKey>,
        unverified_key_changes: &HashMap<usize, UnverifiedKeyChange>,
        undecryptable_key_changes: &HashMap<usize, UndecryptableKeyChange>,
    ) -> Option<SdkError> {
        if error.kind() != crate::error::ErrorKind::Decryption {
            return None;
        }
        let Some(MessageEventDetail::MessageCreateEvent(mce)) = &parsed.detail else {
            return None;
        };
        let version = mce.conversation_key_version.as_deref()?;
        let cached = parsed
            .conversation_id
            .as_deref()
            .and_then(|cid| self.cached_key_for(cid, version));
        if keys.contains_key(version) || cached.is_some() {
            return None;
        }
        let conversation = conversation_of(parsed);
        let of_message = |change_conversation: &Option<String>, change_version: &str| {
            change_version == version
                && change_conversation
                    .as_deref()
                    .map(canonical_event_conversation_id)
                    == conversation
        };

        // A key change the batch holds twice is named by its first copy.
        let dropped = unverified_key_changes
            .iter()
            .filter(|(_, change)| {
                change.key_dropped
                    && of_message(&change.conversation_id, &change.conversation_key_version)
            })
            .min_by_key(|(index, _)| **index);
        let (index, why) = if let Some((index, change)) = dropped {
            let reason = match change.reason {
                UnverifiedKeyChangeReason::MissingSigningKey => format!(
                    "{}; pass that user's public keys as signing keys and decrypt again",
                    missing_signing_key(
                        change.sender_id.as_deref(),
                        change.public_key_version.as_deref()
                    )
                ),
                UnverifiedKeyChangeReason::RejectedSigningKey => rejected_signing_key(
                    change.sender_id.as_deref(),
                    change.public_key_version.as_deref(),
                ),
                UnverifiedKeyChangeReason::InvalidSignature => {
                    "its signature does not verify against its sender's signing key".to_string()
                }
                UnverifiedKeyChangeReason::Unverifiable => {
                    "it carries no signature this SDK can check".to_string()
                }
            };
            (
                *index,
                format!("did not verify, so its key was dropped: {reason}"),
            )
        } else {
            let (index, change) = undecryptable_key_changes
                .iter()
                .filter(|(_, change)| {
                    of_message(&change.conversation_id, &change.conversation_key_version)
                })
                .min_by_key(|(index, _)| **index)?;
            let reason = match change.reason {
                UndecryptableKeyChangeReason::Locked => "no identity key is loaded",
                UndecryptableKeyChangeReason::NotARecipient => {
                    "it holds no key for this chat's user"
                }
                UndecryptableKeyChangeReason::OtherKeyVersion => {
                    "it holds no key for this chat's key version"
                }
                UndecryptableKeyChangeReason::DecryptionFailed => {
                    "its key for this chat does not decrypt under the loaded identity key"
                }
            };
            (
                *index,
                format!("holds no key this chat can decrypt: {reason}"),
            )
        };
        Some(SdkError::Crypto(CryptoError::DecryptionFailed(format!(
            "Message encrypted with key version '{version}' but no matching key found: the key \
             change for that version, event {index} of the batch, {why}"
        ))))
    }

    /// Decode and Thrift-parse a raw base64 event, so each event is parsed
    /// once and the result shared between sender-key filtering and decryption.
    pub(super) fn parse_event_b64(event_b64: &str) -> Result<MessageEvent, SdkError> {
        let event_bytes = base64_decode(event_b64)?;
        parse_message_event(&event_bytes)
    }

    /// Decrypt a raw webhook event payload.
    ///
    /// `params.conversation_keys` is a map of `key_version →
    /// conversation_key` from `decrypt_events()` or
    /// `extract_conversation_keys()`. For non-message events the map is
    /// unused and may be empty.
    ///
    /// `params.signing_keys` may contain keys for any set of users (e.g. every
    /// conversation participant); unset or empty, the keys stored via
    /// [`Self::set_signing_keys`] are used. Before verification the SDK keeps
    /// only the entries whose identity binding checks out **and** whose
    /// `user_id` matches the event's sender, then picks the one matching the
    /// version embedded in the message signature — the same selection
    /// [`Self::decrypt_events`] applies. Under the default reject-unverified
    /// policy, no matching key makes every signed event fail; only after
    /// [`Self::set_reject_unverified`]`(false)` are such events returned with
    /// `verified: false`.
    ///
    /// A member removal re-encrypts the group's title and description under
    /// the new key and marks them as key-rotation re-encryptions. They aren't
    /// changes, so decrypt drops them under either policy: this call fails
    /// with an [`SdkError::InvalidInput`] that says so, and
    /// [`Self::decrypt_events`] leaves them out of `events` and records them
    /// in `errors`. The removal itself and its key change decrypt as usual.
    ///
    /// A key change that verifies is recorded as [`Self::decrypt_events`]
    /// records it: its version is the conversation's newest verified one
    /// unless a newer is known, and while the key cache is on its key is
    /// cached. The key is the one the event holds for this identity, or the
    /// one `params.conversation_keys` holds for the key change's version.
    pub fn decrypt_event(&self, params: &DecryptEventParams) -> Result<Event, SdkError> {
        self.decrypt_event_with(
            &params.event_b64,
            &params.conversation_keys,
            params.signing_keys.as_deref().unwrap_or_default(),
        )
    }

    /// [`Self::decrypt_event`] over borrowed inputs.
    pub(crate) fn decrypt_event_with(
        &self,
        event_b64: &str,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
    ) -> Result<Event, SdkError> {
        // Empty inputs fall back to the session stores: signing keys from
        // set_signing_keys, conversation keys from the opt-in key cache.
        let signing_keys = self.checked_signing_keys(signing_keys);
        let parsed = Self::parse_event_b64(event_b64)?;
        self.decrypt_event_prefiltered(&parsed, conversation_keys, &signing_keys)
    }

    /// [`Self::decrypt_event`] body for an already-parsed event and signing
    /// keys whose bindings are already checked: the event's signature is
    /// checked against its sender's keys among them, and reply-preview
    /// validation verifies raw events from other senders against the rest.
    /// The batch path does the binding verification once per batch instead
    /// of once per event.
    pub(super) fn decrypt_event_prefiltered(
        &self,
        parsed: &MessageEvent,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &CheckedSigningKeys,
    ) -> Result<Event, SdkError> {
        let meta = EventMeta {
            sequence_id: parsed.sequence_id.clone(),
            id: parsed.message_id.clone(),
            sender_id: parsed.sender_id.clone(),
            conversation_id: parsed.conversation_id.clone(),
            created_at_msec: parsed
                .created_at_msec
                .as_ref()
                .and_then(|s| s.parse::<i64>().ok()),
        };

        let detail = match &parsed.detail {
            Some(d) => d,
            None => {
                return Ok(Event::Unknown(UnknownEvent {
                    meta,
                    event_type_id: None,
                }))
            }
        };

        let event = match detail {
            MessageEventDetail::ConversationKeyChangeEvent(key_change) => {
                let participant_keys: Vec<ConversationParticipantKey> = key_change
                    .conversation_participant_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|pk| {
                                Some(ConversationParticipantKey {
                                    user_id: pk.user_id.clone()?,
                                    encrypted_conversation_key: pk
                                        .encrypted_conversation_key
                                        .clone()?,
                                    public_key_version: pk
                                        .public_key_version
                                        .clone()
                                        .unwrap_or_default(),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // CKCE v6+ signs the plaintext conversation key. Prefer the
                // caller-supplied key map; otherwise self-decrypt it from this
                // event's participant keys so a standalone KeyChange still
                // verifies without extra caller code. The base64 of the live
                // key is wiped on drop like the sign-path payloads.
                let ckey_version = key_change.conversation_key_version.as_deref().unwrap_or("");
                let ckey = conversation_keys
                    .get(ckey_version)
                    .cloned()
                    .or_else(|| self.decrypt_key_change_ckey(key_change));
                let ckey_b64 = ckey
                    .as_ref()
                    .map(|k| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(k.encoded())));
                let check = match self.check_sender_signature(
                    parsed,
                    detail,
                    signing_keys,
                    ckey_b64.as_deref().map(String::as_str),
                ) {
                    // From CKEY_PLAINTEXT_SIGNATURE_VERSION on the payload
                    // holds the plaintext key, so without the key there is
                    // none to rebuild.
                    SignatureCheck::NoPayload
                        if ckey_b64.is_none()
                            && signature_version(parsed).is_some_and(|v| {
                                v >= crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION
                            }) =>
                    {
                        SignatureCheck::NoConversationKey
                    }
                    check => check,
                };
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "KeyChange")?;
                if verified {
                    self.raise_key_change_signature_floor_for(parsed);
                    // As the batch path does for a key change that verifies:
                    // its version becomes the conversation's newest verified
                    // one unless a newer is known, and its key is cached.
                    if let Some(key) = &ckey {
                        self.record_verified_key_change(parsed, ckey_version, key);
                    }
                }
                Event::KeyChange(KeyChangeEvent {
                    meta,
                    conversation_key_version: key_change
                        .conversation_key_version
                        .clone()
                        .unwrap_or_default(),
                    verified,
                    conversation_participant_keys: participant_keys,
                })
            }
            MessageEventDetail::MessageTypingEvent(_) => Event::Typing(TypingEvent { meta }),
            MessageEventDetail::MarkConversationReadEvent(read_event) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "ReadReceipt")?;
                Event::ReadReceipt(ReadReceiptEvent {
                    meta,
                    verified,
                    seen_until_sequence_id: read_event.seen_until_sequence_id.clone(),
                    seen_at_msec: read_event.seen_at_millis,
                })
            }
            MessageEventDetail::MarkConversationUnreadEvent(unread_event) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "MarkedUnread")?;
                Event::MarkedUnread(MarkedUnreadEvent {
                    meta,
                    verified,
                    seen_until_sequence_id: unread_event.seen_until_sequence_id.clone(),
                })
            }
            MessageEventDetail::MessageDeleteEvent(del_event) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "MessageDelete")?;
                let delete_for_all = del_event
                    .delete_message_action
                    .as_ref()
                    .map(|a| a.0 == 2)
                    .unwrap_or(false);
                Event::MessageDeleted(MessageDeletedEvent {
                    meta,
                    verified,
                    sequence_ids: del_event.sequence_ids.clone().unwrap_or_default(),
                    delete_for_all,
                })
            }
            MessageEventDetail::ConversationDeleteEvent(conv_del) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "ConversationDelete")?;
                let clear_all = conv_del
                    .clear_conversation_options
                    .as_ref()
                    .and_then(|o| o.clear_all_messages)
                    .unwrap_or(false);
                Event::ConversationDeleted(ConversationDeletedEvent {
                    meta,
                    verified,
                    clear_all_messages: clear_all,
                })
            }
            MessageEventDetail::MessageFailureEvent(failure) => {
                let failure_type = convert_failure_type(failure.failure_type.as_ref());
                Event::Failure(FailureEvent {
                    meta,
                    failure: failure_type,
                    rate_limit_tier: convert_rate_limit_tier(failure.rate_limit_tier.as_ref()),
                })
            }
            MessageEventDetail::MemberAccountDeleteEvent(member_del) => {
                Event::MemberDeleted(MemberDeletedEvent {
                    meta,
                    member_id: member_del.member_id.clone().unwrap_or_default(),
                })
            }
            MessageEventDetail::GroupChangeEvent(group_change) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "GroupChange")?;
                reject_key_rotation_reencryption(group_change)?;
                let change = self.group_change(
                    parsed.conversation_id.as_deref(),
                    group_change.group_change.as_ref(),
                    conversation_keys,
                );
                Event::GroupChange(GroupChangeEvent {
                    meta,
                    verified,
                    change,
                })
            }
            MessageEventDetail::ConversationMetadataChangeEvent(settings) => {
                let check = self.check_sender_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "SettingsChange")?;
                let change =
                    convert_settings_change(settings.conversation_metadata_change.as_ref());
                Event::SettingsChange(SettingsChangeEvent {
                    meta,
                    verified,
                    change,
                })
            }
            MessageEventDetail::MessageCreateEvent(mce) => {
                let contents = match &mce.contents {
                    Some(c) => c,
                    None => {
                        return Ok(Event::Unknown(UnknownEvent {
                            meta,
                            event_type_id: Some(1),
                        }))
                    }
                };

                // Unencrypted MCE: conversation_key_version is None — contents
                // are already plaintext Thrift bytes, no signature to verify.
                let is_unencrypted = mce.conversation_key_version.is_none();

                // Verify before decrypt so that an invalid signature never
                // results in plaintext being returned (when reject_unverified).
                // Unencrypted messages carry no signature, so they are treated
                // as unverifiable and rejected under reject_unverified too.
                let check = if is_unencrypted {
                    SignatureCheck::Unsigned
                } else {
                    self.check_sender_signature(parsed, detail, signing_keys, None)
                };
                let verified = check.is_verified();

                self.reject_if_unverified(&check, parsed, "Message")?;

                let plaintext = if is_unencrypted {
                    contents.clone()
                } else {
                    let version = mce.conversation_key_version.as_deref().unwrap_or("");
                    // The caller-supplied map wins; the opt-in key cache
                    // covers callers that no longer hold the key map.
                    let ckey = match conversation_keys.get(version) {
                        Some(k) => k.clone(),
                        None => parsed
                            .conversation_id
                            .as_deref()
                            .and_then(|cid| self.cached_key_for(cid, version))
                            .ok_or_else(|| {
                                let available = conversation_keys
                                    .keys()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                SdkError::Crypto(CryptoError::DecryptionFailed(format!(
                                    "Message encrypted with key version '{}' but no matching key \
                                     found. Available versions: [{}]. Include the conversation's \
                                     KeyChange events in the batch passed to decrypt_events(), \
                                     or pass the matching key map to decrypt_event().",
                                    version, available
                                )))
                            })?,
                    };
                    let message_key = Self::message_key_for(parsed, &ckey)?;
                    decrypt_message_bytes(message_key.as_ref().unwrap_or(&ckey), contents)?
                };

                let parsed_content = parse_message_content(&plaintext)?;

                // A preview that embeds its raw source event is always
                // validated; without one it passes through unvalidated.
                let reply_preview_validation = parsed_content
                    .raw_reply_preview
                    .as_ref()
                    .filter(|p| p.raw_event_message_create.is_some())
                    .map(|p| {
                        self.validate_reply_preview(
                            parsed,
                            p,
                            conversation_keys,
                            &signing_keys.verified,
                        )
                    });

                Event::Message(Box::new(Message {
                    meta,
                    content: parsed_content.content,
                    conversation_key_version: mce.conversation_key_version.clone(),
                    verified,
                    should_notify: mce.should_notify,
                    ttl_msec: mce.ttl_msec,
                    attachments: parsed_content.attachments,
                    media_hashes: parsed_content.media_hashes,
                    reply_preview_validation,
                }))
            }
            _ => Event::Unknown(UnknownEvent {
                meta,
                event_type_id: None,
            }),
        };

        Ok(event)
    }

    /// The group change an event carries, its title and description
    /// decrypted under the conversation key for the change's key version.
    pub(super) fn group_change(
        &self,
        conversation_id: Option<&str>,
        change: Option<&crate::thrift::event::GroupChange>,
        conversation_keys: &HashMap<String, XChatConversationKey>,
    ) -> GroupChange {
        use crate::thrift::event::GroupChange as GenGC;
        let text = |version: &Option<String>, value: &Option<String>| {
            self.group_text(
                conversation_id,
                conversation_keys,
                version.as_deref(),
                value.as_deref().unwrap_or_default(),
            )
        };
        match change {
            Some(GenGC::GroupCreate(c)) => GroupChange::Created {
                member_ids: c.member_ids.clone().unwrap_or_default(),
                admin_ids: c.admin_ids.clone().unwrap_or_default(),
                title: c
                    .title
                    .as_deref()
                    .filter(|title| !title.is_empty())
                    .map(|_| text(&c.conversation_key_version, &c.title)),
                avatar_url: c.avatar_url.clone(),
                conversation_key_version: c.conversation_key_version.clone(),
            },
            Some(GenGC::GroupTitleChange(c)) => GroupChange::TitleChanged {
                new_title: text(&c.conversation_key_version, &c.custom_title),
            },
            Some(GenGC::GroupAvatarChange(c)) => GroupChange::AvatarChanged {
                new_avatar_url: c.custom_avatar_url.clone().unwrap_or_default(),
                conversation_key_version: c.conversation_key_version.clone(),
            },
            Some(GenGC::GroupDescriptionChange(c)) => GroupChange::DescriptionChanged {
                new_description: text(&c.conversation_key_version, &c.custom_description),
            },
            Some(GenGC::GroupAdminAdd(c)) => GroupChange::AdminsAdded {
                admin_ids: c.admin_ids.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupAdminRemove(c)) => GroupChange::AdminsRemoved {
                admin_ids: c.admin_ids.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupMemberAdd(c)) => GroupChange::MembersAdded {
                member_ids: c.member_ids.clone().unwrap_or_default(),
                current_member_ids: c.current_member_ids.clone().unwrap_or_default(),
                current_admin_ids: c.current_admin_ids.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupMemberRemove(c)) => GroupChange::MembersRemoved {
                member_ids: c.member_ids.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupInviteEnable(c)) => GroupChange::InviteEnabled {
                invite_url: c.invite_url.clone().unwrap_or_default(),
                expires_at_msec: c.expires_at_msec,
            },
            Some(GenGC::GroupInviteDisable(c)) => GroupChange::InviteDisabled {
                disabled_by: c.disabled_by_member_id.clone(),
            },
            Some(GenGC::GroupJoinRequest(c)) => GroupChange::JoinRequested {
                user_id: c.requesting_user_id.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupJoinReject(c)) => GroupChange::JoinRejected {
                user_ids: c.rejected_user_ids.clone().unwrap_or_default(),
            },
            Some(GenGC::GroupAdminSettingsChange(_)) | None => GroupChange::Unknown,
        }
    }

    /// A group title or description as an event carries it: base64
    /// ciphertext under the conversation key for `conversation_key_version`,
    /// from the caller's key map or the opt-in key cache. A value an event
    /// carries without a key version is plaintext. A value whose key isn't
    /// available, or that doesn't decrypt under it, is `Unavailable` with the
    /// value as carried, and the rest of the event still decrypts.
    pub(super) fn group_text(
        &self,
        conversation_id: Option<&str>,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        conversation_key_version: Option<&str>,
        value: &str,
    ) -> GroupText {
        let version = match conversation_key_version.filter(|version| !version.is_empty()) {
            Some(version) if !value.is_empty() => version,
            _ => {
                return GroupText::Text {
                    text: value.to_string(),
                }
            }
        };
        let key = conversation_keys
            .get(version)
            .cloned()
            .or_else(|| conversation_id.and_then(|cid| self.cached_key_for(cid, version)));
        let text = key.and_then(|key| {
            let ciphertext = base64_decode(value).ok()?;
            String::from_utf8(decrypt_message_bytes(&key, &ciphertext).ok()?).ok()
        });
        match text {
            Some(text) => GroupText::Text { text },
            None => GroupText::Unavailable {
                raw: value.to_string(),
            },
        }
    }
}

/// Whether decrypt checks the signature of an event with this detail. A
/// message without a key version is unencrypted and carries no signature to
/// check.
fn has_checked_signature(detail: &MessageEventDetail) -> bool {
    match detail {
        MessageEventDetail::MessageCreateEvent(create) => {
            create.contents.is_some() && create.conversation_key_version.is_some()
        }
        MessageEventDetail::ConversationKeyChangeEvent(_)
        | MessageEventDetail::MarkConversationReadEvent(_)
        | MessageEventDetail::MarkConversationUnreadEvent(_)
        | MessageEventDetail::MessageDeleteEvent(_)
        | MessageEventDetail::ConversationDeleteEvent(_)
        | MessageEventDetail::GroupChangeEvent(_)
        | MessageEventDetail::ConversationMetadataChangeEvent(_) => true,
        _ => false,
    }
}

/// Whether key version `candidate` replaces `current` as the highest of a
/// batch: a numeric version replaces a lower or a non-numeric one, and a
/// non-numeric version is kept only while no other has been seen.
fn is_newer_key_version(current: Option<&str>, candidate: &str) -> bool {
    match (current, candidate.parse::<u64>()) {
        (None, _) => true,
        (Some(current), Ok(candidate)) => current
            .parse::<u64>()
            .map_or(true, |current| candidate > current),
        (Some(_), Err(_)) => false,
    }
}

/// A member removal re-encrypts the group's title and description under the
/// new key and marks them `for_key_rotation`: the same text, not a change,
/// so decrypt drops them. The flag is outside the signed payload, so a relay
/// that sets it gains nothing over withholding the event.
fn reject_key_rotation_reencryption(
    event: &crate::thrift::event::GroupChangeEvent,
) -> Result<(), SdkError> {
    use crate::thrift::event::GroupChange as GenGC;
    if event.for_key_rotation != Some(true) {
        return Ok(());
    }
    let field = match event.group_change {
        Some(GenGC::GroupTitleChange(_)) => "title",
        Some(GenGC::GroupDescriptionChange(_)) => "description",
        _ => return Ok(()),
    };
    Err(SdkError::InvalidInput(format!(
        "GroupChange re-encrypts the group's {field} for a key rotation (for_key_rotation), \
         not a {field} change: decrypt does not return it"
    )))
}
