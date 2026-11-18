//! Event decryption: the single-event and batch paths.

use super::*;

impl ChatCore {
    // Events

    /// Extract and decrypt conversation keys from a batch of raw event strings.
    ///
    /// Parses each event, attempts to decrypt participant keys using the loaded
    /// identity key, and returns a `ConversationKeyResult` with:
    /// - `keys`: Map of key version → conversation key
    /// - `latest_version`: The highest key version
    /// - `latest_versions`: Each conversation's highest key version
    ///
    /// Events that are not `KeyChange` events, or whose keys can't be decrypted
    /// by this identity key, are silently skipped.
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
    /// `latest_version` here is the highest version within this batch only,
    /// across every conversation the batch spans; `latest_versions` holds
    /// the highest per conversation.
    pub fn extract_conversation_keys(&self, events: &[&str]) -> ConversationKeyResult {
        if self.keypair_manager.get_identity_keypair().is_err() {
            return ConversationKeyResult {
                keys: HashMap::new(),
                latest_version: None,
                latest_versions: HashMap::new(),
            };
        }

        let mut result = HashMap::new();
        let mut latest_version: Option<String> = None;
        let mut latest_versions: HashMap<String, String> = HashMap::new();

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
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(ckey) = self.decrypt_key_change_ckey(kce) else {
                continue;
            };

            if is_newer_key_version(latest_version.as_deref(), &version) {
                latest_version = Some(version.clone());
            }
            if let Some(conversation_id) = parsed.conversation_id.as_deref() {
                let current = latest_versions.get(conversation_id).map(String::as_str);
                if is_newer_key_version(current, &version) {
                    latest_versions.insert(conversation_id.to_string(), version.clone());
                }
            }
            result.insert(version.clone(), ckey);
        }

        ConversationKeyResult {
            keys: result,
            latest_version,
            latest_versions,
        }
    }

    /// The key changes of a batch whose key this identity decrypted but
    /// whose signature does not verify, in batch order, each with why.
    /// `adopted` holds the keys [`Self::extract_conversation_keys`] took
    /// from the batch, and every entry's `key_dropped` is left `false` for
    /// the caller to set once signature enforcement has run.
    ///
    /// Each key change is checked against the key adopted for its version,
    /// as [`Self::enforce_ckey_signatures`] checks it, so an entry explains
    /// what enforcement does to that key. A key change signed below
    /// [`crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION`] signs a
    /// payload no recipient can rebuild, so it is unverifiable whichever
    /// signing keys are given.
    pub(super) fn unverified_key_changes(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        adopted: &HashMap<String, XChatConversationKey>,
    ) -> Vec<UnverifiedKeyChange> {
        let mut unverified = Vec::new();
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
            let Some(key) = adopted.get(&version) else {
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
                let sender_keys: Vec<SigningKeyEntry> = match parsed.sender_id.as_deref() {
                    Some(sid) => signing_keys
                        .iter()
                        .filter(|k| k.user_id == sid)
                        .cloned()
                        .collect(),
                    None => Vec::new(),
                };
                let check =
                    self.check_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64));
                match check {
                    SignatureCheck::Verified => continue,
                    SignatureCheck::MissingSigningKey => {
                        UnverifiedKeyChangeReason::MissingSigningKey
                    }
                    SignatureCheck::Mismatch(_) => UnverifiedKeyChangeReason::InvalidSignature,
                    SignatureCheck::Unsigned
                    | SignatureCheck::UnacceptedVersion(_)
                    | SignatureCheck::NoPayload => UnverifiedKeyChangeReason::Unverifiable,
                }
            };
            unverified.push(UnverifiedKeyChange {
                index,
                reason,
                key_dropped: false,
                conversation_id: parsed.conversation_id.clone(),
                conversation_key_version: version,
                sender_id: parsed.sender_id.clone(),
                public_key_version: signature_key_version(&parsed).map(str::to_string),
            });
        }
        unverified
    }

    /// Drop adopted conversation keys whose key change fails signature
    /// enforcement.
    ///
    /// A key change is rejected only when its sequence number is at or above
    /// the configured threshold, its signature version is missing or carries
    /// a verifiable plaintext-key payload, and its signature does not verify.
    /// Below the threshold, or for earlier signature versions whose payload
    /// cannot be reproduced, the key is left adopted. Does nothing while
    /// `floor` is at the maximum.
    pub(super) fn enforce_ckey_signatures(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        result: &mut ConversationKeyResult,
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
            // be verified, so it stays adopted; one without a version fails
            // verification below.
            if signature_version(&parsed)
                .is_some_and(|v| v < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION)
            {
                continue;
            }

            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Some(adopted) = result.keys.get(&version) else {
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
                result.keys.remove(&version);
            }
        }
    }

    /// Set the reported latest conversation-key versions to the newest one
    /// whose key change verified, per conversation and monotonically across
    /// this instance's lifetime.
    ///
    /// A malicious relay can replay an old, validly signed key change to make a
    /// caller encrypt under a stale key, or inject a key change it cannot sign.
    /// Recording the highest *verified* version per conversation and never
    /// reporting a lower or unverified one defeats both, while every adopted
    /// version stays available for decryption. Only signature versions
    /// carrying a reproducible plaintext-key payload can be verified, so a
    /// batch whose conversations have no verified key change reports no
    /// latest version.
    ///
    /// `latest_versions` takes each of the batch's conversations that has a
    /// verified version, and `latest_version` that version when there is one
    /// such conversation. A batch with more leaves `latest_version` unset
    /// rather than report the highest: it would be another conversation's
    /// key version for all but one of them.
    pub(super) fn apply_ckey_freshness(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
        result: &mut ConversationKeyResult,
    ) {
        let mut batch_conversations: Vec<String> = Vec::new();
        let mut verified_max: HashMap<String, u64> = HashMap::new();

        for event_b64 in events {
            let Ok(event_bytes) = base64_decode(event_b64) else {
                continue;
            };
            let Ok(parsed) = parse_message_event(&event_bytes) else {
                continue;
            };
            if let Some(conv_id) = parsed.conversation_id.as_deref() {
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
            let Some(conv_id) = parsed.conversation_id.as_deref() else {
                continue;
            };
            let version = kce.conversation_key_version.clone().unwrap_or_default();
            let Ok(version_num) = version.parse::<u64>() else {
                continue;
            };

            match signature_version(&parsed) {
                Some(v) if v >= crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION => {}
                _ => continue,
            }

            let Some(adopted) = result.keys.get(&version) else {
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
                let entry = verified_max.entry(conv_id.to_string()).or_insert(0);
                *entry = (*entry).max(version_num);
            }
        }

        {
            let mut high_water = self
                .conversation_key_high_water
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for (conv_id, version_num) in &verified_max {
                let entry = high_water.entry(conv_id.clone()).or_insert(0);
                if version_num > entry {
                    *entry = *version_num;
                }
            }
        }

        if self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
            // Cache only keys whose key change verified above, at the
            // conversation's high-water version — never a merely adopted key,
            // and never over a newer cached one.
            let high_water = self
                .conversation_key_high_water
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let mut cache = self
                .conversation_key_cache
                .write()
                .unwrap_or_else(|e| e.into_inner());
            // Re-check under the write lock: a concurrent set_cache_keys(false)
            // clears the cache, and inserting after that clear would leave a
            // populated cache while the feature is off.
            if self.cache_keys.load(std::sync::atomic::Ordering::Relaxed) {
                for (conv_id, version_num) in &verified_max {
                    if high_water.get(conv_id) != Some(version_num) {
                        continue;
                    }
                    let Some(key) = result.keys.get(&version_num.to_string()) else {
                        continue;
                    };
                    match cache.get(conv_id) {
                        Some(existing) if existing.version >= *version_num => {}
                        _ => {
                            cache.insert(
                                conv_id.clone(),
                                CachedConversationKey {
                                    version: *version_num,
                                    key: key.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        let high_water = self
            .conversation_key_high_water
            .read()
            .unwrap_or_else(|e| e.into_inner());
        result.latest_versions = batch_conversations
            .iter()
            .filter_map(|c| {
                high_water
                    .get(c)
                    .map(|version_num| (c.clone(), version_num.to_string()))
            })
            .collect();
        // One version can name the key to encrypt with only when it belongs
        // to one conversation: across several, the highest would name
        // another conversation's key for all but one of them.
        result.latest_version = match result.latest_versions.len() {
            1 => result.latest_versions.values().next().cloned(),
            _ => None,
        };
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
    /// * `conversation_keys` - Extracted conversation keys (for caching). Its
    ///   `latest_versions` holds, for each of the batch's conversations, the
    ///   newest version whose key change verified, held monotonic for this
    ///   instance's lifetime; `latest_version` is that version when one
    ///   conversation has one, and `None` until a key change verifies or
    ///   when several do. A key from a key change that did not verify never
    ///   becomes the latest; it still decrypts unless it was dropped.
    /// * `errors` - Map of event index → error message for the events left
    ///   out of `events`: those that failed, and those decrypt drops, as
    ///   [`Self::decrypt_event`] describes
    /// * `unverified_key_changes` - The key changes whose signature did not
    ///   verify, each with why (no signing key for its sender, an invalid
    ///   signature, or a signature the SDK cannot check), the sender and
    ///   signing-key version to fetch, and whether its key was dropped
    pub fn decrypt_events(&self, params: &DecryptEventsParams) -> DecryptEventsResult {
        let events: Vec<&str> = params.events.iter().map(String::as_str).collect();
        self.decrypt_events_with(&events, params.signing_keys.as_deref().unwrap_or_default())
    }

    /// [`Self::decrypt_events`] over borrowed inputs.
    pub(crate) fn decrypt_events_with(
        &self,
        events: &[&str],
        signing_keys: &[SigningKeyEntry],
    ) -> DecryptEventsResult {
        // An empty slice falls back to the keys stored via set_signing_keys.
        let signing_keys = self.resolve_signing_keys(signing_keys);
        // Verify signing key bindings — filter out keys with invalid
        // cross-signatures so they can't be used for verification.
        let verified_signing_keys: Vec<SigningKeyEntry> = signing_keys
            .iter()
            .filter(|k| {
                self.verify_key_binding(
                    &k.identity_public_key,
                    &k.public_key,
                    &k.identity_public_key_signature,
                )
                .unwrap_or(false)
            })
            .cloned()
            .collect();

        // First pass: extract conversation keys, note the key changes whose
        // signature does not verify, then drop the keys of those that fail
        // signature enforcement.
        let mut conv_keys_result = self.extract_conversation_keys(events);
        let mut unverified_key_changes =
            self.unverified_key_changes(events, &verified_signing_keys, &conv_keys_result.keys);
        self.enforce_ckey_signatures(
            events,
            &verified_signing_keys,
            &mut conv_keys_result,
            CKEY_SIG_V6_ENFORCE_AFTER_SEQ,
        );
        for change in &mut unverified_key_changes {
            change.key_dropped = !conv_keys_result
                .keys
                .contains_key(&change.conversation_key_version);
        }
        // Only a verified key change may set the reported latest version, and
        // a replayed older one cannot lower it.
        self.apply_ckey_freshness(events, &verified_signing_keys, &mut conv_keys_result);

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

            let sender_signing_keys: Vec<SigningKeyEntry> = match &parsed.sender_id {
                Some(sid) => verified_signing_keys
                    .iter()
                    .filter(|k| &k.user_id == sid)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };

            match self.decrypt_event_prefiltered(
                &parsed,
                &conv_keys_result.keys,
                &sender_signing_keys,
                &verified_signing_keys,
            ) {
                Ok(event) => {
                    decrypted.push(DecryptedEvent {
                        event,
                        original_b64: Some((*event_b64).to_string()),
                    });
                }
                Err(e) => {
                    let error = self
                        .dropped_key_error(
                            &parsed,
                            &e,
                            &conv_keys_result.keys,
                            &unverified_key_changes,
                        )
                        .unwrap_or(e);
                    errors.insert(idx, error.to_string());
                }
            }
        }

        DecryptEventsResult {
            events: decrypted,
            conversation_keys: conv_keys_result,
            errors,
            unverified_key_changes,
        }
    }

    /// The error of a message that found no conversation key because the
    /// batch's key change for its key version did not verify and had its
    /// key dropped: it names that key change and why it did not verify,
    /// where `error` only reports that no key was found. `None` for any
    /// other failure.
    fn dropped_key_error(
        &self,
        parsed: &MessageEvent,
        error: &SdkError,
        keys: &HashMap<String, XChatConversationKey>,
        unverified_key_changes: &[UnverifiedKeyChange],
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
        let change = unverified_key_changes.iter().find(|change| {
            change.key_dropped
                && change.conversation_key_version == version
                && change.conversation_id == parsed.conversation_id
        })?;
        let reason = match change.reason {
            UnverifiedKeyChangeReason::MissingSigningKey => format!(
                "{}; pass that user's public keys as signing keys and decrypt again",
                missing_signing_key(
                    change.sender_id.as_deref(),
                    change.public_key_version.as_deref()
                )
            ),
            UnverifiedKeyChangeReason::InvalidSignature => {
                "its signature does not verify against its sender's signing key".to_string()
            }
            UnverifiedKeyChangeReason::Unverifiable => {
                "it carries no signature this SDK can check".to_string()
            }
        };
        Some(SdkError::Crypto(CryptoError::DecryptionFailed(format!(
            "Message encrypted with key version '{}' but no matching key found: the key \
             change for that version, event {} of the batch, did not verify, so its key was \
             dropped: {}",
            version, change.index, reason
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
        let signing_keys = self.resolve_signing_keys(signing_keys);
        let parsed = Self::parse_event_b64(event_b64)?;
        let verified_signing_keys: Vec<SigningKeyEntry> = signing_keys
            .iter()
            .filter(|k| {
                self.verify_key_binding(
                    &k.identity_public_key,
                    &k.public_key,
                    &k.identity_public_key_signature,
                )
                .unwrap_or(false)
            })
            .cloned()
            .collect();
        let sender_signing_keys: Vec<SigningKeyEntry> = match &parsed.sender_id {
            Some(sid) => verified_signing_keys
                .iter()
                .filter(|k| &k.user_id == sid)
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        self.decrypt_event_prefiltered(
            &parsed,
            conversation_keys,
            &sender_signing_keys,
            &verified_signing_keys,
        )
    }

    /// [`Self::decrypt_event`] body for an already-parsed event and signing
    /// keys that are already binding-verified: `signing_keys` filtered to the
    /// event's sender, `all_signing_keys` unfiltered (reply-preview
    /// validation verifies raw events from other senders). The batch path
    /// does the binding verification once per batch instead of once per
    /// event.
    pub(super) fn decrypt_event_prefiltered(
        &self,
        parsed: &MessageEvent,
        conversation_keys: &HashMap<String, XChatConversationKey>,
        signing_keys: &[SigningKeyEntry],
        all_signing_keys: &[SigningKeyEntry],
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
                let ckey_b64 = conversation_keys
                    .get(ckey_version)
                    .map(|k| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(k.encoded())))
                    .or_else(|| {
                        self.decrypt_key_change_ckey(key_change)
                            .map(|k| zeroize::Zeroizing::new(STANDARD_NO_PAD.encode(k.encoded())))
                    });
                let check = self.check_event_signature(
                    parsed,
                    detail,
                    signing_keys,
                    ckey_b64.as_deref().map(String::as_str),
                );
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "KeyChange")?;
                if verified {
                    self.raise_key_change_signature_floor_for(parsed);
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
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
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
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
                let verified = check.is_verified();
                self.reject_if_unverified(&check, parsed, "MarkedUnread")?;
                Event::MarkedUnread(MarkedUnreadEvent {
                    meta,
                    verified,
                    seen_until_sequence_id: unread_event.seen_until_sequence_id.clone(),
                })
            }
            MessageEventDetail::MessageDeleteEvent(del_event) => {
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
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
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
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
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
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
                let check = self.check_event_signature(parsed, detail, signing_keys, None);
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
                    self.check_event_signature(parsed, detail, signing_keys, None)
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
                        self.validate_reply_preview(parsed, p, conversation_keys, all_signing_keys)
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
