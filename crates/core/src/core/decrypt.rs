//! Event decryption: the single-event and batch paths.

use super::*;

impl ChatCore {
    // Events

    /// Extract and decrypt conversation keys from a batch of raw event strings.
    ///
    /// Parses each event, attempts to decrypt participant keys using the loaded
    /// identity key, and returns a `ConversationKeyResult` with:
    /// - `keys`: Map of key version → conversation key
    /// - `latest_version`: The highest key version (for encryption)
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
    /// `latest_version` here is the highest version within this batch only.
    pub fn extract_conversation_keys(&self, events: &[&str]) -> ConversationKeyResult {
        if self.keypair_manager.get_identity_keypair().is_err() {
            return ConversationKeyResult {
                keys: HashMap::new(),
                latest_version: None,
            };
        }

        let mut result = HashMap::new();
        let mut latest_version: Option<String> = None;

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

            // Track the latest version (highest numeric value)
            let is_newer = match (&latest_version, version.parse::<u64>()) {
                (None, Ok(_)) => true,
                (Some(current), Ok(new_ver)) => {
                    current.parse::<u64>().map_or(true, |c| new_ver > c)
                }
                _ => latest_version.is_none(),
            };
            if is_newer {
                latest_version = Some(version.clone());
            }
            result.insert(version.clone(), ckey);
        }

        ConversationKeyResult {
            keys: result,
            latest_version,
        }
    }

    /// Drop adopted conversation keys whose key change fails signature
    /// enforcement.
    ///
    /// A key change is rejected only when its sequence number is at or above
    /// the configured threshold, its signature version carries a verifiable
    /// plaintext-key payload, and its signature does not verify. Below the
    /// threshold, or for earlier signature versions whose payload cannot be
    /// reproduced, the key is left adopted. Does nothing while `floor` is at
    /// the maximum.
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

            let sig_version = parsed
                .message_event_signature
                .as_ref()
                .and_then(|s| s.signature_version.as_deref())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);
            if sig_version < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION {
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
            let verified = matches!(
                self.verify_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64)),
                Ok(true)
            );
            if !verified {
                result.keys.remove(&version);
            }
        }
    }

    /// Set the reported latest conversation-key version to the newest one
    /// whose key change verified, monotonically across this instance's
    /// lifetime.
    ///
    /// A malicious relay can replay an old, validly signed key change to make a
    /// caller encrypt under a stale key, or inject a key change it cannot sign.
    /// Recording the highest *verified* version per conversation and never
    /// reporting a lower or unverified one defeats both, while every adopted
    /// version stays available for decryption. Only signature versions
    /// carrying a reproducible plaintext-key payload can be verified, so a
    /// batch whose conversations have no verified key change reports no
    /// latest version.
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

            let sig_version = parsed
                .message_event_signature
                .as_ref()
                .and_then(|s| s.signature_version.as_deref())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(crate::signatures::CURRENT_SIGNATURE_VERSION);
            if sig_version < crate::signatures::CKEY_PLAINTEXT_SIGNATURE_VERSION {
                continue;
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
            if matches!(
                self.verify_event_signature(&parsed, detail, &sender_keys, Some(&ckey_b64)),
                Ok(true)
            ) {
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
        result.latest_version = batch_conversations
            .iter()
            .filter_map(|c| high_water.get(c).copied())
            .max()
            .map(|version_num| version_num.to_string());
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
    /// [`Self::set_signing_keys`] when unset or empty.
    ///
    /// # Returns
    /// A `DecryptEventsResult` containing:
    /// * `events` - The events that decrypted, of every event type
    /// * `conversation_keys` - Extracted conversation keys (for caching). Its
    ///   `latest_version` is the newest version whose key change verified, for
    ///   the batch's conversations and held monotonic for this instance's
    ///   lifetime; `None` until a key change verifies. A key from a key change
    ///   that did not verify still decrypts but never becomes the latest.
    /// * `errors` - Map of event index → error message for failed decryptions
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

        // First pass: extract conversation keys, then drop any whose key
        // change fails signature enforcement (no-op while held at the max).
        let mut conv_keys_result = self.extract_conversation_keys(events);
        self.enforce_ckey_signatures(
            events,
            &verified_signing_keys,
            &mut conv_keys_result,
            CKEY_SIG_V6_ENFORCE_AFTER_SEQ,
        );
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
                    errors.insert(idx, e.to_string());
                }
            }
        }

        DecryptEventsResult {
            events: decrypted,
            conversation_keys: conv_keys_result,
            errors,
        }
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
                let sig_result = self.verify_event_signature(
                    parsed,
                    detail,
                    signing_keys,
                    ckey_b64.as_deref().map(String::as_str),
                );
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "KeyChange")?;
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
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "ReadReceipt")?;
                Event::ReadReceipt(ReadReceiptEvent {
                    meta,
                    verified,
                    seen_until_sequence_id: read_event.seen_until_sequence_id.clone(),
                    seen_at_msec: read_event.seen_at_millis,
                })
            }
            MessageEventDetail::MarkConversationUnreadEvent(unread_event) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "MarkedUnread")?;
                Event::MarkedUnread(MarkedUnreadEvent {
                    meta,
                    verified,
                    seen_until_sequence_id: unread_event.seen_until_sequence_id.clone(),
                })
            }
            MessageEventDetail::MessageDeleteEvent(del_event) => {
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "MessageDelete")?;
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
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "ConversationDelete")?;
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
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "GroupChange")?;
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
                let sig_result = self.verify_event_signature(parsed, detail, signing_keys, None);
                let verified = matches!(sig_result, Ok(true));
                self.reject_if_unverified(&sig_result, "SettingsChange")?;
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
                let (verified, sig_result) = if is_unencrypted {
                    (false, Ok(false))
                } else {
                    let r = self.verify_event_signature(parsed, detail, signing_keys, None);
                    let v = matches!(r, Ok(true));
                    (v, r)
                };

                self.reject_if_unverified(&sig_result, "Message")?;

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
