//! The `Chat` class.

use super::*;

/// The main Chat SDK interface.
///
/// Example:
/// ```python
/// chat = Chat(config_json)  # or Chat() then update_config(...)
/// chat.unlock(pin)
/// chat.set_identity(SetIdentityParams(my_user_id, signing_key_version))
///
/// # Decrypt webhook events
/// event = chat.decrypt_event(
///     DecryptEventParams(event_b64, conversation_keys, signing_keys=signing_keys)
/// )
/// if event["type"] == "Message":
///     print(event["content"]["text"])
///
/// # Encrypt outgoing messages
/// payload = chat.encrypt_message(
///     EncryptMessageParams(conversation_id, "Hello!",
///                          conversation_key=key, conversation_key_version=version)
/// )
/// ```
#[pyclass(subclass)]
pub struct Chat {
    pub(crate) inner: chat_xdk_core::Chat,
    pub(crate) runtime: tokio::runtime::Runtime,
}

impl Chat {
    pub(crate) fn create(config_json: Option<&str>) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        // An empty JSON object means no Juicebox config, same as None.
        // Anything else (including unparseable JSON) goes through the X API
        // config parser, which reports the malformed field.
        let inner = match config_json {
            Some(json) => match serde_json::from_str::<serde_json::Value>(json) {
                Ok(serde_json::Value::Object(m)) if m.is_empty() => chat_xdk_core::Chat::default(),
                _ => chat_xdk_core::Chat::new(parse_juicebox_config(json)?),
            },
            None => chat_xdk_core::Chat::default(),
        };

        Ok(Self { inner, runtime })
    }
}

#[pymethods]
impl Chat {
    /// Create a new Chat instance.
    ///
    /// Args:
    ///     config_json: Juicebox configuration JSON.
    ///         Pass ``None`` or an empty JSON object (e.g. ``"{}"``) for a
    ///         chat without one, which manages its keys with ``import_keys``
    ///         or takes its config later from ``update_config``; until then
    ///         ``setup``, ``unlock``, ``change_pin`` and ``delete`` raise
    ///         ``InvalidStateError``. An empty or blank string raises that
    ///         ``InvalidStateError`` here.
    #[new]
    #[pyo3(signature = (config_json=None))]
    pub(crate) fn new(py: Python<'_>, config_json: Option<&str>) -> PyResult<Self> {
        let chat = Self::create(config_json)?;
        start_feature_read(py, &chat.inner);
        Ok(chat)
    }

    /// For this repository's tests: a chat that reads its feature switches
    /// from ``endpoint``, within ``timeout`` seconds, again ``refresh``
    /// seconds after each answer.
    #[staticmethod]
    #[pyo3(
        name = "_reading_features_from",
        signature = (endpoint, timeout, refresh=300.0, config_json=None)
    )]
    pub(crate) fn reading_features_from(
        py: Python<'_>,
        endpoint: &str,
        timeout: f64,
        refresh: f64,
        config_json: Option<&str>,
    ) -> PyResult<Self> {
        let chat = Self::create(config_json)?;
        chat.inner.configure_features(
            endpoint,
            (timeout * 1000.0) as u64,
            (refresh * 1000.0) as u64,
        );
        start_feature_read(py, &chat.inner);
        Ok(chat)
    }

    /// Set or replace the Juicebox configuration: on first boot, for a chat
    /// created without one, or to refresh its auth tokens.
    pub(crate) fn update_config(&self, config_json: &str) -> PyResult<()> {
        let config = parse_juicebox_config(config_json)?;
        self.inner.update_config(config);
        Ok(())
    }

    /// Returns True when both identity and signing keys are loaded.
    pub(crate) fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Returns True when the identity key is loaded (sufficient for decryption).
    pub(crate) fn has_identity_key(&self) -> bool {
        self.inner.has_identity_key()
    }

    /// When enabled — the default — `decrypt_event` raises for any signed
    /// event whose signature cannot be verified (invalid, missing, or no
    /// matching signing key) instead of returning it with `verified: false`.
    pub(crate) fn set_reject_unverified(&self, reject: bool) {
        self.inner.set_reject_unverified(reject);
    }

    /// Set the session identity: your user id and registered signing-key
    /// version, used as the defaults wherever a params ``sender_id`` /
    /// ``signing_key_version`` is ``None``. A resolved default and an
    /// explicitly passed value produce identical signed output. The
    /// signing-key version is the ``public_key_version`` returned when your
    /// keys were registered. The chat then reads its feature switches for
    /// this sender's bucket, the last four digits of the user id.
    pub(crate) fn set_identity(
        &self,
        py: Python<'_>,
        params: PyRef<'_, SetIdentityParams>,
    ) -> PyResult<()> {
        self.inner
            .set_identity(&chat_xdk_core::SetIdentityParams::new(
                params.user_id.as_str(),
                params.signing_key_version.as_str(),
            ))
            .map_err(to_py_err)?;
        start_feature_read(py, &self.inner);
        Ok(())
    }

    /// Enable or disable the conversation-key cache (off by default).
    ///
    /// While enabled, the cache keeps, per conversation, the key of every
    /// key change whose signature verified in ``decrypt_events`` or
    /// ``decrypt_event``, and the key of every key change this chat prepared
    /// (a conversation-key change, a group create, a member add or a member
    /// removal). A call that leaves its conversation key ``None`` reads it
    /// from there: the encrypt methods and the title, description and avatar
    /// changes use the conversation's newest key, and the decrypt methods
    /// the key at the version the event names. Disabling clears the cache.
    ///
    /// A prepared key is cached when the prepare call returns, before its
    /// request is sent. If the X API rejects the request, no one else holds
    /// that key: prepare the change again, or pass the key to encrypt with
    /// explicitly, until a newer key change verifies.
    pub(crate) fn set_cache_keys(&self, enabled: bool) {
        self.inner.set_cache_keys(enabled);
    }

    /// Store signing keys to use when a decrypt call's ``signing_keys`` is
    /// ``None`` or empty.
    ///
    /// Args:
    ///     signing_keys: Same list of dicts ``DecryptEventsParams`` takes.
    ///         Each call replaces the previous set; ``add_signing_keys``
    ///         and ``add_public_keys`` keep it. Only these three calls
    ///         populate the store — keys carried inside events are never
    ///         trusted.
    pub(crate) fn set_signing_keys(&self, py: Python<'_>, signing_keys: Py<PyAny>) -> PyResult<()> {
        let entries: Vec<SigningKeyEntry> = json_field(py, &signing_keys, "signing_keys")?;
        self.inner.set_signing_keys(&entries);
        Ok(())
    }

    /// Add signing keys to the set ``set_signing_keys`` stores, keeping the
    /// keys it holds.
    ///
    /// Args:
    ///     signing_keys: Same list of dicts ``set_signing_keys`` takes. An
    ///         entry replaces the stored entry of the same ``user_id`` and
    ///         ``public_key_version``, and any other is added.
    pub(crate) fn add_signing_keys(&self, py: Python<'_>, signing_keys: Py<PyAny>) -> PyResult<()> {
        let entries: Vec<SigningKeyEntry> = json_field(py, &signing_keys, "signing_keys")?;
        self.inner.add_signing_keys(&entries);
        Ok(())
    }

    /// Add users' public keys to the stored signing keys, as
    /// ``add_signing_keys`` adds entries.
    ///
    /// The decrypt calls verify with the stored keys when their
    /// ``signing_keys`` is ``None`` or empty, and the four prepare calls
    /// that encrypt a new conversation key (a conversation-key change, a
    /// group create, a member add and a member removal) read their members'
    /// identity keys from them when their ``public_keys`` is ``None`` or
    /// empty.
    ///
    /// Args:
    ///     records: Dict from user id to the list of records
    ///         ``GET /2/users/{id}/public_keys`` returns in ``data`` for
    ///         that user, each a dict with ``public_key_version``,
    ///         ``public_key``, ``signing_public_key`` and
    ///         ``identity_public_key_signature``. A record is read as the X
    ///         API sends it: ``public_key_version`` may be a ``str`` or an
    ///         ``int``, and any other key, such as ``juicebox_config``, is
    ///         ignored. A record without a key version, an identity key or
    ///         a signing key is left out. ``None`` adds nothing.
    pub(crate) fn add_public_keys(&self, py: Python<'_>, records: Py<PyAny>) -> PyResult<()> {
        let records: Option<HashMap<String, Vec<chat_xdk_core::PublicKeyRecord>>> =
            json_field(py, &records, "records")?;
        if let Some(records) = records {
            self.inner.add_public_keys(&records);
        }
        Ok(())
    }

    /// The users whose public keys a ``decrypt_events`` result was missing.
    ///
    /// Fetch their keys (``GET /2/users/{id}/public_keys``), add them with
    /// ``add_public_keys``, and decrypt the batch again.
    ///
    /// A key this call returned a user for is not asked for again for a
    /// minute, so a lookup that brought no key is not repeated with every
    /// batch. A key that arrives is no longer missing, and a key version
    /// not asked for before is asked for at once.
    ///
    /// Args:
    ///     result: The dict ``decrypt_events`` returned, or its
    ///         ``missing_signing_keys`` dict.
    ///
    /// Returns:
    ///     list[str]: The user ids, each once, in batch order.
    pub(crate) fn missing_public_keys(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<String>> {
        // Only the result's missing keys cross into the core: a result also
        // holds conversation keys as bytes, which JSON cannot carry.
        let from_result = match result.cast::<pyo3::types::PyDict>() {
            Ok(result) => result.get_item("missing_signing_keys")?,
            Err(_) => None,
        };
        let missing = from_result.unwrap_or_else(|| result.clone()).unbind();
        let missing: Option<HashMap<String, chat_xdk_core::MissingSigningKey>> =
            json_field(py, &missing, "missing_signing_keys")?;
        let missing = bindings::missing_signing_keys_in_order(missing.unwrap_or_default());
        Ok(self.inner.missing_public_keys_among(&missing))
    }

    /// The users whose public keys the prepare call ``call`` would be
    /// missing with ``params``: the members it encrypts its key to who have
    /// no stored public key. Empty when ``params`` passes ``public_keys``.
    ///
    /// The prepare methods of ``chat_xdk.Chat`` call this before they run
    /// the hook ``set_resolve_public_keys`` set. ``call`` is the prepare
    /// method's name without ``prepare_``.
    #[pyo3(name = "_missing_public_keys_for")]
    pub(crate) fn missing_public_keys_for(
        &self,
        py: Python<'_>,
        call: &str,
        params: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<String>> {
        Ok(match call {
            "conversation_key_change" => {
                let params: PyRef<'_, ConversationKeyChangeParams> = params.extract()?;
                let params = params.to_core(py)?;
                self.inner
                    .missing_public_keys_for(KeyChangeCall::ConversationKeyChange(&params))
            }
            "group_create" => {
                let params: PyRef<'_, GroupCreateParams> = params.extract()?;
                let params = params.to_core(py)?;
                self.inner
                    .missing_public_keys_for(KeyChangeCall::GroupCreate(&params))
            }
            "group_members_change" => {
                let params: PyRef<'_, GroupMembersChangeParams> = params.extract()?;
                let params = params.to_core(py)?;
                self.inner
                    .missing_public_keys_for(KeyChangeCall::GroupMembersChange(&params))
            }
            "group_members_remove" => {
                let params: PyRef<'_, GroupMembersRemoveParams> = params.extract()?;
                let params = params.to_core(py)?;
                self.inner
                    .missing_public_keys_for(KeyChangeCall::GroupMembersRemove(&params))
            }
            other => {
                return Err(invalid_input(format!(
                    "Unknown prepare call {other:?}: expected conversation_key_change, \
                     group_create, group_members_change or group_members_remove"
                )))
            }
        })
    }

    /// Lock the SDK, clearing keys from memory.
    pub(crate) fn lock(&self) {
        self.inner.lock()
    }

    /// Delete keys from Juicebox and clear from memory.
    ///
    /// Warning: This is irreversible. The user will lose access to their encrypted messages.
    pub(crate) fn delete(&self, py: Python<'_>) -> PyResult<()> {
        // Release the GIL for the Juicebox round trips so other Python
        // threads keep running; no Python objects cross into the closure.
        py.detach(|| self.runtime.block_on(self.inner.delete()))
            .map_err(to_py_err)
    }

    /// Register existing keys with Juicebox.
    ///
    /// Args:
    ///     pin: The user's PIN for key protection (str, bytes, or bytearray;
    ///         a bytearray can be zeroed by the caller afterwards).
    ///
    /// Returns:
    ///     PublicKeys with identity and signing keys.
    pub(crate) fn setup(&self, py: Python<'_>, pin: &Bound<'_, PyAny>) -> PyResult<PublicKeys> {
        let pin = extract_pin(pin)?;
        // Release the GIL for the Juicebox round trips so other Python
        // threads keep running; no Python objects cross into the closure.
        let keys = py
            .detach(|| self.runtime.block_on(self.inner.setup(&pin)))
            .map_err(to_py_err)?;

        Ok(PublicKeys {
            identity: keys.identity,
            signing: keys.signing,
        })
    }

    /// Unlock the SDK by recovering keys from Juicebox.
    ///
    /// Args:
    ///     pin: The user's PIN (str, bytes, or bytearray; a bytearray can be
    ///         zeroed by the caller afterwards).
    pub(crate) fn unlock(&self, py: Python<'_>, pin: &Bound<'_, PyAny>) -> PyResult<()> {
        let pin = extract_pin(pin)?;
        // Release the GIL for the Juicebox round trips so other Python
        // threads keep running; no Python objects cross into the closure.
        py.detach(|| self.runtime.block_on(self.inner.unlock(&pin)))
            .map_err(to_py_err)
    }

    /// Re-register keys with a new PIN.
    ///
    /// Args:
    ///     old_pin: The current PIN (str, bytes, or bytearray).
    ///     new_pin: The new PIN to set (str, bytes, or bytearray).
    pub(crate) fn change_pin(
        &self,
        py: Python<'_>,
        old_pin: &Bound<'_, PyAny>,
        new_pin: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let old_pin = extract_pin(old_pin)?;
        let new_pin = extract_pin(new_pin)?;
        // Release the GIL for the Juicebox round trips so other Python
        // threads keep running; no Python objects cross into the closure.
        py.detach(|| {
            self.runtime
                .block_on(self.inner.change_pin(&old_pin, &new_pin))
        })
        .map_err(to_py_err)
    }

    /// Generate new keypairs and return the registration payload.
    ///
    /// No signing-key version is set: after registering the keys, call
    /// ``set_identity`` with the ``public_key_version`` the registration
    /// returns.
    ///
    /// Returns:
    ///     PublicKeyRegistrationPayload for the X API.
    pub(crate) fn generate_keypairs(&self) -> PyResult<PublicKeyRegistrationPayload> {
        let payload = self.inner.generate_keypairs().map_err(to_py_err)?;
        Ok(PublicKeyRegistrationPayload {
            public_key: PublicKeyRegistration {
                identity_public_key_signature: payload.public_key.identity_public_key_signature,
                public_key: payload.public_key.public_key,
                public_key_fingerprint: payload.public_key.public_key_fingerprint,
                registration_method: payload.public_key.registration_method,
                signing_public_key: payload.public_key.signing_public_key,
                signing_public_key_signature: payload.public_key.signing_public_key_signature,
            },
        })
    }

    /// Get the user's public keys.
    pub(crate) fn get_public_keys(&self) -> PyResult<PublicKeys> {
        let keys = self.inner.get_public_keys().map_err(to_py_err)?;
        Ok(PublicKeys {
            identity: keys.identity,
            signing: keys.signing,
        })
    }

    /// Get the fingerprint of the loaded identity public key.
    ///
    /// Returns a URL-safe base64 string (SHA-256 of the SPKI-encoded key)
    /// that users can compare out-of-band to verify key authenticity.
    pub(crate) fn get_public_key_fingerprint(&self) -> PyResult<String> {
        self.inner.get_public_key_fingerprint().map_err(to_py_err)
    }

    /// Extract and decrypt conversation keys from raw KeyChange event strings.
    ///
    /// Args:
    ///     events: List of base64-encoded raw event strings (from webhook).
    ///
    /// Returns:
    ///     A dict with:
    ///     - ``keys``: Dict mapping key version string to raw 32-byte
    ///       conversation key (``bytes``); a version that key changes of more
    ///       than one conversation carry is left out
    ///     - ``keys_by_conversation``: Dict mapping each conversation id to
    ///       that conversation's ``keys``
    ///     - ``latest_version``: The highest key version when every event
    ///       belongs to one conversation, ``None`` when they belong to more
    ///       than one; signatures are not checked
    ///     - ``latest_versions``: Dict mapping each conversation id to its
    ///       highest key version; signatures are not checked
    pub(crate) fn extract_conversation_keys(&self, events: Vec<String>) -> PyResult<Py<PyAny>> {
        let refs: Vec<&str> = events.iter().map(|s| s.as_str()).collect();
        let result = self.inner.extract_conversation_keys(&refs);
        Python::attach(|py| Ok(conversation_keys_dict(py, result)?.into()))
    }

    /// Decrypt multiple events in batch.
    ///
    /// This is the recommended API for decrypting events. It:
    /// 1. Extracts conversation keys from any KeyChange events
    /// 2. For each event, finds the correct signing key by matching user_id + version
    /// 3. Decrypts the event using the appropriate conversation key
    ///
    /// Args:
    ///     params: A ``DecryptEventsParams``: the events, and the signing keys of
    ///         all participants, the members who signed the batch's key
    ///         changes included. The SDK matches keys by user_id and version
    ///         and verifies each key's identity binding. With
    ///         ``signing_keys`` ``None`` or empty, the stored keys
    ///         (``set_signing_keys``, ``add_signing_keys``,
    ///         ``add_public_keys``) are used.
    ///
    /// With a hook set (``set_resolve_public_keys``) and no signing keys
    /// passed, ``chat_xdk.Chat.decrypt_events`` calls the hook for
    /// ``missing_public_keys`` of the result, adds the records it returns
    /// with ``add_public_keys``, and returns the result of decrypting the
    /// batch once more. An exception the hook raises reaches the caller.
    ///
    /// Returns:
    ///     A dict with:
    ///     - ``events``: List of ``{"event": dict, "original_b64": str}``, one
    ///       per event that decrypted, of every event type
    ///     - ``conversation_keys``: ``{"keys": dict, "keys_by_conversation":
    ///       dict, "latest_version": str, "latest_versions": dict}``;
    ///       ``keys_by_conversation`` maps each conversation id to that
    ///       conversation's ``keys``, ``latest_versions`` maps each of the
    ///       batch's conversations to the newest version whose key change
    ///       verified, and ``latest_version`` is that version when every
    ///       event of the batch belongs to one conversation: ``None`` until
    ///       one verifies, and ``None`` for a batch of more than one
    ///       conversation
    ///     - ``errors``: Dict mapping event index (string, e.g. ``"0"``) to error
    ///       message, for each event left out of ``events``: one that failed,
    ///       or one decrypt drops, such as a member removal's title or
    ///       description re-encrypted under the new key
    ///     - ``unverified_key_changes``: Dict mapping event index (string) to
    ///       the key change there, for each key change whose signature did
    ///       not verify: a dict with ``reason`` (``"MissingSigningKey"``,
    ///       ``"RejectedSigningKey"``, ``"InvalidSignature"`` or
    ///       ``"Unverifiable"``), ``key_dropped``, ``conversation_id``,
    ///       ``conversation_key_version``, ``sender_id`` and
    ///       ``public_key_version``
    ///     - ``undecryptable_key_changes``: Dict mapping event index (string)
    ///       to the key change there, for each key change whose conversation
    ///       key this identity could not decrypt: a dict with ``reason``
    ///       (``"Locked"``, ``"NotARecipient"``, ``"OtherKeyVersion"`` or
    ///       ``"DecryptionFailed"``), ``conversation_id``,
    ///       ``conversation_key_version`` and ``sender_id``
    ///     - ``rejected_signing_keys``: Dict mapping signing key index
    ///       (string) to the signing key there, for each one left out
    ///       because its identity binding does not verify: a dict with
    ///       ``user_id`` and ``public_key_version``
    ///     - ``missing_signing_keys``: Dict mapping event index (string) to
    ///       the signing key the event there names, for each signed event
    ///       whose sender's signing key was not among the keys the call
    ///       verified with: a dict with ``user_id``, the sender, and
    ///       ``public_key_version``, the key version the event's signature
    ///       names. ``missing_public_keys`` reads the users to fetch keys
    ///       for from it
    pub(crate) fn decrypt_events(
        &self,
        py: Python<'_>,
        params: PyRef<'_, DecryptEventsParams>,
    ) -> PyResult<Py<PyAny>> {
        let params = params.to_core(py)?;
        // Release the GIL for the batch crypto so other Python threads keep
        // running; only Rust data crosses into the closure.
        let result = py.detach(|| self.inner.decrypt_events(&params));

        let outer = pyo3::types::PyDict::new(py);

        let events = pyo3::types::PyList::empty(py);
        let json_module = py.import("json")?;
        for decrypted in result.events {
            let entry = pyo3::types::PyDict::new(py);
            let event_json = serde_json::to_string(&decrypted.event).map_err(internal_err)?;
            let event_dict = json_module.call_method1("loads", (event_json,))?;
            entry.set_item("event", event_dict)?;
            if let Some(b64) = decrypted.original_b64 {
                entry.set_item("original_b64", b64)?;
            }
            events.append(entry)?;
        }
        outer.set_item("events", events)?;

        outer.set_item(
            "conversation_keys",
            conversation_keys_dict(py, result.conversation_keys)?,
        )?;

        // Convert errors; keys are the stringified event indices.
        let errors_dict = pyo3::types::PyDict::new(py);
        for (idx, err) in result.errors {
            errors_dict.set_item(idx.to_string(), err)?;
        }
        outer.set_item("errors", errors_dict)?;

        // Each is a dict keyed by the stringified index, as `errors` is.
        for (name, json) in [
            (
                "unverified_key_changes",
                serde_json::to_string(&result.unverified_key_changes),
            ),
            (
                "undecryptable_key_changes",
                serde_json::to_string(&result.undecryptable_key_changes),
            ),
            (
                "rejected_signing_keys",
                serde_json::to_string(&result.rejected_signing_keys),
            ),
            (
                "missing_signing_keys",
                serde_json::to_string(&result.missing_signing_keys),
            ),
        ] {
            let json = json.map_err(internal_err)?;
            outer.set_item(name, json_module.call_method1("loads", (json,))?)?;
        }

        Ok(outer.into())
    }

    /// Decrypt a raw webhook event payload.
    ///
    /// A key change that verifies is recorded as ``decrypt_events`` records
    /// it: its version is the conversation's newest verified one unless a
    /// newer is known, and while the key cache is on (``set_cache_keys``)
    /// its key is cached.
    ///
    /// Args:
    ///     params: A ``DecryptEventParams``: the event, the conversation's key
    ///         map, and the signing keys. The SDK picks the sender's key for
    ///         the version the event carries. Under the default
    ///         reject-unverified policy no usable signing key makes every
    ///         signed event raise; only after ``set_reject_unverified(False)``
    ///         are such events returned with ``verified: False``.
    ///
    /// Returns:
    ///     A dictionary representing the decrypted event.
    ///
    /// Raises:
    ///     InvalidInputError: for a member removal's title or description
    ///         re-encrypted under the new key. It isn't a change, so decrypt
    ///         drops it; ``decrypt_events`` records it in ``errors``.
    pub(crate) fn decrypt_event(
        &self,
        py: Python<'_>,
        params: PyRef<'_, DecryptEventParams>,
    ) -> PyResult<Py<PyAny>> {
        let event = self
            .inner
            .decrypt_event(&params.to_core(py)?)
            .map_err(to_py_err)?;
        let json_str = serde_json::to_string(&event).map_err(internal_err)?;
        let dict = py.import("json")?.call_method1("loads", (json_str,))?;
        Ok(dict.into())
    }

    /// Encrypt a message for the X API.
    ///
    /// The message id comes back in ``payload.message_id``. A v1 message
    /// with files takes an id derived from its files, so building it again
    /// gives the same id; other messages take a random id. Encrypt each file
    /// afterwards with ``encrypt_file`` or ``file_encryptor`` and
    /// ``payload.event_b64``.
    ///
    /// Args:
    ///     params: An ``EncryptMessageParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_message(
        &self,
        py: Python<'_>,
        params: PyRef<'_, EncryptMessageParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_message(&params.to_core(py)?)
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Encrypt a forward of an existing message for the X API.
    ///
    /// The forward is a new message carrying the original's full text and
    /// entities, an optional comment, and the original's attachments
    /// uploaded again to this conversation. Its id and files work as for
    /// ``encrypt_message``.
    ///
    /// Args:
    ///     params: An ``EncryptForwardParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_forward(
        &self,
        py: Python<'_>,
        params: PyRef<'_, EncryptForwardParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_forward(&params.to_core(py)?)
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Encrypt a reply message for the X API.
    /// Encrypt a reply message for the X API.
    ///
    /// Like ``encrypt_message`` but populates the replying_to_preview so the
    /// receiving client renders it as a reply to an existing message. The
    /// reply's id and files work as in ``encrypt_message``.
    ///
    /// Args:
    ///     params: An ``EncryptReplyParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_reply(
        &self,
        py: Python<'_>,
        params: PyRef<'_, EncryptReplyParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_reply(&params.to_core(py)?)
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Encrypt a reaction-add for the X API.
    ///
    /// The SDK generates the message id and returns it in the payload; read it
    /// back from ``payload.message_id``.
    ///
    /// Args:
    ///     params: An ``EncryptReactionParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_add_reaction(
        &self,
        params: PyRef<'_, EncryptReactionParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_add_reaction(&params.to_core())
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Encrypt a reaction-remove for the X API.
    ///
    /// Takes the same params as ``encrypt_add_reaction`` — pass the same
    /// values to remove a previously added reaction.
    ///
    /// Args:
    ///     params: An ``EncryptReactionParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_remove_reaction(
        &self,
        params: PyRef<'_, EncryptReactionParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_remove_reaction(&params.to_core())
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Encrypt a message edit for the X API.
    ///
    /// The SDK generates the message id and returns it in the payload; read it
    /// back from ``payload.message_id``.
    ///
    /// Args:
    ///     params: An ``EncryptEditParams``.
    ///
    /// Returns:
    ///     The ``SendPayload`` to send to the X API.
    pub(crate) fn encrypt_edit(
        &self,
        py: Python<'_>,
        params: PyRef<'_, EncryptEditParams>,
    ) -> PyResult<SendPayload> {
        let payload = self
            .inner
            .encrypt_edit(&params.to_core(py)?)
            .map_err(to_py_err)?;
        Ok(to_py_send_payload(payload))
    }

    /// Decrypt an encrypted conversation key (ECIES).
    ///
    /// Call this once per key version, then pass the result to ``decrypt_event()``.
    ///
    /// Args:
    ///     encrypted_key_b64: Base64-encoded **encrypted** key from KeyChange event.
    ///
    /// Returns:
    ///     Raw 32-byte decrypted conversation key as ``bytes``.
    pub(crate) fn decrypt_conversation_key<'py>(
        &self,
        py: Python<'py>,
        encrypted_key_b64: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let ckey = self
            .inner
            .decrypt_conversation_key(encrypted_key_b64)
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, ckey.encoded()))
    }

    /// Encrypt a file of an outgoing message, after the message is built.
    ///
    /// The SDK finds the attachment that names ``params.media_hash_key`` in
    /// the message ``params.event_b64`` carries, and encrypts the file under
    /// that attachment's key. Upload the result under the same media hash
    /// key; its size is ``encrypted_file_size(len(file))``.
    ///
    /// Args:
    ///     params: An ``EncryptFileParams``.
    ///
    /// Returns:
    ///     Encrypted bytes.
    ///
    /// Raises:
    ///     ValueError: The event is not a message with this file, or the
    ///         conversation key is not the one the message was encrypted
    ///         under. The message says what to pass instead.
    pub(crate) fn encrypt_file<'py>(
        &self,
        py: Python<'py>,
        params: PyRef<'_, EncryptFileParams>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let params = params.to_core();
        // Release the GIL for the file crypto; only Rust data crosses into
        // the closure.
        let output = py
            .detach(|| self.inner.encrypt_file(&params))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Create an incremental encryptor for a file too large to hold in
    /// memory. Takes the params of ``encrypt_file`` apart from the file,
    /// which is fed to the encryptor.
    pub(crate) fn file_encryptor(
        &self,
        params: PyRef<'_, FileEncryptorParams>,
    ) -> PyResult<FileEncryptor> {
        let inner = self
            .inner
            .file_encryptor(&params.to_core())
            .map_err(to_py_err)?;
        Ok(FileEncryptor { inner: Some(inner) })
    }

    /// Decrypt an encrypted file, as downloaded.
    ///
    /// Args:
    ///     params: A ``DecryptFileParams``. With its ``conversation_keys``
    ///         left ``None`` or empty, the keys of the message's
    ///         conversation come from the key cache (``set_cache_keys``).
    ///
    /// Returns:
    ///     Decrypted bytes.
    ///
    /// Raises:
    ///     ValueError: The key version is missing, the event is not an encrypted
    ///         message with this file, or ``encrypted`` is not the file's
    ///         complete encrypted bytes. The message says what to pass instead.
    pub(crate) fn decrypt_file<'py>(
        &self,
        py: Python<'py>,
        params: PyRef<'_, DecryptFileParams>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let params = params.to_core(py)?;
        // Release the GIL for the file crypto; only Rust data crosses into
        // the closure.
        let output = py
            .detach(|| self.inner.decrypt_file(&params))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Create an incremental decryptor for an encrypted file too large to
    /// hold in memory. Takes the params of ``decrypt_file`` apart from the
    /// encrypted bytes, which are fed to the decryptor; a key map left
    /// ``None`` or empty reads the key cache as it does there.
    pub(crate) fn file_decryptor(
        &self,
        py: Python<'_>,
        params: PyRef<'_, FileDecryptorParams>,
    ) -> PyResult<FileDecryptor> {
        let inner = self
            .inner
            .file_decryptor(&params.to_core(py)?)
            .map_err(to_py_err)?;
        Ok(FileDecryptor { inner: Some(inner) })
    }

    /// Encrypt a file under a key you already hold, rather than from a
    /// message: a group's avatar image under the conversation key whose
    /// version is signed next to the avatar URL, or an app's own files at
    /// rest. The file is encrypted under the key itself, in the format
    /// ``encrypt_file`` writes; its size is ``encrypted_file_size(len(file))``.
    ///
    /// Args:
    ///     params: An ``EncryptFileWithKeyParams``.
    ///
    /// Returns:
    ///     Encrypted bytes.
    ///
    /// Raises:
    ///     InvalidInputError: The key is not 32 bytes.
    pub(crate) fn encrypt_file_with_key<'py>(
        &self,
        py: Python<'py>,
        params: PyRef<'_, EncryptFileWithKeyParams>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let params = params.to_core();
        // Release the GIL for the file crypto; only Rust data crosses into
        // the closure.
        let output = py
            .detach(|| self.inner.encrypt_file_with_key(&params))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Decrypt a file encrypted under a key you already hold, as downloaded,
    /// such as a group's avatar image under the conversation key for the
    /// version its avatar change names.
    ///
    /// Args:
    ///     params: A ``DecryptFileWithKeyParams``.
    ///
    /// Returns:
    ///     Decrypted bytes.
    ///
    /// Raises:
    ///     InvalidInputError: The key is not 32 bytes.
    ///     DecryptionError: ``encrypted`` is not the complete file encrypted
    ///         under the key.
    pub(crate) fn decrypt_file_with_key<'py>(
        &self,
        py: Python<'py>,
        params: PyRef<'_, DecryptFileWithKeyParams>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let params = params.to_core();
        // Release the GIL for the file crypto; only Rust data crosses into
        // the closure.
        let output = py
            .detach(|| self.inner.decrypt_file_with_key(&params))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Decrypt a group title or description the X API returns for a
    /// conversation. Group changes in events need no call of their own:
    /// ``decrypt_event`` returns them decrypted.
    ///
    /// Args:
    ///     ciphertext_b64: Base64-encoded ciphertext (``str``).
    ///     conversation_key: Raw 32-byte conversation key (``bytes``).
    ///
    /// Returns:
    ///     Decrypted UTF-8 string (``str``).
    pub(crate) fn decrypt(
        &self,
        ciphertext_b64: &str,
        conversation_key: &[u8],
    ) -> PyResult<String> {
        let ckey = bindings::conversation_key(conversation_key).map_err(to_py_err)?;
        self.inner.decrypt(ciphertext_b64, &ckey).map_err(to_py_err)
    }

    /// Prepare a signed conversation-key change, ready to send to the X API.
    ///
    /// Use this to start a one-to-one or rotate an existing conversation's key
    /// (one-to-one or group). Creating a group or adding members requires a
    /// paired group signature as well — use ``prepare_group_create`` or
    /// ``prepare_group_members_change`` for those.
    ///
    /// Generates a fresh conversation key, encrypts it for every participant,
    /// and signs the change. Leave ``conversation_id`` ``None`` for a
    /// one-to-one (it is derived from the two participants); pass the
    /// existing id for a group key rotation.
    ///
    /// While the key cache is on (``set_cache_keys``) the call caches the
    /// new key as the conversation's newest key, as every prepare call that
    /// makes a conversation key does.
    ///
    /// With ``public_keys`` ``None`` or empty, the key is encrypted to the
    /// stored public keys (``add_public_keys``) of the params'
    /// ``member_ids``, or, without ``member_ids``, of the two users of the
    /// one-to-one conversation ``conversation_id`` names. A user with no
    /// stored key raises ``InvalidInputError`` naming the user. With a hook
    /// set (``set_resolve_public_keys``), ``chat_xdk.Chat`` first fetches
    /// the keys of the users who have none through it.
    ///
    /// Args:
    ///     params: A ``ConversationKeyChangeParams``.
    ///
    /// Returns:
    ///     A dict with ``conversation_id``, ``conversation_key`` (bytes),
    ///     ``conversation_key_version``, ``conversation_participant_keys``, ``action_signatures``.
    pub(crate) fn prepare_conversation_key_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, ConversationKeyChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let result = self
            .inner
            .prepare_conversation_key_change(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_change_to_pydict(py, &result)
    }

    /// Prepare a signed group member-add change, ready to send to the X API.
    ///
    /// Use this when adding members to an existing group. Creating the group
    /// is ``prepare_group_create``; a key rotation without a roster change is
    /// ``prepare_conversation_key_change``. While the key cache is on
    /// (``set_cache_keys``) the call caches the new key as the conversation's
    /// newest key.
    ///
    /// With ``public_keys`` ``None`` or empty, the key is encrypted to the
    /// stored public keys (``add_public_keys``) of the params'
    /// ``current_member_ids`` and ``new_member_ids``. A user with no stored
    /// key raises ``InvalidInputError`` naming the user. With a hook set
    /// (``set_resolve_public_keys``), ``chat_xdk.Chat`` first fetches the
    /// keys of the users who have none through it.
    ///
    /// Args:
    ///     params: A ``GroupMembersChangeParams``.
    ///
    /// ``current_title`` and ``current_description`` are plaintext: the call
    /// encrypts each under the new conversation key and signs the
    /// ciphertext. ``current_avatar_url`` is signed as is.
    ///
    /// Returns:
    ///     The same dict shape as ``prepare_conversation_key_change``, with
    ///     two action signatures (the conversation-key change and the
    ///     member add) and, for a title or description the params set,
    ///     ``encrypted_title`` and ``encrypted_description``.
    pub(crate) fn prepare_group_members_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupMembersChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let result = self
            .inner
            .prepare_group_members_change(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_change_to_pydict(py, &result)
    }

    /// Prepare a signed group create, ready to send to the X API.
    ///
    /// Use this once, when creating a group (``conversation_id`` is the
    /// g-prefixed id minted by the initialize endpoint). Later key rotations
    /// use ``prepare_conversation_key_change``; roster additions use
    /// ``prepare_group_members_change``. While the key cache is on
    /// (``set_cache_keys``) the call caches the new key as the conversation's
    /// newest key.
    ///
    /// With ``public_keys`` ``None`` or empty, the key is encrypted to the
    /// stored public keys (``add_public_keys``) of the params'
    /// ``member_ids`` and ``admin_ids``. A user with no stored key raises
    /// ``InvalidInputError`` naming the user. With a hook set
    /// (``set_resolve_public_keys``), ``chat_xdk.Chat`` first fetches the
    /// keys of the users who have none through it.
    ///
    /// Args:
    ///     params: A ``GroupCreateParams``.
    ///
    /// ``title`` is plaintext: the call encrypts it under the new
    /// conversation key and signs the ciphertext. A create sets no avatar;
    /// set it afterwards with ``prepare_group_avatar_change``.
    ///
    /// Returns:
    ///     The same dict shape as ``prepare_conversation_key_change``, with
    ///     two action signatures (the conversation-key change and the group
    ///     create) and, when the params set a title, ``encrypted_title``:
    ///     the ``group_name`` the create request sends.
    pub(crate) fn prepare_group_create(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupCreateParams>,
    ) -> PyResult<Py<PyAny>> {
        let result = self
            .inner
            .prepare_group_create(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_change_to_pydict(py, &result)
    }

    /// Build the signed action for deleting messages from a conversation.
    ///
    /// A delete is a signed plaintext event, not an encrypted message, so no
    /// conversation key is involved: the result holds the request's
    /// ``action_signatures``, one entry. The SDK generates the action's
    /// message id; read it back from the entry.
    ///
    /// Args:
    ///     params: A ``MessageDeleteParams``.
    ///
    /// Returns:
    ///     A dict with ``action_signatures``: one dict with ``message_id``,
    ///     ``encoded_message_event_detail``, ``message_event_signature``
    ///     (``signature``, ``signature_version``, ``public_key_version``,
    ///     ``signing_public_key``).
    pub(crate) fn prepare_message_delete(
        &self,
        py: Python<'_>,
        params: PyRef<'_, MessageDeleteParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_message_delete(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Build the signed action for marking a conversation read.
    ///
    /// A read receipt is a signed plaintext event, not an encrypted message,
    /// so no conversation key is involved: the result holds the request's
    /// ``action_signatures``, one entry, nested as the conversation-change
    /// requests nest theirs. The mark-read request
    /// (``POST /2/chat/conversations/{id}/read``) takes them as they are. The
    /// SDK generates the action's message id; read it back from the entry.
    ///
    /// Args:
    ///     params: A ``MarkConversationReadParams``.
    ///
    /// Returns:
    ///     A dict with ``action_signatures``, shaped as
    ///     ``prepare_message_delete`` returns it.
    pub(crate) fn prepare_mark_conversation_read(
        &self,
        py: Python<'_>,
        params: PyRef<'_, MarkConversationReadParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_mark_conversation_read(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign a group member removal and rotate the conversation key for the
    /// members who stay.
    ///
    /// The result carries the new key, the remaining members' participant
    /// keys, and the action signatures: the removal (which names the new key
    /// version), a title and a description change for each one the params
    /// set, re-encrypted under the new key, and the key change. While the
    /// key cache is on (``set_cache_keys``) the call caches the new key as
    /// the conversation's newest key.
    ///
    /// With ``public_keys`` ``None`` or empty, the key is encrypted to the
    /// stored public keys (``add_public_keys``) of the params'
    /// ``remaining_member_ids``. A user with no stored key raises
    /// ``InvalidInputError`` naming the user. With a hook set
    /// (``set_resolve_public_keys``), ``chat_xdk.Chat`` first fetches the
    /// keys of the users who have none through it.
    pub(crate) fn prepare_group_members_remove(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupMembersRemoveParams>,
    ) -> PyResult<Py<PyAny>> {
        let result = self
            .inner
            .prepare_group_members_remove(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_change_to_pydict(py, &result)
    }

    /// Sign leaving a group.
    ///
    /// The signatures are a removal of the sender, an admin add when
    /// ``promote_admin_id`` is set, and a conversation delete. Leave does
    /// not rotate the conversation key.
    pub(crate) fn prepare_group_leave(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupLeaveParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_leave(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Encrypt a new group title under the conversation key and sign the
    /// change.
    ///
    /// Returns a dict: ``encrypted_value`` (the base64 ciphertext the request
    /// sends), ``conversation_key_version``, and ``action_signatures``.
    pub(crate) fn prepare_group_title_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupTitleChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_title_change(&params.to_core())
            .map_err(to_py_err)?;
        prepared_metadata_change_to_pydict(py, &prepared)
    }

    /// Sign a group avatar change: the avatar image's media URL, as is, and
    /// the version of the key the image is encrypted under. With
    /// ``conversation_key_version`` left ``None`` or empty, that is the
    /// version of the conversation's newest key in the key cache
    /// (``set_cache_keys``), the key the encrypt methods resolve; with no
    /// key cached the call raises ``InvalidStateError``.
    ///
    /// Returns a dict with ``action_signatures``, one entry.
    pub(crate) fn prepare_group_avatar_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupAvatarChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_avatar_change(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Encrypt a new group description under the conversation key and sign the
    /// change.
    ///
    /// Returns a dict: ``encrypted_value`` (the base64 ciphertext the request
    /// sends), ``conversation_key_version``, and ``action_signatures``.
    pub(crate) fn prepare_group_description_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupDescriptionChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_description_change(&params.to_core())
            .map_err(to_py_err)?;
        prepared_metadata_change_to_pydict(py, &prepared)
    }

    /// Sign adding group admins.
    pub(crate) fn prepare_group_admins_add(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupAdminsAddParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_admins_add(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign removing group admins.
    pub(crate) fn prepare_group_admins_remove(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupAdminsRemoveParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_admins_remove(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign enabling a group invite.
    pub(crate) fn prepare_group_invite_enable(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupInviteEnableParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_invite_enable(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign disabling a group invite.
    pub(crate) fn prepare_group_invite_disable(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupInviteDisableParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_invite_disable(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign a request to join a group.
    pub(crate) fn prepare_group_join_request(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupJoinRequestParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_join_request(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign rejecting group join requests.
    pub(crate) fn prepare_group_join_reject(
        &self,
        py: Python<'_>,
        params: PyRef<'_, GroupJoinRejectParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_group_join_reject(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign a message-TTL change.
    pub(crate) fn prepare_message_ttl_change(
        &self,
        py: Python<'_>,
        params: PyRef<'_, MessageTtlChangeParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_message_ttl_change(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign clearing a conversation's message TTL.
    pub(crate) fn prepare_message_ttl_remove(
        &self,
        py: Python<'_>,
        params: PyRef<'_, MessageTtlRemoveParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_message_ttl_remove(&params.to_core())
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Sign one screen-capture setting change.
    pub(crate) fn prepare_screen_capture(
        &self,
        py: Python<'_>,
        params: PyRef<'_, ScreenCaptureParams>,
    ) -> PyResult<Py<PyAny>> {
        let prepared = self
            .inner
            .prepare_screen_capture(&params.to_core(py)?)
            .map_err(to_py_err)?;
        prepared_action_to_pydict(py, &prepared)
    }

    /// Export private keys as raw bytes for secure storage.
    ///
    /// Warning: Handle with care — these are your secret keys!
    ///
    /// Returns a mutable ``bytearray`` so the caller can zero it after
    /// use (e.g. ``buf[:] = b"\x00" * len(buf)``); an immutable ``bytes``
    /// object could linger in memory until garbage collection.
    ///
    /// Returns:
    ///     Raw key bytes (32 or 64 bytes) as bytearray.
    ///
    /// Raises:
    ///     InvalidStateError: no identity key is loaded.
    pub(crate) fn export_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        use zeroize::Zeroize;
        let mut key_bytes = self.inner.export_keys().map_err(to_py_err)?;
        let out = PyByteArray::new(py, &key_bytes);
        key_bytes.zeroize();
        Ok(out)
    }

    /// Import private keys from the bytes ``export_keys()`` returned: 32
    /// (identity only) or 64 (identity and signing).
    ///
    /// When ``params.signing_key_version`` is given, it becomes the
    /// signing-key version and enables participant-key filtering by version
    /// in the same call. Without it, no signing-key version is set.
    pub(crate) fn import_keys(&self, params: PyRef<'_, ImportKeysParams>) -> PyResult<()> {
        let mut core = chat_xdk_core::ImportKeysParams::new(params.keys.as_slice());
        core.signing_key_version = params.signing_key_version.clone().filter(|v| !v.is_empty());
        self.inner.import_keys(&core).map_err(to_py_err)
    }

    /// Sign application data. Returns raw signature bytes.
    ///
    /// Args:
    ///     data: Bytes to sign.
    ///
    /// Returns:
    ///     Raw signature bytes (64 bytes).
    ///
    /// Raises:
    ///     InvalidInputError: ``data`` is an event signature payload or a
    ///         public key, which only the SDK signs.
    pub(crate) fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.inner.sign(data).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &sig))
    }

    /// Verify a signature.
    ///
    /// Args:
    ///     public_key_b64: Base64-encoded public key.
    ///     signature: Raw signature bytes.
    ///     data: The signed data.
    ///
    /// Returns:
    ///     True if signature is valid.
    pub(crate) fn verify(
        &self,
        public_key_b64: &str,
        signature: &[u8],
        data: &[u8],
    ) -> PyResult<bool> {
        self.inner
            .verify(public_key_b64, signature, data)
            .map_err(to_py_err)
    }

    /// Verify that a signing key is authentically bound to an identity key.
    ///
    /// Call this when you receive another user's public keys from the X API
    /// to detect server-side key substitution.
    ///
    /// Args:
    ///     identity_public_key_b64: Base64 SPKI identity public key.
    ///     signing_public_key_b64: Base64 SPKI signing public key.
    ///     identity_public_key_signature_b64: Base64 raw r||s signature.
    ///
    /// Returns:
    ///     True if the binding is valid.
    pub(crate) fn verify_key_binding(
        &self,
        identity_public_key_b64: &str,
        signing_public_key_b64: &str,
        identity_public_key_signature_b64: &str,
    ) -> PyResult<bool> {
        self.inner
            .verify_key_binding(
                identity_public_key_b64,
                signing_public_key_b64,
                identity_public_key_signature_b64,
            )
            .map_err(to_py_err)
    }

    /// Report whether the loaded identity public key is the key in
    /// `public_key_b64`.
    ///
    /// The X API returns the identity public key in SPKI/DER encoding while
    /// `get_public_keys` returns the raw SEC1 point; this accepts either
    /// encoding, so use it to check whether the keys on this device belong
    /// to a key registered to the account.
    ///
    /// Args:
    ///     public_key_b64: Base64 public key, raw SEC1 point or SPKI/DER.
    ///
    /// Returns:
    ///     True if it is the loaded identity public key.
    pub(crate) fn matches_registered_key(&self, public_key_b64: &str) -> PyResult<bool> {
        self.inner
            .matches_registered_key(public_key_b64)
            .map_err(to_py_err)
    }
}

/// A `ConversationKeyResult` as the dict `extract_conversation_keys` returns
/// and `decrypt_events` returns as `conversation_keys`.
fn conversation_keys_dict(
    py: Python<'_>,
    result: chat_xdk_core::ConversationKeyResult,
) -> PyResult<Bound<'_, pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("keys", key_map_dict(py, &result.keys)?)?;
    let keys_by_conversation = pyo3::types::PyDict::new(py);
    for (conversation_id, keys) in &result.keys_by_conversation {
        keys_by_conversation.set_item(conversation_id.as_str(), key_map_dict(py, keys)?)?;
    }
    dict.set_item("keys_by_conversation", keys_by_conversation)?;
    match result.latest_version {
        Some(version) => dict.set_item("latest_version", version)?,
        None => dict.set_item("latest_version", py.None())?,
    }
    dict.set_item("latest_versions", result.latest_versions)?;
    Ok(dict)
}

/// A key map as a dict mapping each key version to the raw key (`bytes`).
fn key_map_dict<'py>(
    py: Python<'py>,
    keys: &HashMap<String, XChatConversationKey>,
) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    for (version, key) in keys {
        dict.set_item(version.as_str(), key.encoded().to_vec().into_pyobject(py)?)?;
    }
    Ok(dict)
}
