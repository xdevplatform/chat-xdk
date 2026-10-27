//! The Python values the calls return.

use super::*;

/// Build the Python dict for a prepared key change.
pub(crate) fn prepared_change_to_pydict(
    py: Python<'_>,
    result: &chat_xdk_core::PreparedConversationChange,
) -> PyResult<Py<PyAny>> {
    let outer = pyo3::types::PyDict::new(py);
    outer.set_item("conversation_id", &result.conversation_id)?;
    if let Some(ckey) = &result.conversation_key {
        outer.set_item(
            "conversation_key",
            ckey.encoded().to_vec().into_pyobject(py)?,
        )?;
    }
    outer.set_item("conversation_key_version", &result.conversation_key_version)?;

    let participant_keys = pyo3::types::PyList::empty(py);
    for item in &result.conversation_participant_keys {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("user_id", &item.user_id)?;
        dict.set_item(
            "encrypted_conversation_key",
            &item.encrypted_conversation_key,
        )?;
        dict.set_item("public_key_version", &item.public_key_version)?;
        participant_keys.append(dict)?;
    }
    outer.set_item("conversation_participant_keys", participant_keys)?;

    outer.set_item(
        "action_signatures",
        action_signatures_to_pylist(py, &result.action_signatures)?,
    )?;
    if let Some(encrypted_title) = &result.encrypted_title {
        outer.set_item("encrypted_title", encrypted_title)?;
    }
    if let Some(encrypted_description) = &result.encrypted_description {
        outer.set_item("encrypted_description", encrypted_description)?;
    }

    Ok(outer.into())
}

/// Build the Python dict for a prepared title or description change.
pub(crate) fn prepared_metadata_change_to_pydict(
    py: Python<'_>,
    prepared: &chat_xdk_core::PreparedGroupMetadataChange,
) -> PyResult<Py<PyAny>> {
    let outer = pyo3::types::PyDict::new(py);
    outer.set_item("encrypted_value", &prepared.encrypted_value)?;
    outer.set_item(
        "conversation_key_version",
        &prepared.conversation_key_version,
    )?;
    outer.set_item(
        "action_signatures",
        action_signatures_to_pylist(py, &prepared.action_signatures)?,
    )?;
    Ok(outer.into())
}

/// Build the Python dict for a prepared delete or read receipt.
pub(crate) fn prepared_action_to_pydict(
    py: Python<'_>,
    prepared: &chat_xdk_core::PreparedAction,
) -> PyResult<Py<PyAny>> {
    let outer = pyo3::types::PyDict::new(py);
    outer.set_item(
        "action_signatures",
        action_signatures_to_pylist(py, &prepared.action_signatures)?,
    )?;
    Ok(outer.into())
}

pub(crate) fn action_signatures_to_pylist<'py>(
    py: Python<'py>,
    signatures: &[chat_xdk_core::signatures::ActionSignature],
) -> PyResult<Bound<'py, pyo3::types::PyList>> {
    let list = pyo3::types::PyList::empty(py);
    for sig in signatures {
        list.append(action_signature_to_pydict(py, sig)?)?;
    }
    Ok(list)
}

/// Build the Python dict for a signed action, the signature nested under
/// ``message_event_signature`` as requests carry it.
pub(crate) fn action_signature_to_pydict<'py>(
    py: Python<'py>,
    sig: &chat_xdk_core::signatures::ActionSignature,
) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("message_id", &sig.message_id)?;
    dict.set_item(
        "encoded_message_event_detail",
        &sig.encoded_message_event_detail,
    )?;
    let signed = &sig.message_event_signature;
    let message_event_signature = pyo3::types::PyDict::new(py);
    message_event_signature.set_item("signature", &signed.signature)?;
    message_event_signature.set_item("signature_version", &signed.signature_version)?;
    message_event_signature.set_item("public_key_version", &signed.public_key_version)?;
    message_event_signature.set_item("signing_public_key", &signed.signing_public_key)?;
    dict.set_item("message_event_signature", message_event_signature)?;
    Ok(dict)
}

/// Convert the core SendPayload to the Python SendPayload with matching shape.
pub(crate) fn to_py_send_payload(payload: chat_xdk_core::SendPayload) -> SendPayload {
    SendPayload {
        message_id: payload.message_id,
        event_b64: payload.event_b64,
        encoded_message_create_event: payload.encoded_message_create_event,
        signature: payload.signature,
        encoded_message_event_signature: payload.encoded_message_event_signature,
        signature_info: SignatureInfo {
            public_key_version: payload.signature_info.public_key_version,
            signature_version: payload.signature_info.signature_version,
        },
        conversation_key_version: payload.conversation_key_version,
        should_notify: payload.should_notify,
        xdk_version: payload.xdk_version,
    }
}

/// Public keys returned by setup/get_public_keys.
#[pyclass]
#[derive(Clone)]
pub struct PublicKeys {
    /// Base64-encoded identity public key (P-256, for ECDH).
    #[pyo3(get)]
    pub identity: String,
    /// Base64-encoded signing public key (P-256, for ECDSA).
    #[pyo3(get)]
    pub signing: String,
}

/// Public key registration payload returned by generate_keypairs().
#[pyclass]
#[derive(Clone)]
pub struct PublicKeyRegistrationPayload {
    #[pyo3(get)]
    pub public_key: PublicKeyRegistration,
}

/// Public key registration fields expected by the X API.
#[pyclass]
#[derive(Clone)]
pub struct PublicKeyRegistration {
    #[pyo3(get)]
    pub identity_public_key_signature: String,
    #[pyo3(get)]
    pub public_key: String,
    #[pyo3(get)]
    pub public_key_fingerprint: Option<String>,
    #[pyo3(get)]
    pub registration_method: String,
    #[pyo3(get)]
    pub signing_public_key: String,
    #[pyo3(get)]
    pub signing_public_key_signature: Option<String>,
}

/// Signature metadata for a sent message.
#[pyclass]
#[derive(Clone)]
pub struct SignatureInfo {
    /// Version of the signing key used.
    #[pyo3(get)]
    pub public_key_version: String,
    /// Signature protocol version (e.g. "7").
    #[pyo3(get)]
    pub signature_version: String,
}

/// Encrypted message payload ready to send to the X API.
#[pyclass]
#[derive(Clone)]
pub struct SendPayload {
    /// Message id (UUID) the SDK generated and embedded in the signed event.
    /// Send it as the message's ``message_id``, keep it to dedup and to
    /// anchor replies, and reuse the same encrypted payload on retries so an
    /// id is never minted twice.
    #[pyo3(get)]
    pub message_id: String,
    /// The outgoing message as a base64 event: what recipients receive,
    /// without the fields the server assigns. Pass it to ``encrypt_file`` or
    /// ``file_encryptor`` to encrypt the message's files, or to
    /// ``decrypt_event`` to read the message back.
    #[pyo3(get)]
    pub event_b64: String,
    /// Base64-encoded Thrift ``MessageCreateEvent`` carrying the encrypted
    /// contents: the send request's ``encoded_message_create_event``.
    #[pyo3(get)]
    pub encoded_message_create_event: String,
    /// Base64-encoded signature.
    #[pyo3(get)]
    pub signature: String,
    /// Base64-encoded Thrift ``MessageEventSignature``: the send request's
    /// ``encoded_message_event_signature``.
    #[pyo3(get)]
    pub encoded_message_event_signature: String,
    /// Signature metadata (public_key_version + signature_version).
    #[pyo3(get)]
    pub signature_info: SignatureInfo,
    /// Conversation key version used.
    #[pyo3(get)]
    pub conversation_key_version: String,
    /// Whether to send push notification.
    #[pyo3(get)]
    pub should_notify: bool,
    /// Version of the Chat XDK that built this payload.
    #[pyo3(get)]
    pub xdk_version: String,
}
