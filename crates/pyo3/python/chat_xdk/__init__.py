"""
chat-xdk - Python bindings for the X Chat encryption SDK.

Quick Start:
    from chat_xdk import Chat, DecryptEventParams, EncryptMessageParams, SetIdentityParams

    chat = Chat(config_json)  # the X API's Juicebox config; Chat() without one
                              # loads keys with import_keys instead of unlock
    chat.unlock("2580")
    chat.set_identity(SetIdentityParams(my_user_id, signing_key_version))

    # Decrypt webhook events (returns a dict)
    event = chat.decrypt_event(
        DecryptEventParams(event_b64, conversation_keys, signing_keys=signing_keys)
    )
    if event["type"] == "Message":
        print(event["content"]["text"])

    # Encrypt outgoing messages
    payload = chat.encrypt_message(
        EncryptMessageParams(conversation_id, "Hello!",
                             conversation_key=key,
                             conversation_key_version=version)
    )
    # payload.message_id, payload.encoded_message_create_event, payload.signature, etc.
"""

import asyncio as _asyncio
import atexit as _atexit
import http.client as _http_client
import socket as _socket
import threading as _threading
import time as _time
import urllib.parse as _urllib_parse
from enum import Enum
from typing import Any, Literal, Optional, TypedDict

from chat_xdk import _native
from chat_xdk._native import __version__
from chat_xdk._native import (
    ChatXdkError,
    ConversationKeyChangeParams,
    DecryptEventParams,
    DecryptEventsParams,
    DecryptFileParams,
    EncryptEditParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    DecryptionError,
    FileDecryptor,
    FileDecryptorParams,
    FileEncryptor,
    FileEncryptorParams,
    GroupAdminsAddParams,
    GroupAdminsRemoveParams,
    GroupAvatarChangeParams,
    GroupCreateParams,
    GroupDescriptionChangeParams,
    GroupInviteDisableParams,
    GroupInviteEnableParams,
    GroupJoinRejectParams,
    GroupJoinRequestParams,
    GroupLeaveParams,
    GroupMembersChangeParams,
    GroupMembersRemoveParams,
    GroupTitleChangeParams,
    InvalidInputError,
    InvalidPinError,
    InvalidStateError,
    JuiceboxError,
    MarkConversationReadParams,
    MessageTtlChangeParams,
    MessageTtlRemoveParams,
    ScreenCaptureParams,
    SetIdentityParams,
    ImportKeysParams,
    MessageDeleteParams,
    ParseError,
    PublicKeyRegistration,
    PublicKeyRegistrationPayload,
    PublicKeys,
    SendPayload,
    SignatureInfo,
    VerificationError,
    base64_to_bytes,
    bytes_to_base64,
    bytes_to_hex,
    detect_image_dimensions,
    detect_mime_type,
    encrypted_file_size,
    hex_to_bytes,
)

class ScreenCaptureChange(str, Enum):
    """A screen-capture setting signed by ``prepare_screen_capture``.

    Blocking names are the events X clients sign. Detection names are the
    events this SDK's verifier reconstructs.
    """

    BlockingEnabled = "BlockingEnabled"
    BlockingDisabled = "BlockingDisabled"
    DetectionEnabled = "DetectionEnabled"
    DetectionDisabled = "DetectionDisabled"


# Feature switches (GET /2/chat/features). A chat reads them once, when it is
# created: the native core decides what to fetch and what an answer means, and
# this module performs the GET on a daemon thread. Nothing here is API.


def _start_feature_fetch(fetch_id, url, timeout, max_bytes):
    """Start a chat's feature GET; the core calls this from the constructor."""
    _threading.Thread(
        target=_perform_feature_fetch,
        args=(fetch_id, url, timeout, max_bytes),
        name="chat-xdk-features",
        daemon=True,
    ).start()


def _perform_feature_fetch(fetch_id, url, timeout, max_bytes):
    try:
        status, body = _get_features(url, timeout, max_bytes)
    except Exception:
        status, body = 0, b""
    _native._feature_complete(fetch_id, status, body)


# The sockets of the GETs under way, by thread. At exit they are cut short and
# waited for: a daemon thread still inside OpenSSL when the process exits races
# OpenSSL's own cleanup, which can crash the process.
_requests = {}
_requests_lock = _threading.Lock()
_exiting = False
_tls_context = None


def _get_features(url, timeout, max_bytes):
    """GET ``url`` within ``timeout`` seconds: the status and the body, read
    to its end or to one byte past ``max_bytes``. Status 0 when no complete
    response arrived in time."""
    global _tls_context
    deadline = _time.monotonic() + timeout
    parts = _urllib_parse.urlsplit(url)
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    sock = _socket.create_connection((parts.hostname, port), timeout=timeout)
    thread = _threading.current_thread()
    with _requests_lock:
        if _exiting:
            sock.close()
            return 0, b""
        _requests[thread] = sock
    try:
        if secure:
            if _tls_context is None:
                import ssl

                _tls_context = ssl.create_default_context()
            with _requests_lock:
                if _exiting:
                    return 0, b""
                sock = _tls_context.wrap_socket(
                    sock, server_hostname=parts.hostname, do_handshake_on_connect=False
                )
                _requests[thread] = sock
            sock.do_handshake()
            connection = _http_client.HTTPSConnection(
                parts.hostname, port, timeout=timeout, context=_tls_context
            )
        else:
            connection = _http_client.HTTPConnection(parts.hostname, port, timeout=timeout)
        connection.sock = sock
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        connection.request("GET", target, headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = bytearray()
        while len(body) <= max_bytes:
            if _time.monotonic() >= deadline:
                return 0, b""
            chunk = response.read1(max_bytes + 1 - len(body))
            if not chunk:
                break
            body += chunk
        return response.status, bytes(body)
    finally:
        with _requests_lock:
            _requests.pop(thread, None)
        sock.close()


@_atexit.register
def _end_feature_requests():
    """Start no more GETs, cut short the ones under way, and wait for them to
    end, at most 2 seconds."""
    global _exiting
    with _requests_lock:
        _exiting = True
        for sock in _requests.values():
            try:
                sock.shutdown(_socket.SHUT_RDWR)
            except OSError:
                pass
        threads = list(_requests)
    deadline = _time.monotonic() + 2.0
    for thread in threads:
        thread.join(max(0.0, deadline - _time.monotonic()))


_native._feature_set_starter(_start_feature_fetch)


class QuickReplyOption(TypedDict, total=False):
    """A single selectable quick-reply option."""

    id: Optional[str]
    label: Optional[str]
    metadata: Optional[str]
    description: Optional[str]


class QuickReplyOptionsRequest(TypedDict, total=False):
    """The options offered by a quick-reply request."""

    id: Optional[str]
    options: Optional[list[QuickReplyOption]]


class QuickReplyOptionsResponse(TypedDict, total=False):
    """The option selected in a quick-reply response."""

    request_id: Optional[str]
    metadata: Optional[str]
    selected_option_id: Optional[str]


class QuickReplyRequest(TypedDict):
    """A quick-reply request offering a set of selectable options."""

    options: QuickReplyOptionsRequest


class QuickReplyResponse(TypedDict):
    """A quick-reply response selecting a previously offered option."""

    options: QuickReplyOptionsResponse


class QuickReply(TypedDict, total=False):
    """A quick reply carried by a text message.

    Set exactly one of ``request`` (offering selectable options) or
    ``response`` (selecting one). The ``quick_reply`` of decrypted text
    content has this shape, so a received value can be sent back unchanged.
    """

    request: QuickReplyRequest
    response: QuickReplyResponse


class GroupText(TypedDict, total=False):
    """A group title or description as a received event carries it.

    The ``title`` of a ``Created`` group change, the ``new_title`` of a
    ``TitleChanged`` one and the ``new_description`` of a
    ``DescriptionChanged`` one have this shape. ``kind`` ``"Text"`` carries
    ``text``: the value decrypted, or the plaintext an event that names no
    key version carries. ``kind`` ``"Unavailable"`` carries ``raw``: a value
    the SDK could not decrypt, as the event carries it. 0.5.x apps sent
    titles as plaintext while naming a key version, so show ``raw`` when a
    title isn't decryptable.
    """

    kind: Literal["Text", "Unavailable"]
    text: str
    raw: str


class SigningKeyEntry(TypedDict):
    """A participant's signing key, as ``GET /2/users/:id/public_keys``
    returns it, for verifying the events they sign."""

    user_id: str
    public_key_version: str
    public_key: str
    identity_public_key: str
    identity_public_key_signature: str


class PublicKeyInput(TypedDict):
    """A participant's identity key, to encrypt a new conversation key to."""

    user_id: str
    identity_public_key: str
    public_key_version: str


class ConversationKeyResult(TypedDict):
    """Conversation keys by version, and the version to encrypt with: the
    newest key change whose signature verified, or ``None``."""

    keys: dict[str, bytes]
    latest_version: Optional[str]


class DecryptedEvent(TypedDict, total=False):
    """One event of a ``decrypt_events`` batch: the decrypted ``event`` and,
    for a message, ``original_b64``, its raw event."""

    event: dict[str, Any]
    original_b64: str


class DecryptEventsResult(TypedDict):
    """What ``decrypt_events`` returns. ``errors`` maps the index of each
    event that failed, as a string, to its error."""

    events: list[DecryptedEvent]
    conversation_keys: ConversationKeyResult
    errors: dict[str, str]


class MessageEventSignature(TypedDict):
    """The signature of an action, as requests carry it."""

    signature: str
    signature_version: str
    public_key_version: str
    signing_public_key: str


class ActionSignature(TypedDict):
    """A signed action, ready to send in a request's ``action_signatures``."""

    message_id: str
    encoded_message_event_detail: str
    message_event_signature: MessageEventSignature


class PreparedAction(TypedDict):
    """The signed actions of a ``prepare_*`` call that changes no key."""

    action_signatures: list[ActionSignature]


class PreparedGroupMetadataChange(TypedDict):
    """A group title or description encrypted under the conversation key,
    with its signed action."""

    encrypted_value: str
    conversation_key_version: str
    action_signatures: list[ActionSignature]


class ConversationParticipantKey(TypedDict):
    """A new conversation key encrypted to one participant's identity key."""

    user_id: str
    encrypted_conversation_key: str
    public_key_version: str


class PreparedConversationChange(TypedDict, total=False):
    """A new conversation key, encrypted to every participant, with the
    signed actions that carry it. ``encrypted_title`` and
    ``encrypted_description`` are set for a title and description the
    params set."""

    conversation_id: str
    conversation_key: bytes
    conversation_key_version: str
    conversation_participant_keys: list[ConversationParticipantKey]
    action_signatures: list[ActionSignature]
    encrypted_title: str
    encrypted_description: str


class Chat(_native.Chat):
    """The X Chat encryption SDK.

    ``Chat(config_json)`` keeps the keys in Juicebox with the Juicebox
    configuration the X API returns; ``Chat()`` manages them with
    ``import_keys`` and ``generate_keypairs`` alone, or takes the config
    later from ``update_config``. Until a chat has one, ``setup``,
    ``unlock``, ``change_pin`` and ``delete`` raise ``InvalidStateError``.
    The ``_async`` methods run the Juicebox round trips on a worker thread,
    for an ``asyncio`` loop.
    """

    async def setup_async(self, pin):
        """``setup`` on a worker thread."""
        return await _asyncio.to_thread(self.setup, pin)

    async def unlock_async(self, pin):
        """``unlock`` on a worker thread."""
        return await _asyncio.to_thread(self.unlock, pin)

    async def change_pin_async(self, old_pin, new_pin):
        """``change_pin`` on a worker thread."""
        return await _asyncio.to_thread(self.change_pin, old_pin, new_pin)

    async def delete_async(self):
        """``delete`` on a worker thread."""
        return await _asyncio.to_thread(self.delete)


__all__ = [
    "ActionSignature",
    "Chat",
    "ChatXdkError",
    "ConversationKeyChangeParams",
    "ConversationKeyResult",
    "ConversationParticipantKey",
    "DecryptEventParams",
    "DecryptEventsParams",
    "DecryptEventsResult",
    "DecryptFileParams",
    "DecryptedEvent",
    "DecryptionError",
    "EncryptEditParams",
    "EncryptFileParams",
    "EncryptMessageParams",
    "EncryptReactionParams",
    "EncryptReplyParams",
    "FileDecryptor",
    "FileDecryptorParams",
    "FileEncryptor",
    "FileEncryptorParams",
    "GroupAdminsAddParams",
    "GroupAdminsRemoveParams",
    "GroupAvatarChangeParams",
    "GroupCreateParams",
    "GroupDescriptionChangeParams",
    "GroupInviteDisableParams",
    "GroupInviteEnableParams",
    "GroupJoinRejectParams",
    "GroupJoinRequestParams",
    "GroupLeaveParams",
    "GroupMembersChangeParams",
    "GroupMembersRemoveParams",
    "GroupText",
    "GroupTitleChangeParams",
    "ImportKeysParams",
    "InvalidInputError",
    "InvalidPinError",
    "InvalidStateError",
    "JuiceboxError",
    "MarkConversationReadParams",
    "MessageDeleteParams",
    "MessageEventSignature",
    "MessageTtlChangeParams",
    "MessageTtlRemoveParams",
    "ParseError",
    "PreparedAction",
    "PreparedConversationChange",
    "PreparedGroupMetadataChange",
    "PublicKeyInput",
    "PublicKeyRegistration",
    "PublicKeyRegistrationPayload",
    "PublicKeys",
    "QuickReply",
    "QuickReplyOption",
    "QuickReplyOptionsRequest",
    "QuickReplyOptionsResponse",
    "QuickReplyRequest",
    "QuickReplyResponse",
    "ScreenCaptureChange",
    "ScreenCaptureParams",
    "SendPayload",
    "SetIdentityParams",
    "SignatureInfo",
    "SigningKeyEntry",
    "VerificationError",
    "base64_to_bytes",
    "bytes_to_base64",
    "bytes_to_hex",
    "detect_image_dimensions",
    "detect_mime_type",
    "encrypted_file_size",
    "hex_to_bytes",
]
