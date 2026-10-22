"""
chat-xdk - Python bindings for the X Chat encryption SDK.

Quick Start:
    from chat_xdk import Chat, DecryptEventParams, EncryptMessageParams

    chat = Chat(config_json)  # optional; None or an empty JSON object ("{}")
                              # selects manual key management
    chat.unlock("2580")
    chat.set_identity(my_user_id, signing_key_version)

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

__version__ = "0.1.0"

import re as _re
import threading as _threading
import time as _time
import urllib.request as _urllib_request
from typing import Optional, TypedDict

from chat_xdk import _native
from chat_xdk._native import (
    Chat,
    ConversationKeyChangeParams,
    DecryptEventParams,
    DecryptEventsParams,
    DecryptFileParams,
    EncryptEditParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    FileDecryptor,
    FileDecryptorParams,
    FileEncryptor,
    FileEncryptorParams,
    GroupCreateParams,
    GroupMembersChangeParams,
    MarkConversationReadParams,
    SetIdentityParams,
    ImportKeysParams,
    MessageDeleteParams,
    PublicKeyRegistration,
    PublicKeyRegistrationPayload,
    PublicKeys,
    SendPayload,
    SignatureInfo,
    base64_to_bytes,
    bytes_to_base64,
    bytes_to_hex,
    detect_image_dimensions,
    detect_mime_type,
    encrypted_file_size,
    hex_to_bytes,
)

# Feature switches (GET /2/chat/features). The native core decides when to
# fetch and what an answer means; this module runs a driver thread that polls
# the core, waits here between steps, and performs each GET it is handed.
# Nothing here is API.


class _FeatureDriver:
    """One daemon thread at a time that polls the core for feature GETs.

    It waits in Python rather than inside the core: a daemon thread that takes
    the interpreter lock back from native code while the interpreter shuts
    down is ended in a way native frames cannot unwind."""

    def __init__(self):
        self._lock = _threading.Lock()
        self._woken = _threading.Event()
        self._running = False

    def wake(self):
        """Start the driver, or have it poll again: the core calls this when
        its plan changes."""
        with self._lock:
            self._woken.set()
            if self._running:
                return
            self._running = True
        _threading.Thread(target=self._run, name="chat-xdk-features", daemon=True).start()

    def _run(self):
        while True:
            self._woken.clear()
            step = _native._feature_poll()
            if step is None:
                with self._lock:
                    if not self._woken.is_set():
                        self._running = False
                        return
            elif isinstance(step, tuple):
                _threading.Thread(
                    target=_perform_feature_fetch,
                    args=step,
                    name="chat-xdk-features-request",
                    daemon=True,
                ).start()
            else:
                self._woken.wait(step)


def _perform_feature_fetch(fetch_id, url, timeout, max_bytes):
    try:
        status, body = _get_features(url, timeout, max_bytes)
    except Exception:
        status, body = 0, b""
    _native._feature_complete(fetch_id, status, body)


def _get_features(url, timeout, max_bytes):
    """GET ``url`` within ``timeout`` seconds: the status and the body, read
    to its end or to one byte past ``max_bytes``. Status 0 when no complete
    response arrived in time."""
    deadline = _time.monotonic() + timeout
    request = _urllib_request.Request(url, headers={"Accept": "application/json"})
    with _urllib_request.urlopen(request, timeout=timeout) as response:
        body = bytearray()
        while len(body) <= max_bytes:
            if _time.monotonic() >= deadline:
                return 0, b""
            chunk = response.read1(max_bytes + 1 - len(body))
            if not chunk:
                break
            body += chunk
        return response.status, bytes(body)


_native._feature_set_waker(_FeatureDriver().wake)


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

# Stable invalid-PIN message form the core emits
# ("Invalid PIN: guesses_remaining=N"). Anchored on the full form so a count
# embedded in an unrelated pass-through message is not misread.
_GUESSES_REMAINING = _re.compile(r"\bInvalid PIN: guesses_remaining=(\d+)")


def guesses_remaining(exc):
    """Remaining PIN attempts from an invalid-PIN unlock failure, or None.

    Present only on the exception raised by ``Chat.unlock`` /
    ``Chat.change_pin`` for a wrong PIN; 0 means the guess budget is
    exhausted and the stored keys are locked.
    """
    match = _GUESSES_REMAINING.search(str(exc))
    return int(match.group(1)) if match else None


__all__ = [
    "Chat",
    "ConversationKeyChangeParams",
    "DecryptEventParams",
    "DecryptEventsParams",
    "DecryptFileParams",
    "EncryptEditParams",
    "EncryptFileParams",
    "EncryptMessageParams",
    "EncryptReactionParams",
    "EncryptReplyParams",
    "FileDecryptor",
    "FileDecryptorParams",
    "FileEncryptor",
    "FileEncryptorParams",
    "GroupCreateParams",
    "GroupMembersChangeParams",
    "MarkConversationReadParams",
    "SetIdentityParams",
    "ImportKeysParams",
    "MessageDeleteParams",
    "PublicKeyRegistration",
    "PublicKeyRegistrationPayload",
    "PublicKeys",
    "QuickReply",
    "QuickReplyOption",
    "QuickReplyOptionsRequest",
    "QuickReplyOptionsResponse",
    "QuickReplyRequest",
    "QuickReplyResponse",
    "SendPayload",
    "SignatureInfo",
    "base64_to_bytes",
    "bytes_to_base64",
    "bytes_to_hex",
    "detect_image_dimensions",
    "detect_mime_type",
    "encrypted_file_size",
    "guesses_remaining",
    "hex_to_bytes",
]
