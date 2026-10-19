"""
chat-xdk - Python bindings for the X Chat encryption SDK.

Quick Start:
    from chat_xdk import Chat, DecryptEventParams, EncryptMessageParams

    chat = Chat(config_json)  # optional; None or an empty JSON object ("{}")
                              # selects manual key management
    chat.unlock("2580")
    chat.set_identity(my_user_id, signing_key_version)
    chat.load_feature_config()  # feature switches; sends stay v0 until v1_send is on

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
    # payload.message_id, payload.encrypted_content, payload.signature, etc.
"""

__version__ = "0.1.0"

import re as _re
import threading as _threading
import time as _time
import urllib.request as _urllib_request
import weakref as _weakref
from typing import Optional, TypedDict

from chat_xdk._native import Chat as _NativeChat
from chat_xdk._native import (
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

FEATURES_ENDPOINT = "https://api.x.com/2/chat/features"
"""Default URL of the feature-switch endpoint ``GET /2/chat/features``."""

_MAX_FEATURES_BODY = 64 * 1024
_MAX_REFETCH_BACKOFF_SECONDS = 60.0


class LoadFeatureConfigParams:
    """Parameters for ``Chat.load_feature_config``.

    Args:
        endpoint: URL of ``GET /2/chat/features``; ``None`` selects
            ``FEATURES_ENDPOINT``.
        timeout_ms: Timeout of each request, in milliseconds.
        refresh_seconds: Interval of the background re-check, which can
            only turn flags off. ``0`` disables it.
    """

    def __init__(self, endpoint=None, timeout_ms=2000, refresh_seconds=300):
        self.endpoint = endpoint
        self.timeout_ms = timeout_ms
        self.refresh_seconds = refresh_seconds


class Chat(_NativeChat):
    __doc__ = _NativeChat.__doc__

    # Whether the last applied response came from a request without a
    # bucket, so the refresher watches for keys to load.
    _feature_bucketless = False
    _feature_refresh_stop = None

    def load_feature_config(self, params=None):
        """Fetch the feature switches from ``GET /2/chat/features`` and apply them.

        Call it at startup after loading keys and ``set_identity``, so the
        request carries ``feature_bucket()``. If keys load later, the flags
        are fetched once more with the key's bucket, and every flag reads
        off until they are. A daemon thread re-checks every
        ``refresh_seconds``; a re-check can only turn flags off. Calling
        this again replaces the previous refresher.

        Any failure (network error, timeout, a status other than 200, or a
        malformed body) leaves the flags unchanged, so after a failed first
        load every flag is off and sends stay v0.

        Args:
            params: ``LoadFeatureConfigParams``; ``None`` uses the defaults.

        Returns:
            True when a server response was applied, False otherwise.
        """
        params = params if params is not None else LoadFeatureConfigParams()
        if self._feature_refresh_stop is not None:
            self._feature_refresh_stop.set()
        applied = _fetch_features(self, params, False) or _fetch_features(
            self, params, False
        )
        stop = _threading.Event()
        self._feature_refresh_stop = stop
        _threading.Thread(
            target=_feature_refresh_loop,
            args=(_weakref.ref(self), params, stop),
            name="chat-xdk-features",
            daemon=True,
        ).start()
        return applied


def _fetch_features(chat, params, downgrade_only):
    """Fetch the flags for ``chat``'s bucket and apply them; True on success."""
    endpoint = params.endpoint or FEATURES_ENDPOINT
    bucket = chat.feature_bucket()
    url = endpoint
    if bucket is not None:
        url += ("&" if "?" in endpoint else "?") + "bucket=%d" % bucket
    try:
        request = _urllib_request.Request(url, headers={"Accept": "application/json"})
        with _urllib_request.urlopen(
            request, timeout=params.timeout_ms / 1000.0
        ) as response:
            if response.status != 200:
                return False
            body = response.read(_MAX_FEATURES_BODY + 1)
        if len(body) > _MAX_FEATURES_BODY:
            return False
        chat.apply_feature_config(body.decode("utf-8"), bucket, downgrade_only)
    except Exception:
        return False
    if not downgrade_only:
        chat._feature_bucketless = bucket is None
    return True


def _feature_refresh_loop(chat_ref, params, stop):
    """Re-fetch once keys load after a bucketless response, and re-check.

    Holds ``chat`` only weakly, so the thread ends with it.
    """
    refresh = max(0.0, float(params.refresh_seconds or 0))
    next_recheck = _time.monotonic() + refresh
    retry_at = 0.0
    backoff = 1.0
    while True:
        chat = chat_ref()
        if chat is None:
            return
        now = _time.monotonic()
        try:
            if chat.feature_refetch_due():
                if now >= retry_at:
                    if _fetch_features(chat, params, False):
                        backoff = 1.0
                        next_recheck = now + refresh
                    else:
                        retry_at = now + backoff
                        backoff = min(backoff * 2, _MAX_REFETCH_BACKOFF_SECONDS)
            elif refresh and now >= next_recheck:
                _fetch_features(chat, params, True)
                next_recheck = now + refresh
            watching_keys = chat._feature_bucketless
        except Exception:
            watching_keys = True
        del chat
        if not watching_keys and not refresh:
            return
        wait = 1.0 if watching_keys else max(0.0, next_recheck - _time.monotonic())
        if stop.wait(wait):
            return


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
    "FEATURES_ENDPOINT",
    "FileDecryptor",
    "FileDecryptorParams",
    "FileEncryptor",
    "FileEncryptorParams",
    "GroupCreateParams",
    "GroupMembersChangeParams",
    "LoadFeatureConfigParams",
    "MarkConversationReadParams",
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
