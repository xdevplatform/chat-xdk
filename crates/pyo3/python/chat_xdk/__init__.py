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
    # payload.message_id, payload.encrypted_content, payload.signature, etc.
"""

__version__ = "0.1.0"

import os as _os
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

# Feature switches (GET /2/chat/features). Internal: every Chat fetches them
# itself, without blocking or failing, and sends stay v0 unless a response
# turns v1_send on. Nothing here is API. The module-level settings exist for
# this repository's tests; CHAT_XDK_FEATURES_ENDPOINT overrides the endpoint.
_FEATURES_ENDPOINT = "https://api.x.com/2/chat/features"
_FEATURES_ENDPOINT_ENV = "CHAT_XDK_FEATURES_ENDPOINT"
_FEATURE_TIMEOUT_SECONDS = 2.0
_FEATURE_REFRESH_SECONDS = 300.0
_FEATURE_KEY_POLL_SECONDS = 1.0
_MAX_FEATURES_BODY = 64 * 1024


class Chat(_NativeChat):
    __doc__ = _NativeChat.__doc__

    def __init__(self, config_json=None):
        # The native constructor already took config_json; this only starts
        # the feature-switch thread.
        self._feature_stop = _start_feature_switches(self)

    def close(self):
        """Stop this chat's background work: its fetch of the X API's
        feature switches. A chat that is garbage-collected stops it too."""
        self._feature_stop.set()


def _start_feature_switches(chat):
    """Fetch the flags for ``chat`` on a daemon thread that holds it weakly.
    Returns the event that stops the thread, which ``chat`` being
    garbage-collected also sets."""
    stop = _threading.Event()
    _weakref.finalize(chat, stop.set)
    settings = (
        _os.environ.get(_FEATURES_ENDPOINT_ENV) or _FEATURES_ENDPOINT,
        _FEATURE_TIMEOUT_SECONDS,
        _FEATURE_REFRESH_SECONDS,
        _FEATURE_KEY_POLL_SECONDS,
    )
    _threading.Thread(
        target=_feature_loop,
        args=(_weakref.ref(chat), settings, stop),
        name="chat-xdk-features",
        daemon=True,
    ).start()
    return stop


def _fetch_features(chat, endpoint, timeout, downgrade_only):
    """Fetch the flags for ``chat``'s bucket and apply them; True on success."""
    try:
        bucket = chat._feature_bucket()
        url = endpoint
        if bucket is not None:
            url += ("&" if "?" in endpoint else "?") + "bucket=%d" % bucket
        body = _shared_features(url, timeout)
        if body is None:
            return False
        chat._apply_feature_config(body, bucket, downgrade_only)
    except Exception:
        return False
    return True


# Feature requests in flight, by URL: url -> (done event, [body]).
_feature_requests = {}
_feature_requests_lock = _threading.Lock()


def _shared_features(url, timeout):
    """The body for ``url``, from the request another chat has in flight
    for it or else from a new one, so chats that ask at once share a
    request."""
    with _feature_requests_lock:
        shared = _feature_requests.get(url)
        owner = shared is None
        if owner:
            shared = _feature_requests[url] = (_threading.Event(), [])
    done, result = shared
    if owner:
        try:
            result.append(_get_features(url, timeout))
        finally:
            with _feature_requests_lock:
                del _feature_requests[url]
            done.set()
    else:
        done.wait(timeout + 1.0)
    return result[0] if result else None


def _get_features(url, timeout):
    """The body of a 200 response from ``url``, or None on any failure,
    within ``timeout`` seconds in all. The request runs on its own daemon
    thread, since urllib's timeout covers neither DNS nor the whole read."""
    result = []
    worker = _threading.Thread(
        target=lambda: result.append(_request_features(url, timeout)),
        name="chat-xdk-features-request",
        daemon=True,
    )
    worker.start()
    worker.join(timeout)
    return result[0] if result else None


def _request_features(url, timeout):
    deadline = _time.monotonic() + timeout
    try:
        request = _urllib_request.Request(url, headers={"Accept": "application/json"})
        with _urllib_request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            chunks = []
            size = 0
            while _time.monotonic() < deadline:
                chunk = response.read1(16 * 1024)
                if not chunk:
                    return b"".join(chunks).decode("utf-8")
                size += len(chunk)
                if size > _MAX_FEATURES_BODY:
                    return None
                chunks.append(chunk)
    except Exception:
        pass
    return None


def _feature_loop(chat_ref, settings, stop):
    """Fetch once now (retrying once), then again with the key's bucket once
    keys load, retrying with a backoff that grows to the refresh interval,
    and re-check every refresh interval with a fetch that can only turn
    flags off. Ends when ``stop`` is set."""
    endpoint, timeout, refresh, key_poll = settings
    max_backoff = max(refresh, 1.0)
    chat = chat_ref()
    if chat is None:
        return
    _fetch_features(chat, endpoint, timeout, False) or stop.is_set() or _fetch_features(
        chat, endpoint, timeout, False
    )
    del chat
    next_recheck = _time.monotonic() + refresh
    retry_at = 0.0
    backoff = 1.0
    while not stop.is_set():
        chat = chat_ref()
        if chat is None:
            return
        keyed = False
        try:
            now = _time.monotonic()
            if chat._feature_refetch_due():
                if now >= retry_at:
                    if _fetch_features(chat, endpoint, timeout, False):
                        backoff = 1.0
                        next_recheck = now + refresh
                    else:
                        retry_at = now + backoff
                        backoff = min(backoff * 2, max_backoff)
            elif refresh and now >= next_recheck:
                _fetch_features(chat, endpoint, timeout, True)
                next_recheck = now + refresh
            keyed = chat._feature_bucket() is not None and not chat._feature_refetch_due()
        except Exception:
            pass
        del chat
        if keyed and not refresh:
            return
        # Until a response for the key's bucket applies, watch for keys to
        # load; afterwards, wake only for the re-check.
        wait = max(0.0, next_recheck - _time.monotonic()) if keyed else key_poll
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
