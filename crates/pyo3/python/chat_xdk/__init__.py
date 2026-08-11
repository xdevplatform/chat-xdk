"""
chat-xdk - Python bindings for the X Chat encryption SDK.

Quick Start:
    from chat_xdk import Chat

    chat = Chat(config_json)  # optional; None or an empty JSON object ("{}")
                              # selects manual key management
    chat.unlock("2580")
    chat.set_identity(my_user_id, signing_key_version)

    # Decrypt webhook events (returns a dict)
    event = chat.decrypt_event(event_b64, conversation_keys, signing_keys)
    if event["type"] == "Message":
        print(event["content"]["text"])

    # Encrypt outgoing messages
    payload = chat.encrypt_message(conversation_id, "Hello!",
                                   conversation_key=key,
                                   conversation_key_version=version)
    # payload.message_id, payload.encrypted_content, payload.signature, etc.
"""

__version__ = "0.1.0"

import re as _re

from chat_xdk._native import (
    Chat,
    PublicKeyRegistration,
    PublicKeyRegistrationPayload,
    PublicKeys,
    SendPayload,
    SignatureInfo,
    StreamDecryptor,
    StreamEncryptor,
    base64_to_bytes,
    bytes_to_base64,
    bytes_to_hex,
    detect_image_dimensions,
    detect_mime_type,
    hex_to_bytes,
)

# Stable token the core emits on invalid-PIN failures ("guesses_remaining=N").
_GUESSES_REMAINING = _re.compile(r"\bguesses_remaining=(\d+)")


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
    "PublicKeyRegistration",
    "PublicKeyRegistrationPayload",
    "PublicKeys",
    "SendPayload",
    "SignatureInfo",
    "StreamDecryptor",
    "StreamEncryptor",
    "base64_to_bytes",
    "bytes_to_base64",
    "bytes_to_hex",
    "detect_image_dimensions",
    "detect_mime_type",
    "guesses_remaining",
    "hex_to_bytes",
]
