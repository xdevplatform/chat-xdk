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
    "hex_to_bytes",
]
