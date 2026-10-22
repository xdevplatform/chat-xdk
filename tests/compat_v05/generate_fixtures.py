"""Write compatibility fixtures with a released chatxdk 0.5.x.

One send of each kind (message, message with entities, message with a file,
reply, reaction add and remove, edit) and a file encrypted with encrypt_stream.
The reply and the edit are made twice: from explicit fields, and from the
event of the first message as the backend relays it. The Rust compatibility
tests check that the current SDK decrypts and verifies them, and that its v0
sends match them on the wire.

Run it with the released package installed, never the in-repo one:

    python -m venv /tmp/v05 && /tmp/v05/bin/pip install chatxdk==0.5.2
    /tmp/v05/bin/python tests/compat_v05/generate_fixtures.py tests/fixtures/compat_v0_5_2.json
"""

import base64
import importlib.metadata
import json
import struct
import sys

from chat_xdk import Chat

SENDER = "1001"
CONVERSATION = "1001:2002"
KEY_VERSION = "1700000000123"
SIGNING_KEY_VERSION = "1"
CONVERSATION_KEY = bytes(range(32))
TARGET_SEQUENCE_ID = "100"
MEDIA = {
    "attachment_type": "media",
    "media_hash_key": "compat-file-1",
    "width": 640,
    "height": 480,
    "filesize_bytes": 4096,
    "filename": "compat.jpg",
    "media_type": 1,
}


def b64(data):
    return base64.b64encode(bytes(data)).decode()


def thrift_string(field_id, value):
    data = value.encode()
    return struct.pack(">bhi", 11, field_id, len(data)) + data


def thrift_struct(field_id, body):
    return struct.pack(">bh", 12, field_id) + body


def relayed_event(payload, sequence_id):
    """The base64 MessageEvent the backend relays for `payload`: the sent
    MessageCreateEvent and MessageEventSignature with the sequence id the
    backend assigns. Thrift binary protocol, field ids from thrift/event.thrift."""
    create = base64.b64decode(payload.encrypted_content)
    signature = base64.b64decode(payload.encoded_event_signature)
    event = (
        thrift_string(1, sequence_id)
        + thrift_string(2, payload.message_id)
        + thrift_string(3, SENDER)
        + thrift_string(4, CONVERSATION)
        + thrift_struct(7, thrift_struct(1, create) + b"\x00")
        + thrift_struct(9, signature)
        + b"\x00"
    )
    return base64.b64encode(event).decode()


def send(kind, expected, payload):
    return {
        "kind": kind,
        "expected": expected,
        "message_id": payload.message_id,
        "encrypted_content": payload.encrypted_content,
        "signature": payload.signature,
        "encoded_event_signature": payload.encoded_event_signature,
        "signature_version": payload.signature_info.signature_version,
        "public_key_version": payload.signature_info.public_key_version,
        "conversation_key_version": payload.conversation_key_version,
    }


def main(out_path):
    chat = Chat()
    registration = chat.generate_keypairs()
    common = dict(
        sender_id=SENDER,
        signing_key_version=SIGNING_KEY_VERSION,
        conversation_key=CONVERSATION_KEY,
        conversation_key_version=KEY_VERSION,
    )
    target = dict(conversation_id=CONVERSATION, target_message_sequence_id=TARGET_SEQUENCE_ID)
    original = chat.encrypt_message(CONVERSATION, "hello from 0.5", **common)
    target_event = relayed_event(original, TARGET_SEQUENCE_ID)
    sends = [
        send("message", "hello from 0.5", original),
        send(
            "message_with_entities",
            "see https://x.com",
            chat.encrypt_message(CONVERSATION, "see https://x.com", entities=[(4, 17, "url")], **common),
        ),
        send(
            "reply",
            "a reply",
            chat.encrypt_reply(
                CONVERSATION,
                "a reply",
                reply_to_sequence_id=TARGET_SEQUENCE_ID,
                reply_to_sender_id=int(SENDER),
                reply_to_text="hello from 0.5",
                **common,
            ),
        ),
        send("reaction_add", "\U0001f44d", chat.encrypt_add_reaction(emoji="\U0001f44d", **target, **common)),
        send("reaction_remove", "\U0001f44d", chat.encrypt_remove_reaction(emoji="\U0001f44d", **target, **common)),
        send("edit", "edited text", chat.encrypt_edit(updated_text="edited text", **target, **common)),
        send(
            "message_with_file",
            "a file",
            chat.encrypt_message(CONVERSATION, "a file", attachments=[MEDIA], **common),
        ),
        send(
            "reply_from_event",
            "a reply to the event",
            chat.encrypt_reply(CONVERSATION, "a reply to the event", target_event, **common),
        ),
        send(
            "edit_from_event",
            "edited from the event",
            chat.encrypt_edit(target_event, "edited from the event", **common),
        ),
    ]
    file_plaintext = b"chat-xdk compatibility file\n" * 90
    fixture = {
        "chatxdk_version": importlib.metadata.version("chatxdk"),
        "sender_id": SENDER,
        "conversation_id": CONVERSATION,
        "conversation_key_b64": b64(CONVERSATION_KEY),
        "conversation_key_version": KEY_VERSION,
        "signing_key_version": SIGNING_KEY_VERSION,
        "target_sequence_id": TARGET_SEQUENCE_ID,
        "target_event_b64": target_event,
        "media_attachment": MEDIA,
        "private_keys_b64": b64(chat.export_keys()),
        "signing_key": {
            "user_id": SENDER,
            "public_key_version": SIGNING_KEY_VERSION,
            "public_key": registration.public_key.signing_public_key,
            "identity_public_key": registration.public_key.public_key,
            "identity_public_key_signature": registration.public_key.identity_public_key_signature,
        },
        "sends": sends,
        "file": {
            "plaintext_b64": b64(file_plaintext),
            "ciphertext_b64": b64(chat.encrypt_stream(file_plaintext, CONVERSATION_KEY)),
        },
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
