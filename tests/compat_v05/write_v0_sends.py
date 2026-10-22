"""Write the current SDK's sends with every feature switch off, for verify_with_v05.py.

Runs against the in-repo package (PYTHONPATH=crates/pyo3/python with the built
extension installed, as in CI). Every send must be v0, the 0.5.x format.

    PYTHONPATH=crates/pyo3/python python tests/compat_v05/write_v0_sends.py /tmp/v0_sends.json
"""

import base64
import json
import sys

import chat_xdk
from chat_xdk import (
    Chat,
    EncryptEditParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    SetIdentityParams,
)

SENDER = "1001"
CONVERSATION = "1001:2002"
KEY_VERSION = "1700000000123"
SIGNING_KEY_VERSION = "1"
CONVERSATION_KEY = bytes(range(32))
TARGET_SEQUENCE_ID = "100"


def b64(data):
    return base64.b64encode(bytes(data)).decode()


def main(out_path):
    # Fetch the feature switches from a closed port, so no server answer can
    # turn v1 sends on here.
    chat_xdk._native._feature_set_default_endpoint("http://127.0.0.1:9/2/chat/features")
    chat = Chat()
    registration = chat.generate_keypairs()
    chat.set_identity(SetIdentityParams(SENDER, SIGNING_KEY_VERSION))
    key = dict(conversation_key=CONVERSATION_KEY, conversation_key_version=KEY_VERSION)
    target = dict(conversation_id=CONVERSATION, target_message_sequence_id=TARGET_SEQUENCE_ID)

    original = chat.encrypt_message(EncryptMessageParams(CONVERSATION, "hello from 0.6", **key))
    with_file = chat.encrypt_message(
        EncryptMessageParams(
            CONVERSATION,
            "a file",
            attachments=[
                {
                    "attachment_type": "media",
                    "media_hash_key": "file-1",
                    "width": 1,
                    "height": 1,
                    "filesize_bytes": 4096,
                    "filename": "file-1.bin",
                    "media_type": 5,
                }
            ],
            **key,
        )
    )
    sends = [
        ("message", "hello from 0.6", original),
        (
            "message_with_entities",
            "see https://x.com",
            chat.encrypt_message(
                EncryptMessageParams(CONVERSATION, "see https://x.com", entities=[(4, 17, "url")], **key)
            ),
        ),
        ("message_with_file", "a file", with_file),
        (
            "reply",
            "a reply",
            chat.encrypt_reply(
                EncryptReplyParams(
                    CONVERSATION,
                    "a reply",
                    original.event_b64,
                    reply_to_sequence_id=TARGET_SEQUENCE_ID,
                    **key,
                )
            ),
        ),
        ("reaction_add", "\U0001f44d", chat.encrypt_add_reaction(EncryptReactionParams(None, "\U0001f44d", **target, **key))),
        (
            "reaction_remove",
            "\U0001f44d",
            chat.encrypt_remove_reaction(EncryptReactionParams(None, "\U0001f44d", **target, **key)),
        ),
        ("edit", "edited text", chat.encrypt_edit(EncryptEditParams(None, "edited text", **target, **key))),
        (
            "edit_from_event",
            "edited from the event",
            chat.encrypt_edit(
                EncryptEditParams(
                    original.event_b64,
                    "edited from the event",
                    target_message_sequence_id=TARGET_SEQUENCE_ID,
                    **key,
                )
            ),
        ),
    ]
    for kind, _, payload in sends:
        assert payload.signature_info.signature_version == "7", (kind, payload.signature_info.signature_version)

    file_plaintext = b"chat-xdk compatibility file\n" * 90
    file_ciphertext = chat.encrypt_file(
        EncryptFileParams(
            file_plaintext,
            with_file.event_b64,
            "file-1",
            conversation_key=CONVERSATION_KEY,
            conversation_key_version=KEY_VERSION,
        )
    )
    out = {
        "conversation_key_b64": b64(CONVERSATION_KEY),
        "conversation_key_version": KEY_VERSION,
        "signing_key": {
            "user_id": SENDER,
            "public_key_version": SIGNING_KEY_VERSION,
            "public_key": registration.public_key.signing_public_key,
            "identity_public_key": registration.public_key.public_key,
            "identity_public_key_signature": registration.public_key.identity_public_key_signature,
        },
        "sends": [
            {"kind": kind, "expected": expected, "event_b64": payload.event_b64} for kind, expected, payload in sends
        ],
        "file": {"plaintext_b64": b64(file_plaintext), "ciphertext_b64": b64(file_ciphertext)},
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main(sys.argv[1])
