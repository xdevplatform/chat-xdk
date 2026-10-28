"""Check that a released chatxdk 0.5.x reads the current SDK's v0 sends.

Reads the JSON write_v0_sends.py produced. Every send must decrypt and verify
(the default reject-unverified policy raises otherwise) and carry its expected
text or emoji, and the message's file and the files encrypted with
encrypt_file_with_key must open with decrypt_stream under the conversation
key. Run it with the released package installed:

    /tmp/v05/bin/python tests/compat_v05/verify_with_v05.py /tmp/v0_sends.json
"""

import base64
import importlib.metadata
import json
import sys

from chat_xdk import Chat


def main(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    version = importlib.metadata.version("chatxdk")
    conversation_key = base64.b64decode(data["conversation_key_b64"])
    keys = {data["conversation_key_version"]: conversation_key}
    chat = Chat()
    for send in data["sends"]:
        event = chat.decrypt_event(send["event_b64"], keys, [data["signing_key"]])
        assert event["type"] == "Message", (send["kind"], event)
        assert event["verified"] is True, (send["kind"], event)
        content = json.dumps(event["content"], ensure_ascii=False)
        assert send["expected"] in content, (send["kind"], content)
        print(f"chatxdk {version} reads {send['kind']}")

    ciphertext = base64.b64decode(data["file"]["ciphertext_b64"])
    plaintext = base64.b64decode(data["file"]["plaintext_b64"])
    assert bytes(chat.decrypt_stream(ciphertext, conversation_key)) == plaintext
    print(f"chatxdk {version} reads the file")

    for name, entry in data["files_with_key"].items():
        ciphertext = base64.b64decode(entry["ciphertext_b64"])
        plaintext = base64.b64decode(entry["plaintext_b64"])
        assert bytes(chat.decrypt_stream(ciphertext, conversation_key)) == plaintext, name
        print(f"chatxdk {version} reads the {name} file encrypted with encrypt_file_with_key")


if __name__ == "__main__":
    main(sys.argv[1])
