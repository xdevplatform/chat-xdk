import base64
import json
import os
import sys
import unittest
import uuid

# Keep every chat's automatic feature fetch off the network.
os.environ.setdefault("CHAT_XDK_FEATURES_ENDPOINT", "http://127.0.0.1:9/2/chat/features")


def _repo_root() -> str:
    # .../crates/pyo3/python/tests/test_sdk_vectors.py -> repo root is 4 levels up
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _load_vectors() -> dict:
    path = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _fixture_signing_keys(v: dict) -> list[dict]:
    return _signing_keys_for(v, v["event_sender_id"])


def _signing_keys_for(v: dict, *user_ids: str) -> list[dict]:
    """The fixture signing key, registered to each of ``user_ids``."""
    return [{
        "user_id": user_id,
        "public_key_version": v["event_signing_key_version"],
        "public_key": v["signing_public_b64"],
        "identity_public_key": v["identity_public_b64"],
        "identity_public_key_signature": v["identity_public_key_signature_b64"],
    } for user_id in user_ids]


def _delivered(event_b64: str, sequence_id: str) -> str:
    """``event_b64`` as delivered: with the sequence id the server assigns,
    prepended as Thrift string field 1."""
    data = sequence_id.encode("utf-8")
    field = b"\x0b\x00\x01" + len(data).to_bytes(4, "big") + data
    return base64.b64encode(field + base64.b64decode(event_b64)).decode("ascii")


def _media(media_hash_key: str) -> dict:
    return {
        "attachment_type": "media",
        "media_hash_key": media_hash_key,
        "width": 4,
        "height": 3,
        "filesize_bytes": 64,
        "filename": f"{media_hash_key}.jpg",
        "media_type": 1,
    }


QUICK_REPLY_REQUEST = {
    "request": {
        "options": {
            "id": "qr-1",
            "options": [
                {"id": "yes", "label": "Yes", "metadata": "m-yes", "description": "Confirm"},
                {"id": "no", "label": "No", "metadata": "m-no", "description": "Decline"},
            ],
        }
    }
}

QUICK_REPLY_RESPONSE = {
    "response": {
        "options": {"request_id": "qr-1", "metadata": "m-yes", "selected_option_id": "yes"}
    }
}


class TestPythonSdkVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure the in-repo Python package is importable.
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)

        try:
            from chat_xdk import Chat  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")

    def test_public_keys_and_signature_match_fixture(self):
        from chat_xdk import Chat, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        keys = chat.get_public_keys()
        self.assertEqual(keys.identity, v["identity_public_b64"])
        self.assertEqual(keys.signing, v["signing_public_b64"])
        self.assertIsInstance(keys.version, str)

        sig_bytes = chat.sign(v["message_utf8"].encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        self.assertEqual(sig_b64, v["signature_b64"])

        self.assertTrue(chat.verify(v["signing_public_b64"], sig_bytes, v["message_utf8"].encode("utf-8")))
        self.assertFalse(chat.verify(v["signing_public_b64"], sig_bytes, (v["message_utf8"] + "!").encode("utf-8")))

    def test_ecies_conversation_key_roundtrip(self):
        from chat_xdk import Chat, ConversationKeyChangeParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        public_keys = [{"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}]
        result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                public_keys, conversation_id="conv-1", sender_id="me", signing_key_version="1"
            )
        )
        encrypted_key_b64 = result["participant_keys"][0]["encrypted_key"]

        decrypted_ckey = chat.decrypt_conversation_key(encrypted_key_b64)
        self.assertEqual(decrypted_ckey, result["conversation_key"])

    def test_encrypt_message_smoke_and_invalid_import(self):
        from chat_xdk import Chat, EncryptMessageParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()

        # Invalid import payload (not 32 or 64 bytes)
        with self.assertRaises(Exception):
            chat.import_keys(ImportKeysParams(b"\x00"))

        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_message(
            EncryptMessageParams(
                "conv-1", "hello from python",
                sender_id=v["event_sender_id"],
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        )

        self.assertTrue(payload.message_id)
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.conversation_key_version is not None)
        self.assertTrue(payload.signature_info.public_key_version is not None)

    def test_decrypt_events_fixture_vectors_batch_and_single(self):
        from chat_xdk import Chat, DecryptEventParams, DecryptEventsParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()  # default reject-unverified policy
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))

        signing_keys = _fixture_signing_keys(v)

        # Batch path never raises: the garbage event is collected as an
        # indexed error, the signed KeyChange's key is adopted, and the
        # message verifies with the fixture text.
        result = chat.decrypt_events(
            DecryptEventsParams(
                [v["event_key_change_b64"], v["event_message_b64"], v["event_garbage_b64"]],
                signing_keys=signing_keys,
            )
        )
        self.assertEqual(list(result["errors"].keys()), ["2"])

        ck_version = v["event_conversation_key_version"]
        self.assertEqual(result["conversation_keys"]["latest_version"], ck_version)
        self.assertEqual(
            bytes(result["conversation_keys"]["keys"][ck_version]),
            base64.b64decode(v["conversation_key_b64"]),
        )

        key_changes = [m["event"] for m in result["messages"] if m["event"]["type"] == "KeyChange"]
        self.assertEqual(len(key_changes), 1)
        self.assertTrue(key_changes[0]["verified"])
        self.assertEqual(key_changes[0]["key_version"], ck_version)

        messages = [m["event"] for m in result["messages"] if m["event"]["type"] == "Message"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["text"], v["event_message_text"])
        self.assertTrue(messages[0]["verified"])

        # Single-event path with pre-cached keys verifies the same message ...
        cached = {ck_version: bytes(result["conversation_keys"]["keys"][ck_version])}
        event = chat.decrypt_event(
            DecryptEventParams(v["event_message_b64"], cached, signing_keys=signing_keys)
        )
        self.assertEqual(event["type"], "Message")
        self.assertEqual(event["content"]["text"], v["event_message_text"])
        self.assertTrue(event["verified"])

        # ... and raises on the garbage event.
        with self.assertRaises(Exception):
            chat.decrypt_event(
                DecryptEventParams(v["event_garbage_b64"], {}, signing_keys=signing_keys)
            )

    def test_key_cache_resolves_omitted_conversation_key(self):
        from chat_xdk import Chat, DecryptEventParams, DecryptEventsParams, EncryptMessageParams, ImportKeysParams, SetIdentityParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        chat.set_identity(SetIdentityParams(v["event_sender_id"], v["event_signing_key_version"]))
        chat.set_cache_keys(True)

        result = chat.decrypt_events(
            DecryptEventsParams([v["event_key_change_b64"]], signing_keys=_fixture_signing_keys(v))
        )
        self.assertEqual(result["errors"], {})

        # No conversation keys passed: decrypt_event takes the key from the cache.
        event = chat.decrypt_event(
            DecryptEventParams(v["event_message_b64"], signing_keys=_fixture_signing_keys(v))
        )
        self.assertEqual(event["content"]["text"], v["event_message_text"])

        # No key passed: the encrypt resolves the cached verified key.
        payload = chat.encrypt_message(EncryptMessageParams(v["event_conversation_id"], "hi"))
        self.assertEqual(
            payload.conversation_key_version, v["event_conversation_key_version"]
        )
        self.assertTrue(payload.encrypted_content)

    def test_key_cache_off_omitted_conversation_key_raises(self):
        from chat_xdk import Chat, DecryptEventsParams, EncryptMessageParams, ImportKeysParams, SetIdentityParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        chat.set_identity(SetIdentityParams(v["event_sender_id"], v["event_signing_key_version"]))

        # Same decrypt, but the cache is off (the default): nothing to resolve.
        result = chat.decrypt_events(
            DecryptEventsParams([v["event_key_change_b64"]], signing_keys=_fixture_signing_keys(v))
        )
        self.assertEqual(result["errors"], {})
        with self.assertRaises(ValueError):
            chat.encrypt_message(EncryptMessageParams(v["event_conversation_id"], "hi"))

    def test_signing_key_store_verifies_when_arg_omitted(self):
        from chat_xdk import Chat, DecryptEventParams, DecryptEventsParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        chat.set_signing_keys(_fixture_signing_keys(v))

        # No signing_keys anywhere: both decrypt paths fall back to the store
        # and still positively verify.
        batch = chat.decrypt_events(DecryptEventsParams([v["event_key_change_b64"]]))
        self.assertEqual(batch["errors"], {})
        extracted = {
            version: bytes(key)
            for version, key in batch["conversation_keys"]["keys"].items()
        }

        event = chat.decrypt_event(DecryptEventParams(v["event_message_b64"], extracted))
        self.assertEqual(event["type"], "Message")
        self.assertEqual(event["content"]["text"], v["event_message_text"])
        self.assertTrue(event["verified"])

    def test_reply_preview_validation_valid_and_forged(self):
        from chat_xdk import Chat, DecryptEventsParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))

        result = chat.decrypt_events(
            DecryptEventsParams(
                [v["event_key_change_b64"], v["event_reply_valid_b64"], v["event_reply_forged_b64"]],
                signing_keys=_fixture_signing_keys(v),
            )
        )
        self.assertEqual(result["errors"], {})

        messages = [m["event"] for m in result["messages"] if m["event"]["type"] == "Message"]
        self.assertEqual(len(messages), 2)
        # Both replies decrypt; the derived preview validates against the
        # embedded raw original, the forged preview text is flagged.
        self.assertEqual(messages[0]["content"]["text"], v["event_reply_text"])
        self.assertEqual(messages[0]["reply_preview_validation"], "Valid")
        self.assertEqual(messages[1]["reply_preview_validation"], "Invalid")

    def test_failure_event_decodes_type_and_rate_limit_tier(self):
        from chat_xdk import Chat, DecryptEventParams

        v = _load_vectors()
        chat = Chat()  # default reject-unverified policy

        # Failure events are unsigned by protocol, so the fixture failure
        # decodes with no conversation or signing keys.
        event = chat.decrypt_event(DecryptEventParams(v["event_failure_b64"], {}))
        self.assertEqual(event["type"], "Failure")
        self.assertEqual(event["failure"], "RateLimitUpsell")
        self.assertEqual(event["rate_limit_tier"], "Premium")
        self.assertEqual(event["sender_id"], v["event_sender_id"])

    def test_encrypt_reply_derives_preview_from_raw_event(self):
        from chat_xdk import Chat, EncryptReplyParams, ImportKeysParams, SetIdentityParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        chat.set_identity(SetIdentityParams(v["event_sender_id"], v["event_signing_key_version"]))

        payload = chat.encrypt_reply(
            EncryptReplyParams(
                v["event_conversation_id"],
                "a reply",
                v["event_message_b64"],
                conversation_key=base64.b64decode(v["conversation_key_b64"]),
                conversation_key_version=v["event_conversation_key_version"],
            )
        )
        # The SDK mints the message id as a UUID.
        uuid.UUID(payload.message_id)
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.encoded_event_signature)

    def _decrypt_own(self, chat, v, payload) -> dict:
        from chat_xdk import DecryptEventParams

        event = chat.decrypt_event(
            DecryptEventParams(
                payload.event_b64,
                {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])},
                signing_keys=_fixture_signing_keys(v),
            )
        )
        self.assertTrue(event["verified"])
        return event["content"]

    def _identity_chat(self, v):
        from chat_xdk import Chat, ImportKeysParams, SetIdentityParams

        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))
        chat.set_identity(SetIdentityParams(v["event_sender_id"], v["event_signing_key_version"]))
        return chat

    def test_encrypt_message_quick_reply_round_trips(self):
        from chat_xdk import EncryptMessageParams

        v = _load_vectors()
        chat = self._identity_chat(v)
        key = base64.b64decode(v["conversation_key_b64"])
        key_version = v["event_conversation_key_version"]

        for quick_reply in (QUICK_REPLY_REQUEST, QUICK_REPLY_RESPONSE):
            payload = chat.encrypt_message(
                EncryptMessageParams(
                    v["event_conversation_id"],
                    "Continue?",
                    conversation_key=key,
                    conversation_key_version=key_version,
                    quick_reply=quick_reply,
                )
            )
            content = self._decrypt_own(chat, v, payload)
            self.assertEqual(content["text"], "Continue?")
            self.assertEqual(content["quick_reply"], quick_reply)

            # A received quick reply can be sent back unchanged.
            resent = chat.encrypt_message(
                EncryptMessageParams(
                    v["event_conversation_id"],
                    "again",
                    conversation_key=key,
                    conversation_key_version=key_version,
                    quick_reply=content["quick_reply"],
                )
            )
            self.assertEqual(self._decrypt_own(chat, v, resent)["quick_reply"], quick_reply)

        plain = chat.encrypt_message(
            EncryptMessageParams(
                v["event_conversation_id"],
                "no quick reply",
                conversation_key=key,
                conversation_key_version=key_version,
            )
        )
        self.assertNotIn("quick_reply", self._decrypt_own(chat, v, plain))

    def test_encrypt_reply_quick_reply_round_trips(self):
        from chat_xdk import EncryptReplyParams

        v = _load_vectors()
        chat = self._identity_chat(v)

        payload = chat.encrypt_reply(
            EncryptReplyParams(
                v["event_conversation_id"],
                "Yes",
                None,
                reply_to_sequence_id="seq-orig",
                reply_to_sender_id=int(v["event_sender_id"]),
                reply_to_text="Continue?",
                conversation_key=base64.b64decode(v["conversation_key_b64"]),
                conversation_key_version=v["event_conversation_key_version"],
                quick_reply=QUICK_REPLY_RESPONSE,
            )
        )
        content = self._decrypt_own(chat, v, payload)
        self.assertEqual(content["quick_reply"], QUICK_REPLY_RESPONSE)

    def test_encrypt_message_rejects_invalid_quick_reply(self):
        from chat_xdk import EncryptMessageParams

        v = _load_vectors()
        chat = self._identity_chat(v)

        both = {**QUICK_REPLY_REQUEST, **QUICK_REPLY_RESPONSE}
        for invalid in ({}, both):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "Invalid quick_reply"
            ):
                chat.encrypt_message(
                    EncryptMessageParams(
                        v["event_conversation_id"],
                        "bad",
                        conversation_key=base64.b64decode(v["conversation_key_b64"]),
                        conversation_key_version=v["event_conversation_key_version"],
                        quick_reply=invalid,
                    )
                )

    def test_quick_reply_typed_dicts_build_the_sent_shape(self):
        from chat_xdk import (
            QuickReply,
            QuickReplyOption,
            QuickReplyOptionsRequest,
            QuickReplyOptionsResponse,
            QuickReplyRequest,
            QuickReplyResponse,
        )

        request = QuickReply(
            request=QuickReplyRequest(
                options=QuickReplyOptionsRequest(
                    id="qr-1",
                    options=[
                        QuickReplyOption(
                            id="yes", label="Yes", metadata="m-yes", description="Confirm"
                        ),
                        QuickReplyOption(
                            id="no", label="No", metadata="m-no", description="Decline"
                        ),
                    ],
                )
            )
        )
        response = QuickReply(
            response=QuickReplyResponse(
                options=QuickReplyOptionsResponse(
                    request_id="qr-1", metadata="m-yes", selected_option_id="yes"
                )
            )
        )
        self.assertEqual(request, QUICK_REPLY_REQUEST)
        self.assertEqual(response, QUICK_REPLY_RESPONSE)

    def _open_media(self, event_b64, keys, media_hash_key, encrypted_b64):
        """Decrypt media whole and in 700-byte chunks, checking both agree."""
        from chat_xdk import Chat, DecryptFileParams, FileDecryptorParams

        chat = Chat()
        encrypted = base64.b64decode(encrypted_b64)
        whole = chat.decrypt_file(DecryptFileParams(encrypted, event_b64, keys, media_hash_key))
        decryptor = chat.file_decryptor(FileDecryptorParams(event_b64, keys, media_hash_key))
        incremental = b"".join(
            decryptor.push(encrypted[i:i + 700]) for i in range(0, len(encrypted), 700)
        ) + decryptor.finish()
        self.assertEqual(whole, incremental)
        return whole

    def test_message_key_event_decrypts_with_the_conversation_key(self):
        from chat_xdk import Chat, DecryptEventParams, hex_to_bytes

        v = _load_vectors()
        event = Chat().decrypt_event(
            DecryptEventParams(
                v["event_message_key_b64"],
                {v["message_key_conversation_key_version"]: hex_to_bytes(v["message_key_conversation_key_hex"])},
                signing_keys=_signing_keys_for(v, v["message_key_sender_id"]),
            )
        )
        self.assertEqual(event["type"], "Message")
        self.assertTrue(event["verified"])
        self.assertEqual(event["content"]["text"], v["event_message_key_text"])
        self.assertEqual(
            [h["media_hash_key"] for h in event["media_hashes"]],
            [v["media_first_hash_key"], v["media_second_hash_key"]],
        )

    def test_one_media_file_opens_from_its_message(self):
        from chat_xdk import hex_to_bytes

        v = _load_vectors()
        keys = {
            v["message_key_short_conversation_key_version"]:
                hex_to_bytes(v["message_key_short_conversation_key_hex"]),
        }
        self.assertEqual(
            self._open_media(
                v["event_message_key_short_b64"], keys, v["media_short_hash_key"],
                v["media_short_encrypted_b64"],
            ),
            base64.b64decode(v["media_short_plaintext_b64"]),
        )

    def test_several_media_files_open_from_their_message(self):
        from chat_xdk import hex_to_bytes

        v = _load_vectors()
        keys = {v["message_key_conversation_key_version"]: hex_to_bytes(v["message_key_conversation_key_hex"])}
        for name in ("first", "second"):
            with self.subTest(media=name):
                self.assertEqual(
                    self._open_media(
                        v["event_message_key_b64"], keys, v[f"media_{name}_hash_key"],
                        v[f"media_{name}_encrypted_b64"],
                    ),
                    base64.b64decode(v[f"media_{name}_plaintext_b64"]),
                )

    def test_link_card_images_open_from_their_message(self):
        from chat_xdk import hex_to_bytes

        v = _load_vectors()
        keys = {v["message_key_conversation_key_version"]: hex_to_bytes(v["message_key_conversation_key_hex"])}
        for name in ("banner", "favicon"):
            with self.subTest(image=name):
                self.assertEqual(
                    self._open_media(
                        v["event_link_card_b64"], keys, v[f"media_{name}_hash_key"],
                        v[f"media_{name}_encrypted_b64"],
                    ),
                    base64.b64decode(v[f"media_{name}_plaintext_b64"]),
                )

    def test_conversation_key_media_opens_from_its_message(self):
        v = _load_vectors()
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        self.assertEqual(
            self._open_media(
                v["event_conversation_key_media_b64"], keys, v["media_conversation_key_hash_key"],
                v["media_conversation_key_encrypted_b64"],
            ),
            base64.b64decode(v["media_conversation_key_plaintext_b64"]),
        )

    def test_media_errors_say_what_to_pass(self):
        from chat_xdk import Chat, DecryptFileParams, FileDecryptorParams, hex_to_bytes

        v = _load_vectors()
        chat = Chat()
        mk_keys = {v["message_key_conversation_key_version"]: hex_to_bytes(v["message_key_conversation_key_hex"])}
        fixture_keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        first = base64.b64decode(v["media_first_encrypted_b64"])
        second = base64.b64decode(v["media_second_encrypted_b64"])
        first_hash = v["media_first_hash_key"]
        cases = [
            (first, v["event_message_key_b64"], fixture_keys, first_hash,
             f"no key for version '{v['message_key_conversation_key_version']}'"),
            (first, v["event_message_key_b64"], mk_keys, "not-a-hash-key", "is not in the message"),
            (first, v["event_key_change_b64"], mk_keys, first_hash, "the event is not a message"),
            (first, v["event_message_b64"], fixture_keys, first_hash, "the message has no media"),
            (second, v["event_message_key_b64"], mk_keys, first_hash,
             f"encrypted file of media_hash_key '{first_hash}'"),
            (first[:len(first) // 2], v["event_message_key_b64"], mk_keys, first_hash, "truncated"),
            (first, v["event_unencrypted_b64"], mk_keys, v["media_unencrypted_hash_key"],
             "the message is not encrypted"),
            (first, v["event_message_key_b64"], {v["message_key_conversation_key_version"]: b"short"},
             first_hash, "is not 32 bytes"),
        ]
        for encrypted, event, keys, media_hash_key, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(ValueError) as ctx:
                    chat.decrypt_file(DecryptFileParams(encrypted, event, keys, media_hash_key))
                self.assertIn(expected, str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            chat.file_decryptor(
                FileDecryptorParams(v["event_message_key_b64"], fixture_keys, first_hash)
            )
        self.assertIn("no key for version", str(ctx.exception))

    def test_message_key_event_decrypts_in_a_batch_with_its_key_change(self):
        from chat_xdk import Chat, DecryptEventsParams, hex_to_bytes, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        result = chat.decrypt_events(
            DecryptEventsParams(
                [v["event_key_change_message_key_b64"], v["event_message_key_b64"]],
                signing_keys=_signing_keys_for(v, v["event_sender_id"], v["message_key_sender_id"]),
            )
        )
        self.assertEqual(result["errors"], {})
        version = v["message_key_conversation_key_version"]
        ckey = bytes(result["conversation_keys"]["keys"][version])
        self.assertEqual(ckey, hex_to_bytes(v["message_key_conversation_key_hex"]))
        texts = [
            m["event"]["content"]["text"]
            for m in result["messages"]
            if m["event"]["type"] == "Message"
        ]
        self.assertEqual(texts, [v["event_message_key_text"]])
        batch_keys = {k: bytes(key) for k, key in result["conversation_keys"]["keys"].items()}
        self.assertEqual(
            self._open_media(
                v["event_message_key_b64"], batch_keys, v["media_second_hash_key"],
                v["media_second_encrypted_b64"],
            ),
            base64.b64decode(v["media_second_plaintext_b64"]),
        )

    def test_short_sender_message_key_event_verifies_at_v11(self):
        from chat_xdk import Chat, DecryptEventParams, hex_to_bytes

        v = _load_vectors()
        event = Chat().decrypt_event(
            DecryptEventParams(
                v["event_message_key_short_b64"],
                {
                    v["message_key_short_conversation_key_version"]:
                        hex_to_bytes(v["message_key_short_conversation_key_hex"]),
                },
                signing_keys=_signing_keys_for(v, v["message_key_short_sender_id"]),
            )
        )
        self.assertTrue(event["verified"])
        self.assertEqual(event["content"]["text"], v["event_message_key_short_text"])

    def test_reply_carrying_a_message_key_validates_and_opens_the_quoted_media(self):
        from chat_xdk import Chat, DecryptEventParams

        v = _load_vectors()
        chat = Chat()
        ckey = base64.b64decode(v["conversation_key_b64"])
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_reply_message_key_b64"],
                {v["event_conversation_key_version"]: ckey},
                signing_keys=_signing_keys_for(v, v["event_sender_id"], v["message_key_sender_id"]),
            )
        )
        self.assertTrue(event["verified"])
        self.assertEqual(event["content"]["text"], v["event_reply_message_key_text"])
        self.assertEqual(event["reply_preview_validation"], "Valid")
        self.assertEqual(
            self._open_media(
                v["event_reply_message_key_b64"], {v["event_conversation_key_version"]: ckey},
                v["media_first_hash_key"], v["media_first_encrypted_b64"],
            ),
            base64.b64decode(v["media_first_plaintext_b64"]),
        )

    def test_known_signature_covers_the_contents_encryption_version(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        signature = base64.b64decode(v["signature_v10_cev1_b64"])
        public_key = v["signature_v10_cev1_public_key_b64"]
        self.assertTrue(chat.verify(public_key, signature, v["payload_message_v10_cev1"].encode()))
        self.assertFalse(chat.verify(public_key, signature, v["payload_message_v10"].encode()))

    def _send_files(self, chat, v, text, attachments):
        """Send a v1 message with ``attachments``, check it verifies, and
        return its payload."""
        from chat_xdk import EncryptMessageParams

        chat._apply_feature_config('{"features":{"v1_send":true}}', chat._feature_bucket())
        payload = chat.encrypt_message(
            EncryptMessageParams(
                v["event_conversation_id"],
                text,
                conversation_key=base64.b64decode(v["conversation_key_b64"]),
                conversation_key_version=v["event_conversation_key_version"],
                attachments=attachments,
            )
        )
        self.assertEqual(payload.signature_info.signature_version, "10")
        self.assertEqual(self._decrypt_own(chat, v, payload)["text"], text)
        return payload

    def test_files_encrypted_from_the_payload_open_from_the_sent_message(self):
        from chat_xdk import (
            Chat,
            DecryptFileParams,
            EncryptFileParams,
            FileDecryptorParams,
            FileEncryptorParams,
        )

        v = _load_vectors()
        chat = self._identity_chat(v)
        key = base64.b64decode(v["conversation_key_b64"])
        keys = {v["event_conversation_key_version"]: key}
        photos = [b"\x01" * 3000, b"\x02" * 5000]
        payload = self._send_files(chat, v, "two photos", [_media("photo-0"), _media("photo-1")])

        # A session with no identity encrypts the files from the payload.
        worker = Chat()
        first = worker.encrypt_file(EncryptFileParams(photos[0], payload.event_b64, keys, "photo-0"))
        # Randomized nonces: two encryptions differ.
        self.assertNotEqual(
            worker.encrypt_file(EncryptFileParams(photos[0], payload.event_b64, keys, "photo-0")),
            first,
        )
        encryptor = worker.file_encryptor(FileEncryptorParams(payload.event_b64, keys, "photo-1"))
        second = b"".join(
            encryptor.push(photos[1][i:i + 700]) for i in range(0, len(photos[1]), 700)
        ) + encryptor.finish()

        for name, encrypted, plaintext in (("photo-0", first, photos[0]), ("photo-1", second, photos[1])):
            with self.subTest(media=name):
                self.assertEqual(
                    self._open_media(payload.event_b64, keys, name, base64.b64encode(encrypted)),
                    plaintext,
                )

        with self.assertRaises(ValueError):
            chat.decrypt_file(DecryptFileParams(second, payload.event_b64, keys, "photo-0"))
        wrong_key = bytearray(key)
        wrong_key[31] ^= 0xFF
        with self.assertRaises(ValueError) as ctx:
            chat.decrypt_file(
                DecryptFileParams(
                    first, payload.event_b64,
                    {v["event_conversation_key_version"]: bytes(wrong_key)}, "photo-0",
                )
            )
        self.assertIn("does not decrypt the message", str(ctx.exception))
        truncated = chat.file_decryptor(FileDecryptorParams(payload.event_b64, keys, "photo-1"))
        truncated.push(second[:-4])
        with self.assertRaises(ValueError) as ctx:
            truncated.finish()
        self.assertIn("truncated", str(ctx.exception))

    def test_link_card_images_take_the_cards_key(self):
        from chat_xdk import EncryptFileParams

        v = _load_vectors()
        chat = self._identity_chat(v)
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        card = {
            "attachment_type": "url",
            "url": "https://example.com",
            "banner_image": {"media_hash_key": "banner", "filesize_bytes": 12, "filename": "banner.png"},
            "favicon_image": {"media_hash_key": "favicon", "filesize_bytes": 13, "filename": "favicon.png"},
        }
        payload = self._send_files(chat, v, "a link", [card])
        for name, plaintext in (("banner", b"banner bytes"), ("favicon", b"favicon bytes")):
            with self.subTest(image=name):
                encrypted = chat.encrypt_file(EncryptFileParams(plaintext, payload.event_b64, keys, name))
                self.assertEqual(
                    self._open_media(payload.event_b64, keys, name, base64.b64encode(encrypted)),
                    plaintext,
                )

    def test_a_rebuilt_message_keeps_its_encrypted_files_valid(self):
        from chat_xdk import EncryptFileParams

        v = _load_vectors()
        chat = self._identity_chat(v)
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        draft = self._send_files(chat, v, "draft", [_media("photo-0"), _media("photo-1")])
        encrypted = chat.encrypt_file(EncryptFileParams(b"photo", draft.event_b64, keys, "photo-1"))

        rebuilt = self._send_files(chat, v, "final text", [_media("photo-0"), _media("photo-1")])
        self.assertEqual(rebuilt.message_id, draft.message_id)
        self.assertEqual(str(uuid.UUID(rebuilt.message_id)), rebuilt.message_id)
        self.assertEqual(
            self._open_media(rebuilt.event_b64, keys, "photo-1", base64.b64encode(encrypted)),
            b"photo",
        )

    def test_a_reply_encrypts_its_own_files_but_not_the_quoted_ones(self):
        from chat_xdk import EncryptFileParams, EncryptReplyParams

        v = _load_vectors()
        chat = self._identity_chat(v)
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        original = self._send_files(chat, v, "a photo", [_media("original-photo")])
        with self.assertRaisesRegex(ValueError, "reply_to_event carries no sequence_id"):
            chat.encrypt_reply(
                EncryptReplyParams(
                    v["event_conversation_id"],
                    "too early",
                    original.event_b64,
                    conversation_key=base64.b64decode(v["conversation_key_b64"]),
                    conversation_key_version=v["event_conversation_key_version"],
                )
            )
        reply = chat.encrypt_reply(
            EncryptReplyParams(
                v["event_conversation_id"],
                "and mine",
                _delivered(original.event_b64, "100"),
                conversation_key=base64.b64decode(v["conversation_key_b64"]),
                conversation_key_version=v["event_conversation_key_version"],
                attachments=[_media("reply-photo")],
            )
        )
        encrypted = chat.encrypt_file(EncryptFileParams(b"mine", reply.event_b64, keys, "reply-photo"))
        self.assertEqual(
            self._open_media(reply.event_b64, keys, "reply-photo", base64.b64encode(encrypted)),
            b"mine",
        )
        with self.assertRaisesRegex(ValueError, "is media the reply quotes"):
            chat.encrypt_file(EncryptFileParams(b"x", reply.event_b64, keys, "original-photo"))

    def test_a_message_with_files_needs_an_identity(self):
        from chat_xdk import Chat, EncryptMessageParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))
        key = base64.b64decode(v["conversation_key_b64"])
        with self.assertRaisesRegex(ValueError, "call set_identity\\(\\) first"):
            chat.encrypt_message(
                EncryptMessageParams(
                    v["event_conversation_id"],
                    "a photo",
                    conversation_key=key,
                    conversation_key_version=v["event_conversation_key_version"],
                    attachments=[_media("photo")],
                )
            )
        payload = chat.encrypt_message(
            EncryptMessageParams(
                v["event_conversation_id"],
                "a photo",
                sender_id=v["event_sender_id"],
                signing_key_version=v["event_signing_key_version"],
                conversation_key=key,
                conversation_key_version=v["event_conversation_key_version"],
                attachments=[_media("photo")],
            )
        )
        self.assertEqual(self._decrypt_own(chat, v, payload)["text"], "a photo")
