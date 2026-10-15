import base64
import json
import os
import sys
import unittest
import uuid


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
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(base64.b64decode(v["private_keys_concat_b64"]))

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
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(base64.b64decode(v["private_keys_concat_b64"]))

        public_keys = [{"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}]
        result = chat.prepare_conversation_key_change(
            public_keys, conversation_id="conv-1", sender_id="me", signing_key_version="1"
        )
        encrypted_key_b64 = result["participant_keys"][0]["encrypted_key"]

        decrypted_ckey = chat.decrypt_conversation_key(encrypted_key_b64)
        self.assertEqual(decrypted_ckey, result["conversation_key"])

    def test_encrypt_message_smoke_and_invalid_import(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()

        # Invalid import payload (not 32 or 64 bytes)
        with self.assertRaises(Exception):
            chat.import_keys(b"\x00")

        chat.import_keys(base64.b64decode(v["private_keys_concat_b64"]))

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_message(
            "conv-1", "hello from python",
            sender_id="me",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertTrue(payload.message_id)
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.conversation_key_version is not None)
        self.assertTrue(payload.signature_info.public_key_version is not None)

    def test_decrypt_events_fixture_vectors_batch_and_single(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()  # default reject-unverified policy
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )

        signing_keys = _fixture_signing_keys(v)

        # Batch path never raises: the garbage event is collected as an
        # indexed error, the signed KeyChange's key is adopted, and the
        # message verifies with the fixture text.
        result = chat.decrypt_events(
            [v["event_key_change_b64"], v["event_message_b64"], v["event_garbage_b64"]],
            signing_keys,
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
        event = chat.decrypt_event(v["event_message_b64"], cached, signing_keys)
        self.assertEqual(event["type"], "Message")
        self.assertEqual(event["content"]["text"], v["event_message_text"])
        self.assertTrue(event["verified"])

        # ... and raises on the garbage event.
        with self.assertRaises(Exception):
            chat.decrypt_event(v["event_garbage_b64"], {}, signing_keys)

    def test_key_cache_resolves_omitted_conversation_key(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )
        chat.set_identity(v["event_sender_id"], v["event_signing_key_version"])
        chat.set_cache_keys(True)

        result = chat.decrypt_events([v["event_key_change_b64"]], _fixture_signing_keys(v))
        self.assertEqual(result["errors"], {})

        # No key passed: the encrypt resolves the cached verified key.
        payload = chat.encrypt_message(v["event_conversation_id"], "hi")
        self.assertEqual(
            payload.conversation_key_version, v["event_conversation_key_version"]
        )
        self.assertTrue(payload.encrypted_content)

    def test_key_cache_off_omitted_conversation_key_raises(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )
        chat.set_identity(v["event_sender_id"], v["event_signing_key_version"])

        # Same decrypt, but the cache is off (the default): nothing to resolve.
        result = chat.decrypt_events([v["event_key_change_b64"]], _fixture_signing_keys(v))
        self.assertEqual(result["errors"], {})
        with self.assertRaises(ValueError):
            chat.encrypt_message(v["event_conversation_id"], "hi")

    def test_signing_key_store_verifies_when_arg_omitted(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )
        chat.set_signing_keys(_fixture_signing_keys(v))

        # No signing_keys argument anywhere: both decrypt paths fall back to
        # the store and still positively verify.
        batch = chat.decrypt_events([v["event_key_change_b64"]])
        self.assertEqual(batch["errors"], {})
        extracted = {
            version: bytes(key)
            for version, key in batch["conversation_keys"]["keys"].items()
        }

        event = chat.decrypt_event(v["event_message_b64"], conversation_keys=extracted)
        self.assertEqual(event["type"], "Message")
        self.assertEqual(event["content"]["text"], v["event_message_text"])
        self.assertTrue(event["verified"])

    def test_reply_preview_validation_valid_and_forged(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )

        result = chat.decrypt_events(
            [v["event_key_change_b64"], v["event_reply_valid_b64"], v["event_reply_forged_b64"]],
            _fixture_signing_keys(v),
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
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()  # default reject-unverified policy

        # Failure events are unsigned by protocol, so the fixture failure
        # decodes with no conversation or signing keys.
        event = chat.decrypt_event(v["event_failure_b64"], {}, [])
        self.assertEqual(event["type"], "Failure")
        self.assertEqual(event["failure"], "RateLimitUpsell")
        self.assertEqual(event["rate_limit_tier"], "Premium")
        self.assertEqual(event["sender_id"], v["event_sender_id"])

    def test_encrypt_reply_derives_preview_from_raw_event(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )
        chat.set_identity(v["event_sender_id"], v["event_signing_key_version"])

        payload = chat.encrypt_reply(
            v["event_conversation_id"],
            "a reply",
            reply_to_event=v["event_message_b64"],
            conversation_key=base64.b64decode(v["conversation_key_b64"]),
            conversation_key_version=v["event_conversation_key_version"],
        )
        # The SDK mints the message id as a UUID.
        uuid.UUID(payload.message_id)
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.encoded_event_signature)

    def _open_media(self, event_b64, keys, media_hash_key, encrypted_b64):
        """Decrypt media whole and in 700-byte chunks, checking both agree."""
        from chat_xdk import Chat

        chat = Chat()
        encrypted = base64.b64decode(encrypted_b64)
        whole = chat.decrypt_stream(encrypted, event_b64, keys, media_hash_key)
        decryptor = chat.stream_decryptor(event_b64, keys, media_hash_key)
        incremental = b"".join(
            decryptor.push(encrypted[i:i + 700]) for i in range(0, len(encrypted), 700)
        ) + decryptor.finish()
        self.assertEqual(whole, incremental)
        return whole

    def test_message_key_event_decrypts_with_the_conversation_key(self):
        from chat_xdk import Chat, hex_to_bytes

        v = _load_vectors()
        event = Chat().decrypt_event(
            v["event_message_key_b64"],
            {v["message_key_conversation_key_version"]: hex_to_bytes(v["message_key_conversation_key_hex"])},
            _signing_keys_for(v, v["message_key_sender_id"]),
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
                v["event_legacy_media_b64"], keys, v["media_legacy_hash_key"],
                v["media_legacy_encrypted_b64"],
            ),
            base64.b64decode(v["media_legacy_plaintext_b64"]),
        )

    def test_media_errors_say_what_to_pass(self):
        from chat_xdk import Chat, hex_to_bytes

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
                    chat.decrypt_stream(encrypted, event, keys, media_hash_key)
                self.assertIn(expected, str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            chat.stream_decryptor(v["event_message_key_b64"], fixture_keys, first_hash)
        self.assertIn("no key for version", str(ctx.exception))

    def test_message_key_event_decrypts_in_a_batch_with_its_key_change(self):
        from chat_xdk import Chat, hex_to_bytes

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(
            base64.b64decode(v["private_keys_concat_b64"]),
            version=v["event_recipient_key_version"],
        )
        result = chat.decrypt_events(
            [v["event_key_change_message_key_b64"], v["event_message_key_b64"]],
            _signing_keys_for(v, v["event_sender_id"], v["message_key_sender_id"]),
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
        from chat_xdk import Chat, hex_to_bytes

        v = _load_vectors()
        event = Chat().decrypt_event(
            v["event_message_key_short_b64"],
            {
                v["message_key_short_conversation_key_version"]:
                    hex_to_bytes(v["message_key_short_conversation_key_hex"]),
            },
            _signing_keys_for(v, v["message_key_short_sender_id"]),
        )
        self.assertTrue(event["verified"])
        self.assertEqual(event["content"]["text"], v["event_message_key_short_text"])

    def test_reply_carrying_a_message_key_validates_and_opens_the_quoted_media(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        ckey = base64.b64decode(v["conversation_key_b64"])
        event = chat.decrypt_event(
            v["event_reply_message_key_b64"],
            {v["event_conversation_key_version"]: ckey},
            _signing_keys_for(v, v["event_sender_id"], v["message_key_sender_id"]),
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

