import base64
import json
import os
import sys
import unittest


def _repo_root() -> str:
    # .../crates/pyo3/python/tests/test_api.py -> repo root is 4 levels up
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _load_vectors() -> dict:
    path = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Minimal PNG header with a valid IHDR chunk declaring 16x8 dimensions.
_PNG_16x8 = (
    b"\x89PNG\r\n\x1a\n"
    + b"\x00\x00\x00\x0d"  # IHDR length (13)
    + b"IHDR"
    + (16).to_bytes(4, "big")  # width
    + (8).to_bytes(4, "big")  # height
    + b"\x08\x06\x00\x00\x00"  # bit depth, color type, etc.
)

# Minimal JPEG SOI + APP0 marker. detect_mime_type requires >= 12 bytes.
_JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00"


class TestUtilityFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)

        try:
            import chat_xdk  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")

    def test_base64_roundtrip(self):
        from chat_xdk import base64_to_bytes, bytes_to_base64

        data = bytes(range(256))
        encoded = bytes_to_base64(data)
        self.assertIsInstance(encoded, str)
        self.assertEqual(base64_to_bytes(encoded), data)

    def test_base64_invalid_returns_none(self):
        from chat_xdk import base64_to_bytes

        self.assertIsNone(base64_to_bytes("!!!not base64!!!"))

    def test_hex_roundtrip(self):
        from chat_xdk import bytes_to_hex, hex_to_bytes

        data = bytes(range(256))
        encoded = bytes_to_hex(data)
        self.assertIsInstance(encoded, str)
        self.assertEqual(encoded, encoded.lower())
        self.assertEqual(hex_to_bytes(encoded), data)

    def test_hex_invalid_returns_none(self):
        from chat_xdk import hex_to_bytes

        self.assertIsNone(hex_to_bytes("xyz"))

    def test_detect_mime_type_png(self):
        from chat_xdk import detect_mime_type

        self.assertEqual(detect_mime_type(_PNG_16x8), "image/png")

    def test_detect_mime_type_jpeg(self):
        from chat_xdk import detect_mime_type

        self.assertEqual(detect_mime_type(_JPEG_HEADER), "image/jpeg")

    def test_detect_mime_type_unknown_returns_none(self):
        from chat_xdk import detect_mime_type

        self.assertIsNone(detect_mime_type(b"not an image"))

    def test_detect_image_dimensions_png(self):
        from chat_xdk import detect_image_dimensions

        dims = detect_image_dimensions(_PNG_16x8)
        self.assertEqual(tuple(dims), (16, 8))

    def test_detect_image_dimensions_unknown_returns_none(self):
        from chat_xdk import detect_image_dimensions

        self.assertIsNone(detect_image_dimensions(b"not an image"))


class TestApiShapes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)

        try:
            from chat_xdk import Chat  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")

    def _unlocked_chat(self):
        from chat_xdk import Chat

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(base64.b64decode(v["private_keys_concat_b64"]))
        return chat, v

    def test_constructor_accepts_empty_config_document(self):
        from chat_xdk import Chat

        # Documented manual-key-management forms: no config, or any JSON
        # document that is an empty object, whatever its whitespace.
        for config in (None, "{}", " {} ", "{ }", "{\n}"):
            chat = Chat(config) if config is not None else Chat()
            self.assertFalse(chat.is_unlocked())

    def test_x_api_juicebox_config_shape(self):
        from chat_xdk import Chat

        # The X API juicebox_config object (key_store_token_map_json +
        # token_map) must be accepted as-is; the embedded config carries
        # realm public keys and server thresholds that the realms require.
        key_store = json.dumps(
            {
                "realms": [
                    {"id": "aa11", "address": "https://realm-b.example/"},
                    {
                        "id": "bb22",
                        "address": "https://realm-east.example/",
                        "public_key": "e8b2",
                    },
                ],
                "register_threshold": 2,
                "recover_threshold": 2,
                "pin_hashing_mode": "Standard2019",
            }
        )
        x_api_config = json.dumps(
            {
                "key_store_token_map_json": key_store,
                "max_guess_count": 20,
                "token_map": [
                    {
                        "key": "aa11",
                        "value": {"address": "https://realm-b.example/", "token": "t1"},
                    },
                    {
                        "key": "bb22",
                        "value": {"address": "https://realm-east.example/", "token": "t2"},
                    },
                ],
            }
        )
        chat = Chat(x_api_config)
        self.assertFalse(chat.is_unlocked())
        chat.update_config(x_api_config)

        # A malformed embedded config must error, not silently fall back to
        # the lossy token_map derivation.
        bad_config = json.dumps(
            {
                "key_store_token_map_json": "not json",
                "token_map": [
                    {
                        "key": "aa11",
                        "value": {"address": "https://realm-b.example/", "token": "t1"},
                    }
                ],
            }
        )
        with self.assertRaises(ValueError) as ctx:
            chat.update_config(bad_config)
        self.assertIn("Invalid key_store_token_map_json", str(ctx.exception))

    def test_guesses_remaining_parses_invalid_pin_message(self):
        from chat_xdk import guesses_remaining

        # The core's invalid-PIN unlock error carries the stable
        # "guesses_remaining=N" token in the message; 0 means exhausted.
        self.assertEqual(
            guesses_remaining(ValueError("Juicebox error: Invalid PIN: guesses_remaining=3")),
            3,
        )
        self.assertEqual(
            guesses_remaining(ValueError("Juicebox error: Invalid PIN: guesses_remaining=0")),
            0,
        )
        self.assertIsNone(guesses_remaining(ValueError("Juicebox error: Invalid PIN")))
        # The count is read only from the invalid-PIN form, not from unrelated
        # messages that happen to contain the token.
        self.assertIsNone(guesses_remaining(ValueError("Delete failed: guesses_remaining=7")))

    def test_guesses_remaining_none_on_non_pin_errors(self):
        from chat_xdk import Chat, guesses_remaining

        chat = Chat()
        with self.assertRaises(ValueError) as ctx:
            chat.update_config("not json")
        self.assertIsNone(guesses_remaining(ctx.exception))

    def test_pin_accepts_str_bytes_and_bytearray(self):
        from chat_xdk import Chat

        # No Juicebox config is loaded, so a well-typed PIN fails past
        # argument extraction with a runtime error; a mistyped PIN must
        # fail extraction itself.
        for pin in ("1234", b"1234", bytearray(b"1234")):
            chat = Chat()
            with self.assertRaises(Exception) as ctx:
                chat.unlock(pin)
            self.assertNotIsInstance(ctx.exception, TypeError)

        # Only the three documented types are accepted: an int or a sequence
        # of ints must fail extraction, not be silently read as PIN bytes.
        for bad_pin in (1234, [49, 50, 51, 52], (49, 50, 51, 52)):
            chat = Chat()
            with self.assertRaises(TypeError):
                chat.unlock(bad_pin)

    def test_generate_keypairs_shape(self):
        from chat_xdk import Chat

        chat = Chat()
        payload = chat.generate_keypairs()

        self.assertTrue(payload.public_key.public_key)
        self.assertTrue(payload.public_key.signing_public_key)
        self.assertTrue(payload.public_key.identity_public_key_signature)
        self.assertIsInstance(payload.public_key.registration_method, str)
        self.assertIsInstance(payload.generate_version, bool)

    def test_encrypt_message_signature_version_is_7(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_message(
            "conv-1", "hello from python",
            sender_id="me",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertEqual(payload.signature_info.signature_version, "7")
        # The SDK generates and returns the message id.
        self.assertTrue(payload.message_id)

    def test_encrypt_message_key_without_version_rejected(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        # conversation_key and conversation_key_version travel together.
        with self.assertRaises(ValueError):
            chat.encrypt_message(
                "conv-1", "hello",
                sender_id="me",
                signing_key_version="1",
                conversation_key=conv_key,
            )

    def test_encrypt_reply_shape(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_reply(
            "conv-1", "this is my reply",
            reply_to_sequence_id="seq-42",
            reply_to_sender_id=12345,
            reply_to_text="original message",
            sender_id="me",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertTrue(payload.message_id)
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_event_signature)
        self.assertEqual(payload.conversation_key_version, "1")
        self.assertEqual(payload.signature_info.signature_version, "7")

    def test_encrypt_reply_without_target_rejected(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        # Neither reply_to_event nor reply_to_sequence_id: no reply target.
        with self.assertRaises(ValueError):
            chat.encrypt_reply(
                "conv-1", "this is my reply",
                sender_id="me",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )

    def test_encrypt_add_reaction_shape(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_add_reaction(
            None, "\U0001F44D",
            conversation_id="conv-1",
            target_message_sequence_id="seq-99",
            sender_id="me",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_event_signature)

    def test_encrypt_reaction_requires_emoji(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        with self.assertRaises(TypeError):
            chat.encrypt_add_reaction(
                conversation_id="conv-1",
                target_message_sequence_id="seq-99",
                sender_id="me",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )

    def test_encrypt_remove_reaction_shape(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_remove_reaction(
            None, "\U0001F44D",
            conversation_id="conv-1",
            target_message_sequence_id="seq-99",
            sender_id="me",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_event_signature)

    def test_encrypt_edit_shape(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_edit(
            None, "see https://example.com",
            entities=[(4, 23, "url")],
            conversation_id="conv-1",
            target_message_sequence_id="seq-99",
            sender_id="111",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )

        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_event_signature)
        self.assertTrue(payload.message_id)

    def test_encrypt_edit_requires_updated_text(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        with self.assertRaises(TypeError):
            chat.encrypt_edit(
                conversation_id="conv-1",
                target_message_sequence_id="seq-99",
                sender_id="me",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )

    def test_prepare_conversation_key_change_shape(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_conversation_key_change(
            public_keys, conversation_id="conv-1", sender_id="me", signing_key_version="1"
        )

        self.assertEqual(result["conversation_id"], "conv-1")
        self.assertIn("conversation_key", result)
        self.assertIsInstance(result["conversation_key"], bytes)
        self.assertEqual(len(result["conversation_key"]), 32)
        self.assertIsInstance(result["conversation_key_version"], str)

        self.assertIn("participant_keys", result)
        self.assertEqual(len(result["participant_keys"]), 1)
        entry = result["participant_keys"][0]
        self.assertEqual(entry["user_id"], "me")
        self.assertTrue(entry["encrypted_key"])
        self.assertIn("public_key_version", entry)

        self.assertEqual(len(result["action_signatures"]), 1)
        sig = result["action_signatures"][0]
        self.assertTrue(sig["signature"])
        # Absent: the payload embeds the plaintext conversation key and is withheld.
        self.assertNotIn("signature_payload", sig)

    def test_extract_conversation_keys_empty_shape(self):
        chat, _ = self._unlocked_chat()

        result = chat.extract_conversation_keys([])
        self.assertIn("keys", result)
        self.assertEqual(result["keys"], {})
        self.assertIn("latest_version", result)
        self.assertIsNone(result["latest_version"])

    def test_prepare_group_members_change_shape(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_members_change(
            public_keys,
            "g123",         # conversation_id
            ["new-user"],   # new_member_ids
            ["me"],         # current_member_ids
            ["me"],         # current_admin_ids
            [],             # current_pending_member_ids
            sender_id="me",
            signing_key_version="1",
            current_title="Team",
        )

        self.assertEqual(result["conversation_id"], "g123")
        self.assertEqual(len(result["participant_keys"]), 1)
        # A member add emits two signed actions: the key change and the add.
        self.assertEqual(len(result["action_signatures"]), 2)
        ckce = result["action_signatures"][0]
        # Absent: the payload embeds the plaintext conversation key and is withheld.
        self.assertNotIn("signature_payload", ckce)
        self.assertTrue(ckce["encoded_message_event_detail"])
        add = result["action_signatures"][1]
        self.assertTrue(add["signature"])
        self.assertTrue(
            add["signature_payload"].startswith("GroupChangeEvent.GroupMemberAddChange,")
        )
        self.assertTrue(add["encoded_message_event_detail"])
        # Unset screen-capture blocking signs as the trailing null sentinel.
        self.assertTrue(add["signature_payload"].endswith(",null"))

    def test_prepare_group_members_change_screen_capture_blocking(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_members_change(
            public_keys,
            "g123",
            ["new-user"],
            ["me"],
            ["me"],
            [],
            sender_id="me",
            signing_key_version="1",
            current_screen_capture_blocking_enabled=True,
        )

        add = result["action_signatures"][1]
        # The group's screen-capture-blocking state fills the trailing slot.
        self.assertTrue(
            add["signature_payload"].startswith("GroupChangeEvent.GroupMemberAddChange,")
        )
        self.assertTrue(add["signature_payload"].endswith(",true"))
        self.assertTrue(add["encoded_message_event_detail"])

    def test_prepare_group_create_shape(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_create(
            public_keys,
            "g123",            # conversation_id
            ["me", "friend"],  # member_ids
            ["me"],            # admin_ids
            sender_id="me",
            signing_key_version="1",
            title="Team",
        )

        self.assertEqual(result["conversation_id"], "g123")
        self.assertEqual(len(result["participant_keys"]), 1)
        # A group create emits two signed actions: the key change and the create.
        self.assertEqual(len(result["action_signatures"]), 2)
        ckce = result["action_signatures"][0]
        # Absent: the payload embeds the plaintext conversation key and is withheld.
        self.assertNotIn("signature_payload", ckce)
        self.assertTrue(ckce["encoded_message_event_detail"])
        create = result["action_signatures"][1]
        self.assertTrue(create["signature"])
        self.assertTrue(
            create["signature_payload"].startswith("GroupChangeEvent.GroupCreate,")
        )
        self.assertTrue(create["encoded_message_event_detail"])

    def test_prepare_group_create_empty_title_signs_as_omitted(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        # An empty string is the "not set" encoding: it must sign the null
        # sentinel, exactly like omitting the argument.
        empty = chat.prepare_group_create(
            public_keys,
            "g123",
            ["me", "friend"],
            ["me"],
            sender_id="me",
            signing_key_version="1",
            title="",
            avatar_url="",
        )
        omitted = chat.prepare_group_create(
            public_keys,
            "g123",
            ["me", "friend"],
            ["me"],
            sender_id="me",
            signing_key_version="1",
        )
        for result in (empty, omitted):
            payload = result["action_signatures"][1]["signature_payload"]
            self.assertTrue(
                payload.endswith(",null,null,null"),
                f"title/avatar must sign as the null sentinel, got: {payload}",
            )

    def test_prepare_message_delete_shape(self):
        chat, v = self._unlocked_chat()

        # A 1:1 id is signed in its canonical colon form; delete-for-all
        # signs the wire action 2.
        sig = chat.prepare_message_delete(
            "222-111",
            ["seq-10", "seq-11"],
            True,
            sender_id="111",
            signing_key_version="1",
        )

        self.assertTrue(sig["message_id"])
        self.assertTrue(sig["encoded_message_event_detail"])
        self.assertTrue(sig["signature"])
        self.assertEqual(
            sig["signature_payload"],
            f"MessageDeleteEvent,{sig['message_id']},111,111:222,2,seq-10,seq-11",
        )

    def test_prepare_message_delete_for_self(self):
        chat, v = self._unlocked_chat()

        # Group ids pass through unchanged; delete-for-self signs the wire
        # action 1.
        sig = chat.prepare_message_delete(
            "g999",
            ["seq-1"],
            False,
            sender_id="111",
            signing_key_version="1",
        )

        self.assertEqual(
            sig["signature_payload"],
            f"MessageDeleteEvent,{sig['message_id']},111,g999,1,seq-1",
        )

    def test_optional_arguments_are_keyword_only(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "me", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        # Optionals passed positionally must raise TypeError.
        with self.assertRaises(TypeError):
            chat.prepare_group_members_change(
                public_keys,
                "g123",
                ["new-user"],
                ["me"],
                ["me"],
                [],
                "me",  # sender_id is keyword-only
            )
        with self.assertRaises(TypeError):
            chat.prepare_group_create(
                public_keys,
                "g123",
                ["me", "friend"],
                ["me"],
                "me",  # sender_id is keyword-only
            )
        conv_key = base64.b64decode(v["conversation_key_b64"])
        with self.assertRaises(TypeError):
            chat.encrypt_message(
                "conv-1",
                "hello",
                "me",  # sender_id is keyword-only
            )
        with self.assertRaises(TypeError):
            chat.encrypt_reply(
                "conv-1",
                "hello",
                None,
                "seq-42",  # reply_to_sequence_id is keyword-only
            )

    def test_prepare_conversation_key_change_derives_one_to_one_id(self):
        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "1491585161162473473", "public_key": v["identity_public_b64"], "key_version": "1"},
            {"user_id": "17380288", "public_key": v["identity_public_b64"], "key_version": "1"},
        ]
        # Omitting conversation_id derives the canonical numeric-sorted id.
        result = chat.prepare_conversation_key_change(
            public_keys, sender_id="1491585161162473473", signing_key_version="1"
        )
        self.assertEqual(result["conversation_id"], "17380288:1491585161162473473")

    def test_encrypt_decrypt_generic_roundtrip(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        plaintext = "metadata payload \U0001F31F with unicode"
        ciphertext = chat.encrypt(plaintext, conv_key)
        self.assertIsInstance(ciphertext, str)
        self.assertNotEqual(ciphertext, plaintext)
        # Randomized nonce: two encryptions differ.
        self.assertNotEqual(chat.encrypt(plaintext, conv_key), ciphertext)
        self.assertEqual(chat.decrypt(ciphertext, conv_key), plaintext)

    def test_stream_roundtrip_and_wrong_key_fails(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        plaintext = base64.b64decode(v["plaintext_b64"])

        encrypted = chat.encrypt_stream(plaintext, conv_key)
        self.assertNotEqual(encrypted, plaintext)
        # Randomized nonces: two encryptions differ.
        self.assertNotEqual(chat.encrypt_stream(plaintext, conv_key), encrypted)
        self.assertEqual(chat.decrypt_stream(encrypted, conv_key), plaintext)

        wrong_key = bytearray(conv_key)
        wrong_key[31] ^= 0xFF
        with self.assertRaises(Exception):
            chat.decrypt_stream(encrypted, bytes(wrong_key))

    def test_incremental_stream_roundtrip_and_truncation(self):
        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        # A multi-frame payload so chunking and re-framing are exercised.
        plaintext = b"\xab" * 5000

        enc = chat.stream_encryptor(conv_key)
        ciphertext = b""
        for i in range(0, len(plaintext), 700):
            ciphertext += enc.push(plaintext[i:i + 700])
        ciphertext += enc.finish()

        dec = chat.stream_decryptor(conv_key)
        out = b""
        for i in range(0, len(ciphertext), 333):
            out += dec.push(ciphertext[i:i + 333])
        out += dec.finish()
        self.assertEqual(out, plaintext)

        # A truncated stream is missing its final frame: finish() raises.
        truncated = chat.stream_decryptor(conv_key)
        truncated.push(ciphertext[:-4])
        with self.assertRaises(Exception):
            truncated.finish()

    def test_export_lock_reimport_roundtrip(self):
        chat, v = self._unlocked_chat()

        exported = chat.export_keys()
        self.assertIsNotNone(exported)
        # The exported blob is exactly the fixture private-key concat.
        self.assertEqual(bytes(exported), base64.b64decode(v["private_keys_concat_b64"]))

        chat.lock()
        self.assertFalse(chat.is_unlocked())
        # Locked: export returns None instead of raising.
        self.assertIsNone(chat.export_keys())

        chat.import_keys(bytes(exported))
        self.assertTrue(chat.is_unlocked())
        keys = chat.get_public_keys()
        self.assertEqual(keys.identity, v["identity_public_b64"])
        self.assertEqual(keys.signing, v["signing_public_b64"])

    def test_export_keys_identity_only_round_trip(self):
        from chat_xdk import Chat

        v = _load_vectors()
        identity_only = base64.b64decode(v["private_keys_concat_b64"])[:32]

        chat = Chat()
        chat.import_keys(identity_only)
        # Identity-only sessions can export (32 bytes), matching core; only
        # a session with no identity key at all returns None.
        exported = chat.export_keys()
        self.assertIsNotNone(exported)
        self.assertEqual(bytes(exported), identity_only)

    def test_attachment_missing_required_field_rejected(self):
        chat, v = self._unlocked_chat()

        with self.assertRaises(ValueError):
            chat.encrypt_message(
                "123:456",
                "hi",
                sender_id="123",
                signing_key_version="1",
                conversation_key=bytes(32),
                conversation_key_version="1",
                attachments=[
                    {
                        "attachment_type": "media",
                        "media_hash_key": "hash",
                        # width/height/filesize_bytes/filename omitted
                    }
                ],
            )

    def test_mixed_attachment_types_rejected(self):
        chat, v = self._unlocked_chat()

        # Only image/gif/video media may appear in multiples; any other
        # attachment type must be the message's only attachment.
        with self.assertRaisesRegex(ValueError, "attachment combination"):
            chat.encrypt_message(
                "123:456",
                "hi",
                sender_id="123",
                signing_key_version="1",
                conversation_key=bytes(32),
                conversation_key_version="1",
                attachments=[
                    {
                        "attachment_type": "media",
                        "media_hash_key": "hash",
                        "width": 100,
                        "height": 100,
                        "filesize_bytes": 1000,
                        "filename": "pic.jpg",
                        "media_type": 1,
                    },
                    {"attachment_type": "url", "url": "https://example.com"},
                ],
            )

    def test_url_attachment_with_banner_image_encrypts(self):
        chat, v = self._unlocked_chat()

        payload = chat.encrypt_message(
            "123:456",
            "check this out",
            sender_id="123",
            signing_key_version="1",
            conversation_key=bytes(32),
            conversation_key_version="1",
            attachments=[
                {
                    "attachment_type": "url",
                    "url": "https://example.com/product",
                    "display_title": "Example Product",
                    "banner_image": {
                        "media_hash_key": "banner-hash",
                        "filesize_bytes": 24000,
                        "filename": "banner.jpg",
                        "width": 1200,
                        "height": 630,
                    },
                    "favicon_image": {
                        "media_hash_key": "favicon-hash",
                        "filesize_bytes": 1200,
                        "filename": "favicon.ico",
                    },
                }
            ],
        )
        self.assertTrue(payload.encrypted_content)
        self.assertTrue(payload.signature)

    def test_url_attachment_banner_missing_required_field_rejected(self):
        # media_hash_key, filesize_bytes, and filename are all required:
        # receiving clients silently discard the preview image when any is
        # missing on the wire.
        chat, v = self._unlocked_chat()

        incomplete_banners = [
            {"filesize_bytes": 24000, "filename": "banner.jpg"},  # no media_hash_key
            {"media_hash_key": "banner-hash", "filename": "banner.jpg"},  # no filesize_bytes
            {"media_hash_key": "banner-hash", "filesize_bytes": 24000},  # no filename
        ]
        for banner in incomplete_banners:
            with self.assertRaises(ValueError, msg=f"banner={banner}"):
                chat.encrypt_message(
                    "123:456",
                    "hi",
                    sender_id="123",
                    signing_key_version="1",
                    conversation_key=bytes(32),
                    conversation_key_version="1",
                    attachments=[
                        {
                            "attachment_type": "url",
                            "url": "https://example.com",
                            "banner_image": banner,
                        }
                    ],
                )

    def test_verify_key_binding_valid_and_tampered(self):
        chat, v = self._unlocked_chat()

        self.assertTrue(
            chat.verify_key_binding(
                v["identity_public_b64"],
                v["signing_public_b64"],
                v["identity_public_key_signature_b64"],
            )
        )

        tampered = bytearray(base64.b64decode(v["identity_public_key_signature_b64"]))
        tampered[0] ^= 0xFF
        self.assertFalse(
            chat.verify_key_binding(
                v["identity_public_b64"],
                v["signing_public_b64"],
                base64.b64encode(bytes(tampered)).decode("ascii"),
            )
        )
        # Wrong key in the identity slot: the binding no longer verifies.
        self.assertFalse(
            chat.verify_key_binding(
                v["signing_public_b64"],
                v["signing_public_b64"],
                v["identity_public_key_signature_b64"],
            )
        )

    def test_matches_registered_key_both_encodings(self):
        from chat_xdk import Chat

        chat = Chat()
        payload = chat.generate_keypairs()

        # SPKI/DER form (registration payload) and raw SEC1 form
        # (get_public_keys) both identify the loaded key.
        self.assertTrue(chat.matches_registered_key(payload.public_key.public_key))
        self.assertTrue(chat.matches_registered_key(chat.get_public_keys().identity))

        other = Chat()
        other_payload = other.generate_keypairs()
        self.assertFalse(
            chat.matches_registered_key(other_payload.public_key.public_key)
        )

        # No identity loaded and invalid base64 raise rather than return False.
        locked = Chat()
        with self.assertRaises(Exception):
            locked.matches_registered_key(payload.public_key.public_key)
        with self.assertRaises(Exception):
            chat.matches_registered_key("not base64!!")

    def test_get_public_key_fingerprint(self):
        chat, _ = self._unlocked_chat()

        fingerprint = chat.get_public_key_fingerprint()
        # SHA-256 -> 32 bytes -> 43 URL-safe base64 chars (no padding), and
        # deterministic for the fixture key.
        self.assertEqual(len(fingerprint), 43)
        self.assertEqual(fingerprint, chat.get_public_key_fingerprint())

    def test_decrypt_events_rejects_incomplete_signing_key(self):
        chat, _ = self._unlocked_chat()

        # Missing the identity binding fields (identity_public_key /
        # identity_public_key_signature) -> raises ValueError.
        incomplete = [{
            "user_id": "me",
            "public_key_version": "1",
            "public_key": "abc",
        }]
        with self.assertRaises(ValueError):
            chat.decrypt_events([], incomplete)

    def test_decrypt_event_rejects_incomplete_signing_key(self):
        chat, _ = self._unlocked_chat()

        incomplete = [{
            "user_id": "me",
            "public_key_version": "1",
            "public_key": "abc",
            "identity_public_key": "def",
            # identity_public_key_signature intentionally omitted
        }]
        with self.assertRaises(ValueError):
            chat.decrypt_event("", {}, incomplete)

    def test_session_identity_is_the_default_sender(self):
        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])

        chat.set_identity("me", "7")
        payload = chat.encrypt_message(
            "conv-1", "hi",
            conversation_key=conv_key,
            conversation_key_version="1",
        )
        self.assertEqual(payload.signature_info.public_key_version, "7")
        self.assertTrue(payload.encrypted_content)

        # The explicit-override form signs with the same key version and
        # produces an equally complete payload.
        explicit = chat.encrypt_message(
            "conv-1", "hi",
            sender_id="me",
            signing_key_version="7",
            conversation_key=conv_key,
            conversation_key_version="1",
        )
        self.assertEqual(explicit.signature_info.public_key_version, "7")
        self.assertTrue(explicit.encrypted_content)
        self.assertTrue(explicit.signature)

    def test_encrypt_without_identity_mentions_sender_id(self):
        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])

        with self.assertRaises(ValueError) as ctx:
            chat.encrypt_message(
                "conv-1", "hi",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        self.assertIn("sender_id", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
