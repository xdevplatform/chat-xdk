import base64
import json
import os
import re
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


def _media(media_hash_key: str, filesize_bytes: int = 1000) -> dict:
    return {
        "attachment_type": "media",
        "media_hash_key": media_hash_key,
        "width": 100,
        "height": 100,
        "filesize_bytes": filesize_bytes,
        "filename": f"{media_hash_key}.jpg",
        "media_type": 1,
    }



def _key_kwargs(keys):
    """The one conversation key of a key map, as the file encrypt params take it."""
    ((version, key),) = keys.items()
    return {"conversation_key": key, "conversation_key_version": version}


def _only_action(prepared):
    """The one ``action_signatures`` entry of a prepared delete or read receipt."""
    assert list(prepared) == ["action_signatures"], prepared
    (entry,) = prepared["action_signatures"]
    return entry


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
        from features_support import keep_offline

        keep_offline()

    def test_version_is_the_release_version(self):
        import chat_xdk

        with open(os.path.join(_repo_root(), "Cargo.toml"), encoding="utf-8") as f:
            cargo = f.read()
        workspace = cargo[cargo.index("[workspace.package]"):]
        version = re.search(r'^version\s*=\s*"([^"]+)"', workspace, re.M).group(1)
        self.assertEqual(chat_xdk.__version__, version)

    def test_base64_roundtrip(self):
        from chat_xdk import base64_to_bytes, bytes_to_base64

        data = bytes(range(256))
        encoded = bytes_to_base64(data)
        self.assertIsInstance(encoded, str)
        self.assertEqual(base64_to_bytes(encoded), data)

    def test_encrypted_file_size(self):
        from chat_xdk import encrypted_file_size

        self.assertEqual(encrypted_file_size(0), 24)
        self.assertEqual(encrypted_file_size(1), 42)
        self.assertEqual(encrypted_file_size(1024), 1065)
        self.assertEqual(encrypted_file_size(1025), 1083)
        with self.assertRaises(OverflowError):
            encrypted_file_size(2**64 - 1)

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


class TestParams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)

        try:
            import chat_xdk  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")
        from features_support import keep_offline

        keep_offline()

    def test_every_params_class_is_exported(self):
        import chat_xdk

        for name in (
            "EncryptMessageParams",
            "EncryptReplyParams",
            "EncryptReactionParams",
            "EncryptEditParams",
            "ConversationKeyChangeParams",
            "GroupMembersChangeParams",
            "GroupCreateParams",
            "MessageDeleteParams",
            "MarkConversationReadParams",
            "SetIdentityParams",
            "ImportKeysParams",
            "DecryptEventParams",
            "DecryptEventsParams",
            "EncryptFileParams",
            "FileEncryptorParams",
            "DecryptFileParams",
            "FileDecryptorParams",
        ):
            self.assertIn(name, chat_xdk.__all__)
            self.assertTrue(isinstance(getattr(chat_xdk, name), type), name)

    def test_fields_are_read_write_attributes(self):
        from chat_xdk import EncryptMessageParams

        params = EncryptMessageParams("conv-1", "hi", ttl_msec=5)
        self.assertEqual(params.conversation_id, "conv-1")
        self.assertEqual(params.text, "hi")
        self.assertEqual(params.ttl_msec, 5)
        self.assertIsNone(params.sender_id)
        self.assertIsNone(params.attachments)

        params.text = "edited"
        params.sender_id = "1001"
        params.conversation_key = bytes(range(32))
        self.assertEqual(params.text, "edited")
        self.assertEqual(params.sender_id, "1001")
        self.assertEqual(params.conversation_key, bytes(range(32)))
        self.assertIsInstance(params.conversation_key, bytes)

    def test_list_fields_keep_the_callers_object(self):
        from chat_xdk import DecryptEventsParams, EncryptMessageParams

        attachments = [_media("photo-a")]
        params = EncryptMessageParams("conv-1", "hi", attachments=attachments)
        self.assertIs(params.attachments, attachments)
        params.attachments.append(_media("photo-b"))
        self.assertEqual(len(params.attachments), 2)

        events = []
        batch = DecryptEventsParams(events)
        batch.events.append("event")
        self.assertEqual(batch.events, ["event"])

    def test_required_fields_are_required_and_optional_fields_keyword_only(self):
        from chat_xdk import (
            ConversationKeyChangeParams,
            DecryptEventParams,
            DecryptEventsParams,
            DecryptFileParams,
            EncryptEditParams,
            EncryptFileParams,
            EncryptMessageParams,
            EncryptReactionParams,
            EncryptReplyParams,
            FileDecryptorParams,
            FileEncryptorParams,
            GroupCreateParams,
            GroupMembersChangeParams,
            ImportKeysParams,
            MarkConversationReadParams,
            MessageDeleteParams,
            SetIdentityParams,
        )

        missing_required = [
            lambda: EncryptMessageParams("conv-1"),
            lambda: EncryptReplyParams("conv-1"),
            lambda: EncryptReactionParams(None),
            lambda: EncryptEditParams(None),
            lambda: ConversationKeyChangeParams(),
            lambda: GroupMembersChangeParams([], "g1", [], [], []),
            lambda: GroupCreateParams([], "g1", []),
            lambda: MessageDeleteParams("conv-1", []),
            lambda: MarkConversationReadParams("conv-1"),
            lambda: SetIdentityParams("1001"),
            lambda: ImportKeysParams(),
            lambda: DecryptEventParams(),
            lambda: DecryptEventsParams(),
            lambda: EncryptFileParams(b"file", "event"),
            lambda: FileEncryptorParams("event"),
            lambda: DecryptFileParams(b"file", "event", {}),
            lambda: FileDecryptorParams("event", {}),
        ]
        for make in missing_required:
            with self.assertRaises(TypeError):
                make()

        optional_positional = [
            lambda: EncryptMessageParams("conv-1", "hi", "1001"),
            lambda: EncryptReplyParams("conv-1", "hi", None, "edit"),
            lambda: EncryptReactionParams(None, "x", "conv-1"),
            lambda: EncryptEditParams(None, "x", []),
            lambda: ConversationKeyChangeParams([], "1001"),
            lambda: GroupMembersChangeParams([], "g1", [], [], [], [], "1001"),
            lambda: GroupCreateParams([], "g1", [], [], "1001"),
            lambda: MessageDeleteParams("conv-1", [], True, "1001"),
            lambda: MarkConversationReadParams("conv-1", "seq-1", 1700000000123),
            lambda: ImportKeysParams(b"keys", "1"),
            lambda: DecryptEventParams("event", {}, []),
            lambda: DecryptEventsParams([], []),
        ]
        for make in optional_positional:
            with self.assertRaises(TypeError):
                make()

    def test_the_event_a_reply_reaction_or_edit_targets_is_optional(self):
        from chat_xdk import EncryptEditParams, EncryptReactionParams, EncryptReplyParams

        reply = EncryptReplyParams("conv-1", "hi", reply_to_sequence_id="5", reply_to_sender_id="1001")
        self.assertIsNone(reply.reply_to_event)
        self.assertEqual(EncryptReplyParams("conv-1", "hi", "event").reply_to_event, "event")
        self.assertEqual(
            EncryptReplyParams("conv-1", "hi", reply_to_event="event").reply_to_event, "event"
        )

        reaction = EncryptReactionParams(
            emoji="👍", conversation_id="conv-1", target_message_sequence_id="5"
        )
        self.assertIsNone(reaction.target_event)
        self.assertEqual(EncryptReactionParams("event", "👍").emoji, "👍")
        edit = EncryptEditParams(
            updated_text="fixed", conversation_id="conv-1", target_message_sequence_id="5"
        )
        self.assertIsNone(edit.target_event)
        self.assertEqual(EncryptEditParams("event", "fixed").updated_text, "fixed")

        with self.assertRaisesRegex(TypeError, "missing required argument: 'emoji'"):
            EncryptReactionParams("event")
        with self.assertRaisesRegex(TypeError, "missing required argument: 'updated_text'"):
            EncryptEditParams(target_event="event")

    def test_chat_shows_its_constructor_signature(self):
        import inspect

        from chat_xdk import Chat

        params = inspect.signature(Chat).parameters
        self.assertEqual(list(params), ["config_json"])
        self.assertIsNone(params["config_json"].default)
        with self.assertRaises(TypeError):
            Chat(None, None)

    def test_methods_take_only_their_params_class(self):
        from chat_xdk import Chat, DecryptEventParams, EncryptMessageParams

        chat = Chat()
        with self.assertRaises(TypeError):
            chat.encrypt_message(DecryptEventParams("event", {}))
        with self.assertRaises(TypeError):
            chat.decrypt_event(EncryptMessageParams("conv-1", "hi"))
        with self.assertRaises(TypeError):
            chat.encrypt_message("conv-1", "hi")

    def test_a_field_of_the_wrong_type_names_the_field(self):
        from chat_xdk import Chat, DecryptEventsParams

        with self.assertRaises(TypeError) as ctx:
            Chat().decrypt_events(DecryptEventsParams("not a list"))
        self.assertIn("events", str(ctx.exception))


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
        from features_support import keep_offline

        keep_offline()

    def _unlocked_chat(self, chat=None):
        from chat_xdk import Chat, ImportKeysParams

        v = _load_vectors()
        chat = Chat() if chat is None else chat
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))
        return chat, v

    def _signing_key(self, user_id: str, version: str) -> dict:
        v = _load_vectors()
        return {
            "user_id": user_id,
            "public_key_version": version,
            "public_key": v["signing_public_b64"],
            "identity_public_key": v["identity_public_b64"],
            "identity_public_key_signature": v["identity_public_key_signature_b64"],
        }

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

    def test_encrypt_message_signs_at_version_7_until_v1_send_is_on(self):
        from chat_xdk import EncryptMessageParams
        from features_support import FeatureServer, reading, wait_for_v1

        server = FeatureServer()
        server.delay = 0.5
        self.addCleanup(server.close)
        chat, v = self._unlocked_chat(reading(server.url))

        conv_key = base64.b64decode(v["conversation_key_b64"])

        def send():
            return chat.encrypt_message(
                EncryptMessageParams(
                    "conv-1", "hello from python",
                    sender_id="1001",
                    signing_key_version="1",
                    conversation_key=conv_key,
                    conversation_key_version="1",
                )
            )

        self.assertEqual(send().signature_info.signature_version, "7")
        wait_for_v1(chat, sender_id="1001", signing_key_version="1")
        payload = send()
        self.assertEqual(payload.signature_info.signature_version, "10")
        self.assertTrue(payload.xdk_version)
        # The SDK generates and returns the message id.
        self.assertTrue(payload.message_id)
        self.assertTrue(payload.event_b64)

    def test_encrypt_message_key_without_version_rejected(self):
        from chat_xdk import EncryptMessageParams

        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        # conversation_key and conversation_key_version travel together.
        with self.assertRaises(ValueError):
            chat.encrypt_message(
                EncryptMessageParams(
                    "conv-1", "hello",
                    sender_id="1001",
                    signing_key_version="1",
                    conversation_key=conv_key,
                )
            )

    def test_event_b64_decrypts_as_the_sent_message(self):
        from chat_xdk import DecryptEventParams, EncryptMessageParams

        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_message(
            EncryptMessageParams(
                "1002-1001", "read me back",
                sender_id="1001",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="7",
            )
        )
        event = chat.decrypt_event(
            DecryptEventParams(
                payload.event_b64,
                {"7": conv_key},
                signing_keys=[self._signing_key("1001", "1")],
            )
        )
        self.assertEqual(event["type"], "Message")
        self.assertTrue(event["verified"])
        self.assertEqual(event["content"]["text"], "read me back")
        self.assertEqual(event["id"], payload.message_id)
        self.assertEqual(event["conversation_id"], "1001:1002")
        self.assertIsNone(event.get("sequence_id"))

    def test_encrypt_reply_shape(self):
        from chat_xdk import EncryptReplyParams

        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_reply(
            EncryptReplyParams(
                "conv-1", "this is my reply", None,
                reply_to_sequence_id="seq-42",
                reply_to_sender_id="12345",
                reply_to_text="original message",
                sender_id="1001",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        )

        self.assertTrue(payload.message_id)
        self.assertTrue(payload.encoded_message_create_event)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_message_event_signature)
        self.assertEqual(payload.conversation_key_version, "1")
        self.assertEqual(payload.signature_info.signature_version, "7")

    def test_user_ids_are_digit_strings(self):
        from chat_xdk import EncryptReplyParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        with self.assertRaisesRegex(ValueError, "Invalid user_id 'user-1'"):
            chat.set_identity(SetIdentityParams("user-1", "1"))
        with self.assertRaisesRegex(ValueError, "Invalid signing_key_version 'v1'"):
            chat.set_identity(SetIdentityParams("1001", "v1"))

        params = EncryptReplyParams(
            "conv-1", "reply", None,
            reply_to_sequence_id="seq-42",
            reply_to_sender_id="12x",
            sender_id="1001",
            signing_key_version="1",
            conversation_key=base64.b64decode(v["conversation_key_b64"]),
            conversation_key_version="1",
        )
        with self.assertRaisesRegex(ValueError, "Invalid reply_to_sender_id '12x'"):
            chat.encrypt_reply(params)
        with self.assertRaises(TypeError):
            params.reply_to_sender_id = 12345

    def test_encrypt_reply_without_target_rejected(self):
        from chat_xdk import EncryptReplyParams

        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        # Neither reply_to_event nor reply_to_sequence_id: no reply target.
        with self.assertRaises(ValueError):
            chat.encrypt_reply(
                EncryptReplyParams(
                    "conv-1", "this is my reply", None,
                    sender_id="1001",
                    signing_key_version="1",
                    conversation_key=conv_key,
                    conversation_key_version="1",
                )
            )

    def test_encrypt_add_and_remove_reaction_shape(self):
        from chat_xdk import EncryptReactionParams

        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        params = EncryptReactionParams(
            None, "\U0001F44D",
            conversation_id="conv-1",
            target_message_sequence_id="seq-99",
            sender_id="1001",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="1",
        )
        for payload in (chat.encrypt_add_reaction(params), chat.encrypt_remove_reaction(params)):
            self.assertTrue(payload.encoded_message_create_event)
            self.assertTrue(payload.signature)
            self.assertTrue(payload.encoded_message_event_signature)

    def test_encrypt_edit_shape(self):
        from chat_xdk import EncryptEditParams

        chat, v = self._unlocked_chat()

        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_edit(
            EncryptEditParams(
                None, "see https://example.com",
                entities=[(4, 23, "url")],
                conversation_id="conv-1",
                target_message_sequence_id="seq-99",
                sender_id="111",
                signing_key_version="1",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        )

        self.assertTrue(payload.encoded_message_create_event)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.encoded_message_event_signature)
        self.assertTrue(payload.message_id)

    def test_prepare_conversation_key_change_shape(self):
        from chat_xdk import ConversationKeyChangeParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                public_keys, conversation_id="conv-1", sender_id="910002", signing_key_version="1"
            )
        )

        self.assertEqual(result["conversation_id"], "conv-1")
        self.assertIn("conversation_key", result)
        self.assertIsInstance(result["conversation_key"], bytes)
        self.assertEqual(len(result["conversation_key"]), 32)
        self.assertIsInstance(result["conversation_key_version"], str)

        self.assertIn("conversation_participant_keys", result)
        self.assertEqual(len(result["conversation_participant_keys"]), 1)
        entry = result["conversation_participant_keys"][0]
        # The entries take the request's field names.
        self.assertEqual(set(entry), {"user_id", "encrypted_conversation_key", "public_key_version"})
        self.assertEqual(entry["user_id"], "910002")
        self.assertTrue(entry["encrypted_conversation_key"])

        self.assertEqual(len(result["action_signatures"]), 1)
        sig = result["action_signatures"][0]
        self.assertTrue(sig["message_event_signature"]["signature"])
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
        from chat_xdk import GroupMembersChangeParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_members_change(
            GroupMembersChangeParams(
                public_keys,
                "g123",         # conversation_id
                ["910009"],   # new_member_ids
                ["910002"],         # current_member_ids
                ["910002"],         # current_admin_ids
                [],             # current_pending_member_ids
                sender_id="910002",
                signing_key_version="1",
                current_title="Team",
            )
        )

        self.assertEqual(result["conversation_id"], "g123")
        self.assertEqual(len(result["conversation_participant_keys"]), 1)
        # A member add emits two signed actions: the key change and the add.
        self.assertEqual(len(result["action_signatures"]), 2)
        ckce = result["action_signatures"][0]
        # Absent: the payload embeds the plaintext conversation key and is withheld.
        self.assertNotIn("signature_payload", ckce)
        self.assertTrue(ckce["encoded_message_event_detail"])
        add = result["action_signatures"][1]
        self.assertTrue(add["message_event_signature"]["signature"])
        self.assertTrue(
            add["signature_payload"].startswith("GroupChangeEvent.GroupMemberAddChange,")
        )
        self.assertTrue(add["encoded_message_event_detail"])
        # Unset screen-capture blocking signs as the trailing null sentinel.
        self.assertTrue(add["signature_payload"].endswith(",null"))

    def test_prepare_group_members_change_screen_capture_blocking(self):
        from chat_xdk import GroupMembersChangeParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_members_change(
            GroupMembersChangeParams(
                public_keys,
                "g123",
                ["910009"],
                ["910002"],
                ["910002"],
                [],
                sender_id="910002",
                signing_key_version="1",
                current_screen_capture_blocking_enabled=True,
            )
        )

        add = result["action_signatures"][1]
        # The group's screen-capture-blocking state fills the trailing slot.
        self.assertTrue(
            add["signature_payload"].startswith("GroupChangeEvent.GroupMemberAddChange,")
        )
        self.assertTrue(add["signature_payload"].endswith(",true"))
        self.assertTrue(add["encoded_message_event_detail"])

    def test_prepare_group_create_shape(self):
        from chat_xdk import GroupCreateParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        result = chat.prepare_group_create(
            GroupCreateParams(
                public_keys,
                "g123",            # conversation_id
                ["910002", "910005"],  # member_ids
                ["910002"],            # admin_ids
                sender_id="910002",
                signing_key_version="1",
                title="Team",
            )
        )

        self.assertEqual(result["conversation_id"], "g123")
        self.assertEqual(len(result["conversation_participant_keys"]), 1)
        # A group create emits two signed actions: the key change and the create.
        self.assertEqual(len(result["action_signatures"]), 2)
        ckce = result["action_signatures"][0]
        # Absent: the payload embeds the plaintext conversation key and is withheld.
        self.assertNotIn("signature_payload", ckce)
        self.assertTrue(ckce["encoded_message_event_detail"])
        create = result["action_signatures"][1]
        self.assertTrue(create["message_event_signature"]["signature"])
        self.assertTrue(
            create["signature_payload"].startswith("GroupChangeEvent.GroupCreate,")
        )
        self.assertTrue(create["encoded_message_event_detail"])

    def test_prepare_group_create_empty_title_signs_as_omitted(self):
        from chat_xdk import GroupCreateParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "public_key": v["identity_public_b64"], "key_version": "1"}
        ]
        # An empty string is the "not set" encoding: it must sign the null
        # sentinel, exactly like leaving the field None.
        empty = chat.prepare_group_create(
            GroupCreateParams(
                public_keys,
                "g123",
                ["910002", "910005"],
                ["910002"],
                sender_id="910002",
                signing_key_version="1",
                title="",
                avatar_url="",
            )
        )
        omitted = chat.prepare_group_create(
            GroupCreateParams(
                public_keys,
                "g123",
                ["910002", "910005"],
                ["910002"],
                sender_id="910002",
                signing_key_version="1",
            )
        )
        for result in (empty, omitted):
            payload = result["action_signatures"][1]["signature_payload"]
            self.assertTrue(
                payload.endswith(",null,null,null"),
                f"title/avatar must sign as the null sentinel, got: {payload}",
            )

    def test_prepare_message_delete_shape(self):
        from chat_xdk import MessageDeleteParams

        chat, v = self._unlocked_chat()

        # A 1:1 id is signed in its canonical colon form; delete-for-all
        # signs the wire action 2.
        sig = _only_action(
            chat.prepare_message_delete(
                MessageDeleteParams(
                    "222-111",
                    ["seq-10", "seq-11"],
                    True,
                    sender_id="111",
                    signing_key_version="1",
                )
            )
        )

        self.assertTrue(sig["message_id"])
        self.assertTrue(sig["encoded_message_event_detail"])
        # The signature is nested as the request's action_signatures carry it.
        signed = sig["message_event_signature"]
        self.assertEqual(
            sorted(signed),
            ["public_key_version", "signature", "signature_version", "signing_public_key"],
        )
        self.assertTrue(signed["signature"])
        self.assertEqual(signed["signature_version"], "7")
        self.assertEqual(signed["public_key_version"], "1")
        self.assertEqual(signed["signing_public_key"], chat.get_public_keys().signing)
        self.assertEqual(
            sig["signature_payload"],
            f"MessageDeleteEvent,{sig['message_id']},111,111:222,2,seq-10,seq-11",
        )

    def test_prepare_message_delete_for_self(self):
        from chat_xdk import MessageDeleteParams

        chat, v = self._unlocked_chat()

        # Group ids pass through unchanged; delete-for-self signs the wire
        # action 1.
        sig = _only_action(
            chat.prepare_message_delete(
                MessageDeleteParams(
                    "g999",
                    ["seq-1"],
                    False,
                    sender_id="111",
                    signing_key_version="1",
                )
            )
        )

        self.assertEqual(
            sig["signature_payload"],
            f"MessageDeleteEvent,{sig['message_id']},111,g999,1,seq-1",
        )

    def test_prepare_mark_conversation_read_shape(self):
        from chat_xdk import MarkConversationReadParams

        chat, v = self._unlocked_chat()

        # A 1:1 id is signed in its canonical colon form, followed by the
        # read point and its time.
        sig = _only_action(
            chat.prepare_mark_conversation_read(
                MarkConversationReadParams(
                    "222-111",
                    "2011626338877079553",
                    seen_at_msec=1700000000123,
                    sender_id="111",
                    signing_key_version="1",
                )
            )
        )

        self.assertTrue(sig["message_id"])
        self.assertTrue(sig["encoded_message_event_detail"])
        self.assertEqual(sig["message_event_signature"]["public_key_version"], "1")
        self.assertEqual(
            sig["message_event_signature"]["signing_public_key"], chat.get_public_keys().signing
        )
        self.assertEqual(
            sig["signature_payload"],
            f"MarkConversationReadEvent,{sig['message_id']},111,111:222,"
            "2011626338877079553,1700000000123",
        )
        signature = sig["message_event_signature"]["signature"]
        self.assertTrue(
            chat.verify(
                v["signing_public_b64"],
                base64.b64decode(signature + "=" * (-len(signature) % 4)),
                sig["signature_payload"].encode(),
            )
        )

    def test_prepare_mark_conversation_read_defaults_seen_at_to_now(self):
        import time

        from chat_xdk import MarkConversationReadParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("111", "7"))

        before = int(time.time() * 1000)
        sig = _only_action(
            chat.prepare_mark_conversation_read(MarkConversationReadParams("g999", "seq-1"))
        )
        after = int(time.time() * 1000)

        # The session identity signs; the unset time is the current time.
        self.assertEqual(sig["message_event_signature"]["public_key_version"], "7")
        prefix = f"MarkConversationReadEvent,{sig['message_id']},111,g999,seq-1,"
        self.assertTrue(sig["signature_payload"].startswith(prefix))
        seen_at = int(sig["signature_payload"][len(prefix) :])
        self.assertGreaterEqual(seen_at, before)
        self.assertLessEqual(seen_at, after)

    def test_prepare_mark_conversation_read_rejects_empty_ids(self):
        from chat_xdk import MarkConversationReadParams

        chat, v = self._unlocked_chat()

        with self.assertRaisesRegex(ValueError, "conversation_id is empty"):
            chat.prepare_mark_conversation_read(
                MarkConversationReadParams("", "seq-1", sender_id="111", signing_key_version="1")
            )
        with self.assertRaisesRegex(ValueError, "seen_until_sequence_id is empty"):
            chat.prepare_mark_conversation_read(
                MarkConversationReadParams("g999", "", sender_id="111", signing_key_version="1")
            )

    def test_prepare_conversation_key_change_derives_one_to_one_id(self):
        from chat_xdk import ConversationKeyChangeParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "1491585161162473473", "public_key": v["identity_public_b64"], "key_version": "1"},
            {"user_id": "17380288", "public_key": v["identity_public_b64"], "key_version": "1"},
        ]
        # Leaving conversation_id None derives the canonical numeric-sorted id.
        result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                public_keys, sender_id="1491585161162473473", signing_key_version="1"
            )
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

    def test_export_lock_reimport_roundtrip(self):
        from chat_xdk import ImportKeysParams
        chat, v = self._unlocked_chat()

        exported = chat.export_keys()
        self.assertIsNotNone(exported)
        # The exported blob is exactly the fixture private-key concat.
        self.assertEqual(bytes(exported), base64.b64decode(v["private_keys_concat_b64"]))

        chat.lock()
        self.assertFalse(chat.is_unlocked())
        # Locked: export returns None instead of raising.
        self.assertIsNone(chat.export_keys())

        chat.import_keys(ImportKeysParams(bytes(exported)))
        self.assertTrue(chat.is_unlocked())
        keys = chat.get_public_keys()
        self.assertEqual(keys.identity, v["identity_public_b64"])
        self.assertEqual(keys.signing, v["signing_public_b64"])

    def test_export_keys_identity_only_round_trip(self):
        from chat_xdk import Chat, ImportKeysParams

        v = _load_vectors()
        identity_only = base64.b64decode(v["private_keys_concat_b64"])[:32]

        chat = Chat()
        chat.import_keys(ImportKeysParams(identity_only))
        # Identity-only sessions can export (32 bytes), matching core; only
        # a session with no identity key at all returns None.
        exported = chat.export_keys()
        self.assertIsNotNone(exported)
        self.assertEqual(bytes(exported), identity_only)

    def test_attachment_missing_required_field_rejected(self):
        from chat_xdk import EncryptMessageParams

        chat, v = self._unlocked_chat()

        with self.assertRaisesRegex(ValueError, "Invalid attachments"):
            chat.encrypt_message(
                EncryptMessageParams(
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
            )

    def test_mixed_attachment_types_rejected(self):
        from chat_xdk import EncryptMessageParams

        chat, v = self._unlocked_chat()

        # Only image/gif/video media may appear in multiples; any other
        # attachment type must be the message's only attachment.
        with self.assertRaisesRegex(ValueError, "attachment combination"):
            chat.encrypt_message(
                EncryptMessageParams(
                    "123:456",
                    "hi",
                    sender_id="123",
                    signing_key_version="1",
                    conversation_key=bytes(32),
                    conversation_key_version="1",
                    attachments=[
                        _media("hash"),
                        {"attachment_type": "url", "url": "https://example.com"},
                    ],
                )
            )

    def test_url_attachment_with_banner_image_encrypts(self):
        from chat_xdk import EncryptMessageParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("123", "1"))

        payload = chat.encrypt_message(
            EncryptMessageParams(
                "123:456",
                "check this out",
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
        )
        self.assertTrue(payload.encoded_message_create_event)
        self.assertTrue(payload.signature)
        self.assertTrue(payload.message_id)

    def test_url_attachment_banner_missing_required_field_rejected(self):
        from chat_xdk import EncryptMessageParams

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
                    EncryptMessageParams(
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
                )

    def test_files_encrypt_from_the_payload_and_decrypt_from_the_event(self):
        from chat_xdk import (
            DecryptFileParams,
            EncryptFileParams,
            EncryptMessageParams,
            FileDecryptorParams,
            FileEncryptorParams,
            encrypted_file_size,
            SetIdentityParams,
        )

        chat, v = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("1001", "1"))
        conv_key = base64.b64decode(v["conversation_key_b64"])
        keys = {"7": conv_key}
        photos = {"photo-a": bytes(range(256)) * 40, "photo-b": b"second photo"}
        payload = chat.encrypt_message(
            EncryptMessageParams(
                "1001:1002", "two photos",
                conversation_key=conv_key,
                conversation_key_version="7",
                attachments=[_media(h, len(f)) for h, f in photos.items()],
            )
        )

        for media_hash_key, photo in photos.items():
            encrypted = chat.encrypt_file(
                EncryptFileParams(photo, payload.event_b64, media_hash_key, **_key_kwargs(keys))
            )
            self.assertEqual(len(encrypted), encrypted_file_size(len(photo)))

            encryptor = chat.file_encryptor(
                FileEncryptorParams(payload.event_b64, media_hash_key, **_key_kwargs(keys))
            )
            streamed = b"".join(encryptor.push(photo[i:i + 700]) for i in range(0, len(photo), 700))
            streamed += encryptor.finish()
            self.assertEqual(len(streamed), len(encrypted))

            for blob in (encrypted, streamed):
                self.assertEqual(
                    chat.decrypt_file(
                        DecryptFileParams(blob, payload.event_b64, keys, media_hash_key)
                    ),
                    photo,
                )
                decryptor = chat.file_decryptor(
                    FileDecryptorParams(payload.event_b64, keys, media_hash_key)
                )
                opened = b"".join(decryptor.push(blob[i:i + 333]) for i in range(0, len(blob), 333))
                opened += decryptor.finish()
                self.assertEqual(opened, photo)

        with self.assertRaises(RuntimeError):
            encryptor.finish()

    def _sender_of_files(self, chat=None):
        from chat_xdk import EncryptMessageParams, SetIdentityParams

        chat, v = self._unlocked_chat(chat)
        chat.set_identity(SetIdentityParams("1001", "1"))
        conv_key = base64.b64decode(v["conversation_key_b64"])

        def send(text, hashes):
            return chat.encrypt_message(
                EncryptMessageParams(
                    "1001:1002", text,
                    conversation_key=conv_key,
                    conversation_key_version="7",
                    attachments=[_media(h) for h in hashes],
                )
            ).message_id

        return chat, send

    def test_a_v1_message_with_files_takes_the_id_its_files_derive(self):
        from features_support import v1_chat, wait_for_v1

        chat, send = self._sender_of_files(v1_chat())
        wait_for_v1(chat)

        first = send("draft", ["photo-a", "photo-b"])
        self.assertEqual(send("final text", ["photo-a", "photo-b"]), first)
        self.assertNotEqual(send("draft", ["photo-b", "photo-a"]), first)
        self.assertNotEqual(send("draft", []), send("draft", []))

    def test_a_v0_message_with_files_takes_a_random_id(self):
        _, send = self._sender_of_files()

        self.assertNotEqual(send("draft", ["photo-a", "photo-b"]), send("draft", ["photo-a", "photo-b"]))

    def test_file_errors_say_what_to_pass(self):
        from chat_xdk import EncryptFileParams, EncryptMessageParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("1001", "1"))
        conv_key = base64.b64decode(v["conversation_key_b64"])
        payload = chat.encrypt_message(
            EncryptMessageParams(
                "1001:1002", "a photo",
                conversation_key=conv_key,
                conversation_key_version="7",
                attachments=[_media("photo")],
            )
        )
        cases = [
            ({"7": conv_key}, "other", "is not one of the message's files"),
            ({"8": conv_key}, "photo", "conversation_key_version '8' is not the message's key version '7'"),
            ({"7": bytes(3)}, "photo", "Invalid conversation key (expected 32 bytes)"),
        ]
        for keys, media_hash_key, expected in cases:
            with self.assertRaises(ValueError) as ctx:
                chat.encrypt_file(EncryptFileParams(b"x", payload.event_b64, media_hash_key, **_key_kwargs(keys)))
            self.assertIn(expected, str(ctx.exception))

    def test_each_file_needs_its_own_media_hash_key(self):
        from chat_xdk import EncryptMessageParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("1001", "1"))
        with self.assertRaisesRegex(ValueError, "media_hash_key 'photo' is in more than one attachment"):
            chat.encrypt_message(
                EncryptMessageParams(
                    "1001:1002", "two photos",
                    conversation_key=bytes(32),
                    conversation_key_version="7",
                    attachments=[_media("photo"), _media("photo")],
                )
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
        from chat_xdk import DecryptEventsParams

        chat, _ = self._unlocked_chat()

        # Missing the identity binding fields (identity_public_key /
        # identity_public_key_signature) -> raises ValueError.
        incomplete = [{
            "user_id": "910002",
            "public_key_version": "1",
            "public_key": "abc",
        }]
        with self.assertRaises(ValueError):
            chat.decrypt_events(DecryptEventsParams([], signing_keys=incomplete))

    def test_decrypt_event_rejects_incomplete_signing_key(self):
        from chat_xdk import DecryptEventParams

        chat, _ = self._unlocked_chat()

        incomplete = [{
            "user_id": "910002",
            "public_key_version": "1",
            "public_key": "abc",
            "identity_public_key": "def",
            # identity_public_key_signature intentionally omitted
        }]
        with self.assertRaises(ValueError):
            chat.decrypt_event(DecryptEventParams("", {}, signing_keys=incomplete))

    def test_decrypt_event_rejects_a_malformed_key_map_entry(self):
        from chat_xdk import DecryptEventParams

        chat, v = self._unlocked_chat()
        with self.assertRaises(ValueError) as ctx:
            chat.decrypt_event(DecryptEventParams(v["event_message_b64"], {"1": b"short"}))
        self.assertIn("the key for version '1' in the conversation key map is not 32 bytes", str(ctx.exception))

    def test_session_identity_is_the_default_sender(self):
        from chat_xdk import EncryptMessageParams, SetIdentityParams

        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])

        chat.set_identity(SetIdentityParams("1001", "7"))
        payload = chat.encrypt_message(
            EncryptMessageParams(
                "conv-1", "hi",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        )
        self.assertEqual(payload.signature_info.public_key_version, "7")
        self.assertTrue(payload.encoded_message_create_event)

        # The explicit-override form signs with the same key version and
        # produces an equally complete payload.
        explicit = chat.encrypt_message(
            EncryptMessageParams(
                "conv-1", "hi",
                sender_id="1001",
                signing_key_version="7",
                conversation_key=conv_key,
                conversation_key_version="1",
            )
        )
        self.assertEqual(explicit.signature_info.public_key_version, "7")
        self.assertTrue(explicit.encoded_message_create_event)
        self.assertTrue(explicit.signature)

    def test_encrypt_without_identity_mentions_sender_id(self):
        from chat_xdk import EncryptMessageParams

        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])

        for attachments in (None, [_media("photo")]):
            with self.assertRaises(ValueError) as ctx:
                chat.encrypt_message(
                    EncryptMessageParams(
                        "conv-1", "hi",
                        conversation_key=conv_key,
                        conversation_key_version="1",
                        attachments=attachments,
                    )
                )
            self.assertIn("sender_id", str(ctx.exception))

    def test_generated_keys_sign_only_with_the_registered_version(self):
        from chat_xdk import Chat, MessageDeleteParams, SetIdentityParams, ImportKeysParams

        chat = Chat()
        chat.generate_keypairs()
        with self.assertRaises(ValueError) as ctx:
            chat.prepare_message_delete(
                MessageDeleteParams("1234-5678", ["seq-1"], False, sender_id="1234")
            )
        self.assertIn("signing_key_version", str(ctx.exception))

        chat.set_identity(SetIdentityParams("1234", "1700000000123"))
        sig = _only_action(
            chat.prepare_message_delete(MessageDeleteParams("1234-5678", ["seq-1"], False))
        )
        self.assertEqual(sig["message_event_signature"]["public_key_version"], "1700000000123")

        # Restored keys carry the version passed to import_keys, and none
        # without it.
        keys = bytes(chat.export_keys())
        restored = Chat()
        restored.import_keys(ImportKeysParams(keys, signing_key_version="1700000000456"))
        sig = _only_action(
            restored.prepare_message_delete(
                MessageDeleteParams("1234-5678", ["seq-1"], False, sender_id="1234")
            )
        )
        self.assertEqual(sig["message_event_signature"]["public_key_version"], "1700000000456")
        restored.import_keys(ImportKeysParams(keys))
        with self.assertRaises(ValueError):
            restored.prepare_message_delete(
                MessageDeleteParams("1234-5678", ["seq-1"], False, sender_id="1234")
            )


if __name__ == "__main__":
    unittest.main()
