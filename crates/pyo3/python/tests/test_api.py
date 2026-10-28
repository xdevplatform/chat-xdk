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


def _signs(chat, sig, payload):
    """Whether ``sig``'s signature verifies, under the signer's own signing
    key, over ``payload``: the comma-joined fields its event signs."""
    signed = sig["message_event_signature"]
    signature = signed["signature"]
    return chat.verify(
        signed["signing_public_key"],
        base64.b64decode(signature + "=" * (-len(signature) % 4)),
        payload.encode(),
    )


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

    def test_stub_parameter_names_match_the_native_code(self):
        """A keyword argument the stub names must be one the native call takes."""
        import ast
        import inspect

        import chat_xdk

        stub_path = os.path.join(os.path.dirname(chat_xdk.__file__), "__init__.pyi")
        with open(stub_path, "r", encoding="utf-8") as f:
            stub = ast.parse(f.read())

        def names(fn):
            return [a.arg for a in fn.args.args + fn.args.kwonlyargs if a.arg != "self"]

        def native(obj):
            return [name for name in inspect.signature(obj).parameters if name != "self"]

        checked = 0
        for node in stub.body:
            if isinstance(node, ast.FunctionDef) and hasattr(chat_xdk, node.name):
                self.assertEqual(names(node), native(getattr(chat_xdk, node.name)), node.name)
                checked += 1
            if isinstance(node, ast.ClassDef) and node.name == "Chat":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef) and not fn.name.startswith("__"):
                        self.assertEqual(names(fn), native(getattr(chat_xdk.Chat, fn.name)), fn.name)
                        checked += 1
        self.assertGreater(checked, 50)

    def test_every_params_class_is_exported(self):
        import chat_xdk

        for name in (
            "EncryptMessageParams",
            "EncryptReplyParams",
            "EncryptReactionParams",
            "EncryptEditParams",
            "ConversationKeyChangeParams",
            "GroupMembersChangeParams",
            "GroupAdminsAddParams",
            "GroupAdminsRemoveParams",
            "GroupAvatarChangeParams",
            "GroupCreateParams",
            "GroupDescriptionChangeParams",
            "GroupInviteDisableParams",
            "GroupInviteEnableParams",
            "GroupJoinRejectParams",
            "GroupJoinRequestParams",
            "GroupLeaveParams",
            "GroupMembersRemoveParams",
            "GroupTitleChangeParams",
            "MessageDeleteParams",
            "MessageTtlChangeParams",
            "MessageTtlRemoveParams",
            "ScreenCaptureChange",
            "ScreenCaptureParams",
            "MarkConversationReadParams",
            "SetIdentityParams",
            "ImportKeysParams",
            "DecryptEventParams",
            "DecryptEventsParams",
            "EncryptFileParams",
            "FileEncryptorParams",
            "DecryptFileParams",
            "FileDecryptorParams",
            "EncryptFileWithKeyParams",
            "DecryptFileWithKeyParams",
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
            DecryptFileWithKeyParams,
            EncryptEditParams,
            EncryptFileParams,
            EncryptFileWithKeyParams,
            EncryptMessageParams,
            EncryptReactionParams,
            EncryptReplyParams,
            FileDecryptorParams,
            FileEncryptorParams,
            GroupCreateParams,
            GroupMembersChangeParams,
            GroupMembersRemoveParams,
            GroupTitleChangeParams,
            ImportKeysParams,
            MarkConversationReadParams,
            MessageDeleteParams,
            ScreenCaptureParams,
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
            lambda: GroupMembersRemoveParams([], "g1"),
            lambda: GroupTitleChangeParams("g1"),
            lambda: ScreenCaptureParams("g1"),
            lambda: MarkConversationReadParams("conv-1"),
            lambda: SetIdentityParams("1001"),
            lambda: ImportKeysParams(),
            lambda: DecryptEventParams(),
            lambda: DecryptEventsParams(),
            lambda: EncryptFileParams(b"file", "event"),
            lambda: FileEncryptorParams("event"),
            lambda: DecryptFileParams(b"file", "event", {}),
            lambda: FileDecryptorParams("event", {}),
            lambda: EncryptFileWithKeyParams(b"file"),
            lambda: DecryptFileWithKeyParams(b"encrypted"),
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
            lambda: GroupMembersRemoveParams([], "g1", ["1"], "1001"),
            lambda: GroupTitleChangeParams("g1", "Board", "1001"),
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

    def test_errors_are_typed_by_kind(self):
        from chat_xdk import (
            Chat,
            ChatXdkError,
            DecryptEventParams,
            InvalidInputError,
            InvalidStateError,
            ParseError,
        )

        chat = Chat()
        with self.assertRaises(InvalidInputError) as ctx:
            chat.update_config("not json")
        self.assertEqual(ctx.exception.kind, "invalid_input")
        self.assertIsNone(ctx.exception.guesses_remaining)
        self.assertIsInstance(ctx.exception, ChatXdkError)
        self.assertIsInstance(ctx.exception, ValueError)
        with self.assertRaises(InvalidInputError):
            chat.setup("123")
        with self.assertRaises(ParseError) as ctx:
            chat.decrypt_event(DecryptEventParams("not base64!"))
        self.assertEqual(ctx.exception.kind, "parse")
        with self.assertRaises(InvalidStateError) as ctx:
            chat.sign(b"data")
        self.assertEqual(ctx.exception.kind, "invalid_state")
        with self.assertRaises(InvalidStateError):
            chat.export_keys()

    def test_juicebox_calls_without_a_config_fail_with_the_cores_invalid_state_error(self):
        import asyncio

        from chat_xdk import Chat, InvalidStateError

        want = (
            "Invalid state: no Juicebox config: pass the juicebox_config the X API returns "
            "when you create the chat, or call update_config() first"
        )
        for chat in (Chat(), Chat("{}")):
            chat.generate_keypairs()
            for call in (
                lambda: chat.setup("2580"),
                lambda: chat.unlock("2580"),
                lambda: chat.change_pin("2580", "1359"),
                lambda: chat.delete(),
                lambda: asyncio.run(chat.unlock_async("2580")),
            ):
                with self.assertRaises(InvalidStateError) as ctx:
                    call()
                self.assertEqual(ctx.exception.kind, "invalid_state")
                self.assertEqual(str(ctx.exception), want)
            self.assertTrue(chat.is_unlocked())

    def test_async_variants_run_the_same_calls(self):
        import asyncio

        from chat_xdk import Chat, InvalidInputError

        chat = Chat()
        with self.assertRaises(InvalidInputError):
            asyncio.run(chat.setup_async("123"))
        with self.assertRaises(InvalidInputError):
            asyncio.run(chat.change_pin_async("2580", "1111"))

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
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
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

    def test_results_carry_the_keys_their_types_declare(self):
        import chat_xdk
        from chat_xdk import (
            ConversationKeyChangeParams,
            DecryptEventsParams,
            GroupTitleChangeParams,
            MessageDeleteParams,
        )

        def declared(typed_dict):
            return set(typed_dict.__annotations__)

        chat, v = self._unlocked_chat()
        key_input: chat_xdk.PublicKeyInput = {
            "user_id": "910002",
            "identity_public_key": v["identity_public_b64"],
            "public_key_version": "1",
        }
        change = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                [key_input], conversation_id="conv-1", sender_id="910002", signing_key_version="1"
            )
        )
        self.assertEqual(
            set(change) | {"encrypted_title", "encrypted_description"},
            declared(chat_xdk.PreparedConversationChange),
        )
        self.assertEqual(
            set(change["conversation_participant_keys"][0]),
            declared(chat_xdk.ConversationParticipantKey),
        )
        signature = change["action_signatures"][0]
        self.assertEqual(set(signature), declared(chat_xdk.ActionSignature))
        self.assertEqual(
            set(signature["message_event_signature"]),
            declared(chat_xdk.MessageEventSignature),
        )
        title = chat.prepare_group_title_change(
            GroupTitleChangeParams(
                "g100",
                "Team",
                sender_id="910002",
                signing_key_version="1",
                conversation_key=change["conversation_key"],
                conversation_key_version=change["conversation_key_version"],
            )
        )
        self.assertEqual(set(title), declared(chat_xdk.PreparedGroupMetadataChange))
        delete = chat.prepare_message_delete(
            MessageDeleteParams("conv-1", ["1"], True, sender_id="910002", signing_key_version="1")
        )
        self.assertEqual(set(delete), declared(chat_xdk.PreparedAction))

        signing_key: chat_xdk.SigningKeyEntry = self._signing_key(
            v["event_sender_id"], v["event_signing_key_version"]
        )
        self.assertEqual(set(signing_key), declared(chat_xdk.SigningKeyEntry))
        batch = chat.decrypt_events(
            DecryptEventsParams(
                [v["event_key_change_b64"], v["event_message_b64"]], signing_keys=[signing_key]
            )
        )
        self.assertEqual(set(batch), declared(chat_xdk.DecryptEventsResult))
        self.assertEqual(
            set(batch["conversation_keys"]), declared(chat_xdk.ConversationKeyResult)
        )
        for decrypted in batch["events"]:
            self.assertLessEqual(set(decrypted), declared(chat_xdk.DecryptedEvent))

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
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
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
        self.assertTrue(ckce["encoded_message_event_detail"])
        add = result["action_signatures"][1]
        self.assertTrue(add["encoded_message_event_detail"])
        # The title goes out encrypted under the new key, the value the
        # request sends as encrypted_title; the signature covers the
        # ciphertext. Unset screen-capture blocking signs as the trailing null
        # sentinel.
        encrypted_title = result["encrypted_title"]
        self.assertTrue(
            _signs(
                chat,
                add,
                f"GroupChangeEvent.GroupMemberAddChange,{add['message_id']},910002,g123,"
                f"910009,910002,910002,{encrypted_title},null,null,"
                f"{result['conversation_key_version']},null",
            )
        )
        self.assertEqual(chat.decrypt(encrypted_title, result["conversation_key"]), "Team")
        self.assertNotIn("encrypted_description", result)
        self.assertEqual(add["message_event_signature"]["signature_version"], "7")

    def test_prepare_group_members_change_encrypts_the_description(self):
        from chat_xdk import GroupMembersChangeParams

        chat, v = self._unlocked_chat()
        public_keys = [
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
        ]
        avatar_url = "https://ton.x.com/xchat_media/g123/avatar"
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
                current_title="Team",
                current_description="Ships the app",
                current_avatar_url=avatar_url,
            )
        )
        add = result["action_signatures"][1]
        encrypted_description = result["encrypted_description"]
        self.assertEqual(
            chat.decrypt(encrypted_description, result["conversation_key"]), "Ships the app"
        )
        # The description is signed at version 8, after the screen-capture
        # slot; the avatar URL is signed as passed.
        self.assertEqual(add["message_event_signature"]["signature_version"], "8")
        self.assertTrue(
            _signs(
                chat,
                add,
                f"GroupChangeEvent.GroupMemberAddChange,{add['message_id']},910002,g123,"
                f"910009,910002,910002,{result['encrypted_title']},{avatar_url},null,"
                f"{result['conversation_key_version']},null,{encrypted_description}",
            )
        )

    def test_prepare_group_members_change_screen_capture_blocking(self):
        from chat_xdk import GroupMembersChangeParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
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
            _signs(
                chat,
                add,
                f"GroupChangeEvent.GroupMemberAddChange,{add['message_id']},910002,g123,"
                f"910009,910002,910002,null,null,null,{result['conversation_key_version']},true",
            )
        )
        self.assertTrue(add["encoded_message_event_detail"])

    def test_prepare_group_create_shape(self):
        from chat_xdk import GroupCreateParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
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
        self.assertTrue(ckce["encoded_message_event_detail"])
        create = result["action_signatures"][1]
        self.assertTrue(create["encoded_message_event_detail"])
        # The title goes out encrypted under the new key, the value the
        # request sends as group_name; the signature covers the ciphertext.
        encrypted_title = result["encrypted_title"]
        self.assertTrue(
            _signs(
                chat,
                create,
                f"GroupChangeEvent.GroupCreate,{create['message_id']},910002,"
                f"{result['conversation_key_version']},910002,910005,null,{encrypted_title},null",
            )
        )
        self.assertEqual(chat.decrypt(encrypted_title, result["conversation_key"]), "Team")
        self.assertNotIn("encrypted_description", result)

    def test_prepare_group_create_encrypts_a_title_with_a_comma(self):
        from chat_xdk import GroupCreateParams

        chat, v = self._unlocked_chat()
        public_keys = [
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
        ]
        result = chat.prepare_group_create(
            GroupCreateParams(
                public_keys,
                "g123",
                ["910002"],
                ["910002"],
                sender_id="910002",
                signing_key_version="1",
                title="Team, the sequel",
            )
        )
        key = result["conversation_key"]
        self.assertEqual(chat.decrypt(result["encrypted_title"], key), "Team, the sequel")

    def test_prepare_group_create_empty_title_signs_as_omitted(self):
        from chat_xdk import GroupCreateParams

        chat, v = self._unlocked_chat()

        public_keys = [
            {"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}
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
            create = result["action_signatures"][1]
            self.assertTrue(
                _signs(
                    chat,
                    create,
                    f"GroupChangeEvent.GroupCreate,{create['message_id']},910002,"
                    f"{result['conversation_key_version']},910002,910005,null,null,null",
                ),
                "the title and avatar must sign as the null sentinel",
            )
            self.assertNotIn("encrypted_title", result)

    def test_group_actions_sign_the_verifier_payloads(self):
        from chat_xdk import (
            GroupAdminsAddParams,
            GroupAvatarChangeParams,
            GroupDescriptionChangeParams,
            GroupInviteEnableParams,
            GroupJoinRejectParams,
            GroupLeaveParams,
            GroupMembersRemoveParams,
            GroupTitleChangeParams,
            MessageTtlChangeParams,
            MessageTtlRemoveParams,
            ScreenCaptureChange,
            ScreenCaptureParams,
        )

        chat, v = self._unlocked_chat()
        ident = dict(sender_id="910002", signing_key_version="1")

        remaining = [
            {
                "user_id": "910002",
                "identity_public_key": v["identity_public_b64"],
                "public_key_version": "1",
            }
        ]
        rotated = chat.prepare_group_members_remove(
            GroupMembersRemoveParams(remaining, "g100", ["910007"], **ident)
        )
        self.assertEqual(len(rotated["conversation_key"]), 32)
        self.assertEqual(len(rotated["conversation_participant_keys"]), 1)
        self.assertEqual(len(rotated["action_signatures"]), 2)
        with_title = chat.prepare_group_members_remove(
            GroupMembersRemoveParams(remaining, "g100", ["910007"], title="Board", **ident)
        )
        self.assertEqual(len(with_title["action_signatures"]), 3)
        version = with_title["conversation_key_version"]
        removal, title = with_title["action_signatures"][:2]
        self.assertTrue(
            _signs(
                chat,
                removal,
                f"GroupChangeEvent.GroupMemberRemoveChange,{removal['message_id']},910002,g100,"
                f"910007,{version},signature_version=11",
            )
        )
        self.assertEqual(title["message_event_signature"]["signature_version"], "7")
        self.assertTrue(title["encoded_message_event_detail"])
        removal = rotated["action_signatures"][0]
        self.assertEqual(removal["message_event_signature"]["signature_version"], "11")
        self.assertTrue(
            _signs(
                chat,
                removal,
                f"GroupChangeEvent.GroupMemberRemoveChange,{removal['message_id']},910002,g100,"
                f"910007,{rotated['conversation_key_version']},signature_version=11",
            )
        )
        with self.assertRaises(ValueError) as raised:
            chat.prepare_group_members_remove(
                GroupMembersRemoveParams([], "g100", ["910007"], **ident)
            )
        self.assertEqual(
            str(raised.exception),
            "public_keys is empty: pass the public keys of the remaining members",
        )

        left = chat.prepare_group_leave(
            GroupLeaveParams("g100", promote_admin_id="910008", conversation_key_version="7", **ident)
        )
        self.assertEqual(len(left["action_signatures"]), 3)
        removal, promote, delete = left["action_signatures"]
        self.assertTrue(
            _signs(
                chat,
                removal,
                f"GroupChangeEvent.GroupMemberRemoveChange,{removal['message_id']},910002,g100,"
                "910002,7,signature_version=11",
            )
        )
        self.assertTrue(
            _signs(
                chat,
                promote,
                f"GroupChangeEvent.GroupAdminAddChange,{promote['message_id']},910002,g100,910008",
            )
        )
        self.assertTrue(
            _signs(chat, delete, f"ConversationDeleteEvent,{delete['message_id']},910002,g100")
        )

        conv_key = base64.b64decode(v["conversation_key_b64"])
        key = dict(conversation_key=conv_key, conversation_key_version="4")
        metadata = [
            (
                chat.prepare_group_title_change(
                    GroupTitleChangeParams("g100", "Board: layoffs, Q3", **key, **ident)
                ),
                "GroupChangeEvent.GroupTitleChange,",
                "Board: layoffs, Q3",
            ),
            (
                chat.prepare_group_description_change(
                    GroupDescriptionChangeParams("g100", "Rules: be kind", **key, **ident)
                ),
                "GroupChangeEvent.GroupDescriptionChange,",
                "Rules: be kind",
            ),
        ]
        for prepared, prefix, plaintext in metadata:
            self.assertEqual(
                set(prepared), {"encrypted_value", "conversation_key_version", "action_signatures"}
            )
            self.assertEqual(prepared["conversation_key_version"], "4")
            sig = prepared["action_signatures"][0]
            self.assertTrue(
                _signs(
                    chat,
                    sig,
                    f"{prefix}{sig['message_id']},910002,g100,4,{prepared['encrypted_value']}",
                )
            )
            self.assertEqual(chat.decrypt(prepared["encrypted_value"], conv_key), plaintext)
        avatar_url = "https://ton.x.com/xchat_media/g100/avatar"
        avatar = chat.prepare_group_avatar_change(
            GroupAvatarChangeParams("g100", avatar_url, "4", **ident)
        )
        self.assertEqual(set(avatar), {"action_signatures"})
        sig = avatar["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                sig,
                f"GroupChangeEvent.GroupAvatarUrlChange,{sig['message_id']},910002,g100,4,{avatar_url}",
            )
        )
        with self.assertRaises(ValueError) as raised:
            chat.prepare_group_title_change(GroupTitleChangeParams("g100", "Board", **ident))
        self.assertIn("no cached conversation key for 'g100'", str(raised.exception))
        admins = chat.prepare_group_admins_add(
            GroupAdminsAddParams("g100", ["910008", "910009"], **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                admins,
                f"GroupChangeEvent.GroupAdminAddChange,{admins['message_id']},910002,g100,"
                "910008,910009",
            )
        )
        invite = chat.prepare_group_invite_enable(
            GroupInviteEnableParams("g100", "https://x.com/i/invite/abc", **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                invite,
                f"GroupChangeEvent.GroupInviteEnable,{invite['message_id']},910002,g100,"
                "https://x.com/i/invite/abc,null,null",
            )
        )
        rejected = chat.prepare_group_join_reject(
            GroupJoinRejectParams("g100", ["910010"], **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                rejected,
                f"GroupChangeEvent.GroupJoinReject,{rejected['message_id']},910002,g100,910010",
            )
        )
        ttl = chat.prepare_message_ttl_change(
            MessageTtlChangeParams("g100", 86400000, **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                ttl,
                "ConversationMetadataChangeEvent.MessageDurationChange,"
                f"{ttl['message_id']},910002,g100,86400000",
            )
        )
        cleared = chat.prepare_message_ttl_remove(
            MessageTtlRemoveParams("g100", **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                cleared,
                "ConversationMetadataChangeEvent.MessageDurationRemove,"
                f"{cleared['message_id']},910002,g100",
            )
        )
        blocking = chat.prepare_screen_capture(
            ScreenCaptureParams("g100", ScreenCaptureChange.BlockingEnabled, **ident)
        )["action_signatures"][0]
        self.assertTrue(
            _signs(
                chat,
                blocking,
                "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,"
                f"{blocking['message_id']},910002,g100",
            )
        )
        with self.assertRaises(ValueError) as raised:
            chat.prepare_screen_capture(ScreenCaptureParams("g100", "nope", **ident))
        self.assertIn("Invalid screen capture change: 'nope'", str(raised.exception))

    def test_group_actions_sign_each_action(self):
        """The group and conversation-metadata actions each sign one action at
        signature version 7 over the event name, the action's message id, the
        sender, the conversation and the signed fields, and the signature
        verifies with the signer's signing key."""
        from chat_xdk import (
            GroupAdminsAddParams,
            GroupAdminsRemoveParams,
            GroupAvatarChangeParams,
            GroupDescriptionChangeParams,
            GroupInviteDisableParams,
            GroupInviteEnableParams,
            GroupJoinRejectParams,
            GroupJoinRequestParams,
            MessageTtlChangeParams,
            MessageTtlRemoveParams,
            SetIdentityParams,
        )

        chat, _ = self._unlocked_chat()
        chat.set_identity(SetIdentityParams("111", "1"))
        signing_key = chat.get_public_keys().signing
        description = lambda: chat.prepare_group_description_change(
            GroupDescriptionChangeParams(
                "g100",
                "Ships the app",
                conversation_key=bytes(32),
                conversation_key_version="4",
            )
        )
        cases = [
            ("GroupChangeEvent.GroupAvatarUrlChange", lambda result: ",g100,4,https://img/a.png",
             lambda: chat.prepare_group_avatar_change(GroupAvatarChangeParams("g100", "https://img/a.png", "4"))),
            ("GroupChangeEvent.GroupDescriptionChange",
             lambda result: ",g100,4," + result["encrypted_value"], description),
            ("GroupChangeEvent.GroupAdminAddChange", lambda result: ",g100,910008,910009",
             lambda: chat.prepare_group_admins_add(GroupAdminsAddParams("g100", ["910008", "910009"]))),
            ("GroupChangeEvent.GroupAdminRemoveChange", lambda result: ",g100,910008",
             lambda: chat.prepare_group_admins_remove(GroupAdminsRemoveParams("g100", ["910008"]))),
            ("GroupChangeEvent.GroupInviteEnable", lambda result: ",g100,https://x.com/i/invite/abc,null,null",
             lambda: chat.prepare_group_invite_enable(GroupInviteEnableParams("g100", "https://x.com/i/invite/abc"))),
            ("GroupChangeEvent.GroupInviteDisable", lambda result: ",g100,111",
             lambda: chat.prepare_group_invite_disable(GroupInviteDisableParams("g100"))),
            ("GroupChangeEvent.GroupJoinRequest", lambda result: ",g100,111",
             lambda: chat.prepare_group_join_request(GroupJoinRequestParams("g100"))),
            ("GroupChangeEvent.GroupJoinReject", lambda result: ",g100,910010",
             lambda: chat.prepare_group_join_reject(GroupJoinRejectParams("g100", ["910010"]))),
            ("ConversationMetadataChangeEvent.MessageDurationChange", lambda result: ",g100,86400000",
             lambda: chat.prepare_message_ttl_change(MessageTtlChangeParams("g100", 86400000))),
            ("ConversationMetadataChangeEvent.MessageDurationRemove", lambda result: ",g100",
             lambda: chat.prepare_message_ttl_remove(MessageTtlRemoveParams("g100"))),
        ]
        for event, signed_fields, prepare in cases:
            with self.subTest(event=event):
                result = prepare()
                (action,) = result["action_signatures"]
                payload = f"{event},{action['message_id']},111{signed_fields(result)}"
                sig = action["message_event_signature"]
                self.assertEqual(sig["signature_version"], "7")
                self.assertEqual(sig["signing_public_key"], signing_key)
                # The signature is base64 without padding, as the wire carries it.
                raw = base64.b64decode(sig["signature"] + "=" * (-len(sig["signature"]) % 4))
                self.assertTrue(chat.verify(signing_key, raw, payload.encode("utf-8")), payload)

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
        self.assertTrue(
            _signs(chat, sig, f"MessageDeleteEvent,{sig['message_id']},111,111:222,2,seq-10,seq-11")
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

        self.assertTrue(_signs(chat, sig, f"MessageDeleteEvent,{sig['message_id']},111,g999,1,seq-1"))

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
        self.assertEqual(sig["message_event_signature"]["signing_public_key"], v["signing_public_b64"])
        self.assertTrue(
            _signs(
                chat,
                sig,
                f"MarkConversationReadEvent,{sig['message_id']},111,111:222,"
                "2011626338877079553,1700000000123",
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
        self.assertTrue(
            any(_signs(chat, sig, f"{prefix}{seen_at}") for seen_at in range(before, after + 1))
        )

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
            {"user_id": "1491585161162473473", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"},
            {"user_id": "17380288", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"},
        ]
        # Leaving conversation_id None derives the canonical numeric-sorted id.
        result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                public_keys, sender_id="1491585161162473473", signing_key_version="1"
            )
        )
        self.assertEqual(result["conversation_id"], "17380288:1491585161162473473")

    def test_decrypt_reads_the_title_a_title_change_sends(self):
        from chat_xdk import GroupTitleChangeParams

        chat, v = self._unlocked_chat()
        conv_key = base64.b64decode(v["conversation_key_b64"])
        title = "metadata payload \U0001F31F with unicode"
        params = GroupTitleChangeParams(
            "g100",
            title,
            sender_id="910002",
            signing_key_version="1",
            conversation_key=conv_key,
            conversation_key_version="4",
        )
        first = chat.prepare_group_title_change(params)["encrypted_value"]
        self.assertNotEqual(first, title)
        # Randomized nonce: two encryptions differ.
        self.assertNotEqual(chat.prepare_group_title_change(params)["encrypted_value"], first)
        self.assertEqual(chat.decrypt(first, conv_key), title)

    def test_export_lock_reimport_roundtrip(self):
        from chat_xdk import ImportKeysParams
        chat, v = self._unlocked_chat()

        exported = chat.export_keys()
        self.assertIsNotNone(exported)
        # The exported blob is exactly the fixture private-key concat.
        self.assertEqual(bytes(exported), base64.b64decode(v["private_keys_concat_b64"]))

        chat.lock()
        self.assertFalse(chat.is_unlocked())
        with self.assertRaises(ValueError):
            chat.export_keys()

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

    def test_a_file_without_a_name_or_a_size_fails_with_invalid_input(self):
        from chat_xdk import EncryptMessageParams, InvalidInputError

        chat, v = self._unlocked_chat()
        no_name = "has an empty filename: pass the file's original name"
        no_size = (
            "has filesize_bytes 0: pass the encrypted file's size, which encrypted_file_size gives"
        )

        def card(**image):
            return {"attachment_type": "url", "url": "https://example.com", **image}

        cases = [
            ({**_media("photo"), "filename": ""}, f"media_hash_key 'photo' {no_name}"),
            (_media("photo", filesize_bytes=0), f"media_hash_key 'photo' {no_size}"),
            (
                card(banner_image={"media_hash_key": "banner", "filesize_bytes": 1000, "filename": ""}),
                f"media_hash_key 'banner' {no_name}",
            ),
            (
                card(favicon_image={"media_hash_key": "favicon", "filesize_bytes": 0, "filename": "f.png"}),
                f"media_hash_key 'favicon' {no_size}",
            ),
        ]
        for attachment, message in cases:
            with self.assertRaises(InvalidInputError) as ctx:
                chat.encrypt_message(
                    EncryptMessageParams(
                        "123:456",
                        "a file",
                        sender_id="123",
                        signing_key_version="1",
                        conversation_key=bytes(32),
                        conversation_key_version="1",
                        attachments=[attachment],
                    )
                )
            self.assertEqual(ctx.exception.kind, "invalid_input")
            self.assertEqual(str(ctx.exception), message)

    def test_invalid_offsets_links_posts_and_dimensions_fail_with_invalid_input(self):
        from chat_xdk import EncryptMessageParams, InvalidInputError

        chat, v = self._unlocked_chat()

        def send(text="hi @bob", **fields):
            return chat.encrypt_message(
                EncryptMessageParams(
                    "123:456",
                    text,
                    sender_id="123",
                    signing_key_version="1",
                    conversation_key=bytes(32),
                    conversation_key_version="1",
                    **fields,
                )
            )

        banner = {"media_hash_key": "banner", "filesize_bytes": 1000, "filename": "b.png"}
        cases = [
            (
                {"entities": [(-1, 4, "mention")]},
                "Invalid entity offsets -1..4: offsets count bytes of the UTF-8 text, from 0",
            ),
            ({"entities": [(5, 3, "mention")]}, "Invalid entity offsets 5..3: end is before start"),
            (
                {"entities": [(3, 8, "mention")]},
                "Invalid entity offsets 3..8: end is past the end of the text, which is 7 bytes "
                "of UTF-8",
            ),
            (
                {"attachments": [{"attachment_type": "url", "url": ""}]},
                "a URL card's url is empty: pass the link the card shows",
            ),
            (
                {"attachments": [{"attachment_type": "post"}]},
                "a post attachment has neither rest_id nor post_url: pass the post's id or its URL",
            ),
            (
                {"attachments": [{**_media("photo"), "width": -1}]},
                "media_hash_key 'photo' has width -1: pass the width in pixels, 0 or more",
            ),
            (
                {
                    "attachments": [
                        {
                            "attachment_type": "url",
                            "url": "https://example.com",
                            "banner_image": {**banner, "height": -1},
                        }
                    ]
                },
                "media_hash_key 'banner' has height -1: pass the height in pixels, 0 or more",
            ),
        ]
        for fields, message in cases:
            with self.assertRaises(InvalidInputError) as ctx:
                send(**fields)
            self.assertEqual(str(ctx.exception), message)
        # Offsets count UTF-8 bytes: "é @bob" is 7 bytes, and "@bob" is bytes 3..7.
        send(text="é @bob", entities=[(3, 7, "mention")])

    def test_an_empty_juicebox_config_fails_with_the_no_config_error(self):
        from chat_xdk import Chat, InvalidStateError

        want = (
            "Invalid state: no Juicebox config: pass the juicebox_config the X API returns "
            "when you create the chat, or call update_config() first"
        )
        for empty in ("", "  "):
            with self.assertRaises(InvalidStateError) as ctx:
                Chat(empty)
            self.assertEqual(str(ctx.exception), want)
        chat = Chat()
        with self.assertRaises(InvalidStateError) as ctx:
            chat.update_config("")
        self.assertEqual(str(ctx.exception), want)

    def test_an_unknown_or_empty_entity_type_fails_with_invalid_input(self):
        from chat_xdk import EncryptMessageParams, InvalidInputError

        chat, v = self._unlocked_chat()
        for entity_type in ("bogus", ""):
            with self.assertRaises(InvalidInputError) as ctx:
                chat.encrypt_message(
                    EncryptMessageParams(
                        "123:456",
                        "hi @bob",
                        sender_id="123",
                        signing_key_version="1",
                        conversation_key=bytes(32),
                        conversation_key_version="1",
                        entities=[(3, 7, entity_type)],
                    )
                )
            self.assertEqual(ctx.exception.kind, "invalid_input")
            self.assertEqual(
                str(ctx.exception),
                f"Invalid entity_type '{entity_type}': pass url, mention, hashtag, cashtag, "
                "email, address or phone_number",
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

    def test_files_round_trip_under_a_key_the_caller_holds(self):
        from chat_xdk import Chat, DecryptFileWithKeyParams, EncryptFileWithKeyParams, encrypted_file_size

        chat = Chat()
        key = bytes(range(32))
        for size in (0, 1, 1023, 1024, 1025, 2048, 3050):
            file = bytes(i % 251 for i in range(size))
            encrypted = chat.encrypt_file_with_key(EncryptFileWithKeyParams(file=file, key=key))
            self.assertEqual(len(encrypted), encrypted_file_size(size))
            self.assertEqual(
                chat.decrypt_file_with_key(DecryptFileWithKeyParams(encrypted=encrypted, key=key)),
                file,
            )
        self.assertNotEqual(
            chat.encrypt_file_with_key(EncryptFileWithKeyParams(b"avatar", key)),
            chat.encrypt_file_with_key(EncryptFileWithKeyParams(b"avatar", key)),
        )

    def test_files_from_0_5_encrypt_stream_decrypt_under_their_key(self):
        from chat_xdk import Chat, DecryptFileWithKeyParams

        chat = Chat()
        for version in ("0_5_0", "0_5_2"):
            path = os.path.join(_repo_root(), "tests", "fixtures", f"compat_v{version}.json")
            with open(path, "r", encoding="utf-8") as f:
                fixture = json.load(f)
            key = base64.b64decode(fixture["conversation_key_b64"])
            for name in ("file", "avatar_file", "empty_file"):
                with self.subTest(version=version, file=name):
                    entry = fixture[name]
                    self.assertEqual(
                        chat.decrypt_file_with_key(
                            DecryptFileWithKeyParams(base64.b64decode(entry["ciphertext_b64"]), key)
                        ),
                        base64.b64decode(entry["plaintext_b64"]),
                    )

    def test_files_under_a_key_are_libsodium_secretstream_files(self):
        """X Android encrypts a group's avatar under the raw conversation key
        with libsodium's crypto_secretstream_xchacha20poly1305 (x-android
        LibsodiumEncryption.kt, ConversationManagerImpl.kt): a header, then
        1,024-byte chunks with no additional data, the last tagged final.
        Files under a key open with libsodium itself, and files libsodium
        writes that way open with decrypt_file_with_key."""
        try:
            from nacl import bindings as sodium
        except ImportError:
            self.skipTest("PyNaCl (libsodium) is not installed")
        from chat_xdk import Chat, DecryptFileWithKeyParams, EncryptFileWithKeyParams

        with open(os.path.join(_repo_root(), "tests", "fixtures", "compat_v0_5_2.json"), encoding="utf-8") as f:
            fixture = json.load(f)
        key = base64.b64decode(fixture["conversation_key_b64"])
        avatar = base64.b64decode(fixture["avatar_file"]["plaintext_b64"])
        header_size = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
        frame_size = 1024 + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
        message = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        final = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL

        chat = Chat()
        for file in (b"", b"x", bytes(1024), bytes(range(256)) * 8, avatar):
            with self.subTest(size=len(file)):
                encrypted = chat.encrypt_file_with_key(EncryptFileWithKeyParams(file, key))
                state = sodium.crypto_secretstream_xchacha20poly1305_state()
                sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, encrypted[:header_size], key)
                frames = [encrypted[i:i + frame_size] for i in range(header_size, len(encrypted), frame_size)]
                pulled = [sodium.crypto_secretstream_xchacha20poly1305_pull(state, frame) for frame in frames]
                self.assertEqual(b"".join(chunk for chunk, _ in pulled), file)
                self.assertEqual([tag for _, tag in pulled], [message] * (len(frames) - 1) + [final] * bool(frames))
                self.assertEqual(len(frames), -(-len(file) // 1024))

                state = sodium.crypto_secretstream_xchacha20poly1305_state()
                pushed = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
                chunks = [file[i:i + 1024] for i in range(0, len(file), 1024)]
                for i, chunk in enumerate(chunks):
                    tag = final if i == len(chunks) - 1 else message
                    pushed += sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, tag=tag)
                self.assertEqual(chat.decrypt_file_with_key(DecryptFileWithKeyParams(pushed, key)), file)

    def test_file_with_key_errors_name_the_key_or_the_file(self):
        from chat_xdk import (
            Chat,
            DecryptFileWithKeyParams,
            DecryptionError,
            EncryptFileWithKeyParams,
            InvalidInputError,
        )

        chat = Chat()
        key = bytes(range(32))
        encrypted = chat.encrypt_file_with_key(EncryptFileWithKeyParams(b"avatar" * 300, key))
        for bad_key in (b"", bytes(16), bytes(31), bytes(33)):
            with self.subTest(key_size=len(bad_key)):
                with self.assertRaises(InvalidInputError) as ctx:
                    chat.encrypt_file_with_key(EncryptFileWithKeyParams(b"avatar", bad_key))
                self.assertEqual(ctx.exception.kind, "invalid_input")
                self.assertIn(f"expected 32 bytes, got {len(bad_key)}", str(ctx.exception))
                with self.assertRaises(InvalidInputError):
                    chat.decrypt_file_with_key(DecryptFileWithKeyParams(encrypted, bad_key))

        frame_end = 24 + 1041
        for name, bad in (
            ("another key", (encrypted, bytes(32))),
            ("a flipped byte", (encrypted[:30] + bytes([encrypted[30] ^ 1]) + encrypted[31:], key)),
            ("cut inside the last frame", (encrypted[:-1], key)),
            ("cut at a frame boundary", (encrypted[:frame_end], key)),
            ("cut inside the header", (encrypted[:10], key)),
            ("trailing bytes", (encrypted + b"\0", key)),
        ):
            with self.subTest(name):
                with self.assertRaises(DecryptionError) as ctx:
                    chat.decrypt_file_with_key(DecryptFileWithKeyParams(*bad))
                self.assertEqual(ctx.exception.kind, "decryption")
                self.assertIn("pass all the encrypted bytes and the key they were encrypted under", str(ctx.exception))

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
