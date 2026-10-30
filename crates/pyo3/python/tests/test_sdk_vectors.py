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



def _key_kwargs(keys):
    """The one conversation key of a key map, as the file encrypt params take it."""
    ((version, key),) = keys.items()
    return {"conversation_key": key, "conversation_key_version": version}

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
        from features_support import keep_offline

        keep_offline()

    def test_public_keys_and_signature_match_fixture(self):
        from chat_xdk import Chat, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        keys = chat.get_public_keys()
        self.assertEqual(keys.identity, v["identity_public_b64"])
        self.assertEqual(keys.signing, v["signing_public_b64"])
        self.assertFalse(hasattr(keys, "version"))

        sig_bytes = chat.sign(v["message_utf8"].encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        self.assertEqual(sig_b64, v["signature_b64"])

        self.assertTrue(chat.verify(v["signing_public_b64"], sig_bytes, v["message_utf8"].encode("utf-8")))
        self.assertFalse(chat.verify(v["signing_public_b64"], sig_bytes, (v["message_utf8"] + "!").encode("utf-8")))

    def test_sign_refuses_data_only_the_sdk_signs(self):
        from chat_xdk import Chat, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        key_change = b"ConversationKeyChangeEvent,mk1,1001,1001:1002,1800000000000,a2V5"
        for data in (key_change, base64.b64decode(v["identity_public_b64"])):
            with self.assertRaisesRegex(ValueError, "only the SDK signs"):
                chat.sign(data)
        # Data that only resembles a payload is application data.
        self.assertEqual(len(chat.sign(b" " + key_change)), 64)

    def test_ecies_conversation_key_roundtrip(self):
        from chat_xdk import Chat, ConversationKeyChangeParams, ImportKeysParams

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))

        public_keys = [{"user_id": "910002", "identity_public_key": v["identity_public_b64"], "public_key_version": "1"}]
        result = chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                public_keys, conversation_id="conv-1", sender_id="910002", signing_key_version="1"
            )
        )
        encrypted_key_b64 = result["conversation_participant_keys"][0]["encrypted_conversation_key"]

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
        self.assertTrue(payload.encoded_message_create_event)
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

        key_changes = [m["event"] for m in result["events"] if m["event"]["type"] == "KeyChange"]
        self.assertEqual(len(key_changes), 1)
        self.assertTrue(key_changes[0]["verified"])
        self.assertEqual(key_changes[0]["conversation_key_version"], ck_version)
        participant_keys = key_changes[0]["conversation_participant_keys"]
        self.assertTrue(participant_keys)
        for key in participant_keys:
            self.assertEqual(set(key), {"user_id", "encrypted_conversation_key", "public_key_version"})

        messages = [m["event"] for m in result["events"] if m["event"]["type"] == "Message"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["text"], v["event_message_text"])
        self.assertTrue(messages[0]["verified"])
        self.assertEqual(messages[0]["conversation_key_version"], ck_version)

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
        from chat_xdk import (
            Chat,
            DecryptEventParams,
            DecryptEventsParams,
            EncryptFileParams,
            EncryptMessageParams,
            ImportKeysParams,
            SetIdentityParams,
        )

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
        self.assertTrue(payload.encoded_message_create_event)

        # A file of a message sent from the cache encrypts under the same cached key.
        photo = chat.encrypt_message(
            EncryptMessageParams(v["event_conversation_id"], "a photo", attachments=[_media("photo")])
        )
        encrypted = chat.encrypt_file(EncryptFileParams(b"photo bytes", photo.event_b64, "photo"))
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        self.assertEqual(
            self._open_media(photo.event_b64, keys, "photo", base64.b64encode(encrypted)), b"photo bytes"
        )

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

        messages = [m["event"] for m in result["events"] if m["event"]["type"] == "Message"]
        self.assertEqual(len(messages), 2)
        # Both replies decrypt; the derived preview validates against the
        # embedded raw original, the forged preview text is flagged.
        self.assertEqual(messages[0]["content"]["text"], v["event_reply_text"])
        self.assertEqual(messages[0]["reply_preview_validation"], "Valid")
        self.assertEqual(messages[1]["reply_preview_validation"], "Invalid")

    def test_group_description_change_decrypts_on_receive(self):
        from chat_xdk import Chat, DecryptEventParams

        v = _load_vectors()
        chat = Chat()
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_group_description_b64"],
                keys,
                signing_keys=_fixture_signing_keys(v),
            )
        )
        self.assertEqual(event["type"], "GroupChange")
        self.assertTrue(event["verified"])
        self.assertEqual(event["conversation_id"], v["event_group_id"])
        self.assertEqual(
            event["change"],
            {
                "change_type": "DescriptionChanged",
                "new_description": {"kind": "Text", "text": v["event_group_description"]},
            },
        )
        # Without the key the description was encrypted under, the change
        # still decrypts, with the description unavailable.
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_group_description_b64"], {}, signing_keys=_fixture_signing_keys(v)
            )
        )
        description = event["change"]["new_description"]
        self.assertEqual(description["kind"], "Unavailable")
        self.assertTrue(description["raw"])
        self.assertNotEqual(description["raw"], v["event_group_description"])

    def test_group_avatar_change_carries_the_media_url(self):
        from chat_xdk import Chat, DecryptEventParams

        v = _load_vectors()
        chat = Chat()
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_group_avatar_change_b64"], {}, signing_keys=_fixture_signing_keys(v)
            )
        )
        self.assertEqual(event["type"], "GroupChange")
        self.assertTrue(event["verified"])
        self.assertEqual(
            event["change"],
            {
                "change_type": "AvatarChanged",
                "new_avatar_url": v["event_group_avatar_url"],
                "conversation_key_version": v["event_conversation_key_version"],
            },
        )

    def test_group_removal_drops_the_title_and_description_reencryptions(self):
        from chat_xdk import (
            Chat,
            DecryptEventParams,
            DecryptEventsParams,
            ImportKeysParams,
            InvalidInputError,
        )

        v = _load_vectors()
        chat = Chat()  # default reject-unverified policy
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"]), signing_key_version=v["event_recipient_key_version"]))
        flow = v["event_group_removal_flow_b64"]
        version = v["event_group_removal_conversation_key_version"]

        result = chat.decrypt_events(
            DecryptEventsParams(flow, signing_keys=_fixture_signing_keys(v))
        )
        dropped = [str(index) for index in v["event_group_removal_dropped_indices"]]
        self.assertEqual(sorted(result["errors"]), dropped)
        self.assertEqual(result["conversation_keys"]["latest_version"], version)
        kept = [m["event"] for m in result["events"]]
        self.assertEqual(len(kept), 3)
        self.assertEqual(
            kept[0]["change"],
            {"change_type": "MembersRemoved", "member_ids": [v["event_group_removed_member_id"]]},
        )
        self.assertEqual(kept[1]["type"], "KeyChange")
        self.assertEqual(kept[1]["conversation_key_version"], version)
        self.assertEqual(
            kept[2]["change"],
            {
                "change_type": "TitleChanged",
                "new_title": {"kind": "Text", "text": v["event_group_renamed_title"]},
            },
        )
        self.assertTrue(all(event["verified"] for event in kept))

        # The single-event path drops the same events, as invalid input.
        for index in v["event_group_removal_dropped_indices"]:
            with self.assertRaises(InvalidInputError) as ctx:
                chat.decrypt_event(
                    DecryptEventParams(
                        flow[index],
                        result["conversation_keys"]["keys"],
                        signing_keys=_fixture_signing_keys(v),
                    )
                )
            self.assertEqual(str(ctx.exception), result["errors"][str(index)])

    def test_group_create_decrypts_its_title_on_receive(self):
        from chat_xdk import Chat, DecryptEventParams, DecryptEventsParams

        v = _load_vectors()
        chat = Chat()
        keys = {
            v["event_group_create_conversation_key_version"]: base64.b64decode(
                v["event_group_create_conversation_key_b64"]
            )
        }
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_group_create_b64"], keys, signing_keys=_fixture_signing_keys(v)
            )
        )
        self.assertEqual(event["type"], "GroupChange")
        self.assertTrue(event["verified"])
        self.assertEqual(
            event["change"],
            {
                "change_type": "Created",
                "member_ids": [v["event_sender_id"]],
                "admin_ids": [v["event_sender_id"]],
                "title": {"kind": "Text", "text": v["event_group_title"]},
                "avatar_url": None,
                "conversation_key_version": v["event_group_create_conversation_key_version"],
            },
        )
        # Without the key the create seeded, the create still decrypts, on
        # both paths, with its title unavailable as the ciphertext it carries.
        unavailable = {"kind": "Unavailable", "raw": v["event_group_create_encrypted_title"]}
        event = chat.decrypt_event(
            DecryptEventParams(
                v["event_group_create_b64"], {}, signing_keys=_fixture_signing_keys(v)
            )
        )
        self.assertEqual(event["change"]["member_ids"], [v["event_sender_id"]])
        self.assertEqual(event["change"]["title"], unavailable)
        result = chat.decrypt_events(
            DecryptEventsParams(
                [v["event_group_create_b64"]], signing_keys=_fixture_signing_keys(v)
            )
        )
        self.assertEqual(result["errors"], {})
        self.assertEqual(result["events"][0]["event"]["change"]["title"], unavailable)

    def test_reactions_and_edits_name_their_target_by_sequence_id(self):
        from chat_xdk import (
            Chat,
            DecryptEventParams,
            EncryptEditParams,
            EncryptReactionParams,
            ImportKeysParams,
            SetIdentityParams,
        )

        v = _load_vectors()
        chat = Chat()
        chat.import_keys(ImportKeysParams(base64.b64decode(v["private_keys_concat_b64"])))
        chat.set_identity(SetIdentityParams(v["event_sender_id"], v["event_signing_key_version"]))
        conv_key = base64.b64decode(v["conversation_key_b64"])
        version = v["event_conversation_key_version"]
        key = dict(conversation_key=conv_key, conversation_key_version=version)

        def content(payload):
            event = chat.decrypt_event(
                DecryptEventParams(
                    payload.event_b64, {version: conv_key}, signing_keys=_fixture_signing_keys(v)
                )
            )
            self.assertTrue(event["verified"])
            return event["content"]

        target = v["event_message_b64"]
        self.assertEqual(
            content(chat.encrypt_add_reaction(EncryptReactionParams(target, "👍", **key))),
            {"content_type": "Reaction", "emoji": "👍", "target_message_sequence_id": "1"},
        )
        self.assertEqual(
            content(chat.encrypt_remove_reaction(EncryptReactionParams(target, "👍", **key))),
            {"content_type": "ReactionRemoved", "emoji": "👍", "target_message_sequence_id": "1"},
        )
        # A v0 edit names its target by sequence id only.
        self.assertEqual(
            content(chat.encrypt_edit(EncryptEditParams(target, "fixed", **key))),
            {"content_type": "Edit", "target_message_sequence_id": "1", "updated_text": "fixed"},
        )

    def test_v1_sends_name_the_original_and_carry_the_file_hash_from_explicit_fields(self):
        """A v1 send built without the original event names it through the
        explicit fields, and a media attachment carries the SHA-256 of its
        plaintext file: ``reply_to_message_id``, ``target_message_id`` and
        ``plaintext_sha256`` each read back from the decrypted send."""
        import hashlib

        from chat_xdk import (
            DecryptEventParams,
            EncryptEditParams,
            EncryptMessageParams,
            EncryptReplyParams,
            InvalidInputError,
        )
        from features_support import wait_for_v1

        v = _load_vectors()
        chat = self._identity_chat(v, v1=True)
        wait_for_v1(chat)
        conversation_id = v["event_conversation_id"]
        version = v["event_conversation_key_version"]
        key = dict(
            conversation_key=base64.b64decode(v["conversation_key_b64"]),
            conversation_key_version=version,
        )
        digest = base64.b64encode(hashlib.sha256(b"the photo's plaintext bytes").digest()).decode()

        def photo(media_hash_key, **extra):
            return {
                "attachment_type": "media",
                "media_hash_key": media_hash_key,
                "width": 4,
                "height": 3,
                "filesize_bytes": 64,
                "filename": f"{media_hash_key}.jpg",
                "media_type": 1,
                **extra,
            }

        sent = chat.encrypt_message(
            EncryptMessageParams(
                conversation_id,
                "a photo",
                attachments=[photo("hashed", plaintext_sha256=digest), photo("unhashed")],
                **key,
            )
        )
        self.assertEqual(sent.signature_info.signature_version, "10")
        event = chat.decrypt_event(
            DecryptEventParams(
                sent.event_b64,
                {version: key["conversation_key"]},
                signing_keys=_fixture_signing_keys(v),
            )
        )
        self.assertTrue(event["verified"])
        self.assertEqual([a["plaintext_sha256"] for a in event["attachments"]], [digest, None])

        replied = self._decrypt_own(
            chat,
            v,
            chat.encrypt_reply(
                EncryptReplyParams(
                    conversation_id,
                    "nice",
                    reply_to_sequence_id="100",
                    reply_to_message_id=sent.message_id,
                    reply_to_sender_id=v["event_sender_id"],
                    reply_to_text="a photo",
                    **key,
                )
            ),
        )
        self.assertEqual(replied["replying_to_preview"]["replying_to_message_id"], sent.message_id)

        edited = self._decrypt_own(
            chat,
            v,
            chat.encrypt_edit(
                EncryptEditParams(
                    updated_text="a better photo",
                    conversation_id=conversation_id,
                    target_message_sequence_id="100",
                    target_message_id=sent.message_id,
                    **key,
                )
            ),
        )
        self.assertEqual(edited["target_message_id"], sent.message_id)

        # With the original's event, an explicit id must be the one it carries.
        other = "6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f"
        with self.assertRaises(InvalidInputError) as raised:
            chat.encrypt_reply(
                EncryptReplyParams(
                    conversation_id,
                    "nice",
                    sent.event_b64,
                    reply_to_sequence_id="100",
                    reply_to_message_id=other,
                    **key,
                )
            )
        self.assertEqual(
            str(raised.exception),
            f"reply_to_message_id '{other}' is not the message_id '{sent.message_id}' that "
            "reply_to_event carries: pass that id or leave reply_to_message_id unset",
        )
        with self.assertRaises(InvalidInputError) as raised:
            chat.encrypt_edit(
                EncryptEditParams(
                    sent.event_b64,
                    "a better photo",
                    conversation_id=conversation_id,
                    target_message_sequence_id="100",
                    target_message_id=other,
                    **key,
                )
            )
        self.assertEqual(
            str(raised.exception),
            f"target_message_id '{other}' is not the message_id '{sent.message_id}' that "
            "target_event carries: pass that id or leave target_message_id unset",
        )

        with self.assertRaises(InvalidInputError) as raised:
            chat.encrypt_message(
                EncryptMessageParams(
                    conversation_id,
                    "a photo",
                    attachments=[photo("hashed", plaintext_sha256="c2hvcnQ=")],
                    **key,
                )
            )
        self.assertEqual(
            str(raised.exception),
            "media_hash_key 'hashed' has plaintext_sha256 'c2hvcnQ=': pass the base64 SHA-256 "
            "of the file's plaintext bytes (32 bytes)",
        )

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
        self.assertTrue(payload.encoded_message_create_event)
        self.assertTrue(payload.encoded_message_event_signature)

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

    def _identity_chat(self, v, v1=False):
        """A chat with the fixture's keys and identity. With ``v1``, its
        feature switches turn v1_send on."""
        from chat_xdk import Chat, ImportKeysParams, SetIdentityParams
        from features_support import v1_chat

        chat = v1_chat() if v1 else Chat()
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
                reply_to_sender_id=v["event_sender_id"],
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
            for m in result["events"]
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
        from features_support import wait_for_v1

        wait_for_v1(chat)
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
        chat = self._identity_chat(v, v1=True)
        key = base64.b64decode(v["conversation_key_b64"])
        keys = {v["event_conversation_key_version"]: key}
        photos = [b"\x01" * 3000, b"\x02" * 5000]
        payload = self._send_files(chat, v, "two photos", [_media("photo-0"), _media("photo-1")])

        # A session with no identity encrypts the files from the payload.
        worker = Chat()
        first = worker.encrypt_file(EncryptFileParams(photos[0], payload.event_b64, "photo-0", **_key_kwargs(keys)))
        # Randomized nonces: two encryptions differ.
        self.assertNotEqual(
            worker.encrypt_file(EncryptFileParams(photos[0], payload.event_b64, "photo-0", **_key_kwargs(keys))),
            first,
        )
        encryptor = worker.file_encryptor(FileEncryptorParams(payload.event_b64, "photo-1", **_key_kwargs(keys)))
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
        chat = self._identity_chat(v, v1=True)
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
                encrypted = chat.encrypt_file(EncryptFileParams(plaintext, payload.event_b64, name, **_key_kwargs(keys)))
                self.assertEqual(
                    self._open_media(payload.event_b64, keys, name, base64.b64encode(encrypted)),
                    plaintext,
                )

    def test_a_rebuilt_message_keeps_its_encrypted_files_valid(self):
        from chat_xdk import EncryptFileParams

        v = _load_vectors()
        chat = self._identity_chat(v, v1=True)
        keys = {v["event_conversation_key_version"]: base64.b64decode(v["conversation_key_b64"])}
        draft = self._send_files(chat, v, "draft", [_media("photo-0"), _media("photo-1")])
        encrypted = chat.encrypt_file(EncryptFileParams(b"photo", draft.event_b64, "photo-1", **_key_kwargs(keys)))

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
        chat = self._identity_chat(v, v1=True)
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
        encrypted = chat.encrypt_file(EncryptFileParams(b"mine", reply.event_b64, "reply-photo", **_key_kwargs(keys)))
        self.assertEqual(
            self._open_media(reply.event_b64, keys, "reply-photo", base64.b64encode(encrypted)),
            b"mine",
        )
        with self.assertRaisesRegex(ValueError, "is media the reply quotes"):
            chat.encrypt_file(EncryptFileParams(b"x", reply.event_b64, "original-photo", **_key_kwargs(keys)))

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
