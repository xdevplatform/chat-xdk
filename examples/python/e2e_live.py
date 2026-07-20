"""Live end-to-end check against the X Chat API.

Uses the example's real ChatCore (chat_xdk binding) and XChatClient (XDK).
Run manually after `pip install -r requirements.txt`:

    CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... \\
    CHAT_SIGNING_KEY_VERSION=... CHAT_CONVERSATION_ID=... python e2e_live.py

Flow (each numbered step asserts against the live API):
  1. batch-decrypt inbound history (pagination when a second page exists)
  2. rotate the conversation key (prepare -> POST /keys -> decrypt own CKCE)
  3. send a threaded reply with an entity + TTL under the rotated key,
     fetch it back, decrypt it via the single-event path, and verify it
  4. react to the sent message (add + remove), decrypting the add back

Optional extras:
  CHATXDK_E2E_MEDIA=1   also stream-encrypts a media blob, uploads it,
                        sends a message referencing it, then downloads and
                        stream-decrypts it back to the original bytes
  CHATXDK_E2E_GROUPS=1  also creates a group (two-signature create), sends a
                        group message, and adds the 1:1 partner as a member
  CHAT_PIN=...          also unlocks keys via live Juicebox and checks they
                        match the blob-loaded ones
"""

from __future__ import annotations

import os
import time

from chat_core import ChatCore, message_text, prep_to_request
from x_api import XChatClient


def _signing_from(pk: dict, user_id: str) -> dict:
    return {
        "user_id": user_id,
        "public_key_version": str(pk.get("public_key_version") or ""),
        "public_key": pk.get("signing_public_key") or "",
        "identity_public_key": pk.get("public_key") or "",
        "identity_public_key_signature": pk.get("identity_public_key_signature") or "",
    }


def _key_entries(pks: list[dict], user_id: str) -> list[dict]:
    """Public-keys response -> the flat entries the prepare methods take."""
    return [
        {
            "user_id": user_id,
            "public_key": pk.get("public_key") or "",
            "key_version": str(pk.get("public_key_version") or ""),
        }
        for pk in pks
    ]


def _await_decrypted(
    api: XChatClient,
    core: ChatCore,
    conversation_id: str,
    conv_keys: dict[str, bytes],
    signing: list[dict],
    message_id: str,
    tries: int = 10,
) -> dict:
    """Poll the conversation until the event for ``message_id`` lands, and
    return it decrypted via the single-event path (``decrypt_one``).

    The target envelope is matched by its raw event id before decrypting, so a
    decrypt failure on our own event (e.g. a broken sign->verify loop) surfaces
    in the timeout message instead of being silently swallowed."""
    last_err: Exception | None = None
    for _ in range(tries):
        page = api.get_events(conversation_id, max_results=25)
        for e in page.get("data") or []:
            if not e.get("encoded_event"):
                continue
            is_target = str(e.get("id") or "") == message_id
            try:
                one = core.decrypt_one(e["encoded_event"], conv_keys, signing)
            except Exception as err:
                if is_target:
                    last_err = err
                continue
            if is_target or str(one.get("id") or "") == message_id:
                if not one.get("sequence_id"):
                    # The REST item's id IS the event's sequence id.
                    one["sequence_id"] = e.get("id")
                return one
        time.sleep(1)
    raise AssertionError(
        f"event for sent message {message_id!r} never appeared"
        + (f" (last decrypt error: {last_err})" if last_err else "")
    )


def main() -> None:
    token = os.environ["X_ACCESS_TOKEN"]
    blob = os.environ["CHAT_PRIVATE_KEYS_B64"]
    version = os.environ.get("CHAT_SIGNING_KEY_VERSION", "1")
    conversation_id = os.environ["CHAT_CONVERSATION_ID"]

    core = ChatCore()
    core.load_keys(blob, version)
    api = XChatClient(token)
    my_id = api.get_my_user_id()
    # All signed actions below resolve their sender from the session identity.
    core.set_identity(my_id)

    # -- 1. Inbound history: batch decrypt (+ pagination when available) ----
    page = api.get_events(conversation_id, max_results=10)
    raw = list(page.get("data") or [])
    next_token = (page.get("meta") or {}).get("next_token")
    if next_token:
        page2 = api.get_events(conversation_id, max_results=10, pagination_token=next_token)
        raw2 = list(page2.get("data") or [])
        ids1 = {str(e.get("id")) for e in raw}
        assert raw2 and not ids1 & {str(e.get("id")) for e in raw2}, "pagination made no progress"
        raw += raw2
        print(f"pagination: fetched second page with {len(raw2)} events")

    ids = {my_id} | {str(e.get("sender_id")) for e in raw if e.get("sender_id")}
    signing: list[dict] = []
    pks_by_user: dict[str, list[dict]] = {}
    for uid in ids:
        try:
            pks = api.get_public_keys(uid)
            pks_by_user[uid] = pks
            signing.extend(_signing_from(pk, uid) for pk in pks)
        except Exception:
            pass

    events_b64 = [e["encoded_event"] for e in raw if e.get("encoded_event")]
    batch = core.decrypt_batch(events_b64, signing)
    decrypted = sum(1 for m in batch["messages"] if message_text(m["event"]))
    conv_keys = dict(batch["conversation_keys"]["keys"])
    print(f"live inbound messages decrypted: {decrypted}; conversation keys: {len(conv_keys)}")
    assert decrypted > 0, "expected to decrypt at least one live message"

    # Canonical conversation_id + partner id from the decrypted events.
    canonical_conv = conversation_id
    partner_id = next(iter(ids - {my_id}), None)
    last_inbound_seq = None
    for m in batch["messages"]:
        ev = m["event"] or {}
        if ev.get("conversation_id"):
            canonical_conv = ev["conversation_id"]
        if ev.get("type") == "Message" and str(ev.get("sender_id")) != my_id:
            last_inbound_seq = ev.get("sequence_id") or last_inbound_seq
    assert partner_id, "expected a conversation partner among the senders"

    # -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE ---------
    both_keys = _key_entries(pks_by_user.get(my_id) or [], my_id) + _key_entries(
        pks_by_user.get(partner_id) or [], partner_id
    )
    prep = core.prepare_conversation_key_change(both_keys)
    resp = api.add_conversation_keys(conversation_id, prep_to_request(prep, core.public_keys()["signing"]))
    data = resp.get("data") or {}
    assert data.get("sequence_id") or data.get("conversation_key_change_sequence_id"), (
        f"key rotation not acknowledged: {resp}"
    )
    print(f"rotated conversation key to version {prep['conversation_key_version']}"
          + (f"; server conversation_id: {data['conversation_id']}" if data.get("conversation_id") else ""))

    # The rotated key becomes the sending key; re-fetch (polling briefly, in
    # case the CKCE has not propagated yet) so our own CKCE decrypts and the
    # cache includes the new version.
    kv = prep["conversation_key_version"]
    for _ in range(5):
        page = api.get_events(conversation_id, max_results=10)
        events_b64 = [e["encoded_event"] for e in (page.get("data") or []) if e.get("encoded_event")]
        batch = core.decrypt_batch(events_b64, signing)
        conv_keys = dict(batch["conversation_keys"]["keys"])
        if kv in conv_keys:
            break
        time.sleep(1.5)
    assert kv in conv_keys, f"own rotated CKCE (version {kv}) did not decrypt+verify"
    key = conv_keys[kv]

    # -- 3. Send under the rotated key; fetch back; single-event decrypt ----
    marker = f"chat-xdk e2e [python] {int(time.time())}"
    body = core.encrypt_reply(
        conversation_id=canonical_conv,
        text=f"@user {marker}",
        conversation_key=key,
        conversation_key_version=kv,
        reply_to_sequence_id=last_inbound_seq,
        entities=[(0, 5, "mention")],
        ttl_msec=24 * 60 * 60 * 1000,
    )
    api.send_message(canonical_conv, body)
    print(f"sent live encrypted message: {marker!r}")

    one = _await_decrypted(api, core, conversation_id, conv_keys, signing, body["message_id"])
    assert message_text(one) == f"@user {marker}", f"round-trip text mismatch: {one}"
    assert one.get("verified") is True, "own sent message failed signature verification"
    seq = str(one.get("sequence_id") or "")
    assert seq, "sent message has no sequence id to react to"
    print("sent message decrypted + verified via the single-event path")

    # -- 4. Reactions: add (round-trip) then remove --------------------------
    add = core.encrypt_reaction(
        add=True,
        conversation_id=canonical_conv,
        target_message_sequence_id=seq,
        emoji="\U0001f44d",
        conversation_key=key,
        conversation_key_version=kv,
    )
    api.send_message(canonical_conv, add)
    one = _await_decrypted(api, core, conversation_id, conv_keys, signing, add["message_id"])
    content = one.get("content") or {}
    assert content.get("content_type") == "Reaction" and content.get("emoji") == "\U0001f44d", (
        f"expected a Reaction event, got {content}"
    )
    assert one.get("verified") is True, "reaction failed signature verification"
    print("reaction add decrypted + verified")

    remove = core.encrypt_reaction(
        add=False,
        conversation_id=canonical_conv,
        target_message_sequence_id=seq,
        emoji="\U0001f44d",
        conversation_key=key,
        conversation_key_version=kv,
    )
    api.send_message(canonical_conv, remove)
    print("reaction remove sent")

    # -- 5. Optional: media — stream-encrypt, upload, send, download, decrypt
    if os.environ.get("CHATXDK_E2E_MEDIA") == "1":
        # A deterministic multi-chunk payload, so the incremental encryptor
        # emits several frames and any corruption is byte-attributable.
        plaintext = bytes((i * 31 + 7) % 256 for i in range(300_000))
        ciphertext = core.encrypt_media(plaintext, key)
        media_hash_key = api.upload_media(canonical_conv, ciphertext)
        print(f"encrypted media uploaded: {media_hash_key} ({len(ciphertext)} bytes)")

        media_msg = core.encrypt_reply(
            conversation_id=canonical_conv,
            text=f"chat-xdk e2e media [python] {int(time.time())}",
            conversation_key=key,
            conversation_key_version=kv,
            attachments=[
                {
                    "attachment_type": "media",
                    "media_hash_key": media_hash_key,
                    "width": 0,
                    "height": 0,
                    "filesize_bytes": len(plaintext),
                    "filename": "e2e.bin",
                    "media_type": 5,
                }
            ],
            ttl_msec=24 * 60 * 60 * 1000,
        )
        api.send_message(canonical_conv, media_msg)
        one = _await_decrypted(api, core, conversation_id, conv_keys, signing, media_msg["message_id"])
        assert one.get("verified") is True, "media message failed signature verification"
        atts = (one.get("content") or {}).get("attachments") or []
        got_key = next(
            (a["media"].get("media_hash_key") for a in atts if a.get("media")), None
        )
        assert got_key == media_hash_key, f"attachment did not round-trip: {atts}"

        downloaded = api.download_media(canonical_conv, media_hash_key)
        assert core.decrypt_media(downloaded, key) == plaintext, (
            "downloaded media did not decrypt to the original bytes"
        )
        print("media downloaded + stream-decrypted to the original bytes")

    # -- 6. Optional: group create + message + member add --------------------
    if os.environ.get("CHATXDK_E2E_GROUPS") == "1":
        _groups_flow(api, core, my_id, partner_id, both_keys, signing)

    # -- 7. Optional: live Juicebox unlock -----------------------------------
    pin = os.environ.get("CHAT_PIN")
    if pin:
        config, latest_version = api.get_juicebox_config(my_id)
        jb = ChatCore()
        jb.unlock(config, pin, latest_version)
        assert jb.public_keys()["identity"] == core.public_keys()["identity"], (
            "Juicebox-unlocked identity key differs from the blob-loaded one"
        )
        print("juicebox live unlock: keys match")

    print("E2E PYTHON: PASS")


def _groups_flow(
    api: XChatClient,
    core: ChatCore,
    my_id: str,
    partner_id: str,
    both_keys: list[dict],
    signing: list[dict],
) -> None:
    my_keys = [k for k in both_keys if k["user_id"] == my_id]
    signing_pub = core.public_keys()["signing"]

    group_id = api.initialize_group()
    assert group_id.startswith("g"), f"unexpected group id: {group_id!r}"

    # Create with the caller as sole member/admin so the member add below
    # exercises prepare_group_members_change with the partner.
    prep = core.prepare_group_create(my_keys, group_id, [my_id], [my_id])
    body = {
        "conversation_id": group_id,
        "group_members": [my_id],
        "group_admins": [my_id],
        "group_name": "chat-xdk e2e",
        **prep_to_request(prep, signing_pub),
    }
    try:
        api.create_conversation(body)
        members = [my_id]
    except Exception:
        # Some deployments reject single-member groups; fall back to creating
        # with both participants (skipping the member-add below).
        prep = core.prepare_group_create(both_keys, group_id, [my_id, partner_id], [my_id])
        body = {
            "conversation_id": group_id,
            "group_members": [my_id, partner_id],
            "group_admins": [my_id],
            "group_name": "chat-xdk e2e",
            **prep_to_request(prep, signing_pub),
        }
        api.create_conversation(body)
        members = [my_id, partner_id]
    kv = prep["conversation_key_version"]
    key = bytes(prep["conversation_key"])
    print(f"group created: {group_id} with {len(members)} member(s)")

    marker = f"chat-xdk e2e group [python] {int(time.time())}"
    msg = core.encrypt_reply(
        conversation_id=group_id,
        text=marker,
        conversation_key=key,
        conversation_key_version=kv,
    )
    api.send_message(group_id, msg)
    conv_keys = {kv: key}
    one = _await_decrypted(api, core, group_id, conv_keys, signing, msg["message_id"])
    assert message_text(one) == marker and one.get("verified") is True, (
        f"group message round-trip failed: {one}"
    )
    print("group message decrypted + verified")

    if partner_id not in members:
        prep = core.prepare_group_members_change(
            both_keys, group_id, [partner_id], members, [my_id]
        )
        api.add_group_members(
            group_id,
            {"user_ids": [partner_id], **prep_to_request(prep, signing_pub)},
        )
        print(f"group member add: {partner_id} added (key rotated to {prep['conversation_key_version']})")


if __name__ == "__main__":
    main()
