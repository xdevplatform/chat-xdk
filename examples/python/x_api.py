"""X Chat API access via the X API SDK (XDK).

The bot's I/O layer: every REST call goes through the XDK Python client so
request signing, models, and endpoint paths stay in sync with the X API.

Authentication is an OAuth2 user access token (scopes ``dm.read`` + ``dm.write``)
read from the environment.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from xdk import Client
from xdk.chat.models import SendMessageRequest

BASE_URL = "https://api.x.com"


class XChatClient:
    def __init__(self, access_token: str) -> None:
        # The XDK client picks OAuth2 user-context auth from the access token.
        self.client = Client(access_token=access_token)
        self._token = access_token

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a chat endpoint not yet covered by the installed XDK release.

        Chat auth is a plain OAuth2 bearer token, so a direct call is
        equivalent to what the XDK sends.
        """
        req = urllib.request.Request(
            BASE_URL + path,
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode() or "{}")

    # -- Identity -----------------------------------------------------------

    def get_my_user_id(self) -> str:
        return str(self.client.users.get_me().data.id)

    def get_public_keys(self, user_id: str) -> list[dict[str, Any]]:
        """Fetch a user's registered public keys (for ECIES + verify, or to
        check your own before registering).

        Every field of the public_key resource (``public_key``,
        ``signing_public_key``, ``identity_public_key_signature``,
        ``public_key_version``, ``juicebox_config``) is always included; the
        route takes no ``public_key.fields`` parameter.
        """
        resp = self.client.users.get_public_key(user_id)
        data = resp.data or []
        items = data if isinstance(data, list) else [data]
        return [d.model_dump() if hasattr(d, "model_dump") else dict(d) for d in items]

    class RateLimited(Exception):
        """Raised when the public-key write bucket is exhausted (HTTP 429).

        The endpoint allows only a few writes per 24h; ``reset_epoch`` is when
        the window frees up. Retrying before then just fails again.
        """

        def __init__(self, reset_epoch: int | None) -> None:
            self.reset_epoch = reset_epoch
            super().__init__("public-key registration rate limited (HTTP 429)")

    def add_user_public_key(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Register a public key: POST /2/users/{id}/public_keys.

        ``payload`` is the registration object from ``generate_keypairs`` in its
        snake_case wire form (``public_key`` object, ``version``,
        ``generate_version``). Raises ``RateLimited`` on 429 so the caller can
        stop instead of burning the daily budget.
        """
        path = f"/2/users/{user_id}/public_keys"
        req = urllib.request.Request(
            BASE_URL + path,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as err:
            if err.code == 429:
                reset = err.headers.get("x-user-limit-24hour-reset")
                raise self.RateLimited(int(reset) if reset else None) from err
            raise

    def get_juicebox_config(self, user_id: str) -> tuple[str, str]:
        """Build the Juicebox config JSON + latest key version for ``ChatCore.unlock``.

        Only needed for the optional Juicebox (production) key-storage path.
        Every public_key field (``juicebox_config`` included) is always
        returned; the route takes no ``public_key.fields`` parameter.
        """
        resp = self.client.users.get_public_key(user_id)
        data = resp.data or []
        items = [
            d.model_dump() if hasattr(d, "model_dump") else dict(d)
            for d in (data if isinstance(data, list) else [data])
        ]
        latest = max(items, key=lambda d: int(d.get("public_key_version") or 0))
        # The X API `juicebox_config` object is accepted as-is: the core reads
        # `key_store_token_map_json` verbatim and auth tokens from `token_map`.
        return json.dumps(latest["juicebox_config"]), str(latest["public_key_version"])

    # -- Conversation events ------------------------------------------------

    def get_events(
        self,
        conversation_id: str,
        *,
        max_results: int = 50,
        pagination_token: str | None = None,
    ) -> dict[str, Any]:
        """GET the raw (encrypted) events for a conversation via the XDK.

        Each ``data`` item carries an ``encoded_event`` base64 blob the crypto
        core decrypts via ``decrypt_batch`` / ``decrypt_one``.
        """
        resp = self.client.chat.get_conversation_events(
            conversation_id.replace(":", "-"),
            max_results=max_results,
            pagination_token=pagination_token,
        )
        return resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)

    # -- Conversation / key management ---------------------------------------

    def add_conversation_keys(self, conversation_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a prepared conversation-key change (initialize or rotate).

        ``body`` is the REST shape built by ``chat_core.prep_to_request``.
        For a 1:1, ``conversation_id`` may be the recipient's user ID; the
        server derives (and returns) the canonical conversation ID.
        """
        path = f"/2/chat/conversations/{conversation_id.replace(':', '-')}/keys"
        return self._post(path, body)

    def initialize_group(self) -> str:
        """Mint a new group conversation id (``g…``)."""
        out = self._post("/2/chat/conversations/group/initialize", {})
        return str((out.get("data") or {}).get("conversation_id") or "")

    def create_conversation(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST /2/chat/conversations/group — create a group conversation.

        ``body`` carries ``conversation_id``, ``group_members``,
        ``group_admins``, and the two-signature key change from
        ``ChatCore.prepare_group_create``.
        """
        return self._post("/2/chat/conversations/group", body)

    def add_group_members(self, conversation_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /2/chat/conversations/{id}/members — add members to a group.

        ``body`` carries ``user_ids`` plus the rotated key change from
        ``ChatCore.prepare_group_members_change``.
        """
        path = f"/2/chat/conversations/{conversation_id}/members"
        return self._post(path, body)

    # -- Media (encrypted blobs) ---------------------------------------------

    UPLOAD_CHUNK = 3 * 1024 * 1024

    def upload_media(self, conversation_id: str, ciphertext: bytes) -> str:
        """Upload an encrypted media blob; returns its ``media_hash_key``.

        Three-step flow: initialize (returns an upload session and the hash
        key), append (3 MB segments), finalize. The media endpoints take the
        colon form of the conversation id in the body.
        """
        conv = conversation_id.replace("-", ":")
        init = self._post(
            "/2/chat/media/upload/initialize",
            {"conversation_id": conv, "total_bytes": len(ciphertext)},
        )
        data = init.get("data") or {}
        session_id = data.get("session_id") or data.get("sessionId")
        media_hash_key = data.get("media_hash_key") or data.get("mediaHashKey")
        if not session_id or not media_hash_key:
            raise RuntimeError(f"media upload initialize failed: {init}")

        segment = 0
        for offset in range(0, len(ciphertext), self.UPLOAD_CHUNK):
            chunk = ciphertext[offset : offset + self.UPLOAD_CHUNK]
            self._post(
                f"/2/chat/media/upload/{session_id}/append",
                {
                    "conversation_id": conv,
                    "media_hash_key": media_hash_key,
                    "segment_index": str(segment),
                    "media": base64.b64encode(chunk).decode(),
                },
            )
            segment += 1

        self._post(
            f"/2/chat/media/upload/{session_id}/finalize",
            {
                "conversation_id": conv,
                "media_hash_key": media_hash_key,
                "num_parts": str(segment),
            },
        )
        return str(media_hash_key)

    def download_media(self, conversation_id: str, media_hash_key: str) -> bytes:
        """Download an encrypted media blob as raw bytes.

        The response body is binary ciphertext — it must be read as bytes;
        any text decoding would corrupt it. The download path takes the
        hyphen form of the conversation id.
        """
        conv = urllib.parse.quote(conversation_id.replace(":", "-"), safe="")
        hash_key = urllib.parse.quote(media_hash_key, safe="")
        req = urllib.request.Request(
            f"{BASE_URL}/2/chat/media/{conv}/{hash_key}",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()

    # -- Sending ------------------------------------------------------------

    def send_message(self, conversation_id: str, body: dict[str, str]) -> Any:
        """POST an encrypted message produced by ``ChatCore.encrypt_reply``.

        For a 1:1 conversation, ``conversation_id`` is the recipient's user ID;
        the server constructs the canonical conversation ID.
        """
        request = SendMessageRequest.model_validate(body)
        return self.client.chat.send_message(conversation_id.replace(":", "-"), request)
