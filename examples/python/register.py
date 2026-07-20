"""One-time public-key registration for a bot identity.

Registering a public key is a rare, rate-limited write (only a few per 24h per
user) that establishes the identity every message is signed and encrypted
against. This script does it safely and is re-runnable: if it is interrupted
after generating keys but before the server confirms, running it again resumes
the same identity instead of minting a new one.

Flow:
  1. Refuse if this identity is already registered (unless --force).
  2. Generate the keypair once; persist the private-key blob AND the (public)
     registration payload to disk BEFORE any network call, so an error never
     loses the identity and a retry re-sends the same registration.
  3. Before POSTing, check whether this exact public key is already on the
     account (a prior POST can apply server-side even after erroring) and adopt
     it instead of re-registering — a duplicate POST wastes the daily budget.
  4. POST the registration; stop cleanly on 429 rather than retrying.
  5. Record the registered key version; optionally back the keys up with a PIN.

Environment (see .env.example):
  X_ACCESS_TOKEN          OAuth2 user token for the bot (dm.read + dm.write)
  CHAT_BOT_USER_ID        the bot's user id (optional; derived from the token)
  CHAT_PIN                optional — also store the keys in Juicebox under a PIN

Run:
  python register.py --confirm
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from chat_xdk import Chat

from x_api import XChatClient

STATE_DIR = Path(__file__).parent / "state"
BLOB_PATH = STATE_DIR / "private_keys.b64"
MARKER_PATH = STATE_DIR / "registration.json"


def _load_env() -> None:
    env = Path(__file__).parent / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _read_marker() -> dict:
    if MARKER_PATH.exists():
        return json.loads(MARKER_PATH.read_text(encoding="utf-8"))
    return {}


def _write_marker(marker: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MARKER_PATH.write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")


def _registration_body(chat: Chat) -> tuple[dict, str]:
    """Generate a fresh identity and return its POST body plus key version.

    The body carries only public material, so it is safe to persist and re-send
    on a later run.
    """
    reg = chat.generate_keypairs()
    version = str(reg.version) if reg.version is not None else "1"
    body = {
        "public_key": {
            "public_key": reg.public_key.public_key,
            "signing_public_key": reg.public_key.signing_public_key,
            "identity_public_key_signature": reg.public_key.identity_public_key_signature,
            "signing_public_key_signature": reg.public_key.signing_public_key_signature,
            "registration_method": reg.public_key.registration_method,
        },
        "version": version,
        "generate_version": bool(reg.generate_version),
    }
    return body, version


def _save_blob(chat: Chat) -> None:
    """Write the exported private keys to disk (mode 600)."""
    exported = chat.export_keys()
    if not exported:
        raise SystemExit("export_keys() returned nothing — no identity to save")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BLOB_PATH.write_text(base64.b64encode(bytes(exported)).decode("ascii") + "\n", encoding="utf-8")
    BLOB_PATH.chmod(0o600)


def register(*, force: bool) -> None:
    token = os.environ.get("X_ACCESS_TOKEN")
    if not token:
        raise SystemExit("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env")
    pin = os.environ.get("CHAT_PIN")

    marker = _read_marker()
    if marker.get("registered") and not force:
        raise SystemExit(
            f"Already registered (version {marker.get('version')}). "
            "Pass --force only if you intend to create a NEW identity."
        )

    api = XChatClient(token)
    user_id = os.environ.get("CHAT_BOT_USER_ID") or api.get_my_user_id()

    chat = Chat()

    # Resume an interrupted run with the SAME identity; only generate a fresh
    # one when there is no saved blob. Persisting the blob and the registration
    # body before the network POST is what makes a failed POST or Juicebox step
    # safe to retry without wasting the daily registration budget.
    resuming = BLOB_PATH.exists() and marker.get("body") and not force
    if resuming:
        chat.import_keys(base64.b64decode(BLOB_PATH.read_text(encoding="utf-8").strip()))
        body = marker["body"]
        version = str(marker.get("version") or "1")
        print(f"Resuming the saved identity ({BLOB_PATH}).")
    else:
        body, version = _registration_body(chat)
        _save_blob(chat)
        _write_marker({"registered": False, "user_id": user_id, "version": version, "body": body})
        print(f"Generated a new identity; private keys saved to {BLOB_PATH}.")

    our_public_key = body["public_key"]["public_key"]

    # Reconcile: if our exact public key is already on the account, adopt it
    # rather than POSTing again (a prior POST may have applied after erroring).
    existing = api.get_public_keys(user_id)
    already = next(
        (k for k in existing if (k.get("public_key") or k.get("publicKey")) == our_public_key),
        None,
    )
    if already:
        version = str(already.get("public_key_version") or version)
        print(f"Public key already registered on the account (version {version}); skipping POST.")
    else:
        print(f"Registering public key version {version} …")
        try:
            resp = api.add_user_public_key(user_id, body)
        except XChatClient.RateLimited as limited:
            when = (
                datetime.fromtimestamp(limited.reset_epoch, tz=timezone.utc).isoformat()
                if limited.reset_epoch
                else "the next window"
            )
            raise SystemExit(
                "Registration is rate limited (429). The daily budget is exhausted; "
                f"wait until {when} and re-run — the saved identity resumes, so no budget is wasted."
            )
        data = resp.get("data") or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        version = str(data.get("public_key_version") or version)

    chat.set_identity(user_id, version)
    _write_marker(
        {
            "registered": True,
            "user_id": user_id,
            "version": version,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Optional Juicebox backup. The private-key blob is already saved, so this
    # is best-effort: a failure here does not lose the identity.
    if pin:
        try:
            config_json, _ = api.get_juicebox_config(user_id)
            jb = Chat(config_json)
            jb.import_keys(base64.b64decode(BLOB_PATH.read_text(encoding="utf-8").strip()))
            jb.setup(pin)
            print("Stored the keys in Juicebox under the PIN.")
        except Exception as err:  # noqa: BLE001 — best-effort; the blob is already safe
            print(f"Juicebox backup failed (keys are still saved locally): {err}", file=sys.stderr)

    print()
    print("Registration complete.")
    print(f"  version:      {version}")
    print(f"  private keys: {BLOB_PATH} (mode 600)")
    print("Add these to .env to run the bot:")
    print(f"  CHAT_PRIVATE_KEYS_B64={BLOB_PATH.read_text(encoding='utf-8').strip()}")
    print(f"  CHAT_SIGNING_KEY_VERSION={version}")


def main() -> None:
    parser = argparse.ArgumentParser(description="One-time X Chat public-key registration.")
    parser.add_argument("--confirm", action="store_true", help="required to run")
    parser.add_argument("--force", action="store_true", help="create a NEW identity (dangerous)")
    args = parser.parse_args()

    _load_env()
    if not args.confirm and not args.force:
        print("This registers a bot identity (a rate-limited, one-time action).")
        print("Re-run with --confirm when ready:  python register.py --confirm")
        sys.exit(1)
    register(force=args.force)


if __name__ == "__main__":
    main()
