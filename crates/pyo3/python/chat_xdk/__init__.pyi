"""Type stubs for chat-xdk Python bindings."""

from typing import Optional, Union, overload

__version__: str

# ---------------------------------------------------------------------------
# Classes
# ---------------------------------------------------------------------------

class PublicKeys:
    identity: str
    signing: str
    version: str

class PublicKeyRegistration:
    identity_public_key_signature: str
    public_key: str
    public_key_fingerprint: Optional[str]
    registration_method: str
    signing_public_key: str
    signing_public_key_signature: Optional[str]

class PublicKeyRegistrationPayload:
    public_key: PublicKeyRegistration
    version: Optional[str]
    generate_version: bool

class SignatureInfo:
    public_key_version: str
    signature_version: str

class SendPayload:
    message_id: str
    encrypted_content: str
    signature: str
    encoded_event_signature: str
    signature_info: SignatureInfo
    conversation_key_version: str
    should_notify: bool

class Chat:
    def __init__(self, config_json: Optional[str] = None) -> None: ...

    # Config
    def update_config(self, config_json: str) -> None: ...
    def set_reject_unverified(self, reject: bool) -> None: ...

    # Session state
    def set_identity(self, user_id: str, signing_key_version: str) -> None: ...
    def set_cache_keys(self, enabled: bool) -> None: ...
    def set_signing_keys(self, signing_keys: list[dict[str, str]]) -> None: ...

    # Juicebox Key Storage
    def setup(self, pin: Union[str, bytes, bytearray]) -> PublicKeys: ...
    def unlock(self, pin: Union[str, bytes, bytearray]) -> None: ...
    def change_pin(
        self,
        old_pin: Union[str, bytes, bytearray],
        new_pin: Union[str, bytes, bytearray],
    ) -> None: ...
    def delete(self) -> None: ...
    def lock(self) -> None: ...
    def is_unlocked(self) -> bool: ...
    def has_identity_key(self) -> bool: ...

    # Key Management
    def generate_keypairs(self) -> PublicKeyRegistrationPayload: ...
    def get_public_keys(self) -> PublicKeys: ...
    def get_public_key_fingerprint(self) -> str: ...
    def export_keys(self) -> Optional[bytearray]: ...
    def import_keys(self, keys: bytes, version: Optional[str] = None) -> None: ...
    def verify_key_binding(
        self,
        identity_public_key_b64: str,
        signing_public_key_b64: str,
        identity_public_key_signature_b64: str,
    ) -> bool: ...
    def matches_registered_key(self, public_key_b64: str) -> bool: ...

    # Conversation Keys
    def decrypt_conversation_key(self, encrypted_key_b64: str) -> bytes: ...
    def prepare_conversation_key_change(
        self,
        public_keys: list[dict[str, str]],
        *,
        conversation_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> dict: ...
    def prepare_group_members_change(
        self,
        public_keys: list[dict[str, str]],
        conversation_id: str,
        new_member_ids: list[str],
        current_member_ids: list[str],
        current_admin_ids: list[str],
        current_pending_member_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        current_title: Optional[str] = None,
        current_avatar_url: Optional[str] = None,
        current_ttl_msec: Optional[int] = None,
        current_screen_capture_blocking_enabled: Optional[bool] = None,
    ) -> dict: ...
    def prepare_group_create(
        self,
        public_keys: list[dict[str, str]],
        conversation_id: str,
        member_ids: list[str],
        admin_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        title: Optional[str] = None,
        avatar_url: Optional[str] = None,
        ttl_msec: Optional[int] = None,
    ) -> dict: ...
    def prepare_message_delete(
        self,
        conversation_id: str,
        sequence_ids: list[str],
        delete_for_all: bool,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> dict: ...

    # Events
    def extract_conversation_keys(self, events: list[str]) -> dict: ...
    def decrypt_events(
        self,
        events: list[str],
        signing_keys: Optional[list[dict[str, str]]] = None,
    ) -> dict: ...
    def decrypt_event(
        self,
        event_b64: str,
        conversation_keys: Optional[dict[str, bytes]] = None,
        signing_keys: Optional[list[dict[str, str]]] = None,
    ) -> dict: ...

    # Message Encryption
    def encrypt_message(
        self,
        conversation_id: str,
        text: str,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
        entities: Optional[list[tuple[int, int, str]]] = None,
        attachments: Optional[list[dict]] = None,
        should_notify: Optional[bool] = None,
        ttl_msec: Optional[int] = None,
    ) -> SendPayload: ...
    def encrypt_reply(
        self,
        conversation_id: str,
        text: str,
        reply_to_event: Optional[str] = None,
        *,
        reply_to_edit_event: Optional[str] = None,
        reply_to_ckces: Optional[list[str]] = None,
        reply_to_sequence_id: Optional[str] = None,
        reply_to_sender_id: Optional[int] = None,
        reply_to_text: Optional[str] = None,
        reply_to_entities: Optional[list[tuple[int, int, str]]] = None,
        reply_to_attachments: Optional[list[dict]] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
        entities: Optional[list[tuple[int, int, str]]] = None,
        attachments: Optional[list[dict]] = None,
        should_notify: Optional[bool] = None,
        ttl_msec: Optional[int] = None,
    ) -> SendPayload: ...
    def encrypt_add_reaction(
        self,
        target_event: Optional[str] = None,
        emoji: str = ...,
        *,
        conversation_id: Optional[str] = None,
        target_message_sequence_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> SendPayload: ...
    def encrypt_remove_reaction(
        self,
        target_event: Optional[str] = None,
        emoji: str = ...,
        *,
        conversation_id: Optional[str] = None,
        target_message_sequence_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> SendPayload: ...
    # `updated_text` is required at runtime (missing it raises TypeError)
    # even though it sits after the optional `target_event` positional; the
    # overloads keep static checkers flagging calls that omit it.
    @overload
    def encrypt_edit(
        self,
        target_event: str,
        updated_text: str,
        *,
        entities: Optional[list[tuple[int, int, str]]] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> SendPayload: ...
    @overload
    def encrypt_edit(
        self,
        *,
        updated_text: str,
        conversation_id: str,
        target_message_sequence_id: str,
        entities: Optional[list[tuple[int, int, str]]] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> SendPayload: ...

    # Streams
    def encrypt_stream(self, plaintext: bytes, conversation_key: bytes) -> bytes: ...
    def decrypt_stream(self, encrypted: bytes, conversation_key: bytes) -> bytes: ...
    def stream_encryptor(self, conversation_key: bytes) -> StreamEncryptor: ...
    def stream_decryptor(self, conversation_key: bytes) -> StreamDecryptor: ...

    # Generic Encrypt / Decrypt
    def encrypt(self, plaintext: str, conversation_key: bytes) -> str: ...
    def decrypt(self, ciphertext_b64: str, conversation_key: bytes) -> str: ...

    # Signing
    def sign(self, data: bytes) -> bytes: ...
    def verify(self, public_key_b64: str, signature: bytes, data: bytes) -> bool: ...

class StreamEncryptor:
    """Incremental stream encryptor for large payloads.

    Feed plaintext with ``push``; call ``finish`` once to emit the final frame.
    """
    def push(self, plaintext: bytes) -> bytes: ...
    def finish(self) -> bytes: ...

class StreamDecryptor:
    """Incremental stream decryptor for large payloads.

    Feed ciphertext with ``push``; call ``finish`` once at end of input.
    ``finish`` raises if the stream ended before its final frame (truncation),
    so do not treat plaintext from ``push`` as complete until ``finish``
    succeeds.
    """
    def push(self, ciphertext: bytes) -> bytes: ...
    def finish(self) -> bytes: ...

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def bytes_to_base64(data: bytes) -> str: ...
def base64_to_bytes(b64: str) -> Optional[bytes]: ...
def bytes_to_hex(data: bytes) -> str: ...
def hex_to_bytes(hex: str) -> Optional[bytes]: ...
def detect_mime_type(data: bytes) -> Optional[str]: ...
def detect_image_dimensions(data: bytes) -> Optional[tuple[int, int]]: ...
def guesses_remaining(exc: BaseException) -> Optional[int]: ...
