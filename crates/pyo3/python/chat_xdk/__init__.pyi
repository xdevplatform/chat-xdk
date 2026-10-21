"""Type stubs for chat-xdk Python bindings."""

from typing import Optional, TypedDict, Union

__version__: str

def encrypted_file_size(plaintext_size: int) -> int: ...

# ---------------------------------------------------------------------------
# Classes
# ---------------------------------------------------------------------------

class QuickReplyOption(TypedDict, total=False):
    """A single selectable quick-reply option."""

    id: Optional[str]
    label: Optional[str]
    metadata: Optional[str]
    description: Optional[str]

class QuickReplyOptionsRequest(TypedDict, total=False):
    """The options offered by a quick-reply request."""

    id: Optional[str]
    options: Optional[list[QuickReplyOption]]

class QuickReplyOptionsResponse(TypedDict, total=False):
    """The option selected in a quick-reply response."""

    request_id: Optional[str]
    metadata: Optional[str]
    selected_option_id: Optional[str]

class QuickReplyRequest(TypedDict):
    """A quick-reply request offering a set of selectable options."""

    options: QuickReplyOptionsRequest

class QuickReplyResponse(TypedDict):
    """A quick-reply response selecting a previously offered option."""

    options: QuickReplyOptionsResponse

class QuickReply(TypedDict, total=False):
    """A quick reply carried by a text message.

    Set exactly one of ``request`` (offering selectable options) or
    ``response`` (selecting one). The ``quick_reply`` of decrypted text
    content has this shape, so a received value can be sent back unchanged.
    """

    request: QuickReplyRequest
    response: QuickReplyResponse

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

class SignatureInfo:
    public_key_version: str
    signature_version: str

class SendPayload:
    message_id: str
    event_b64: str
    encrypted_content: str
    signature: str
    encoded_event_signature: str
    signature_info: SignatureInfo
    conversation_key_version: str
    should_notify: bool
    xdk_version: str

# ---------------------------------------------------------------------------
# Params
# ---------------------------------------------------------------------------

class EncryptMessageParams:
    conversation_id: str
    text: str
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    entities: Optional[list[tuple[int, int, str]]]
    attachments: Optional[list[dict]]
    quick_reply: Optional[QuickReply]
    should_notify: Optional[bool]
    ttl_msec: Optional[int]
    def __init__(
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
        quick_reply: Optional[QuickReply] = None,
        should_notify: Optional[bool] = None,
        ttl_msec: Optional[int] = None,
    ) -> None: ...

class EncryptReplyParams:
    conversation_id: str
    text: str
    reply_to_event: Optional[str]
    reply_to_edit_event: Optional[str]
    reply_to_ckces: Optional[list[str]]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    reply_to_sequence_id: Optional[str]
    reply_to_sender_id: Optional[int]
    reply_to_text: Optional[str]
    entities: Optional[list[tuple[int, int, str]]]
    attachments: Optional[list[dict]]
    reply_to_entities: Optional[list[tuple[int, int, str]]]
    reply_to_attachments: Optional[list[dict]]
    quick_reply: Optional[QuickReply]
    should_notify: Optional[bool]
    ttl_msec: Optional[int]
    def __init__(
        self,
        conversation_id: str,
        text: str,
        reply_to_event: Optional[str] = None,
        *,
        reply_to_edit_event: Optional[str] = None,
        reply_to_ckces: Optional[list[str]] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
        reply_to_sequence_id: Optional[str] = None,
        reply_to_sender_id: Optional[int] = None,
        reply_to_text: Optional[str] = None,
        entities: Optional[list[tuple[int, int, str]]] = None,
        attachments: Optional[list[dict]] = None,
        reply_to_entities: Optional[list[tuple[int, int, str]]] = None,
        reply_to_attachments: Optional[list[dict]] = None,
        quick_reply: Optional[QuickReply] = None,
        should_notify: Optional[bool] = None,
        ttl_msec: Optional[int] = None,
    ) -> None: ...

class EncryptReactionParams:
    target_event: Optional[str]
    emoji: str
    conversation_id: Optional[str]
    target_message_sequence_id: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
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
    ) -> None: ...

class EncryptEditParams:
    target_event: Optional[str]
    updated_text: str
    entities: Optional[list[tuple[int, int, str]]]
    conversation_id: Optional[str]
    target_message_sequence_id: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
        self,
        target_event: Optional[str] = None,
        updated_text: str = ...,
        *,
        entities: Optional[list[tuple[int, int, str]]] = None,
        conversation_id: Optional[str] = None,
        target_message_sequence_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> None: ...

class ConversationKeyChangeParams:
    public_keys: list[dict[str, str]]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_id: Optional[str]
    def __init__(
        self,
        public_keys: list[dict[str, str]],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> None: ...

class GroupMembersChangeParams:
    public_keys: list[dict[str, str]]
    conversation_id: str
    new_member_ids: list[str]
    current_member_ids: list[str]
    current_admin_ids: list[str]
    current_pending_member_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    current_title: Optional[str]
    current_avatar_url: Optional[str]
    current_ttl_msec: Optional[int]
    current_screen_capture_blocking_enabled: Optional[bool]
    def __init__(
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
    ) -> None: ...

class GroupCreateParams:
    public_keys: list[dict[str, str]]
    conversation_id: str
    member_ids: list[str]
    admin_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    title: Optional[str]
    avatar_url: Optional[str]
    ttl_msec: Optional[int]
    def __init__(
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
    ) -> None: ...

class MessageDeleteParams:
    conversation_id: str
    sequence_ids: list[str]
    delete_for_all: bool
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        sequence_ids: list[str],
        delete_for_all: bool,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class SetIdentityParams:
    user_id: str
    signing_key_version: str
    def __init__(self, user_id: str, signing_key_version: str) -> None: ...

class ImportKeysParams:
    keys: bytes
    signing_key_version: Optional[str]
    def __init__(self, keys: bytes, *, signing_key_version: Optional[str] = None) -> None: ...

class MarkConversationReadParams:
    conversation_id: str
    seen_until_sequence_id: str
    seen_at_msec: Optional[int]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        seen_until_sequence_id: str,
        *,
        seen_at_msec: Optional[int] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class DecryptEventParams:
    event_b64: str
    conversation_keys: Optional[dict[str, bytes]]
    signing_keys: Optional[list[dict[str, str]]]
    def __init__(
        self,
        event_b64: str,
        conversation_keys: Optional[dict[str, bytes]] = None,
        *,
        signing_keys: Optional[list[dict[str, str]]] = None,
    ) -> None: ...

class DecryptEventsParams:
    events: list[str]
    signing_keys: Optional[list[dict[str, str]]]
    def __init__(
        self,
        events: list[str],
        *,
        signing_keys: Optional[list[dict[str, str]]] = None,
    ) -> None: ...

class EncryptFileParams:
    file: bytes
    event_b64: str
    conversation_keys: dict[str, bytes]
    media_hash_key: str
    def __init__(
        self,
        file: bytes,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        media_hash_key: str,
    ) -> None: ...

class FileEncryptorParams:
    event_b64: str
    conversation_keys: dict[str, bytes]
    media_hash_key: str
    def __init__(
        self,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        media_hash_key: str,
    ) -> None: ...

class DecryptFileParams:
    encrypted: bytes
    event_b64: str
    conversation_keys: dict[str, bytes]
    media_hash_key: str
    def __init__(
        self,
        encrypted: bytes,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        media_hash_key: str,
    ) -> None: ...

class FileDecryptorParams:
    event_b64: str
    conversation_keys: dict[str, bytes]
    media_hash_key: str
    def __init__(
        self,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        media_hash_key: str,
    ) -> None: ...

class Chat:
    def __init__(self, config_json: Optional[str] = None) -> None: ...

    # Config
    def update_config(self, config_json: str) -> None: ...
    def set_reject_unverified(self, reject: bool) -> None: ...

    # Session state
    def set_identity(self, params: SetIdentityParams) -> None: ...
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
    def close(self) -> None:
        """Stop this chat's background work: its fetch of the X API's
        feature switches. A chat that is garbage-collected stops it too."""
        ...
    def is_unlocked(self) -> bool: ...
    def has_identity_key(self) -> bool: ...

    # Key Management
    def generate_keypairs(self) -> PublicKeyRegistrationPayload: ...
    def get_public_keys(self) -> PublicKeys: ...
    def get_public_key_fingerprint(self) -> str: ...
    def export_keys(self) -> Optional[bytearray]: ...
    def import_keys(self, params: ImportKeysParams) -> None: ...
    def verify_key_binding(
        self,
        identity_public_key_b64: str,
        signing_public_key_b64: str,
        identity_public_key_signature_b64: str,
    ) -> bool: ...
    def matches_registered_key(self, public_key_b64: str) -> bool: ...

    # Conversation Keys
    def decrypt_conversation_key(self, encrypted_key_b64: str) -> bytes: ...
    def prepare_conversation_key_change(self, params: ConversationKeyChangeParams) -> dict: ...
    def prepare_group_members_change(self, params: GroupMembersChangeParams) -> dict: ...
    def prepare_group_create(self, params: GroupCreateParams) -> dict: ...
    def prepare_message_delete(self, params: MessageDeleteParams) -> dict: ...
    def prepare_mark_conversation_read(self, params: MarkConversationReadParams) -> dict: ...

    # Events
    def extract_conversation_keys(self, events: list[str]) -> dict: ...
    def decrypt_events(self, params: DecryptEventsParams) -> dict: ...
    def decrypt_event(self, params: DecryptEventParams) -> dict: ...

    # Message Encryption
    def encrypt_message(self, params: EncryptMessageParams) -> SendPayload: ...
    def encrypt_reply(self, params: EncryptReplyParams) -> SendPayload: ...
    def encrypt_add_reaction(self, params: EncryptReactionParams) -> SendPayload: ...
    def encrypt_remove_reaction(self, params: EncryptReactionParams) -> SendPayload: ...
    def encrypt_edit(self, params: EncryptEditParams) -> SendPayload: ...

    # Files
    def encrypt_file(self, params: EncryptFileParams) -> bytes: ...
    def file_encryptor(self, params: FileEncryptorParams) -> FileEncryptor: ...
    def decrypt_file(self, params: DecryptFileParams) -> bytes: ...
    def file_decryptor(self, params: FileDecryptorParams) -> FileDecryptor: ...

    # Generic Encrypt / Decrypt
    def encrypt(self, plaintext: str, conversation_key: bytes) -> str: ...
    def decrypt(self, ciphertext_b64: str, conversation_key: bytes) -> str: ...

    # Signing
    def sign(self, data: bytes) -> bytes: ...
    def verify(self, public_key_b64: str, signature: bytes, data: bytes) -> bool: ...

class FileEncryptor:
    """Incremental encryptor for one file of an outgoing message.

    Feed the file with ``push``; call ``finish`` once to emit the final frame.
    """
    def push(self, plaintext: bytes) -> bytes: ...
    def finish(self) -> bytes: ...

class FileDecryptor:
    """Incremental decryptor for one encrypted file.

    Feed the encrypted bytes with ``push``; call ``finish`` once at end of
    input. ``finish`` raises if the file ended before its final frame
    (truncation), so do not treat bytes from ``push`` as complete until
    ``finish`` succeeds.
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
