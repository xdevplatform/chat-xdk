"""Type stubs for chat-xdk Python bindings."""

from enum import Enum
from typing import Any, Literal, Optional, TypedDict, Union

__version__: str

def encrypted_file_size(plaintext_size: int) -> int: ...

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ChatXdkError(ValueError):
    """Raised when the SDK fails. ``kind`` names the failure the same way in
    every binding: ``invalid_input``, ``invalid_state``, ``parse``,
    ``decryption``, ``verification``, ``invalid_pin``, ``juicebox`` or
    ``internal``."""

    kind: str
    guesses_remaining: Optional[int]

class InvalidInputError(ChatXdkError):
    """A parameter is missing or invalid; the message names it."""

class InvalidStateError(ChatXdkError):
    """A value was neither passed nor available from the chat's state, such as
    no keys loaded."""

class ParseError(ChatXdkError):
    """Event or other wire data is malformed."""

class DecryptionError(ChatXdkError):
    """Ciphertext did not decrypt, or no key for it was available."""

class VerificationError(ChatXdkError):
    """A signature did not verify, or could not be verified while unverified
    events are rejected."""

class InvalidPinError(ChatXdkError):
    """Juicebox rejected the PIN. ``guesses_remaining`` holds the attempts
    left when Juicebox reports them; 0 means the stored keys are locked."""

class JuiceboxError(ChatXdkError):
    """Another Juicebox key-storage failure."""

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

class GroupText(TypedDict, total=False):
    """A group title or description as a received event carries it.

    ``kind`` ``"Text"`` carries ``text``: the value decrypted, or the
    plaintext an event that names no key version carries. ``kind``
    ``"Unavailable"`` carries ``raw``: a value the SDK could not decrypt, as
    the event carries it. Show ``raw`` when a title isn't decryptable. A
    member removal re-encrypts the title and description under the new key;
    those re-encryptions aren't changes, and decrypt drops them.
    """

    kind: Literal["Text", "Unavailable"]
    text: str
    raw: str


class SigningKeyEntry(TypedDict):
    """A participant's signing key, as ``GET /2/users/:id/public_keys``
    returns it, for verifying the events they sign."""

    user_id: str
    public_key_version: str
    public_key: str
    identity_public_key: str
    identity_public_key_signature: str

class PublicKeyInput(TypedDict):
    """A participant's identity key, to encrypt a new conversation key to."""

    user_id: str
    identity_public_key: str
    public_key_version: str

class ConversationKeyResult(TypedDict):
    """Conversation keys by version, and the version to encrypt with: the
    newest key change whose signature verified, or ``None``."""

    keys: dict[str, bytes]
    latest_version: Optional[str]

class DecryptedEvent(TypedDict, total=False):
    """One event of a ``decrypt_events`` batch: the decrypted ``event`` and,
    for a message, ``original_b64``, its raw event."""

    event: dict[str, Any]
    original_b64: str

class DecryptEventsResult(TypedDict):
    """What ``decrypt_events`` returns. ``errors`` maps the index of each
    event left out of ``events``, as a string, to its error: one that
    failed, or one decrypt drops, such as a member removal's title or
    description re-encrypted under the new key."""

    events: list[DecryptedEvent]
    conversation_keys: ConversationKeyResult
    errors: dict[str, str]

class MessageEventSignature(TypedDict):
    """The signature of an action, as requests carry it."""

    signature: str
    signature_version: str
    public_key_version: str
    signing_public_key: str

class ActionSignature(TypedDict):
    """A signed action, ready to send in a request's ``action_signatures``."""

    message_id: str
    encoded_message_event_detail: str
    message_event_signature: MessageEventSignature

class PreparedAction(TypedDict):
    """The signed actions of a ``prepare_*`` call that changes no key."""

    action_signatures: list[ActionSignature]

class PreparedGroupMetadataChange(TypedDict):
    """A group title or description encrypted under the conversation key,
    with its signed action."""

    encrypted_value: str
    conversation_key_version: str
    action_signatures: list[ActionSignature]

class ConversationParticipantKey(TypedDict):
    """A new conversation key encrypted to one participant's identity key."""

    user_id: str
    encrypted_conversation_key: str
    public_key_version: str

class PreparedConversationChange(TypedDict, total=False):
    """A new conversation key, encrypted to every participant, with the
    signed actions that carry it. ``encrypted_title`` and
    ``encrypted_description`` are set for a title and description the
    params set."""

    conversation_id: str
    conversation_key: bytes
    conversation_key_version: str
    conversation_participant_keys: list[ConversationParticipantKey]
    action_signatures: list[ActionSignature]
    encrypted_title: str
    encrypted_description: str

class PublicKeys:
    identity: str
    signing: str

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
    encoded_message_create_event: str
    signature: str
    encoded_message_event_signature: str
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
    reply_to_sender_id: Optional[str]
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
        reply_to_sender_id: Optional[str] = None,
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
    public_keys: list[PublicKeyInput]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_id: Optional[str]
    def __init__(
        self,
        public_keys: list[PublicKeyInput],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> None: ...

class GroupMembersChangeParams:
    public_keys: list[PublicKeyInput]
    conversation_id: str
    new_member_ids: list[str]
    current_member_ids: list[str]
    current_admin_ids: list[str]
    current_pending_member_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    current_title: Optional[str]
    current_avatar_url: Optional[str]
    current_description: Optional[str]
    current_ttl_msec: Optional[int]
    current_screen_capture_blocking_enabled: Optional[bool]
    def __init__(
        self,
        public_keys: list[PublicKeyInput],
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
        current_description: Optional[str] = None,
        current_ttl_msec: Optional[int] = None,
        current_screen_capture_blocking_enabled: Optional[bool] = None,
    ) -> None: ...

class GroupCreateParams:
    public_keys: list[PublicKeyInput]
    conversation_id: str
    member_ids: list[str]
    admin_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    title: Optional[str]
    ttl_msec: Optional[int]
    def __init__(
        self,
        public_keys: list[PublicKeyInput],
        conversation_id: str,
        member_ids: list[str],
        admin_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        title: Optional[str] = None,
        ttl_msec: Optional[int] = None,
    ) -> None: ...

class ScreenCaptureChange(str, Enum):
    """A screen-capture setting signed by prepare_screen_capture."""

    BlockingEnabled = "BlockingEnabled"
    BlockingDisabled = "BlockingDisabled"
    DetectionEnabled = "DetectionEnabled"
    DetectionDisabled = "DetectionDisabled"

class GroupMembersRemoveParams:
    public_keys: list[PublicKeyInput]
    conversation_id: str
    user_ids: list[str]
    title: Optional[str]
    description: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        public_keys: list[PublicKeyInput],
        conversation_id: str,
        user_ids: list[str],
        *,
        title: Optional[str] = None,
        description: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupLeaveParams:
    conversation_id: str
    promote_admin_id: Optional[str]
    conversation_key_version: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        *,
        promote_admin_id: Optional[str] = None,
        conversation_key_version: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupTitleChangeParams:
    conversation_id: str
    new_title: str
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        new_title: str,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> None: ...

class GroupAvatarChangeParams:
    conversation_id: str
    new_avatar_url: str
    conversation_key_version: str
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        new_avatar_url: str,
        conversation_key_version: str,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupDescriptionChangeParams:
    conversation_id: str
    new_description: str
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        new_description: str,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> None: ...

class GroupAdminsAddParams:
    conversation_id: str
    user_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        user_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupAdminsRemoveParams:
    conversation_id: str
    user_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        user_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupInviteEnableParams:
    conversation_id: str
    invite_url: str
    expires_at_msec: Optional[int]
    affiliate_id: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        invite_url: str,
        *,
        expires_at_msec: Optional[int] = None,
        affiliate_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupInviteDisableParams:
    conversation_id: str
    disabled_by: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        *,
        disabled_by: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupJoinRequestParams:
    conversation_id: str
    requesting_user_id: Optional[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        *,
        requesting_user_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class GroupJoinRejectParams:
    conversation_id: str
    user_ids: list[str]
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        user_ids: list[str],
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class MessageTtlChangeParams:
    conversation_id: str
    ttl_msec: int
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        ttl_msec: int,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class MessageTtlRemoveParams:
    conversation_id: str
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
    ) -> None: ...

class ScreenCaptureParams:
    conversation_id: str
    change: ScreenCaptureChange
    sender_id: Optional[str]
    signing_key_version: Optional[str]
    def __init__(
        self,
        conversation_id: str,
        change: ScreenCaptureChange,
        *,
        sender_id: Optional[str] = None,
        signing_key_version: Optional[str] = None,
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
    signing_keys: Optional[list[SigningKeyEntry]]
    def __init__(
        self,
        event_b64: str,
        conversation_keys: Optional[dict[str, bytes]] = None,
        *,
        signing_keys: Optional[list[SigningKeyEntry]] = None,
    ) -> None: ...

class DecryptEventsParams:
    events: list[str]
    signing_keys: Optional[list[SigningKeyEntry]]
    def __init__(
        self,
        events: list[str],
        *,
        signing_keys: Optional[list[SigningKeyEntry]] = None,
    ) -> None: ...

class EncryptFileParams:
    file: bytes
    event_b64: str
    media_hash_key: str
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
        self,
        file: bytes,
        event_b64: str,
        media_hash_key: str,
        *,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
    ) -> None: ...

class FileEncryptorParams:
    event_b64: str
    media_hash_key: str
    conversation_key: Optional[bytes]
    conversation_key_version: Optional[str]
    def __init__(
        self,
        event_b64: str,
        media_hash_key: str,
        *,
        conversation_key: Optional[bytes] = None,
        conversation_key_version: Optional[str] = None,
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

class EncryptFileWithKeyParams:
    file: bytes
    key: bytes
    def __init__(self, file: bytes, key: bytes) -> None: ...

class DecryptFileWithKeyParams:
    encrypted: bytes
    key: bytes
    def __init__(self, encrypted: bytes, key: bytes) -> None: ...

class Chat:
    def __init__(self, config_json: Optional[str] = None) -> None: ...

    # Config
    def update_config(self, config_json: str) -> None: ...
    def set_reject_unverified(self, reject: bool) -> None: ...

    # Session state
    def set_identity(self, params: SetIdentityParams) -> None: ...
    def set_cache_keys(self, enabled: bool) -> None: ...
    def set_signing_keys(self, signing_keys: list[SigningKeyEntry]) -> None: ...

    # Juicebox Key Storage
    def setup(self, pin: Union[str, bytes, bytearray]) -> PublicKeys: ...
    def unlock(self, pin: Union[str, bytes, bytearray]) -> None: ...
    def change_pin(
        self,
        old_pin: Union[str, bytes, bytearray],
        new_pin: Union[str, bytes, bytearray],
    ) -> None: ...
    def delete(self) -> None: ...
    async def setup_async(self, pin: Union[str, bytes, bytearray]) -> PublicKeys: ...
    async def unlock_async(self, pin: Union[str, bytes, bytearray]) -> None: ...
    async def change_pin_async(
        self,
        old_pin: Union[str, bytes, bytearray],
        new_pin: Union[str, bytes, bytearray],
    ) -> None: ...
    async def delete_async(self) -> None: ...
    def lock(self) -> None: ...
    def is_unlocked(self) -> bool: ...
    def has_identity_key(self) -> bool: ...

    # Key Management
    def generate_keypairs(self) -> PublicKeyRegistrationPayload: ...
    def get_public_keys(self) -> PublicKeys: ...
    def get_public_key_fingerprint(self) -> str: ...
    def export_keys(self) -> bytearray: ...
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
    def prepare_conversation_key_change(self, params: ConversationKeyChangeParams) -> PreparedConversationChange: ...
    def prepare_group_members_change(self, params: GroupMembersChangeParams) -> PreparedConversationChange: ...
    def prepare_group_create(self, params: GroupCreateParams) -> PreparedConversationChange: ...
    def prepare_message_delete(self, params: MessageDeleteParams) -> PreparedAction: ...
    def prepare_mark_conversation_read(self, params: MarkConversationReadParams) -> PreparedAction: ...
    def prepare_group_members_remove(self, params: GroupMembersRemoveParams) -> PreparedConversationChange: ...
    def prepare_group_leave(self, params: GroupLeaveParams) -> PreparedAction: ...
    def prepare_group_title_change(self, params: GroupTitleChangeParams) -> PreparedGroupMetadataChange: ...
    def prepare_group_avatar_change(self, params: GroupAvatarChangeParams) -> PreparedAction: ...
    def prepare_group_description_change(self, params: GroupDescriptionChangeParams) -> PreparedGroupMetadataChange: ...
    def prepare_group_admins_add(self, params: GroupAdminsAddParams) -> PreparedAction: ...
    def prepare_group_admins_remove(self, params: GroupAdminsRemoveParams) -> PreparedAction: ...
    def prepare_group_invite_enable(self, params: GroupInviteEnableParams) -> PreparedAction: ...
    def prepare_group_invite_disable(self, params: GroupInviteDisableParams) -> PreparedAction: ...
    def prepare_group_join_request(self, params: GroupJoinRequestParams) -> PreparedAction: ...
    def prepare_group_join_reject(self, params: GroupJoinRejectParams) -> PreparedAction: ...
    def prepare_message_ttl_change(self, params: MessageTtlChangeParams) -> PreparedAction: ...
    def prepare_message_ttl_remove(self, params: MessageTtlRemoveParams) -> PreparedAction: ...
    def prepare_screen_capture(self, params: ScreenCaptureParams) -> PreparedAction: ...

    # Events
    def extract_conversation_keys(self, events: list[str]) -> ConversationKeyResult: ...
    def decrypt_events(self, params: DecryptEventsParams) -> DecryptEventsResult: ...
    def decrypt_event(self, params: DecryptEventParams) -> dict[str, Any]: ...

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
    def encrypt_file_with_key(self, params: EncryptFileWithKeyParams) -> bytes: ...
    def decrypt_file_with_key(self, params: DecryptFileWithKeyParams) -> bytes: ...

    # Group metadata the X API returns for a conversation
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

def bytes_to_base64(bytes: bytes) -> str: ...
def base64_to_bytes(b64: str) -> Optional[bytes]: ...
def bytes_to_hex(bytes: bytes) -> str: ...
def hex_to_bytes(hex: str) -> Optional[bytes]: ...
def detect_mime_type(bytes: bytes) -> Optional[str]: ...
def detect_image_dimensions(bytes: bytes) -> Optional[tuple[int, int]]: ...
