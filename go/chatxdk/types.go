package chatxdk

import "encoding/json"

// PublicKeys contains the user's public identity and signing keys.
type PublicKeys struct {
	Identity string `json:"identity"`
	Signing  string `json:"signing"`
	Version  string `json:"version,omitempty"`
}

// PublicKeyRegistration contains the fields expected by the X API
// for public key registration.
type PublicKeyRegistration struct {
	IdentityPublicKeySignature string  `json:"identity_public_key_signature"`
	PublicKey                  string  `json:"public_key"`
	PublicKeyFingerprint       *string `json:"public_key_fingerprint,omitempty"`
	RegistrationMethod         string  `json:"registration_method"`
	SigningPublicKey           string  `json:"signing_public_key"`
	SigningPublicKeySignature  *string `json:"signing_public_key_signature,omitempty"`
}

// PublicKeyRegistrationPayload is returned by GenerateKeypairs().
type PublicKeyRegistrationPayload struct {
	PublicKey       PublicKeyRegistration `json:"public_key"`
	Version         *string               `json:"version,omitempty"`
	GenerateVersion bool                  `json:"generate_version"`
}

// SendPayload contains the encrypted message ready to send to the X API.
type SendPayload struct {
	// MessageID is the SDK-generated message id (UUID) embedded in the signed
	// event. Send it as the message's message_id, keep it to dedup and to anchor
	// replies, and reuse the same encrypted payload on retries so an id is never
	// minted twice.
	MessageID              string        `json:"message_id"`
	EncryptedContent       string        `json:"encrypted_content"`
	Signature              string        `json:"signature"`
	EncodedEventSignature  string        `json:"encoded_event_signature"`
	SignatureInfo          SignatureInfo `json:"signature_info"`
	ConversationKeyVersion string        `json:"conversation_key_version"`
	ShouldNotify           bool          `json:"should_notify"`
}

// SignatureInfo contains metadata about the signing key used.
type SignatureInfo struct {
	PublicKeyVersion string `json:"public_key_version"`
	SignatureVersion string `json:"signature_version"`
}

// EncryptedKeyForRecipient is one participant's encrypted conversation key.
type EncryptedKeyForRecipient struct {
	UserID           string `json:"user_id"`
	EncryptedKey     string `json:"encrypted_key"`
	PublicKeyVersion string `json:"public_key_version"`
}

// SigningKeyEntry is used for signature verification in DecryptEvent and DecryptEvents.
// Every field maps to one entry of the X API public keys response, so the API
// data can be passed through unchanged.
type SigningKeyEntry struct {
	// UserID is the X user ID that owns this signing key.
	UserID string `json:"user_id"`
	// PublicKeyVersion is the X API key version (a snowflake/timestamp string).
	// The SDK selects the entry matching the version embedded in the message signature.
	PublicKeyVersion string `json:"public_key_version"`
	// PublicKey is the base64-encoded signing public key.
	PublicKey string `json:"public_key"`
	// IdentityPublicKey is the base64-encoded identity public key for this user.
	IdentityPublicKey string `json:"identity_public_key"`
	// IdentityPublicKeySignature is the base64-encoded raw r||s signature proving
	// the signing key is bound to the identity key. Returned by the X API.
	IdentityPublicKeySignature string `json:"identity_public_key_signature"`
}

// PublicKeyInput is one row from GET /2/dm/encryption/public_keys, passed to the prepare methods.
type PublicKeyInput struct {
	UserID     string `json:"user_id"`
	PublicKey  string `json:"public_key"`
	KeyVersion string `json:"key_version"`
}

// ConversationKeyBundle holds decrypted conversation key material keyed by version.
// Keys maps version string -> raw 32-byte conversation key.
type ConversationKeyBundle struct {
	Keys          map[string][]byte `json:"keys"`
	LatestVersion *string           `json:"latest_version"`
}

// DecryptedEventMessage is one element of DecryptEventsResult.Messages.
// Event decodes to the same typed Event that DecryptEvent returns; use
// Event.Raw() for the underlying JSON.
type DecryptedEventMessage struct {
	Event       Event  `json:"event"`
	OriginalB64 string `json:"original_b64,omitempty"`
}

// DecryptEventsResult is the batch decrypt API.
type DecryptEventsResult struct {
	Messages         []DecryptedEventMessage `json:"messages"`
	ConversationKeys ConversationKeyBundle   `json:"conversation_keys"`
	Errors           map[string]string       `json:"errors"`
}

// PreparedConversationChange is returned by PrepareConversationKeyChange,
// PrepareGroupCreate, and PrepareGroupMembersChange. It carries everything
// needed to POST the change.
type PreparedConversationChange struct {
	ConversationID string `json:"conversation_id"`
	// ConversationKey is the raw 32-byte conversation key that was generated.
	// Unlike a string, the byte slice can be zeroed once no longer needed.
	ConversationKey        []byte                     `json:"conversation_key"`
	ConversationKeyVersion string                     `json:"conversation_key_version"`
	ParticipantKeys        []EncryptedKeyForRecipient `json:"participant_keys"`
	ActionSignatures       []ActionSignature          `json:"action_signatures"`
}

// ConversationKeyChangeParams are the parameters for PrepareConversationKeyChange.
// SenderID and SigningKeyVersion are optional overrides: empty resolves from
// the session identity set via SetIdentity.
type ConversationKeyChangeParams struct {
	SenderID          string           `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion string           `json:"signing_key_version,omitempty"` // empty = session identity
	PublicKeys        []PublicKeyInput `json:"public_keys"`
	ConversationID    string           `json:"conversation_id,omitempty"` // empty = derive the one-to-one id
}

// GroupMembersChangeParams are the parameters for PrepareGroupMembersChange.
// SenderID and SigningKeyVersion are optional overrides: empty resolves from
// the session identity set via SetIdentity.
type GroupMembersChangeParams struct {
	SenderID                            string           `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion                   string           `json:"signing_key_version,omitempty"` // empty = session identity
	PublicKeys                          []PublicKeyInput `json:"public_keys"`
	ConversationID                      string           `json:"conversation_id"`
	NewMemberIDs                        []string         `json:"new_member_ids"`
	CurrentMemberIDs                    []string         `json:"current_member_ids"`
	CurrentAdminIDs                     []string         `json:"current_admin_ids"`
	CurrentPendingMemberIDs             []string         `json:"current_pending_member_ids"`
	CurrentTitle                        string           `json:"current_title,omitempty"`      // empty = unset
	CurrentAvatarURL                    string           `json:"current_avatar_url,omitempty"` // empty = unset
	CurrentTTLMsec                      *int64           `json:"current_ttl_msec,omitempty"`
	CurrentScreenCaptureBlockingEnabled *bool            `json:"current_screen_capture_blocking_enabled,omitempty"`
}

// GroupCreateParams are the parameters for PrepareGroupCreate.
// SenderID and SigningKeyVersion are optional overrides: empty resolves from
// the session identity set via SetIdentity.
type GroupCreateParams struct {
	SenderID          string           `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion string           `json:"signing_key_version,omitempty"` // empty = session identity
	PublicKeys        []PublicKeyInput `json:"public_keys"`
	ConversationID    string           `json:"conversation_id"`
	MemberIDs         []string         `json:"member_ids"`
	AdminIDs          []string         `json:"admin_ids"`
	Title             string           `json:"title,omitempty"`      // empty = unset
	AvatarURL         string           `json:"avatar_url,omitempty"` // empty = unset
	TTLMsec           *int64           `json:"ttl_msec,omitempty"`
}

// EncryptMessageParams are the parameters for EncryptMessage.
//
// Only ConversationID and Text are required. The identity fields (SenderID,
// SigningKeyVersion) and key fields (ConversationKey, ConversationKeyVersion)
// are optional overrides: left at their zero value they resolve from the
// session identity (SetIdentity) and the opt-in key cache (SetCacheKeys).
// ConversationKey and ConversationKeyVersion travel together — set both or
// neither.
type EncryptMessageParams struct {
	ConversationID         string                 `json:"conversation_id"`
	Text                   string                 `json:"text"`
	SenderID               string                 `json:"sender_id,omitempty"`                // empty = session identity
	SigningKeyVersion      string                 `json:"signing_key_version,omitempty"`      // empty = session identity
	ConversationKey        []byte                 `json:"conversation_key,omitempty"`         // raw 32-byte key; nil = key cache
	ConversationKeyVersion string                 `json:"conversation_key_version,omitempty"` // empty = key cache
	Entities               []EntityTuple          `json:"entities,omitempty"`
	Attachments            []AttachmentDescriptor `json:"attachments,omitempty"`
	ShouldNotify           *bool                  `json:"should_notify,omitempty"`
	TTLMsec                *int64                 `json:"ttl_msec,omitempty"`
}

// EntityTuple represents a text entity: [start, end, type].
type EntityTuple [3]interface{}

// NewEntity creates an EntityTuple.
func NewEntity(start, end int, entityType string) EntityTuple {
	return EntityTuple{start, end, entityType}
}

// AttachmentDescriptor describes an attachment.
type AttachmentDescriptor struct {
	AttachmentType string `json:"attachment_type"` // "media", "url", or "post"
	// The media fields are always marshaled (no omitempty): core requires
	// them on "media" attachments and a zero value (e.g. width 0) is valid,
	// so omitting zeros would be rejected. Other variants ignore them.
	MediaHashKey   string  `json:"media_hash_key"`
	Width          int64   `json:"width"`
	Height         int64   `json:"height"`
	FilesizeBytes  int64   `json:"filesize_bytes"`
	Filename       string  `json:"filename"`
	MediaType      *int32  `json:"media_type,omitempty"`
	DurationMillis *int64  `json:"duration_millis,omitempty"`
	URL            string  `json:"url,omitempty"`
	DisplayTitle   *string `json:"display_title,omitempty"`
	// Optional encrypted preview images for "url" attachments. Supplying a
	// display title plus a banner image makes receiving clients render a
	// full clickable preview card: encrypt the image with EncryptStream,
	// upload it to the conversation's media store, and reference the
	// returned media hash key here.
	BannerImage  *URLAttachmentImageDescriptor `json:"banner_image,omitempty"`
	FaviconImage *URLAttachmentImageDescriptor `json:"favicon_image,omitempty"`
	RestID       *string                       `json:"rest_id,omitempty"`
	PostURL      *string                       `json:"post_url,omitempty"`
}

// URLAttachmentImageDescriptor references an encrypted preview image
// (banner or favicon) from a "url" attachment by its media hash key.
//
// FilesizeBytes and Filename are required alongside MediaHashKey: receiving
// clients' shared ingest silently discards the whole preview image when
// either is missing on the wire.
type URLAttachmentImageDescriptor struct {
	MediaHashKey  string `json:"media_hash_key"`
	FilesizeBytes int64  `json:"filesize_bytes"`
	Filename      string `json:"filename"`
	Width         *int64 `json:"width,omitempty"`
	Height        *int64 `json:"height,omitempty"`
}

// EncryptReplyParams are the parameters for EncryptReply.
//
// The preferred reply target is ReplyToEvent — the base64 raw signed event
// being replied to — from which the SDK derives the reply preview (sequence
// id, sender, text, entities, attachments) and which it embeds so recipients
// can validate the preview. The explicit ReplyTo* field overrides remain for
// callers that no longer hold the raw event.
//
// The identity and key fields are optional overrides, as on
// EncryptMessageParams.
type EncryptReplyParams struct {
	ConversationID string `json:"conversation_id"`
	Text           string `json:"text"`
	// ReplyToEvent is the base64 raw signed event being replied to.
	ReplyToEvent string `json:"reply_to_event,omitempty"`
	// ReplyToEditEvent is the base64 raw signed edit event, when the
	// original was edited.
	ReplyToEditEvent string `json:"reply_to_edit_event,omitempty"`
	// ReplyToCkces are base64 raw key-change events needed to decrypt the
	// original when it was encrypted under a different key version than
	// this reply.
	ReplyToCkces           []string               `json:"reply_to_ckces,omitempty"`
	SenderID               string                 `json:"sender_id,omitempty"`                // empty = session identity
	SigningKeyVersion      string                 `json:"signing_key_version,omitempty"`      // empty = session identity
	ConversationKey        []byte                 `json:"conversation_key,omitempty"`         // raw 32-byte key; nil = key cache
	ConversationKeyVersion string                 `json:"conversation_key_version,omitempty"` // empty = key cache
	ReplyToSequenceID      string                 `json:"reply_to_sequence_id,omitempty"`     // empty = derived from ReplyToEvent
	ReplyToSenderID        *int64                 `json:"reply_to_sender_id,omitempty"`
	ReplyToText            *string                `json:"reply_to_text,omitempty"`
	Entities               []EntityTuple          `json:"entities,omitempty"`
	Attachments            []AttachmentDescriptor `json:"attachments,omitempty"`
	ReplyToEntities        []EntityTuple          `json:"reply_to_entities,omitempty"`
	ReplyToAttachments     []AttachmentDescriptor `json:"reply_to_attachments,omitempty"`
	ShouldNotify           *bool                  `json:"should_notify,omitempty"`
	TTLMsec                *int64                 `json:"ttl_msec,omitempty"`
}

// EncryptReactionParams are the parameters for EncryptAddReaction/EncryptRemoveReaction.
//
// The preferred reaction target is TargetEvent — the base64 raw event being
// reacted to — from which the SDK derives ConversationID and
// TargetMessageSequenceID; the explicit fields remain as overrides for
// callers that no longer hold the raw event. The same value can be passed to
// both EncryptAddReaction and EncryptRemoveReaction.
//
// The identity and key fields are optional overrides, as on
// EncryptMessageParams.
type EncryptReactionParams struct {
	// TargetEvent is the base64 raw event being reacted to.
	TargetEvent             string `json:"target_event,omitempty"`
	Emoji                   string `json:"emoji"`
	ConversationID          string `json:"conversation_id,omitempty"`            // empty = derived from TargetEvent
	TargetMessageSequenceID string `json:"target_message_sequence_id,omitempty"` // empty = derived from TargetEvent
	SenderID                string `json:"sender_id,omitempty"`                  // empty = session identity
	SigningKeyVersion       string `json:"signing_key_version,omitempty"`        // empty = session identity
	ConversationKey         []byte `json:"conversation_key,omitempty"`           // raw 32-byte key; nil = key cache
	ConversationKeyVersion  string `json:"conversation_key_version,omitempty"`   // empty = key cache
}

// EncryptEditParams are the parameters for EncryptEdit.
//
// The preferred edit target is TargetEvent — the base64 raw event of the
// message being edited — from which the SDK derives ConversationID and
// TargetMessageSequenceID; the explicit fields remain as overrides for
// callers that no longer hold the raw event.
//
// The identity and key fields are optional overrides, as on
// EncryptMessageParams.
type EncryptEditParams struct {
	// TargetEvent is the base64 raw event being edited.
	TargetEvent string `json:"target_event,omitempty"`
	UpdatedText string `json:"updated_text"`
	// Entities are rich-text entities for the replacement text; nil clears
	// any entities the original carried.
	Entities                []EntityTuple `json:"entities,omitempty"`
	ConversationID          string        `json:"conversation_id,omitempty"`            // empty = derived from TargetEvent
	TargetMessageSequenceID string        `json:"target_message_sequence_id,omitempty"` // empty = derived from TargetEvent
	SenderID                string        `json:"sender_id,omitempty"`                  // empty = session identity
	SigningKeyVersion       string        `json:"signing_key_version,omitempty"`        // empty = session identity
	ConversationKey         []byte        `json:"conversation_key,omitempty"`           // raw 32-byte key; nil = key cache
	ConversationKeyVersion  string        `json:"conversation_key_version,omitempty"`   // empty = key cache
}

// MessageDeleteParams are the parameters for PrepareMessageDelete.
//
// A delete is a signed plaintext event, not an encrypted message, so no
// conversation key is involved. SenderID and SigningKeyVersion are optional
// overrides: empty resolves from the session identity set via SetIdentity.
type MessageDeleteParams struct {
	ConversationID string `json:"conversation_id"`
	// SequenceIDs are the sequence_ids of the messages to delete.
	SequenceIDs []string `json:"sequence_ids"`
	// DeleteForAll deletes for every participant (true, own messages only)
	// or only from the caller's view (false).
	DeleteForAll      bool   `json:"delete_for_all"`
	SenderID          string `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion string `json:"signing_key_version,omitempty"` // empty = session identity
}

// ActionSignature authenticates a conversation key change, member add, or
// message delete.
type ActionSignature struct {
	MessageID                 string `json:"message_id"`
	EncodedMessageEventDetail string `json:"encoded_message_event_detail"`
	Signature                 string `json:"signature"`
	SignatureVersion          string `json:"signature_version"`
	PublicKeyVersion          string `json:"public_key_version"`
	SignaturePayload          string `json:"signature_payload"`
}

// orEmpty returns a non-nil slice so JSON marshals it as [] rather than null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// EventMeta contains common metadata for all events.
type EventMeta struct {
	SequenceID     *string `json:"sequence_id,omitempty"`
	ID             *string `json:"id,omitempty"`
	SenderID       *string `json:"sender_id,omitempty"`
	ConversationID *string `json:"conversation_id,omitempty"`
	CreatedAtMsec  *int64  `json:"created_at_msec,omitempty"`
}

// Event is a decrypted event from the X Chat API.
// Use the Type field to determine which variant it is,
// then access the appropriate fields.
type Event struct {
	// Type is the discriminator selecting the variant: "Message", "KeyChange", "GroupChange", …
	Type string `json:"type"`
	// Remaining fields are decoded based on Type
	raw json.RawMessage
}

// UnmarshalJSON implements custom JSON unmarshaling for Event.
func (e *Event) UnmarshalJSON(data []byte) error {
	e.raw = data
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return err
	}
	e.Type = peek.Type
	return nil
}

// AsMessage decodes the event as a Message. Returns nil if type != "Message".
func (e *Event) AsMessage() *Message {
	if e.Type != "Message" {
		return nil
	}
	var msg Message
	if err := json.Unmarshal(e.raw, &msg); err != nil {
		return nil
	}
	return &msg
}

// AsKeyChange decodes the event as a KeyChangeEvent.
func (e *Event) AsKeyChange() *KeyChangeEvent {
	if e.Type != "KeyChange" {
		return nil
	}
	var kc KeyChangeEvent
	if err := json.Unmarshal(e.raw, &kc); err != nil {
		return nil
	}
	return &kc
}

// AsGroupChange decodes the event as a GroupChangeEvent.
func (e *Event) AsGroupChange() *GroupChangeEvent {
	if e.Type != "GroupChange" {
		return nil
	}
	var gc GroupChangeEvent
	if err := json.Unmarshal(e.raw, &gc); err != nil {
		return nil
	}
	return &gc
}

// Raw returns the raw JSON bytes of the event for custom decoding.
func (e *Event) Raw() json.RawMessage {
	return e.raw
}

// Message is a decrypted chat message.
type Message struct {
	EventMeta
	Content      MessageContent       `json:"content"`
	KeyVersion   *string              `json:"key_version,omitempty"`
	Verified     bool                 `json:"verified"`
	ShouldNotify *bool                `json:"should_notify,omitempty"`
	TTLMsec      *int64               `json:"ttl_msec,omitempty"`
	Attachments  []json.RawMessage    `json:"attachments,omitempty"`
	MediaHashes  []MediaHashReference `json:"media_hashes,omitempty"`
	// ReplyPreviewValidation is the outcome of validating the reply preview
	// against the raw signed original event embedded in it: "Valid" when the
	// raw event verified and the preview matches the original, "Invalid" when
	// it did not (treat the preview as untrusted), and empty when the message
	// carries no preview or the preview carries no raw event.
	ReplyPreviewValidation string `json:"reply_preview_validation,omitempty"`
}

// Text returns the message text if this is a text message.
func (m *Message) Text() string {
	if m.Content.ContentType == "Text" && m.Content.TextContent != nil {
		return m.Content.TextContent.Text
	}
	return ""
}

// MessageContent wraps the content of a decrypted message.
type MessageContent struct {
	// ContentType is the discriminator: "Text", "Reaction", "ReactionRemoved", …
	ContentType string `json:"content_type"`
	// Populated for Text messages
	TextContent *TextContent `json:"-"`
	// Populated for Reaction messages
	ReactionContent *ReactionContent `json:"-"`
	// Raw JSON for custom decoding
	raw json.RawMessage
}

// UnmarshalJSON implements custom unmarshaling for MessageContent.
func (mc *MessageContent) UnmarshalJSON(data []byte) error {
	mc.raw = data
	var peek struct {
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return err
	}
	mc.ContentType = peek.ContentType

	switch peek.ContentType {
	case "Text":
		var tc TextContent
		if err := json.Unmarshal(data, &tc); err == nil {
			mc.TextContent = &tc
		}
	case "Reaction", "ReactionRemoved":
		var rc ReactionContent
		if err := json.Unmarshal(data, &rc); err == nil {
			mc.ReactionContent = &rc
		}
	}
	return nil
}

// TextContent contains the fields for a text message.
type TextContent struct {
	Text              string          `json:"text"`
	Entities          json.RawMessage `json:"entities,omitempty"`
	Attachments       json.RawMessage `json:"attachments,omitempty"`
	ReplyingToPreview json.RawMessage `json:"replying_to_preview,omitempty"`
	ForwardedMessage  json.RawMessage `json:"forwarded_message,omitempty"`
	SentFrom          json.RawMessage `json:"sent_from,omitempty"`
	QuickReply        json.RawMessage `json:"quick_reply,omitempty"`
	CTAs              json.RawMessage `json:"ctas,omitempty"`
}

// ReactionContent contains the fields for a reaction message.
type ReactionContent struct {
	Emoji           string `json:"emoji"`
	TargetMessageID string `json:"target_message_id"`
}

// MediaHashReference is a reference to a media hash key found in attachments.
type MediaHashReference struct {
	Source       string `json:"source"`
	MediaHashKey string `json:"media_hash_key"`
}

// KeyChangeEvent indicates a conversation key rotation.
type KeyChangeEvent struct {
	EventMeta
	KeyVersion      string           `json:"key_version"`
	ParticipantKeys []ParticipantKey `json:"participant_keys"`
	Verified        bool             `json:"verified"`
}

// FindKeyForUser returns the encrypted key for a specific user.
func (kc *KeyChangeEvent) FindKeyForUser(userID string) *ParticipantKey {
	for i := range kc.ParticipantKeys {
		if kc.ParticipantKeys[i].UserID == userID {
			return &kc.ParticipantKeys[i]
		}
	}
	return nil
}

// ParticipantKey is an encrypted conversation key for a participant.
type ParticipantKey struct {
	UserID           string `json:"user_id"`
	EncryptedKey     string `json:"encrypted_key"`
	PublicKeyVersion string `json:"public_key_version"`
}

// GroupChangeEvent indicates a group membership or settings change.
type GroupChangeEvent struct {
	EventMeta
	Change   json.RawMessage `json:"change"`
	Verified bool            `json:"verified"`
}

// TypingEvent indicates someone is typing.
type TypingEvent struct {
	EventMeta
}

// ReadReceiptEvent indicates a conversation was marked as read.
type ReadReceiptEvent struct {
	EventMeta
	SeenUntilID *string `json:"seen_until_id,omitempty"`
	SeenAtMsec  *int64  `json:"seen_at_msec,omitempty"`
	Verified    bool    `json:"verified"`
}
