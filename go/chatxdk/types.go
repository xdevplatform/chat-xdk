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
	PublicKey PublicKeyRegistration `json:"public_key"`
}

// SendPayload contains the encrypted message ready to send to the X API.
type SendPayload struct {
	// MessageID is the message id (UUID) the SDK generated and embedded in
	// the signed event. Send it as the message's message_id, keep it to dedup
	// and to anchor replies, and reuse the same encrypted payload on retries
	// so an id is never minted twice.
	MessageID string `json:"message_id"`
	// EventB64 is the outgoing message as a base64 event: what recipients
	// receive, without the fields the server assigns. Pass it to EncryptFile
	// or FileEncryptor to encrypt the message's files, or to DecryptEvent to
	// read the message back.
	EventB64 string `json:"event_b64"`
	// EncodedMessageCreateEvent is the base64 Thrift MessageCreateEvent
	// carrying the encrypted contents: the send request's
	// encoded_message_create_event.
	EncodedMessageCreateEvent string `json:"encoded_message_create_event"`
	Signature                 string `json:"signature"`
	// EncodedMessageEventSignature is the base64 Thrift
	// MessageEventSignature: the send request's
	// encoded_message_event_signature.
	EncodedMessageEventSignature string        `json:"encoded_message_event_signature"`
	SignatureInfo                SignatureInfo `json:"signature_info"`
	ConversationKeyVersion       string        `json:"conversation_key_version"`
	ShouldNotify                 bool          `json:"should_notify"`
	// XdkVersion is the version of the Chat XDK that built the payload.
	XdkVersion string `json:"xdk_version"`
}

// SignatureInfo contains metadata about the signing key used.
type SignatureInfo struct {
	PublicKeyVersion string `json:"public_key_version"`
	SignatureVersion string `json:"signature_version"`
}

// ConversationParticipantKey is one participant's copy of a conversation key,
// encrypted to their identity key: an entry of the X API's
// conversation_participant_keys. A prepared change carries these for its
// request, and a received key change carries them as delivered.
type ConversationParticipantKey struct {
	UserID                   string `json:"user_id"`
	EncryptedConversationKey string `json:"encrypted_conversation_key"`
	PublicKeyVersion         string `json:"public_key_version"`
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
// Keys maps version string -> raw 32-byte conversation key. LatestVersion is
// the version to encrypt with: from DecryptEvents, the newest version whose
// key change verified (nil until one verifies); from ExtractConversationKeys,
// the batch's highest version.
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
// PrepareGroupCreate, PrepareGroupMembersChange, and PrepareGroupMembersRemove.
// It carries everything needed to POST the change.
type PreparedConversationChange struct {
	ConversationID string `json:"conversation_id"`
	// ConversationKey is the raw 32-byte conversation key that was generated.
	// Unlike a string, the byte slice can be zeroed once no longer needed.
	ConversationKey             []byte                       `json:"conversation_key"`
	ConversationKeyVersion      string                       `json:"conversation_key_version"`
	ConversationParticipantKeys []ConversationParticipantKey `json:"conversation_participant_keys"`
	ActionSignatures            []ActionSignature            `json:"action_signatures"`
	// EncryptedTitle is set by PrepareGroupCreate and
	// PrepareGroupMembersChange when the params carry a title: the title
	// encrypted under the new conversation key, base64, the group_name a
	// create request sends and the encrypted_title an add-members request
	// sends.
	EncryptedTitle *string `json:"encrypted_title,omitempty"`
	// EncryptedDescription is set by PrepareGroupMembersChange when the
	// params carry a description: the description encrypted under the new
	// conversation key, base64, as the signed member add carries it.
	EncryptedDescription *string `json:"encrypted_description,omitempty"`
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
// the session identity set via SetIdentity. CurrentTitle and
// CurrentDescription are plaintext: the call encrypts each under the new
// conversation key it generates. CurrentAvatarURL is the avatar's media URL,
// signed as is.
type GroupMembersChangeParams struct {
	SenderID                            string           `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion                   string           `json:"signing_key_version,omitempty"` // empty = session identity
	PublicKeys                          []PublicKeyInput `json:"public_keys"`
	ConversationID                      string           `json:"conversation_id"`
	NewMemberIDs                        []string         `json:"new_member_ids"`
	CurrentMemberIDs                    []string         `json:"current_member_ids"`
	CurrentAdminIDs                     []string         `json:"current_admin_ids"`
	CurrentPendingMemberIDs             []string         `json:"current_pending_member_ids"`
	CurrentTitle                        string           `json:"current_title,omitempty"`       // empty = unset
	CurrentAvatarURL                    string           `json:"current_avatar_url,omitempty"`  // empty = unset
	CurrentDescription                  string           `json:"current_description,omitempty"` // empty = unset
	CurrentTTLMsec                      *int64           `json:"current_ttl_msec,omitempty"`
	CurrentScreenCaptureBlockingEnabled *bool            `json:"current_screen_capture_blocking_enabled,omitempty"`
}

// GroupCreateParams are the parameters for PrepareGroupCreate.
// SenderID and SigningKeyVersion are optional overrides: empty resolves from
// the session identity set via SetIdentity. Title is plaintext: the create
// encrypts it under the new conversation key. A create sets no avatar; set it
// afterwards with PrepareGroupAvatarChange.
type GroupCreateParams struct {
	SenderID          string           `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion string           `json:"signing_key_version,omitempty"` // empty = session identity
	PublicKeys        []PublicKeyInput `json:"public_keys"`
	ConversationID    string           `json:"conversation_id"`
	MemberIDs         []string         `json:"member_ids"`
	AdminIDs          []string         `json:"admin_ids"`
	Title             string           `json:"title,omitempty"` // empty = unset
	TTLMsec           *int64           `json:"ttl_msec,omitempty"`
}

// SetIdentityParams are the parameters for SetIdentity.
type SetIdentityParams struct {
	// UserID is your user ID: the sender of everything this chat signs.
	UserID string `json:"user_id"`
	// SigningKeyVersion is the public_key_version the X API returned when
	// your keys were registered.
	SigningKeyVersion string `json:"signing_key_version"`
}

// ImportKeysParams are the parameters for ImportKeys.
type ImportKeysParams struct {
	// Keys is the blob ExportKeys returned. It is passed to the native side
	// directly and never serialized.
	Keys []byte `json:"-"`
	// SigningKeyVersion is the public_key_version the X API returned when the
	// keys were registered; empty leaves the signing-key version unset.
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// EncryptMessageParams are the parameters for EncryptMessage.
//
// Only ConversationID and Text are required. The identity fields (SenderID,
// SigningKeyVersion) and key fields (ConversationKey, ConversationKeyVersion)
// are optional overrides: left at their zero value they resolve from the
// session identity (SetIdentity) and the opt-in key cache (SetCacheKeys).
// ConversationKey and ConversationKeyVersion travel together — set both or
// neither. Each file in Attachments names the media hash key its upload
// started with; encrypt the files afterwards with EncryptFile or
// FileEncryptor and the returned payload's EventB64. Upload each file for one
// message only: reusing another message's uploads can give this message that
// message's id.
type EncryptMessageParams struct {
	ConversationID         string                 `json:"conversation_id"`
	Text                   string                 `json:"text"`
	SenderID               string                 `json:"sender_id,omitempty"`                // empty = session identity
	SigningKeyVersion      string                 `json:"signing_key_version,omitempty"`      // empty = session identity
	ConversationKey        []byte                 `json:"conversation_key,omitempty"`         // raw 32-byte key; nil = key cache
	ConversationKeyVersion string                 `json:"conversation_key_version,omitempty"` // empty = key cache
	Entities               []EntityTuple          `json:"entities,omitempty"`
	Attachments            []AttachmentDescriptor `json:"attachments,omitempty"`
	QuickReply             *QuickReply            `json:"quick_reply,omitempty"`
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
	// full clickable preview card: start the image's upload to the
	// conversation's media store, reference the media hash key it returns
	// here, then encrypt the image with EncryptFile or FileEncryptor and the
	// message's EventB64 and finish the upload.
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
// either is missing on the wire. FilesizeBytes is the encrypted image's size,
// EncryptedFileSize of the image's size.
type URLAttachmentImageDescriptor struct {
	MediaHashKey  string `json:"media_hash_key"`
	FilesizeBytes int64  `json:"filesize_bytes"`
	Filename      string `json:"filename"`
	Width         *int64 `json:"width,omitempty"`
	Height        *int64 `json:"height,omitempty"`
}

// QuickReply is a quick reply carried by a text message: set exactly one of
// Request (offering selectable options) or Response (selecting one). The same
// type is decoded into TextContent.QuickReply, so a received value can be sent
// back unchanged.
type QuickReply struct {
	Request  *QuickReplyRequest  `json:"request,omitempty"`
	Response *QuickReplyResponse `json:"response,omitempty"`
}

// QuickReplyRequest offers a set of selectable options.
type QuickReplyRequest struct {
	Options QuickReplyOptionsRequest `json:"options"`
}

// QuickReplyResponse selects a previously offered option.
type QuickReplyResponse struct {
	Options QuickReplyOptionsResponse `json:"options"`
}

// QuickReplyOptionsRequest lists the options offered by a quick-reply request.
type QuickReplyOptionsRequest struct {
	ID      *string            `json:"id,omitempty"`
	Options []QuickReplyOption `json:"options,omitempty"`
}

// QuickReplyOptionsResponse identifies the option selected in a quick-reply response.
type QuickReplyOptionsResponse struct {
	RequestID        *string `json:"request_id,omitempty"`
	Metadata         *string `json:"metadata,omitempty"`
	SelectedOptionID *string `json:"selected_option_id,omitempty"`
}

// QuickReplyOption is a single selectable quick-reply option.
type QuickReplyOption struct {
	ID          *string `json:"id,omitempty"`
	Label       *string `json:"label,omitempty"`
	Metadata    *string `json:"metadata,omitempty"`
	Description *string `json:"description,omitempty"`
}

// EncryptReplyParams are the parameters for EncryptReply.
//
// The preferred reply target is ReplyToEvent — the base64 raw signed event
// being replied to — from which the SDK derives the reply preview (sequence
// id, sender, text, entities, attachments) and which it embeds so recipients
// can validate the preview. The explicit ReplyTo* field overrides remain for
// callers that no longer hold the raw event.
//
// The identity and key fields are optional overrides, and the reply's files
// work, as on EncryptMessageParams.
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
	ReplyToSenderID        string                 `json:"reply_to_sender_id,omitempty"`       // digits; empty = derived from ReplyToEvent
	ReplyToText            *string                `json:"reply_to_text,omitempty"`
	Entities               []EntityTuple          `json:"entities,omitempty"`
	Attachments            []AttachmentDescriptor `json:"attachments,omitempty"`
	ReplyToEntities        []EntityTuple          `json:"reply_to_entities,omitempty"`
	ReplyToAttachments     []AttachmentDescriptor `json:"reply_to_attachments,omitempty"`
	QuickReply             *QuickReply            `json:"quick_reply,omitempty"`
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

// ScreenCaptureChange is the setting signed by PrepareScreenCapture.
//
// Blocking names are the events X clients sign. Detection names are the
// events this SDK's verifier reconstructs.
type ScreenCaptureChange string

const (
	BlockingEnabled   ScreenCaptureChange = "BlockingEnabled"
	BlockingDisabled  ScreenCaptureChange = "BlockingDisabled"
	DetectionEnabled  ScreenCaptureChange = "DetectionEnabled"
	DetectionDisabled ScreenCaptureChange = "DetectionDisabled"
)

// GroupMembersRemoveParams are the parameters for PrepareGroupMembersRemove.
//
// PublicKeys are the identity keys of the members who stay: the call rotates
// the conversation key for them. Title and Description are the group's
// plaintext metadata; each one set is encrypted under the new key and signed
// with the removal as a key-rotation re-encryption.
type GroupMembersRemoveParams struct {
	// PublicKeys are the identity keys of the members who stay.
	PublicKeys     []PublicKeyInput `json:"public_keys"`
	ConversationID string           `json:"conversation_id"`
	// UserIDs are the user ids being removed.
	UserIDs           []string `json:"user_ids"`
	Title             string   `json:"title,omitempty"`       // empty = unset
	Description       string   `json:"description,omitempty"` // empty = unset
	SenderID          string   `json:"sender_id,omitempty"`
	SigningKeyVersion string   `json:"signing_key_version,omitempty"`
}

// GroupLeaveParams are the parameters for PrepareGroupLeave.
//
// Leave removes the sender and does not rotate the conversation key.
// PromoteAdminID adds an admin-promotion signature.
type GroupLeaveParams struct {
	ConversationID string `json:"conversation_id"`
	// PromoteAdminID is the user promoted to admin, when the sender is the only admin.
	PromoteAdminID string `json:"promote_admin_id,omitempty"`
	// ConversationKeyVersion is bound into the removal. Empty signs null.
	ConversationKeyVersion string `json:"conversation_key_version,omitempty"`
	SenderID               string `json:"sender_id,omitempty"`
	SigningKeyVersion      string `json:"signing_key_version,omitempty"`
}

// GroupTitleChangeParams are the parameters for PrepareGroupTitleChange.
//
// NewTitle is plaintext: the call encrypts it under the conversation key, the
// ConversationKey / ConversationKeyVersion pair or, both empty, the key cache.
type GroupTitleChangeParams struct {
	ConversationID         string `json:"conversation_id"`
	NewTitle               string `json:"new_title"`
	SenderID               string `json:"sender_id,omitempty"`                // empty = session identity
	SigningKeyVersion      string `json:"signing_key_version,omitempty"`      // empty = session identity
	ConversationKey        []byte `json:"conversation_key,omitempty"`         // raw 32-byte key; nil = key cache
	ConversationKeyVersion string `json:"conversation_key_version,omitempty"` // empty = key cache
}

// GroupAvatarChangeParams are the parameters for PrepareGroupAvatarChange.
//
// A group's avatar URL is not encrypted. NewAvatarURL is the media URL of the
// avatar image, which the app encrypts under the conversation key and uploads
// first; ConversationKeyVersion is the version of the key the image is
// encrypted under.
type GroupAvatarChangeParams struct {
	ConversationID         string `json:"conversation_id"`
	NewAvatarURL           string `json:"new_avatar_url"`
	ConversationKeyVersion string `json:"conversation_key_version"`
	SenderID               string `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion      string `json:"signing_key_version,omitempty"` // empty = session identity
}

// GroupDescriptionChangeParams are the parameters for PrepareGroupDescriptionChange.
//
// NewDescription is plaintext: the call encrypts it under the conversation key, the
// ConversationKey / ConversationKeyVersion pair or, both empty, the key cache.
type GroupDescriptionChangeParams struct {
	ConversationID         string `json:"conversation_id"`
	NewDescription         string `json:"new_description"`
	SenderID               string `json:"sender_id,omitempty"`                // empty = session identity
	SigningKeyVersion      string `json:"signing_key_version,omitempty"`      // empty = session identity
	ConversationKey        []byte `json:"conversation_key,omitempty"`         // raw 32-byte key; nil = key cache
	ConversationKeyVersion string `json:"conversation_key_version,omitempty"` // empty = key cache
}

// GroupAdminsAddParams are the parameters for PrepareGroupAdminsAdd.
type GroupAdminsAddParams struct {
	ConversationID    string   `json:"conversation_id"`
	UserIDs           []string `json:"user_ids"`
	SenderID          string   `json:"sender_id,omitempty"`
	SigningKeyVersion string   `json:"signing_key_version,omitempty"`
}

// GroupAdminsRemoveParams are the parameters for PrepareGroupAdminsRemove.
type GroupAdminsRemoveParams struct {
	ConversationID    string   `json:"conversation_id"`
	UserIDs           []string `json:"user_ids"`
	SenderID          string   `json:"sender_id,omitempty"`
	SigningKeyVersion string   `json:"signing_key_version,omitempty"`
}

// GroupInviteEnableParams are the parameters for PrepareGroupInviteEnable.
// A nil ExpiresAtMsec and an empty AffiliateID sign null.
type GroupInviteEnableParams struct {
	ConversationID    string `json:"conversation_id"`
	InviteURL         string `json:"invite_url"`
	ExpiresAtMsec     *int64 `json:"expires_at_msec,omitempty"`
	AffiliateID       string `json:"affiliate_id,omitempty"`
	SenderID          string `json:"sender_id,omitempty"`
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// GroupInviteDisableParams are the parameters for PrepareGroupInviteDisable.
// An empty DisabledBy uses the sender.
type GroupInviteDisableParams struct {
	ConversationID    string `json:"conversation_id"`
	DisabledBy        string `json:"disabled_by,omitempty"`
	SenderID          string `json:"sender_id,omitempty"`
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// GroupJoinRequestParams are the parameters for PrepareGroupJoinRequest.
// An empty RequestingUserID uses the sender. An invite token is not signed.
type GroupJoinRequestParams struct {
	ConversationID    string `json:"conversation_id"`
	RequestingUserID  string `json:"requesting_user_id,omitempty"`
	SenderID          string `json:"sender_id,omitempty"`
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// GroupJoinRejectParams are the parameters for PrepareGroupJoinReject.
type GroupJoinRejectParams struct {
	ConversationID    string   `json:"conversation_id"`
	UserIDs           []string `json:"user_ids"`
	SenderID          string   `json:"sender_id,omitempty"`
	SigningKeyVersion string   `json:"signing_key_version,omitempty"`
}

// MessageTtlChangeParams are the parameters for PrepareMessageTtlChange.
type MessageTtlChangeParams struct {
	ConversationID    string `json:"conversation_id"`
	TTLMsec           int64  `json:"ttl_msec"`
	SenderID          string `json:"sender_id,omitempty"`
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// MessageTtlRemoveParams are the parameters for PrepareMessageTtlRemove.
type MessageTtlRemoveParams struct {
	ConversationID    string `json:"conversation_id"`
	SenderID          string `json:"sender_id,omitempty"`
	SigningKeyVersion string `json:"signing_key_version,omitempty"`
}

// ScreenCaptureParams are the parameters for PrepareScreenCapture.
type ScreenCaptureParams struct {
	ConversationID    string              `json:"conversation_id"`
	Change            ScreenCaptureChange `json:"change"`
	SenderID          string              `json:"sender_id,omitempty"`
	SigningKeyVersion string              `json:"signing_key_version,omitempty"`
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

// MarkConversationReadParams are the parameters for
// PrepareMarkConversationRead.
//
// A read receipt is a signed plaintext event, not an encrypted message, so
// no conversation key is involved. SenderID and SigningKeyVersion are
// optional overrides: empty resolves from the session identity set via
// SetIdentity.
type MarkConversationReadParams struct {
	ConversationID string `json:"conversation_id"`
	// SeenUntilSequenceID is the sequence_id of the newest event read.
	SeenUntilSequenceID string `json:"seen_until_sequence_id"`
	// SeenAtMsec is when the conversation was read, in milliseconds since
	// the Unix epoch; nil takes the current time.
	SeenAtMsec        *int64 `json:"seen_at_msec,omitempty"`
	SenderID          string `json:"sender_id,omitempty"`           // empty = session identity
	SigningKeyVersion string `json:"signing_key_version,omitempty"` // empty = session identity
}

// DecryptEventParams are the parameters for DecryptEvent.
type DecryptEventParams struct {
	// EventB64 is the base64 event, as delivered.
	EventB64 string `json:"event_b64"`
	// ConversationKeys maps key version to the raw 32-byte conversation key,
	// from DecryptEvents or ExtractConversationKeys. Leave it nil for events
	// without message contents, or to take the keys from the opt-in key cache
	// (SetCacheKeys).
	ConversationKeys map[string][]byte `json:"conversation_keys"`
	// SigningKeys verify the event; nil or empty uses the keys stored via
	// SetSigningKeys.
	SigningKeys []SigningKeyEntry `json:"signing_keys,omitempty"`
}

// DecryptEventsParams are the parameters for DecryptEvents.
type DecryptEventsParams struct {
	// Events are the base64 events, as delivered. Their key changes supply
	// the conversation keys the messages among them are decrypted with.
	Events []string `json:"events"`
	// SigningKeys are the signing keys of all participants; nil or empty uses
	// the keys stored via SetSigningKeys.
	SigningKeys []SigningKeyEntry `json:"signing_keys,omitempty"`
}

// EncryptFileParams are the parameters for EncryptFile.
type EncryptFileParams struct {
	// File is the file to encrypt.
	File []byte `json:"file"`
	// EventB64 is the EventB64 of the payload that EncryptMessage or
	// EncryptReply returned for the message carrying the file.
	EventB64 string `json:"event_b64"`
	// MediaHashKey is the media hash key the file's upload started with, as
	// listed in the message's attachments.
	MediaHashKey string `json:"media_hash_key"`
	// ConversationKey is the raw 32-byte conversation key the message was
	// encrypted under; with ConversationKeyVersion empty too, it resolves from
	// the key cache, as for EncryptMessageParams.
	ConversationKey []byte `json:"conversation_key,omitempty"`
	// ConversationKeyVersion is the version of ConversationKey: the message's
	// key version.
	ConversationKeyVersion string `json:"conversation_key_version,omitempty"`
}

// FileEncryptorParams are the parameters for FileEncryptor: those of
// EncryptFile apart from the file, which is fed to the encryptor.
type FileEncryptorParams struct {
	EventB64               string `json:"event_b64"`
	MediaHashKey           string `json:"media_hash_key"`
	ConversationKey        []byte `json:"conversation_key,omitempty"`         // nil = key cache
	ConversationKeyVersion string `json:"conversation_key_version,omitempty"` // empty = key cache
}

// DecryptFileParams are the parameters for DecryptFile.
type DecryptFileParams struct {
	// Encrypted is the encrypted file, as downloaded.
	Encrypted []byte `json:"encrypted"`
	// EventB64 is the base64 event of the message that carries the file, as
	// passed to DecryptEvent.
	EventB64 string `json:"event_b64"`
	// ConversationKeys is the conversation's key map, as passed to
	// DecryptEvent; it must hold the key for the message's version.
	ConversationKeys map[string][]byte `json:"conversation_keys"`
	// MediaHashKey is the file's media hash key from the decrypted message: a
	// media attachment, a link card's banner or favicon, or media quoted in
	// its reply preview.
	MediaHashKey string `json:"media_hash_key"`
}

// FileDecryptorParams are the parameters for FileDecryptor: those of
// DecryptFile apart from the encrypted file, which is fed to the decryptor.
type FileDecryptorParams struct {
	EventB64         string            `json:"event_b64"`
	ConversationKeys map[string][]byte `json:"conversation_keys"`
	MediaHashKey     string            `json:"media_hash_key"`
}

// ActionSignature authenticates a conversation key change, group change,
// message delete, or read receipt. It is shaped as an entry of a request's
// action_signatures: the signature is nested under message_event_signature.
type ActionSignature struct {
	MessageID                 string                `json:"message_id"`
	EncodedMessageEventDetail string                `json:"encoded_message_event_detail"`
	MessageEventSignature     MessageEventSignature `json:"message_event_signature"`
	// SignaturePayload is the comma-separated payload that was signed;
	// empty for conversation-key changes, whose payload embeds the
	// plaintext conversation key.
	SignaturePayload string `json:"signature_payload,omitempty"`
}

// MessageEventSignature is the signature of an ActionSignature.
type MessageEventSignature struct {
	Signature        string `json:"signature"`
	SignatureVersion string `json:"signature_version"`
	PublicKeyVersion string `json:"public_key_version"`
	// SigningPublicKey is the signer's base64 signing public key, as
	// GetPublicKeys returns it.
	SigningPublicKey string `json:"signing_public_key"`
}

// PreparedAction is a signed message delete or read receipt: the
// action_signatures a request carries for it, one entry.
type PreparedAction struct {
	ActionSignatures []ActionSignature `json:"action_signatures"`
}

// PreparedGroupMetadataChange is a signed group title or description change,
// returned by PrepareGroupTitleChange and PrepareGroupDescriptionChange.
type PreparedGroupMetadataChange struct {
	// EncryptedValue is the value encrypted under the conversation key,
	// base64: the title or description the request sends.
	EncryptedValue string `json:"encrypted_value"`
	// ConversationKeyVersion is the version of the key the value is
	// encrypted under.
	ConversationKeyVersion string            `json:"conversation_key_version"`
	ActionSignatures       []ActionSignature `json:"action_signatures"`
}

// orEmpty returns a non-nil slice so JSON marshals it as [] rather than null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// orEmptyKeys returns a non-nil map so JSON marshals it as {} rather than
// null.
func orEmptyKeys(keys map[string][]byte) map[string][]byte {
	if keys == nil {
		return map[string][]byte{}
	}
	return keys
}

// orEmptyBytes returns a non-nil slice so JSON marshals it as "" rather
// than null.
func orEmptyBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
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
	Content                MessageContent       `json:"content"`
	ConversationKeyVersion *string              `json:"conversation_key_version,omitempty"`
	Verified               bool                 `json:"verified"`
	ShouldNotify           *bool                `json:"should_notify,omitempty"`
	TTLMsec                *int64               `json:"ttl_msec,omitempty"`
	Attachments            []json.RawMessage    `json:"attachments,omitempty"`
	MediaHashes            []MediaHashReference `json:"media_hashes,omitempty"`
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
	QuickReply        *QuickReply     `json:"quick_reply,omitempty"`
	CTAs              json.RawMessage `json:"ctas,omitempty"`
}

// ReactionContent contains the fields for a reaction message.
type ReactionContent struct {
	Emoji string `json:"emoji"`
	// TargetMessageSequenceID is the sequence_id of the message reacted to.
	TargetMessageSequenceID string `json:"target_message_sequence_id"`
}

// MediaHashReference is a reference to a media hash key found in attachments.
type MediaHashReference struct {
	Source       string `json:"source"`
	MediaHashKey string `json:"media_hash_key"`
}

// KeyChangeEvent indicates a conversation key rotation.
type KeyChangeEvent struct {
	EventMeta
	ConversationKeyVersion      string                       `json:"conversation_key_version"`
	ConversationParticipantKeys []ConversationParticipantKey `json:"conversation_participant_keys"`
	Verified                    bool                         `json:"verified"`
}

// FindKeyForUser returns the encrypted key for a specific user.
func (kc *KeyChangeEvent) FindKeyForUser(userID string) *ConversationParticipantKey {
	for i := range kc.ConversationParticipantKeys {
		if kc.ConversationParticipantKeys[i].UserID == userID {
			return &kc.ConversationParticipantKeys[i]
		}
	}
	return nil
}

// GroupChangeEvent indicates a group membership or settings change.
type GroupChangeEvent struct {
	EventMeta
	Change   json.RawMessage `json:"change"`
	Verified bool            `json:"verified"`
}

// GroupText is a group title or description as a received event carries it:
// the title of a Created group change, the new_title of a TitleChanged one and
// the new_description of a DescriptionChanged one. Kind "Text" carries Text:
// the value decrypted, or the plaintext an event that names no key version
// carries. Kind "Unavailable" carries Raw: a value the SDK could not decrypt,
// as the event carries it. 0.5.x apps sent titles as plaintext while naming a
// key version, so show Raw when a title isn't decryptable.
type GroupText struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

// TypingEvent indicates someone is typing.
type TypingEvent struct {
	EventMeta
}

// ReadReceiptEvent indicates a conversation was marked as read.
type ReadReceiptEvent struct {
	EventMeta
	// SeenUntilSequenceID is the sequence_id of the newest event read.
	SeenUntilSequenceID *string `json:"seen_until_sequence_id,omitempty"`
	SeenAtMsec          *int64  `json:"seen_at_msec,omitempty"`
	Verified            bool    `json:"verified"`
}
